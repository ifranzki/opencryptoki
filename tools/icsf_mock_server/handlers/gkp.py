"""
handlers/gkp.py — CSFPGKP: Generate Key Pair (service tag 4).

Request (from icsf_generate_key_pair() in icsf.c):

    GKPInput ::= SEQUENCE {
        publicKeyAttrList   Attributes,
        privateKeyAttrList  Attributes
    }

    Each attribute list is written by icsf_ber_put_attribute_list() as a
    SEQUENCE-OF-SEQUENCE directly (no extra wrapper).

Response:
    GKPOutput ::= privateKeyHandle  OCTET STRING (44 bytes)

    The *public* key handle is returned in the common header handle field.
    The *private* key handle is the first (and only) field in the service data.

The mock generates a key pair using os.urandom for the key material
(not a real RSA/EC key, but sufficient to satisfy attribute size probes
and round-trip test the mock sign/verify handlers).  All PKCS#11-defined
attributes for the key class are stored with appropriate defaults.
"""

import logging

from ber_codec import (
    encode_response,
    make_object_handle, parse_handle,
    decode_attribute_list, encode_sequence, HANDLE_LEN,
    _decode_tlv
)
from token_store import OBJ_TYPE_TOKEN
from pkcs11_const import (
    CKA_KEY_TYPE, CKA_TOKEN,
    CKA_MODULUS, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT,
    CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2,
    CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT,
    CKA_PRIME, CKA_BASE,
    CKO_PUBLIC_KEY, CKO_PRIVATE_KEY,
    CKK_RSA, CKK_DH, CKK_EC,
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_DH_PKCS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN,
    CKA_EC_PARAMS, CKA_EC_POINT, CKA_VALUE,
)
import secrets
from obj_attrs import (
    make_rsa_keypair_attrs,
    make_ec_keypair_attrs,
    make_dh_keypair_attrs,
)
from rsa_backend import rsa_generate
from ec_backend import ec_generate, CurveNotSupportedError
from dh_backend import dh_generate

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPGKP = 4

RC_SUCCESS           = 0
RC_ERROR             = 8
RSN_TOKEN_NOT_FOUND  = 3024
RSN_INVALID_ATTR     = 3003


def handle_gkp(store, request):
    """
    Process a CSFPGKP request.

    Parameters
    ----------
    store   : TokenStore
    request : ICSFRequest

    Returns
    -------
    bytes — raw BER responseValue
    """
    token_name, _, _ = parse_handle(request.handle)
    if not token_name:
        logger.error('GKP: empty token name in handle')
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPGKP, b'')

    if not store.token_exists(token_name):
        logger.error('GKP: token %r not found', token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPGKP, b'')

    # service_data = GKPInput contents (two consecutive attribute list SEQUENCEs)
    pub_attrs  = []
    priv_attrs = []
    try:
        pos = 0
        # First SEQUENCE = public key attrs
        tag, pub_seq_val, pos = _decode_tlv(request.service_data, pos)
        pub_attrs = decode_attribute_list(encode_sequence(pub_seq_val))
        # Second SEQUENCE = private key attrs
        tag, priv_seq_val, pos = _decode_tlv(request.service_data, pos)
        priv_attrs = decode_attribute_list(encode_sequence(priv_seq_val))
    except Exception as exc:
        logger.warning('GKP: could not decode attribute lists: %s', exc)

    pub_dict  = {t: v for t, v in pub_attrs}
    priv_dict = {t: v for t, v in priv_attrs}

    # Determine key type from public key attrs (canonical source)
    key_type = pub_dict.get(CKA_KEY_TYPE)
    if isinstance(key_type, bytes):
        key_type = int.from_bytes(key_type, 'big')

    # Token persistence
    is_pub_token  = _is_token_obj(pub_dict)
    is_priv_token = _is_token_obj(priv_dict)
    pub_obj_type  = OBJ_TYPE_TOKEN if is_pub_token  else 'S'
    priv_obj_type = OBJ_TYPE_TOKEN if is_priv_token else 'S'

    if key_type == CKK_EC:
        try:
            pub_final, priv_final = _build_ec_attrs(pub_attrs, priv_attrs, pub_dict)
        except CurveNotSupportedError as exc:
            logger.warning('GKP: curve not supported: %s', exc)
            # rc=8 / reason=874 → CKR_CURVE_NOT_SUPPORTED in icsf_to_ock_err.
            return encode_response(
                request.handle, RC_ERROR, 874, ICSF_TAG_CSFPGKP, b'')
    elif key_type == CKK_DH:
        pub_final, priv_final = _build_dh_attrs(pub_attrs, priv_attrs, pub_dict)
    else:
        # Default to RSA for unknown key types
        pub_final, priv_final = _build_rsa_attrs(pub_attrs, priv_attrs, pub_dict)

    pub_obj = store.create_object(token_name, pub_obj_type, pub_final)
    if pub_obj is None:
        logger.error('GKP: failed to create public key in token %r', token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPGKP, b'')

    priv_obj = store.create_object(token_name, priv_obj_type, priv_final)
    if priv_obj is None:
        logger.error('GKP: failed to create private key in token %r', token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPGKP, b'')

    pub_handle  = make_object_handle(token_name, pub_obj.sequence,  pub_obj_type)
    priv_handle = make_object_handle(token_name, priv_obj.sequence, priv_obj_type)

    logger.info('GKP: token=%r pub_seq=%d priv_seq=%d key_type=0x%x pub_attrs=%d priv_attrs=%d',
                token_name, pub_obj.sequence, priv_obj.sequence,
                key_type if key_type else 0,
                len(pub_final), len(priv_final))

    # GKPOutput: the private key handle as a raw OCTET STRING.
    # icsf_generate_key_pair() reads the service context TLV value directly with
    # ber_scanf(result, "m", &bv_priv_handle) — "m" reads the raw bytes of the
    # *current* TLV value (the context tag).  The svc_data therefore IS the
    # 44-byte handle verbatim; no inner OCTET STRING wrapper is added.
    svc_data = priv_handle
    return encode_response(pub_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPGKP, svc_data)


# ---------------------------------------------------------------------------
# RSA key pair builders
# ---------------------------------------------------------------------------

def _build_rsa_attrs(pub_attrs, priv_attrs, pub_dict):
    """Generate a real RSA key pair and build complete attribute lists."""
    mod_bits = pub_dict.get(CKA_MODULUS_BITS, 2048)
    if isinstance(mod_bits, bytes):
        mod_bits = int.from_bytes(mod_bits, 'big')

    key = rsa_generate(mod_bits)

    # Inject all CRT components into the private-key caller attrs so that
    # make_rsa_keypair_attrs / complete_key_attrs stores them on the object.
    priv_extra = [
        (CKA_PRIVATE_EXPONENT, key[CKA_PRIVATE_EXPONENT]),
        (CKA_PRIME_1,          key[CKA_PRIME_1]),
        (CKA_PRIME_2,          key[CKA_PRIME_2]),
        (CKA_EXPONENT_1,       key[CKA_EXPONENT_1]),
        (CKA_EXPONENT_2,       key[CKA_EXPONENT_2]),
        (CKA_COEFFICIENT,      key[CKA_COEFFICIENT]),
    ]

    return make_rsa_keypair_attrs(
        pub_caller_attrs=pub_attrs,
        priv_caller_attrs=list(priv_attrs) + priv_extra,
        modulus=key[CKA_MODULUS],
        public_exponent=key[CKA_PUBLIC_EXPONENT],
        key_gen_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN,
    )


# ---------------------------------------------------------------------------
# EC key pair builders
# ---------------------------------------------------------------------------

# NIST P-256 OID: 1.2.840.10045.3.1.7 (DER encoded)
_P256_PARAMS = bytes.fromhex('06082a8648ce3d030107')


def _build_ec_attrs(pub_attrs, priv_attrs, pub_dict):
    """Generate a real EC key pair and build complete attribute lists."""
    ec_params = pub_dict.get(CKA_EC_PARAMS) or _P256_PARAMS
    key = ec_generate(ec_params)

    # Inject the private scalar into the private-key caller attrs so that
    # make_ec_keypair_attrs / complete_key_attrs stores it on the object.
    priv_extra = [(CKA_VALUE, key[CKA_VALUE])]

    return make_ec_keypair_attrs(
        pub_caller_attrs=pub_attrs,
        priv_caller_attrs=list(priv_attrs) + priv_extra,
        ec_params=key[CKA_EC_PARAMS],
        ec_point=key[CKA_EC_POINT],
        key_gen_mechanism=CKM_EC_KEY_PAIR_GEN,
    )


# ---------------------------------------------------------------------------
# DH key pair builders
# ---------------------------------------------------------------------------

def _build_dh_attrs(pub_attrs, priv_attrs, pub_dict):
    """Generate a DH key pair from domain parameters (p, g) and build attribute lists."""
    prime_bytes = pub_dict.get(CKA_PRIME, b'')
    base_bytes  = pub_dict.get(CKA_BASE, b'')

    if not prime_bytes:
        # Fallback default 1024-bit MODP prime if unspecified
        prime_int = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE653E0"
            "FF2F0B20DF253F3F", 16
        )
        prime_len = (prime_int.bit_length() + 7) // 8
        prime_bytes = prime_int.to_bytes(prime_len, 'big')

    if not base_bytes:
        base_bytes = b'\x02'

    try:
        key = dh_generate(prime_bytes, base_bytes)
        pub_value = key['pub_value']
        priv_value = key['priv_value']
    except Exception as exc:
        logger.warning('GKP: OpenSSL dh_generate failed (%s), falling back to python pow: ', exc)
        prime_int = int.from_bytes(prime_bytes, 'big')
        prime_len = len(prime_bytes)
        base_int = int.from_bytes(base_bytes, 'big')
        x_int = secrets.randbelow(prime_int - 3) + 2
        y_int = pow(base_int, x_int, prime_int)
        priv_value = x_int.to_bytes(prime_len, 'big')
        pub_value  = y_int.to_bytes(prime_len, 'big')

    return make_dh_keypair_attrs(
        pub_caller_attrs=pub_attrs,
        priv_caller_attrs=priv_attrs,
        prime=prime_bytes,
        base=base_bytes,
        pub_value=pub_value,
        priv_value=priv_value,
        key_gen_mechanism=CKM_DH_PKCS_KEY_PAIR_GEN,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_token_obj(attr_dict):
    v = attr_dict.get(CKA_TOKEN, b'\x00')
    return bool(v[0] if isinstance(v, bytes) else v)
