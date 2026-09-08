"""
handlers/wpk.py — CSFPWPK: Wrap Key (service tag 18).

Request (from icsf_wrap_key() in icsf.c):

    WPKInput ::= SEQUENCE {
        wrappingHandle      OCTET STRING (44 bytes),
        wrappedKeyMaxLen    INTEGER,
        initialValue        OCTET STRING   (IV for CBC-PAD; empty for RSA)
    }

    Rule array: ["PKCS-8", "AES"] for AES-CBC-PAD
                ["PKCS-1.2"]      for RSA-PKCS (not currently exercised)

    Request handle: the key *to be wrapped* (icsf_object for the target key).
    The wrapping key handle is inside WPKInput as wrappingHandle.

Response:
    WPKOutput (inside the [18] context tag, no additional SEQUENCE wrapper):
        wrappedKey      OCTET STRING,
        wrappedKeyLen   INTEGER

    Client reads: ber_scanf(result, "{mi}", &bv_wrapped_key, &wrapped_key_len)
    where "{" enters the [18] context-constructed tag directly, then "m" and
    "i" consume the flat OCTET STRING and INTEGER fields.

Implementation
--------------
For PKCS-8 / AES-CBC-PAD wrapping:
  - Secret keys: plaintext = CKA_VALUE (raw key bytes).
  - RSA private keys: plaintext = PKCS#8 PrivateKeyInfo DER encoding of the
    RSA components (modulus, exponents, CRT fields), then AES-CBC-PAD encrypt.

The wrapping key is looked up by the wrappingHandle field in the request body,
not the request header handle (which identifies the key to be wrapped).
"""

import logging

from cipher_backend import aes_encrypt, AES_BLOCK
from rsa_backend import rsa_public_encrypt
from ber_codec import (
    encode_response, encode_octet_string, encode_integer,
    parse_handle, _decode_tlv, decode_integer, HANDLE_LEN,
    rsa_attrs_to_pkcs8, ec_attrs_to_pkcs8,
)
from pkcs11_const import CKA_VALUE, CKA_CLASS, CKO_PRIVATE_KEY, CKA_KEY_TYPE, CKK_EC

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPWPK = 18

RC_SUCCESS        = 0
RC_ERROR          = 8
RSN_OBJ_NOT_FOUND = 3025
RSN_TOO_SHORT     = 3003


def handle_wpk(store, request):
    """Process a CSFPWPK (Wrap Key) request."""
    # The request handle identifies the key TO BE WRAPPED.
    token_name, sequence, _ = parse_handle(request.handle)
    if not token_name or sequence == 0:
        logger.error('WPK: invalid target-key handle')
        return encode_response(request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPWPK, b'')

    target_obj = store.get_object(token_name, sequence)
    if target_obj is None:
        logger.warning('WPK: target key not found token=%r seq=%d', token_name, sequence)
        return encode_response(request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND, ICSF_TAG_CSFPWPK, b'')

    # For private keys the plaintext is a PKCS#8 DER blob; for all other key
    # types it is the raw CKA_VALUE.
    obj_class = target_obj.get_attr(CKA_CLASS)
    if isinstance(obj_class, bytes):
        obj_class = int.from_bytes(obj_class, 'big')
    if obj_class == CKO_PRIVATE_KEY:
        key_type = target_obj.get_attr(CKA_KEY_TYPE)
        if isinstance(key_type, bytes):
            key_type = int.from_bytes(key_type, 'big')
        if key_type == CKK_EC:
            target_key_value = ec_attrs_to_pkcs8(target_obj.attributes)
        else:
            target_key_value = rsa_attrs_to_pkcs8(target_obj.attributes)
    else:
        target_key_value = target_obj.get_attr(CKA_VALUE) or b''

    # Parse WPKInput: wrappingHandle OCTET STRING, wrappedKeyMaxLen INTEGER,
    #                 initialValue OCTET STRING
    try:
        pos = 0
        tag, wrapping_handle, pos = _decode_tlv(request.service_data, pos)
        tag, max_len_val, pos     = _decode_tlv(request.service_data, pos)
        max_len = decode_integer(max_len_val)
        tag, iv_bytes, pos        = _decode_tlv(request.service_data, pos)
    except Exception as exc:
        logger.warning('WPK: failed to decode WPKInput: %s', exc)
        return encode_response(request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPWPK, b'')

    # Determine wrapping algorithm from rule array
    is_rsa = any(rule.strip().upper() == 'PKCS-1.2'
                 for rule in request.rule_array)
    algo = 'AES'
    for rule in request.rule_array:
        if rule.upper() in ('AES', 'DES', 'DES3'):
            algo = rule.upper()
            break

    # Look up the wrapping key by its handle
    wrap_token, wrap_seq, _ = parse_handle(wrapping_handle)
    if not wrap_token or wrap_seq == 0:
        logger.warning('WPK: invalid wrapping handle')
        return encode_response(request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPWPK, b'')

    wrap_obj = store.get_object(wrap_token, wrap_seq)
    if wrap_obj is None:
        logger.warning('WPK: wrapping key not found token=%r seq=%d', wrap_token, wrap_seq)
        return encode_response(request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND, ICSF_TAG_CSFPWPK, b'')

    wrapping_key_value = wrap_obj.get_attr(CKA_VALUE) or b''

    try:
        if is_rsa:
            wrapped = rsa_public_encrypt(wrap_obj.attributes,
                                         target_key_value, 'PKCS1')
        else:
            # Encrypt the target key value with the wrapping key using
            # AES/DES CBC-PAD.
            iv = (iv_bytes or b'').ljust(AES_BLOCK, b'\x00')[:AES_BLOCK]
            wrapped = aes_encrypt(wrapping_key_value, target_key_value,
                                  'CBC-PAD', iv, algo=algo, pad=True)
    except Exception as exc:
        logger.error('WPK: encryption failed: %s', exc)
        return encode_response(request.handle, RC_ERROR, RC_ERROR, ICSF_TAG_CSFPWPK, b'')

    # Check size query (max_len == 0) or buffer too small
    if max_len == 0 or len(wrapped) > max_len:
        # Return the required size; client will re-call with a proper buffer
        # Fields are placed flat inside the context tag — no SEQUENCE wrapper.
        svc_data = (
            encode_octet_string(b'') +
            encode_integer(len(wrapped))
        )
        return encode_response(request.handle, RC_ERROR, RSN_TOO_SHORT,
                               ICSF_TAG_CSFPWPK, svc_data)

    # Build WPKOutput: wrappedKey OCTET STRING, wrappedKeyLen INTEGER
    # Fields are placed flat inside the context tag — no SEQUENCE wrapper.
    svc_data = (
        encode_octet_string(wrapped) +
        encode_integer(len(wrapped))
    )

    logger.info('WPK: token=%r target_seq=%d wrap_seq=%d algo=%s wrapped=%d',
                token_name, sequence, wrap_seq,
                'RSA-PKCS' if is_rsa else algo, len(wrapped))

    return encode_response(request.handle, RC_SUCCESS, 0, ICSF_TAG_CSFPWPK, svc_data)
