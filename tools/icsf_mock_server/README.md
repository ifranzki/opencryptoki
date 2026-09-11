# ICSF Mock LDAP Server

A self-contained Python 3 mock of the z/OS ICSF LDAP interface, designed to
let you run the openCryptoki ICSF token driver and the `pkcsicsf` configuration
tool without a real z/OS system.

## What it implements

### Phase 1 — token management (`pkcsicsf` tool)
| ICSF service | Tag | Operation |
|---|---|---|
| `CSFPTRC` | 14 | Create token (`TOKEN RECREATE`) |
| `CSFPTRD` | 15 | Destroy token (`TOKEN`) |
| `CSFPTRL` | 16 | List tokens (`TOKEN`) |

### Phase 2 — object management (ICSF token driver)
| ICSF service | Tag | Operation |
|---|---|---|
| `CSFPTRC` | 14 | Create object (`OBJECT`) |
| `CSFPTRD` | 15 | Destroy object (`OBJECT`) |
| `CSFPTRL` | 16 | List objects (`OBJECT`, `OBJECT ALL`) |
| `CSFPGAV` |  3 | Get object attributes |
| `CSFPSAV` | 11 | Set object attributes |

### Phase 3 — cryptographic operations
| ICSF service | Tag | Operation | Mock behaviour |
|---|---|---|---|
| `CSFPDMK` |  1 | Derive multiple keys (`CKM_SSL3_KEY_AND_MAC_DERIVE`, `CKM_TLS_KEY_AND_MAC_DERIVE`) | SSL3 / TLS key and MAC material derivation; returns 4 key handles + IVs |
| `CSFPDVK` |  2 | Derive key (EC-DH / `CKM_ECDH1_DERIVE`, SSL-MS / `CKM_SSL3_MASTER_KEY_DERIVE`) | real ECDH via OpenSSL `EVP_PKEY_derive`; X9.63 KDF; SSL 3.0 master secret derivation |
| `CSFPGSK` |  5 | Generate secret key (AES/DES/3DES) | `os.urandom` key material |
| `CSFPGKP` |  4 | Generate RSA/EC key pair | real key generation via libcrypto |
| `CSFPSKE` | 13 | Symmetric key encrypt | real AES-ECB/CBC/CBC-PAD (and DES/3DES) via libcrypto ctypes |
| `CSFPSKD` | 12 | Symmetric key decrypt | real AES-ECB/CBC/CBC-PAD (and DES/3DES) via libcrypto ctypes |
| `CSFPPKS` |  9 | Private key sign / RSA decrypt | XOR-pad with modulus |
| `CSFPPKV` | 10 | Public key verify / RSA encrypt | XOR-pad (verify always succeeds) |
| `CSFPHMG` |  6 | HMAC generate | real `hmac.new()` using stdlib |
| `CSFPHMV` |  7 | HMAC verify | real compare_digest; fails on mismatch |
| `CSFPWPK` | 18 | Wrap key | AES-CBC-PAD encrypt of target key value |
| `CSFPUWK` | 17 | Unwrap key | AES-CBC-PAD decrypt; creates new key object |

> **Note:** SKE/SKD use real AES/3DES (ECB, CBC, CBC-PAD) via OpenSSL
> `libcrypto` through `ctypes` — no third-party Python packages required.
> Known-answer tests (KATs) with published NIST vectors pass.
> WPK/UWK use the same AES-CBC-PAD path for key wrap/unwrap.
> DVK uses `EVP_PKEY_derive` for real ECDH — the same OpenSSL call used by
> `mech_ec.c` in the openCryptoki common library.
> PKS/PKV use XOR-with-modulus (not real RSA); HMAC uses Python's stdlib.

All state is in-memory.  Tokens and objects disappear when the server restarts.

Services not yet implemented (tags 1=DMK, 8=OWH)
return ICSF rc=8/reason=3000 so the token driver fails cleanly instead of
hanging.

## Requirements

- Python 3.8 or later
- **No third-party packages required.**  AES/3DES operations use OpenSSL's EVP
  API via `ctypes` — `libcrypto.so` is already present on any system running
  openCryptoki (it is a dependency of the LDAP stack).

## Quick start

### 1. Start the server

```sh
# Plain LDAP on 127.0.0.1:1389  (no root required)
python tools/icsf_mock_server/server.py --verbose

# Pre-create a token at startup:
python tools/icsf_mock_server/server.py --token MYTOKEN --verbose

# TLS (required for SASL EXTERNAL / certificate auth):
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout server.key -out server.crt -days 365 -subj '/CN=icsf-mock'
python tools/icsf_mock_server/server.py \
    --cert server.crt --key server.key --verbose
```

### 2. Configure the ICSF token

Edit (or create) your `opencryptoki.conf` ICSF slot stanza so that
`uri` points at the mock server:

```
slot 0 {
    stdll = libpkcs11_icsf.so
    confname = icsf.conf
}
```

In `icsf.conf` (default path `/etc/opencryptoki/icsf.conf` or wherever
`$PKCS11_SO_PIN` resolves to for your build):

```
uri        = ldap://127.0.0.1:1389
dn         = cn=testuser,dc=example,dc=com
mech       = simple
```

For SASL EXTERNAL:

```
uri        = ldap://127.0.0.1:1389
mech       = sasl
cert       = /path/to/client.crt
key        = /path/to/client.key
cacert     = /path/to/server.crt
```

### 3. Run `pkcsicsf`

```sh
# List available tokens on the mock server (any password accepted)
pkcsicsf -l \
  -u ldap://127.0.0.1:1389 \
  -b "cn=testuser,dc=example,dc=com" \
  -m simple

# Add a new slot backed by the mock token TESTTOKEN
pkcsicsf -a \
  -u ldap://127.0.0.1:1389 \
  -b "cn=testuser,dc=example,dc=com" \
  -m simple
```

### 4. Phase 2 — object management with the ICSF token driver

Pre-seed test objects at startup so `C_FindObjects` and
`C_GetAttributeValue` have something to return:

```sh
# Start with one token and a mix of test objects
python tools/icsf_mock_server/server.py \
  --token TESTTOKEN \
  --object TESTTOKEN:myaeskey:aes \
  --object TESTTOKEN:mydes3key:des3 \
  --object TESTTOKEN:myrsakey-pub:rsa-pub \
  --object TESTTOKEN:myrsakey-priv:rsa-priv \
  --object TESTTOKEN:myeckey-pub:ec-pub \
  --object TESTTOKEN:myeckey-priv:ec-priv \
  --object TESTTOKEN:mycert:cert \
  --verbose
```

`--object` format: `TOKEN:LABEL:CLASS` where CLASS is one of:
`aes`, `des3`, `rsa-pub`, `rsa-priv`, `ec-pub`, `ec-priv`, `cert`
(default `aes`).

Each pre-seeded object is created with **all** PKCS#11-defined attributes
for its class (common object attributes plus class-specific attributes),
using standard defaults for any attribute not explicitly supplied.

Once the slot is configured via `pkcsicsf -a`, use `pkcs11-tool`:

```sh
export PKCSLIB=/usr/local/lib/pkcs11/libopencryptoki.so
export SLOT=0
export PKCS11_USER_PIN=01234567
export PKCS11_SO_PIN=76543210

# List objects (triggers C_FindObjectsInit → TRL → GAV per object)
pkcs11-tool --module "$PKCSLIB" --slot $SLOT \
  --login --pin $PKCS11_USER_PIN --list-objects

# Create a new data object (triggers TRC OBJECT)
pkcs11-tool --module "$PKCSLIB" --slot $SLOT \
  --login --pin $PKCS11_USER_PIN \
  --write-object /etc/hostname --type data --label myhostname

# Delete an object (triggers TRD OBJECT)
pkcs11-tool --module "$PKCSLIB" --slot $SLOT \
  --login --pin $PKCS11_USER_PIN \
  --delete-object --type data --label myhostname
```

### 5. Phase 3 — crypto operations with the ICSF token driver

```sh
# Generate a new AES-256 key (triggers CSFPGSK)
pkcs11-tool --module "$PKCSLIB" --slot $SLOT \
  --login --pin $PKCS11_USER_PIN \
  --keygen --key-type AES:32 --label myaes

# Generate a 2048-bit RSA key pair (triggers CSFPGKP)
pkcs11-tool --module "$PKCSLIB" --slot $SLOT \
  --login --pin $PKCS11_USER_PIN \
  --keypairgen --key-type RSA:2048 --label myrsa

# Encrypt with AES (triggers CSFPSKE) and decrypt (triggers CSFPSKD)
echo -n "Hello world" | \
  pkcs11-tool --module "$PKCSLIB" --slot $SLOT \
  --login --pin $PKCS11_USER_PIN \
  --encrypt --mechanism AES-CBC --id <key-id> -o /tmp/enc.bin

pkcs11-tool --module "$PKCSLIB" --slot $SLOT \
  --login --pin $PKCS11_USER_PIN \
  --decrypt --mechanism AES-CBC --id <key-id> -i /tmp/enc.bin

# Sign with RSA (triggers CSFPPKS) and verify (triggers CSFPPKV)
echo -n "Hello world" | \
  pkcs11-tool --module "$PKCSLIB" --slot $SLOT \
  --login --pin $PKCS11_USER_PIN \
  --sign --mechanism SHA256-RSA-PKCS --id <key-id> -o /tmp/sig.bin

# HMAC-SHA256 (triggers CSFPHMG and CSFPHMV via p11sak or custom test)
```

### 6. Debugging

Run with `--verbose` to get DEBUG-level logs including hex dumps of every
ICSF request and response payload — invaluable for diagnosing BER encoding
mismatches:

```sh
python tools/icsf_mock_server/server.py --token TESTTOKEN --verbose 2>&1 | tee mock.log
```

## Architecture

```
tools/icsf_mock_server/
├── server.py          LDAPv3 TCP listener, message framing, op dispatch
├── ber_codec.py       BER encode/decode for ICSF request/response envelopes
├── token_store.py     Thread-safe in-memory token and object registry
├── pkcs11_const.py    PKCS#11 CKA_*/CKO_*/CKK_*/CKM_* constants
├── obj_attrs.py       PKCS#11-compliant attribute completion for all object classes
└── handlers/
    ├── __init__.py
    ├── dvk.py         CSFPDVK — derive key (EC-DH)         (tag 2)
    ├── trc.py         CSFPTRC — create token/object        (tag 14)
    ├── trd.py         CSFPTRD — destroy token/object       (tag 15)
    ├── trl.py         CSFPTRL — list tokens/objects        (tag 16)
    ├── gav.py         CSFPGAV — get attribute value        (tag 3)
    ├── sav.py         CSFPSAV — set attribute value        (tag 11)
    ├── gsk.py         CSFPGSK — generate secret key        (tag 5)
    ├── gkp.py         CSFPGKP — generate key pair          (tag 4)
    ├── ske.py         CSFPSKE — symmetric key encrypt      (tag 13)
    ├── skd.py         CSFPSKD — symmetric key decrypt      (tag 12)
    ├── pks.py         CSFPPKS — private key sign/decrypt   (tag 9)
    ├── pkv.py         CSFPPKV — public key verify/encrypt  (tag 10)
    ├── hmg.py         CSFPHMG — HMAC generate              (tag 6)
    └── hmv.py         CSFPHMV — HMAC verify                (tag 7)
```

### Wire protocol summary

Every ICSF call is an LDAPv3 **ExtendedRequest** with OID `1.3.18.0.2.12.83`.
The request body and response body are DER-encoded sequences containing:

- A 44-byte **handle** (token name padded to 32 bytes + 8-byte hex sequence
  number + 1-byte object type `'T'`/`'S'` + 3 bytes padding)
- A **rule array** of 8-byte space-padded keyword items (`TOKEN`, `OBJECT`,
  `RECREATE`, `ALL`, `KEY`, `AES`, `DES3`, `ONLY`, `SHA-256`, etc.)
- A **service-tag-specific** context-constructed TLV whose tag number
  identifies the ICSF service (2=DVK, 3=GAV, 4=GKP, 5=GSK, 6=HMG, 7=HMV,
  9=PKS, 10=PKV, 11=SAV, 12=SKD, 13=SKE, 14=TRC, 15=TRD, 16=TRL, …)

See [`ber_codec.py`](ber_codec.py) for the full encoding and
[`usr/lib/icsf_stdll/icsf.c`](../../usr/lib/icsf_stdll/icsf.c) for the
authoritative client-side reference.

## Limitations

- No persistent storage.  Restart = empty state.
- Authentication is always accepted (suitable for testing only).
- Only `ldap://` URIs tested; TLS (`ldaps://`) works with `--cert`/`--key`
  but StartTLS (`ldap://` + STARTTLS) is not implemented.
- Concurrent connections are fully supported (one thread per connection).
- No LDAP access-control.  Any bind DN is accepted.
- SKE/SKD/WPK/UWK use real AES-CBC-PAD (NIST KAT-compatible).  PKS/PKV still
  use XOR-with-modulus placeholders; not suitable for RSA KATs.
- DVK supports the six KDFs documented by ICSF z/OS: `CKD_NULL`,
  `CKD_SHA1_KDF`, `CKD_SHA224_KDF`, `CKD_SHA256_KDF`, `CKD_SHA384_KDF`,
  `CKD_SHA512_KDF` (all via ANSI X9.63).  PKCS-DH and SSL/TLS derive
  variants are not implemented.
- Multi-part HMAC (FIRST/MIDDLE/LAST chaining) is stateless — each call is
  independent so multi-part HMG/HMV will produce wrong HMAC values.
- EC key pair generation produces real EC key material via OpenSSL.
  RSA key pair generation uses the same real-RSA backend.
