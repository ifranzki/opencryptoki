/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef P11KMIP_H_
#define P11KMIP_H_

#include "pkcs11types.h"
#include "ec_curves.h"
#include <kmipclient/kmipclient.h>

#define P11KMIP_DEFAULT_PKCS11_LIB           "libopencryptoki.so";
#define P11KMIP_PKCSLIB_ENV_NAME             "PKCSLIB"
#define PKCS11_USER_PIN_ENV_NAME             "PKCS11_USER_PIN"
#define PKCS11_PEM_PASSWORD_ENV_NAME         "PKCS11_PEM_PASSWORD"
#define P11KMIP_DEFAULT_CONF_FILE_ENV_NAME   "P11KMIP_DEFAULT_CONF_FILE"
#define P11KMIP_CONFIG_FILE_NAME             "p11kmip_defined_attrs.conf"
#define P11KMIP_DEFAULT_CONFIG_FILE          OCK_CONFDIR "/" P11KMIP_CONFIG_FILE_NAME

#define P11KMIP_CONFIG_KEYWORD_SERVER        "server"
#define P11KMIP_CONFIG_KEYWORD_HOST          "host"
#define P11KMIP_CONFIG_KEYWORD_PORT          "port"
#define P11KMIP_CONFIG_KEYWORD_CLIENT_CERT   "tls_client_cert"
#define P11KMIP_CONFIG_KEYWORD_CLIENT_KEY    "tls_client_key"
#define P11KMIP_CONFIG_KEYWORD_WRAP_KEY_FMT  "wrap_key_format"
#define P11KMIP_CONFIG_KEYWORD_WRAP_KEY_ALG  "wrap_key_algorithm"
#define P11KMIP_CONFIG_KEYWORD_WRAP_KEY_SIZE "wrap_key_size"
#define P11KMIP_CONFIG_KEYWORD_WRAP_PAD_MTHD "wrap_padding_method"
#define P11KMIP_CONFIG_KEYWORD_WRAP_HASH_ALG "wrap_hashing_algorithm"

#define P11KMIP_CONFIG_VALUE_KEY_ALG_RSA     "RSA"
#define P11KMIP_CONFIG_VALUE_FMT_PKCS1       "PKCS1"
#define P11KMIP_CONFIG_VALUE_FMT_PKCS8       "PKCS8"
#define P11KMIP_CONFIG_VALUE_FMT_TRANSPARENT "TransparentPublicKey"
#define P11KMIP_CONFIG_VALUE_METHD_PKCS15    "PKCS1.5"
#define P11KMIP_CONFIG_VALUE_METHD_OAEP      "OAEP"
#define P11KMIP_CONFIG_VALUE_HSH_ALG_SHA_1   "SHA-1"
#define P11KMIP_CONFIG_VALUE_HSH_ALG_SHA_256 "SHA-256"

#define UNUSED(var)             ((void)(var))

#define OPT_FORCE_PIN_PROMPT    256
#define OPT_DETAILED_URI        257
#define OPT_FORCE_PEM_PWD_PROMPT 258

#define MAX_PRINT_LINE_LENGTH   80
#define PRINT_INDENT_POS        35

#define FIND_OBJECTS_COUNT      64
#define LIST_KEYTYPE_CELL_SIZE  22

#define MAX_SYM_CLEAR_KEY_SIZE  64

/* CLI Struct definitions */

enum p11kmip_arg_type {
    ARG_TYPE_PLAIN = 0, /* no argument */
    ARG_TYPE_STRING = 1,
    ARG_TYPE_ENUM = 2,
    ARG_TYPE_NUMBER = 3,
};

struct p11kmip_enum_value {
    const char *value;
    const struct p11kmip_arg *args;
    union {
        const void *ptr;
        CK_ULONG num;
    } private;
    char **any_value; /* if this is not NULL then this enum value matches to
                         any string, and the string is set into any_value */
};

struct p11kmip_arg {
    const char *name;
    enum p11kmip_arg_type type;
    bool required;
    bool case_sensitive;
    const struct p11kmip_enum_value *enum_values;
    union {
        bool *plain;
        char **string;
        struct p11kmip_enum_value **enum_value;
        CK_ULONG *number;
    } value;
    bool (*is_set)(const struct p11kmip_arg *arg);
    const char *description;
};

struct p11kmip_opt {
    char short_opt; /* 0 if no short option is used */
    const char *long_opt; /* NULL if no long option */
    int long_opt_val; /* Used only if short_opt is 0 */
    bool required;
    struct p11kmip_arg arg;
    const char *description;
};

struct p11kmip_cmd {
    const char *cmd;
    const char *cmd_short1;
    const char *cmd_short2;
    CK_RV (*func)(void);
    const struct p11kmip_opt *opts;
    const struct p11kmip_arg *args;
    const char *description;
    void (*help)(void);
    CK_FLAGS session_flags;
};

/* Key object struct definitions */
struct p11kmip_keytype {
    const char *name;
    CK_KEY_TYPE type;
    CK_OBJECT_CLASS class;
    const char *ckk_name;
    CK_MECHANISM keygen_mech;
    bool is_asymmetric;
    bool sign_verify;
    bool encrypt_decrypt;
    bool wrap_unwrap;
    bool derive;
    CK_RV (*keygen_prepare)(const struct p11kmip_keytype *keytype,
                            void **private);
    void (*keygen_cleanup)(const struct p11kmip_keytype *keytype, void *private);
    CK_RV (*keygen_get_key_size)(const struct p11kmip_keytype *keytype,
                                 void *private, CK_ULONG *keysize);
    CK_RV (*keygen_add_secret_attrs)(const struct p11kmip_keytype *keytype,
                                     CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                     void *private);
    CK_RV (*keygen_add_public_attrs)(const struct p11kmip_keytype *keytype,
                                     CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                     void *private);
    CK_RV (*keygen_add_private_attrs)(const struct p11kmip_keytype *keytype,
                                      CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                      void *private);
    CK_ATTRIBUTE_TYPE filter_attr;
    CK_ULONG filter_value;
    CK_ATTRIBUTE_TYPE keysize_attr;
    bool keysize_attr_value_len;
    CK_ULONG (*key_keysize_adjust)(const struct p11kmip_keytype *keytype,
                                   CK_ULONG keysize);
    const struct p11kmip_attr *secret_attrs;
    const struct p11kmip_attr *public_attrs;
    const struct p11kmip_attr *private_attrs;
    CK_RV (*import_check_sym_keysize)(const struct p11kmip_keytype *keytype,
                                      CK_ULONG keysize);
    CK_RV (*import_sym_clear)(const struct p11kmip_keytype *keytype,
                              CK_BYTE *data, CK_ULONG data_len,
                              CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs);
    CK_RV (*import_asym_pkey)(const struct p11kmip_keytype *keytype,
                              EVP_PKEY *pkey, bool private,
                              CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs);
    CK_RV (*import_asym_pem_data)(const struct p11kmip_keytype *keytype,
                                  unsigned char *data, size_t data_len,
                                  bool private, CK_ATTRIBUTE **attrs,
                                  CK_ULONG *num_attrs);
    CK_RV (*export_sym_clear)(const struct p11kmip_keytype *keytype,
                              CK_BYTE **data, CK_ULONG* data_len,
                              CK_OBJECT_HANDLE key, const char *label);
    CK_RV (*export_asym_pkey)(const struct p11kmip_keytype *keytype,
                              EVP_PKEY **pkey, bool private,
                              CK_OBJECT_HANDLE key, const char *label);
    CK_RV (*export_asym_pem_data)(const struct p11kmip_keytype *keytype,
                                  unsigned char **data, size_t *data_len,
                                  bool private, CK_OBJECT_HANDLE key,
                                  const char *label);
    const char *pem_name_private;
    const char *pem_name_public;
};

struct p11kmip_class {
    const char *name;
    CK_OBJECT_CLASS class;
};

struct p11kmip_custom_attr_type {
    const char *type;
    void (*print_long)(const char *attr, const CK_ATTRIBUTE *val,
                       int indent, bool sensitive);
};

#define P11KMIP_P11_UNKNOWN_ALG                0xFFFFFFFF
#define P11KMIP_KMIP_UNKNOWN_ALG               0xFF
#define P11KMIP_P11_KMIP_ALG_TABLE_LENGTH      13
#define P11KMIP_KMIP_P11_ALG_TABLE_LENGTH      32

const CK_KEY_TYPE P11KMIP_KMIP_P11_ALG_TABLE[13] = {
    CKK_DES,
    CKK_DES3,
    CKK_AES,
    CKK_RSA,
    CKK_DSA,
    CKK_ECDSA,
    P11KMIP_P11_UNKNOWN_ALG, // KMIP_CRYPTO_ALGO_HMAC_SHA1
    P11KMIP_P11_UNKNOWN_ALG, // KMIP_CRYPTO_ALGO_HMAC_SHA224
    P11KMIP_P11_UNKNOWN_ALG, // KMIP_CRYPTO_ALGO_HMAC_SHA256
    P11KMIP_P11_UNKNOWN_ALG, // KMIP_CRYPTO_ALGO_HMAC_SHA384
    P11KMIP_P11_UNKNOWN_ALG, // KMIP_CRYPTO_ALGO_HMAC_SHA512
    P11KMIP_P11_UNKNOWN_ALG, // KMIP_CRYPTO_ALGO_HMAC_MD5
    CKK_DH
};

const enum kmip_crypto_algo P11KMIP_P11_KMIP_ALG_TABLE[32] = {
    KMIP_CRYPTO_ALGO_RSA,
    KMIP_CRYPTO_ALGO_DSA,
    KMIP_CRYPTO_ALGO_DH,
    KMIP_CRYPTO_ALGO_ECDSA,
    P11KMIP_KMIP_UNKNOWN_ALG, // CKK_X_42_DH
    P11KMIP_KMIP_UNKNOWN_ALG, // CKK_KEA
    P11KMIP_KMIP_UNKNOWN_ALG, // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG, // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG, // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG, // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG, // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG, // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG, // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG, // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG, // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG, // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG, // CKK_GENERIC_SECRET
    KMIP_CRYPTO_ALGO_RC2,
    KMIP_CRYPTO_ALGO_RC4,
    KMIP_CRYPTO_ALGO_DES,
    P11KMIP_KMIP_UNKNOWN_ALG, // CKK_DES2
    KMIP_CRYPTO_ALGO_3DES,
    P11KMIP_KMIP_UNKNOWN_ALG, // CKK_CAST
    P11KMIP_KMIP_UNKNOWN_ALG, // CKK_CAST3
    KMIP_CRYPTO_ALGO_CAST5,
    KMIP_CRYPTO_ALGO_RC5,
    KMIP_CRYPTO_ALGO_IDEA,
    KMIP_CRYPTO_ALGO_SKIPJACK,
    P11KMIP_KMIP_UNKNOWN_ALG, // CKK_BATON
    P11KMIP_KMIP_UNKNOWN_ALG, // CKK_JUNIPER
    P11KMIP_KMIP_UNKNOWN_ALG, // CKK_CDMF
    KMIP_CRYPTO_ALGO_AES
};

#define P11KMIP_P11_KMIP_OBJ_TABLE_LENGTH      10
#define P11KMIP_KMIP_P11_OBJ_TABLE_LENGTH      10
#define P11KMIP_P11_UNKNOWN_OBJ                0xFFFFFFFF
#define P11KMIP_KMIP_UNKNOWN_OBJ                0xFF

const CK_OBJECT_CLASS P11KMIP_P11_KMIP_OBJ_TABLE[10] = {
    P11KMIP_P11_UNKNOWN_OBJ, // Undefined
    CKO_CERTIFICATE,
    CKO_SECRET_KEY,
    CKO_PUBLIC_KEY,
    CKO_PRIVATE_KEY,
    P11KMIP_P11_UNKNOWN_OBJ, // KMIP_OBJECT_TYPE_SPLIT_KEY
    P11KMIP_P11_UNKNOWN_OBJ, // KMIP_OBJECT_TYPE_TEMPLATE
    P11KMIP_P11_UNKNOWN_OBJ, // KMIP_OBJECT_TYPE_SECRET_DATA
    P11KMIP_P11_UNKNOWN_OBJ, // KMIP_OBJECT_TYPE_OPAQUE_OBJECT
    P11KMIP_P11_UNKNOWN_OBJ, // KMIP_OBJECT_TYPE_PGP_KEY
    P11KMIP_P11_UNKNOWN_OBJ  // KMIP_OBJECT_TYPE_CERTIFICATE_REQUEST
};

const enum kmip_object_type P11KMIP_KMIP_P11_OBJ_TABLE[10] = {
    P11KMIP_KMIP_UNKNOWN_OBJ, // CKO_DATA
    KMIP_OBJECT_TYPE_CERTIFICATE,
    KMIP_OBJECT_TYPE_PUBLIC_KEY,
    KMIP_OBJECT_TYPE_PRIVATE_KEY,
    KMIP_OBJECT_TYPE_SYMMETRIC_KEY,
    P11KMIP_KMIP_UNKNOWN_OBJ, // CKO_HW_FEATURE
    P11KMIP_KMIP_UNKNOWN_OBJ, // CKO_DOMAIN_PARAMETERS
    P11KMIP_KMIP_UNKNOWN_OBJ, // Undefined
    P11KMIP_KMIP_UNKNOWN_OBJ, // Undefined
    P11KMIP_KMIP_UNKNOWN_OBJ, // Undefined
    P11KMIP_KMIP_UNKNOWN_OBJ  // CKO_PROFILE
};

#endif