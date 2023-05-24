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

#define P11KMIP_CONFIG_KEYWORD_ATTRIBUTE     "attribute"
#define P11KMIP_CONFIG_KEYWORD_NAME          "name"
#define P11KMIP_CONFIG_KEYWORD_ID            "id"
#define P11KMIP_CONFIG_KEYWORD_TYPE          "type"

#define P11KMIP_CONFIG_TYPE_BOOL             "CK_BBOOL"
#define P11KMIP_CONFIG_TYPE_ULONG            "CK_ULONG"
#define P11KMIP_CONFIG_TYPE_BYTE             "CK_BYTE"
#define P11KMIP_CONFIG_TYPE_DATE             "CK_DATE"

#define UNUSED(var)             ((void)(var))

#define MAX_PRINT_LINE_LENGTH   80
#define PRINT_INDENT_POS        35

#define FIND_OBJECTS_COUNT      64
#define LIST_KEYTYPE_CELL_SIZE  22

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

#endif