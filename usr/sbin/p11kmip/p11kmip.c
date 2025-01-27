/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <err.h>
#include <limits.h>
#include <dlfcn.h>
#include <pwd.h>
#include <ctype.h>
#include <fnmatch.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "p11kmip.h"
#include "p11util.h"
#include "pin_prompt.h"
#include "cfgparser.h"
#include "configuration.h"
#include "mechtable.h"
#include "defs.h"
#include "uri.h"

#if OPENSSL_VERSION_PREREQ(3, 0)
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/param_build.h>
#endif

/*****************************************************************************/
/* Global Variables                                                          */
/*****************************************************************************/

/* PKCS11 */
static void *pkcs11_lib = NULL;
static bool pkcs11_initialized = false;
static CK_FUNCTION_LIST *pkcs11_funcs = NULL;
static CK_SESSION_HANDLE pkcs11_session = CK_INVALID_HANDLE;
static CK_INFO pkcs11_info;
static CK_TOKEN_INFO pkcs11_tokeninfo;
static CK_SLOT_INFO pkcs11_slotinfo;

/* KMIP */
struct kmip_connection *kmip_conn = NULL;
struct kmip_conn_config *kmip_conf = NULL;
struct kmip_version kmip_vers;

enum kmip_key_format_type kmip_wrap_key_format;
enum kmip_crypto_algo kmip_wrap_key_alg;
uint kmip_wrap_key_size;
enum kmip_padding_method kmip_wrap_padding_method;
enum kmip_hashing_algo kmip_wrap_hash_alg;

/* Configuration */
static struct ConfigBaseNode *p11kmip_cfg = NULL;

/* Environment variables */
static CK_SLOT_ID env_pkcs_slot = (CK_SLOT_ID) - 1;
static char *env_pkcs_pin = NULL;
static char *env_kmip_hostname = NULL;
static char *env_kmip_client_cert = NULL;
static char *env_kmip_client_key = NULL;

/* Options */
static bool opt_help = false;
static bool opt_version = false;
static bool opt_verbose = false;
static bool opt_short = false;
static bool opt_quiet = false;
static CK_SLOT_ID opt_slot = (CK_SLOT_ID) - 1;
static char *opt_pin = NULL;
static bool opt_force_pin_prompt = false;

static char *opt_kmip_hostname = NULL;
static char *opt_kmip_client_cert = NULL;
static char *opt_kmip_client_key = NULL;
static bool opt_tls_verify_hostname = false;
static bool opt_tls_no_verify_cert = false;
static bool opt_tls_trust_server = false;

static char *opt_wrap_label = NULL;
static char *opt_wrap_attrs = NULL;
static char *opt_wrap_id = NULL;
static char *opt_target_label = NULL;
static char *opt_target_attrs = NULL;
static char *opt_target_id = NULL;
static CK_ULONG opt_target_length = (CK_ULONG) - 1;
static char *opt_unwrap_label = NULL;

static bool opt_gen_targkey = false;
static bool opt_retr_wrapkey = false;
static bool opt_send_wrapkey = false;

static char *opt_pem_password = NULL;
static bool opt_force_pem_pwd_prompt = false;

/*****************************************************************************/
/* Function Prototypes                                                       */
/*****************************************************************************/

/* Config */

/* KMIP Remote Function Prototypes */
static CK_RV p11kmip_locate_remote_key(const char *label, const struct
                                       p11kmip_keytype *keytype,
                                       struct kmip_node **obj_uid);
static CK_RV p11kmip_register_remote_public_key(
                                        const struct p11kmip_keytype *keytype,
                                        CK_OBJECT_HANDLE wrapping_pubkey, 
                                        const char *wrapping_key_label,
                                        struct kmip_node **key_uid);
static CK_RV p11kmip_register_remote_wrapped_key(
                                const struct p11kmip_keytype *wrapped_keytype,
                                CK_ULONG wrapped_key_length,
                                const CK_BYTE *wrapped_key_blob, 
                                const char *wrapped_key_label,
                                struct kmip_node *wrapkey_uid,
                                struct kmip_node **key_uid);
static CK_RV p11kmip_retrieve_remote_public_key(
                                struct p11kmip_keytype *public_keytype,
                                struct kmip_node *pubkey_uid,
                                EVP_PKEY ** pub_key);
static CK_RV p11kmip_retrieve_remote_wrapped_key(
                                struct kmip_node *wrapping_key_uid, 
                                struct p11kmip_keytype *wrapped_keytype, 
                                struct kmip_node *wrapped_key_uid, 
                                unsigned long *wrapped_key_length,
                                CK_BYTE ** wrapped_key_blob);
static CK_RV p11kmip_generate_remote_secret_key(
                                struct p11kmip_keytype *keytype,
                                const char *secret_key_label,
                                struct kmip_node **secret_key_uid);
static CK_RV p11kmip_digest_remote_key(struct kmip_node *key_uid,
                                       enum kmip_hashing_algo *digest_alg,
                                       CK_BYTE * digest,
                                       u_int32_t * digest_len);

/* PKCS#11 Local Function Prototypes*/
static CK_RV p11kmip_unwrap_local_secret_key(
                                CK_OBJECT_HANDLE wrapping_key_handle,
                                const struct p11kmip_keytype *wrapped_keytype,
                                unsigned long wrapped_key_length,
                                CK_BYTE * wrapped_key_blob,
                                char *wrapped_key_label,
                                CK_ATTRIBUTE_PTR wrapped_key_attrs,
                                CK_ULONG wrapped_key_num_attrs,
                                CK_OBJECT_HANDLE_PTR unwrapped_key_handle);
static CK_RV p11kmip_wrap_local_secret_key(
                                        CK_OBJECT_HANDLE wrapping_key_handle,
                                        CK_OBJECT_HANDLE secret_key_handle,
                                        CK_ULONG_PTR wrapped_key_length,
                                        CK_BYTE ** wrapped_key_blob);
static CK_RV p11kmip_create_local_public_key(
                                const struct p11kmip_keytype *public_keytype,
                                EVP_PKEY *pub_key,
                                char *public_key_label,
                                CK_ATTRIBUTE_PTR public_key_attrs,
                                CK_ULONG public_key_num_attrs,
                                CK_OBJECT_HANDLE_PTR public_key_handle);
static CK_RV p11kmip_find_local_key(const struct p11kmip_keytype *keytype,
                                    const char *label, const char *id,
                                    CK_OBJECT_HANDLE *key);
static CK_RV p11kmip_digest_local_key(CK_BYTE_PTR digest,
                                      CK_ULONG_PTR digestLen,
                                      CK_OBJECT_HANDLE key,
                                      CK_MECHANISM_PTR digestMech);

/* P11 function prototypes */
static bool opt_slot_is_set(const struct p11kmip_arg *arg);
static bool opt_targkey_length_is_set(const struct p11kmip_arg *arg);
static CK_RV p11kmip_import_key(void);
static CK_RV p11kmip_export_key(void);
static CK_RV p11kmip_export_local_rsa_pkey(
                                        const struct p11kmip_keytype *keytype, 
                                        EVP_PKEY ** pkey,
                                        bool private,
                                        CK_OBJECT_HANDLE key,
                                        const char *label);

static CK_RV get_key_size(const struct p11kmip_keytype *keytype,
                          void *private, CK_ULONG * keysize);

static void free_attr_array_attr(CK_ATTRIBUTE * attr);
static void print_bool_attr_short(const CK_ATTRIBUTE * val, bool applicable);
static void print_bool_attr_long(const char *attr, const CK_ATTRIBUTE * val,
                                 int indent, bool sensitive);

/* KMIP function prototypes */
static int perform_kmip_request2(enum kmip_operation operation1,
                                 struct kmip_node *req_pl1,
                                 struct kmip_node **resp_pl1,
                                 enum kmip_result_status *status1,
                                 enum kmip_result_reason *reason1,
                                 enum kmip_operation operation2,
                                 struct kmip_node *req_pl2,
                                 struct kmip_node **resp_pl2,
                                 enum kmip_result_status *status2,
                                 enum kmip_result_reason *reason2,
                                 enum kmip_batch_error_cont_option
                                 batch_err_opt);
static int perform_kmip_request(enum kmip_operation operation,
                                struct kmip_node *req_pl,
                                struct kmip_node **resp_pl,
                                enum kmip_result_status *status,
                                enum kmip_result_reason *reason);
static int discover_kmip_versions(struct kmip_version *version);
static struct kmip_node *build_custom_attr(const char *name, 
                                           const char *value);
static struct kmip_node *build_description_attr(const char *description);

/*****************************************************************************/
/* Static Structure Declarations                                             */
/*****************************************************************************/

/* Key object structure declarations */
static const struct p11kmip_keytype p11kmip_aes_keytype = {
    .name = "AES", .type = CKK_AES, .ckk_name = "CKK_AES",
    .class = CKO_SECRET_KEY,
    .keygen_mech = {.mechanism = CKM_AES_KEY_GEN,},
    .is_asymmetric = false,
    .keygen_get_key_size = get_key_size,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_AES,
    .keysize_attr = CKA_VALUE_LEN,
};

static const struct p11kmip_keytype p11kmip_rsa_keytype = {
    .name = "RSA", .type = CKK_RSA, .ckk_name = "CKK_RSA",
    .class = CKO_PUBLIC_KEY,    /* Leave this as the default */
    .keygen_mech = {.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,},
    .is_asymmetric = true,
    .keygen_get_key_size = get_key_size,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = false,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_RSA,
    .keysize_attr = CKA_MODULUS, .keysize_attr_value_len = true,
    .export_asym_pkey = p11kmip_export_local_rsa_pkey,
};

/* Commandline interface structure declarations */
static const struct p11kmip_opt p11kmip_generic_opts[] = {
    {.short_opt = 'h', .long_opt = "help", .required = false,
     .arg = {.type = ARG_TYPE_PLAIN, .required = false,
             .value.plain = &opt_help,},
     .description = "Print this help, then exit."},
    {.short_opt = 'v', .long_opt = "version", .required = false,
     .arg = {.type = ARG_TYPE_PLAIN, .required = false,
             .value.plain = &opt_version,},
     .description = "Print version information, then exit."},
    {.short_opt = 'd', .long_opt = "debug", .required = false,
     .arg = {.type = ARG_TYPE_PLAIN, .required = false,
             .value.plain = &opt_verbose,},
     .description = "Increase debug information."},
    {.short_opt = 'q', .long_opt = "quiet", .required = false,
     .arg = {.type = ARG_TYPE_PLAIN, .required = false,
             .value.plain = &opt_quiet,},
     .description = "Suppress messages."},
    {.short_opt = 'r', .long_opt = "short", .required = false,
     .arg = {.type = ARG_TYPE_PLAIN, .required = false,
             .value.plain = &opt_short,},
     .description = "Print shortened results."},
    {.short_opt = 0, .long_opt = NULL,},

};

#define PKCS11_OPTS                                                            \
    { .short_opt = 's', .long_opt = "slot", .required = false,                 \
      .arg =  { .type = ARG_TYPE_NUMBER, .required = true,                     \
                .value.number = &opt_slot, .is_set = opt_slot_is_set,          \
                .name = "SLOT", },                                             \
      .description = "The PKCS#11 slot ID.", },                                \
    { .short_opt = 'p', .long_opt = "pin", .required = false,                  \
      .arg = { .type = ARG_TYPE_STRING, .required = true,                      \
               .value.string = &opt_pin, .name = "USER-PIN" },                 \
      .description = "The PKCS#11 user pin. If this option is not specified, " \
                     "and environment variable PKCS11_USER_PIN is not set, "   \
                     "then you will be prompted for the PIN.", },              \
    { .short_opt = 0, .long_opt = "force-pin-prompt", .required = false,       \
      .long_opt_val = OPT_FORCE_PIN_PROMPT,                                    \
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,                      \
               .value.plain = &opt_force_pin_prompt, },                        \
      .description = "Enforce user PIN prompt, even if environment variable "  \
                     "PKCS11_USER_PIN is set, or the '-p'/'--pin' option is "  \
                     "specified.", }

#define KMIP_OPTS                                                              \
    { .short_opt = 0, .long_opt = "kmip-host", .required = false,              \
      .long_opt_val = OPT_KMIP_HOSTNAME,                                       \
      .arg =  { .type = ARG_TYPE_STRING, .required = true,                     \
                .value.string = &opt_kmip_hostname,                            \
                .name = "HOSTNAME" },                                          \
      .description = "The hostname of the KMIP server to use (optional).", },  \
    { .short_opt = 0, .long_opt = "kmip-client-cert", .required = false,       \
      .long_opt_val = OPT_KMIP_CLIENT_CERT,                                    \
      .arg =  { .type = ARG_TYPE_STRING, .required = true,                     \
                .value.string = &opt_kmip_client_cert,                         \
                .name = "CERT-PATH" },                                         \
      .description = "The path to the TLS client certificate to use for the "  \
                     "KMIP connection (optional).", },                         \
    { .short_opt = 0, .long_opt = "kmip-client-key", .required = false,        \
      .long_opt_val = OPT_KMIP_CLIENT_KEY,                                     \
      .arg =  { .type = ARG_TYPE_STRING, .required = true,                     \
                .value.string = &opt_kmip_client_key,                          \
                .name = "KEY-PATH" },                                          \
      .description = "The path to the TLS client key to use for the "          \
                     "KMIP connection (optional).", },                         \
    { .short_opt = 0, .long_opt = "pem-password", .required = false,           \
      .long_opt_val = OPT_PEM_PASSWORD,                                        \
      .arg =  { .type = ARG_TYPE_STRING, .required = true,                     \
                .value.string = &opt_pem_password,                             \
                .name = "PEM-PASSWORD" },                                      \
      .description = "The password for the client key PEM file, if required"   \
                     " (optional).", },                                        \
    { .short_opt = 0, .long_opt = "force-pem-password-prompt",                 \
      .required = false, .long_opt_val = OPT_FORCE_PEM_PWD_PROMPT,             \
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,                      \
               .value.plain = &opt_force_pem_pwd_prompt, },                    \
      .description = "Force a prompt for the client key PEM file"              \
                     " (optional).", },                                        \
    { .short_opt = 0, .long_opt = "tls-verify-hostname",                       \
      .long_opt_val = OPT_TLS_VERIFY_HOSTNAME,                                 \
      .required = false, .arg = { .type = ARG_TYPE_PLAIN, .required = false,   \
                                  .value.plain = &opt_tls_verify_hostname, },  \
      .description = "Enforce verification of the KMIP server hostname.", },   \
    { .short_opt = 0, .long_opt = "tls-no-verify-server-cert",                 \
      .long_opt_val = OPT_TLS_NO_VERIFY_CERT,                                  \
      .required = false, .arg = { .type = ARG_TYPE_PLAIN, .required = false,   \
                                  .value.plain = &opt_tls_no_verify_cert, },   \
      .description = "Skip verification of KMIP server TLS certificate.", },   \
    { .short_opt = 0, .long_opt = "tls-trust-server-cert",                     \
      .long_opt_val = OPT_TLS_TRUST_CERT,                                      \
      .required = false, .arg = { .type = ARG_TYPE_PLAIN, .required = false,   \
                                  .value.plain = &opt_tls_trust_server, },     \
      .description = "Perform verification of KMIP server TLS certificate, "   \
                     "but do not prompt user for trust of this server.", }     \

static const struct p11kmip_arg p11kmip_import_key_args[] = {
    {.name = NULL},
};

static const struct p11kmip_arg p11kmip_export_key_args[] = {
    {.name = NULL},
};

static const struct p11kmip_opt p11kmip_import_key_opts[] = {
    PKCS11_OPTS,
    KMIP_OPTS,
    {.short_opt = 'w', .long_opt = "wrapkey-label", .required = true,
     .arg = {.type = ARG_TYPE_STRING, .required = true,
             .value.string = &opt_wrap_label, .name = "WRAPKEY-LABEL",},
     .description = "The label of the public key to be used for wrapping.",},
    {.short_opt = 't', .long_opt = "targkey-label", .required = true,
     .arg = {.type = ARG_TYPE_STRING, .required = true,
             .value.string = &opt_target_label, .name = "TARGKEY-LABEL",},
     .description = "The label of the secret key to be imported from the "
                    "KMIP server.",},
    {.short_opt = 0, .long_opt = "targkey-attrs", .required = false,
     .long_opt_val = OPT_TARGKEY_ATTRS,
     .arg = {.type = ARG_TYPE_STRING, .required = true,
             .value.string = &opt_target_attrs, .name = "TARGKEY-ATTRS",},
     .description = "The boolean attributes to set for the secret key "
                    "after it has been imported (optional):"
                    "  P M B Y S X K. "
                    "Specify a set of these letters without any "
                    "blanks in between. See below for the meaning "
                    "of the attribute letters. Restrictions on "
                    "attribute values may apply.",},
    {.short_opt = 0, .long_opt = "targkey-id", .required = false,
     .long_opt_val = OPT_TARGKEY_ID,
     .arg = {.type = ARG_TYPE_STRING, .required = true,
             .value.string = &opt_target_id, .name = "TARGKEY-ID",},
     .description = "The value to be set for the CKA_ID attribute of "
                    "the imported secret key (optional)",},
    {.short_opt = 'u', .long_opt = "unwrapkey-label", .required = false,
     .arg = {.type = ARG_TYPE_STRING, .required = true,
             .value.string = &opt_unwrap_label, .name = "UNWRAPKEY-LABEL",},
     .description = "The label of the private key in the PKCS#11 "
                    "slot to be used for unwrapping the target key, "
                    "if different from the label of the public key used "
                    "for wrapping (optional).",},
    {.short_opt = 0, .long_opt = "send-wrapkey", .required = false,
     .long_opt_val = OPT_SEND_WRAPKEY,
     .arg = {.type = ARG_TYPE_PLAIN, .required = false,
             .value.plain = &opt_send_wrapkey,},
     .description = "If specified, registers a public key from the "
     "PKCS#11 slot with the KMIP server and uses it for wrapping. In "
     "this case, the label specified by the 'wrapkey-label' option is used to "
     "select the local public key to be sent, and the public key is "
     "registered with a name attribute value of the label on the "
     "KMIP server.",},
    {.short_opt = 0, .long_opt = "gen-targkey", .required = false,
     .long_opt_val = OPT_GEN_TARGKEY,
     .arg = {.type = ARG_TYPE_PLAIN, .required = false,
             .value.plain = &opt_gen_targkey,},
     .description = "If specified, the secret key to be imported is "
                    "first created on the KMIP server. Currently only" 
                    " supports AES keys.",},
    { .short_opt = 0, .long_opt = "targkey-length", .required = false,      
      .long_opt_val = OPT_TARGKEY_LEN,
      .arg =  { .type = ARG_TYPE_NUMBER, .required = true,                     
                .value.number = &opt_target_length,
                .is_set = opt_targkey_length_is_set,
                .name = "LENGTH", },
     .description = "The length in bits of the target key being generated. "
                    "Must be one of 128, 192, or 256. Only valid" 
                    " with option 'gen-targkey'. Defaults to 256.",},
    {.short_opt = 0, .long_opt = NULL,},
};

static const struct p11kmip_opt p11kmip_export_key_opts[] = {
    PKCS11_OPTS,
    KMIP_OPTS,
    {.short_opt = 'w', .long_opt = "wrapkey-label", .required = true,
     .arg = {.type = ARG_TYPE_STRING, .required = true,
             .value.string = &opt_wrap_label, .name = "WRAPKEY-LABEL",},
     .description = "The label of the public key to be used for wrapping. "
                    "Must exist on the KMIP server, and must exist "
                    "in the PKCS#11 repository unless specified with "
                    "option '--retr-wrapkey'.",},
    {.short_opt = 't', .long_opt = "targkey-label", .required = true,
     .arg = {.type = ARG_TYPE_STRING, .required = true,
             .value.string = &opt_target_label, .name = "TARGKEY-LABEL",},
     .description = "The label of the secret key to be exported to the "
                    "KMIP server. Must exist in the PKCS#11 repository. "
                    "This label will be used as the name attribute of "
                    "the exported key.",},
    {.short_opt = 0, .long_opt = "retr-wrapkey", .required = false,
     .long_opt_val = OPT_RETR_WRAPKEY,
     .arg = {.type = ARG_TYPE_PLAIN, .required = false,
             .value.plain = &opt_retr_wrapkey,},
     .description = "If specified, the public key to be used for "
                    "wrapping is first retrieved from the KMIP server and "
                    "stored in the PKCS#11 repository. The new key is stored "
                    "using the same label specified in the "
                    "'wrapkey-label' option.",},
    {.short_opt = 0, .long_opt = "wrapkey-attrs", .required = false,
     .long_opt_val = OPT_WRAPKEY_ATTRS,
     .arg = {.type = ARG_TYPE_STRING, .required = true,
             .value.string = &opt_wrap_attrs, .name = "WRAPKEY-ATTRS",},
     .description = "The boolean attributes to set for the public key "
                    "after it has been imported (optional). Only compatible "
                    " with the '--retr-wrapkey' option:"
                    "  P M B Y S X K H. "
                    "Specify a set of these letters without any "
                    "blanks in between. See below for the meaning "
                    "of the attribute letters. Restrictions on "
                    "attribute values may apply.",},
    {.short_opt = 0, .long_opt = "wrapkey-id", .required = false,
     .long_opt_val = OPT_WRAPKEY_ID,
     .arg = {.type = ARG_TYPE_STRING, .required = true,
             .value.string = &opt_wrap_id, .name = "WRAPKEY-ID",},
     .description = "The value to be set for the CKA_ID attribute of "
                    "the imported wrapping key. Only compatible with the "
                     "'--retr-wrapkey' option.",},
    {.short_opt = 0, .long_opt = NULL,},
};

static const struct p11kmip_cmd p11kmip_commands[] = {
    {.cmd = "import-key", .cmd_short1 = "import", .cmd_short2 = "imp",
     .func = p11kmip_import_key,
     .opts = p11kmip_import_key_opts, .args = p11kmip_import_key_args,
     .description = "Import a key from a KMIP server.",
     /*.help = print_generate_import_key_attr_help, */
     .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION,},
    {.cmd = "export-key", .cmd_short1 = "export", .cmd_short2 = "exp",
     .func = p11kmip_export_key,
     .opts = p11kmip_export_key_opts, .args = p11kmip_export_key_args,
     .description = "Export a key into a KMIP server.",
     /*.help = print_generate_import_key_attr_help, */
     .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION,},
    {.cmd = NULL, .func = NULL},
};

/* PKCS#11 attribute declarations */

#define DECLARE_BOOL_ATTR(attr, ch, sec, pub, priv, set)                       \
    { .name = # attr, .type = attr, .letter = ch,                              \
      .secret = sec, .public = pub, .private = priv,                           \
      .settable = set, .print_short = print_bool_attr_short,                   \
      .print_long = print_bool_attr_long, }

static const struct p11kmip_attr p11kmip_bool_attrs[] = {
    DECLARE_BOOL_ATTR(CKA_PRIVATE, 'P', true, true, true, true),
    DECLARE_BOOL_ATTR(CKA_MODIFIABLE, 'M', true, true, true, true),
    DECLARE_BOOL_ATTR(CKA_COPYABLE, 'B', true, true, true, true),
    DECLARE_BOOL_ATTR(CKA_DESTROYABLE, 'Y', true, true, true, true),
    DECLARE_BOOL_ATTR(CKA_SENSITIVE, 'S', true, false, true, true),
    DECLARE_BOOL_ATTR(CKA_EXTRACTABLE, 'X', true, false, true, true),
    DECLARE_BOOL_ATTR(CKA_TOKEN, 'H', true, true, true, false),
    DECLARE_BOOL_ATTR(CKA_IBM_PROTKEY_EXTRACTABLE,
                      'K', true, false, true, true),
    {.name = NULL,},
};


/* KMIP connection structure declarations */

static struct kmip_conn_config kmip_default_config = {
    /** Encoding used for the KMIP messages */
    .encoding = KMIP_ENCODING_TTLV,
    /** Transport method used to deliver KMIP messages */
    .transport = KMIP_TRANSPORT_PLAIN_TLS,
    /**
	 * The KMIP server.
	 * For Plain-TLS transport, only the hostname and optional port number.
	 * For HTTPS transport, an URL in the form
	 * 'https://hostname[:port]/uri'
	 */
    .server = "0.0.0.0:5696",
    /** The client key as an OpenSSL PKEY object. */
    .tls_client_key = NULL,
    /** File name of the client certificate PEM file */
    .tls_client_cert = NULL,
    /**
	 * Optional: File name of the CA bundle PEM file, or a name of a
	 * directory the multiple CA certificates. If this is NULL, then the
	 * default system path for CA certificates is used
	 */
    .tls_ca = NULL,
    /**
	 * Optional: File name of a PEM file holding a CA certificate of the
	 * issuer
	 */
    .tls_issuer_cert = NULL,
    /**
	 * Optional: File name of a PEM file containing the servers pinned
	 * public key. Public key pinning requires that verify_peer or
	 * verify_host (or both) is true.
	 */
    .tls_pinned_pubkey = NULL,
    /**
	 * Optional: File name of a PEM file containing the server's
	 * certificate. This can be used to allow peer verification with
	 * self-signed server certificates
	 */
    .tls_server_cert = NULL,
    /** If true, the peer certificate is verified */
    .tls_verify_peer = true,
    /**
	 * If true, that the server certificate is for the server it is known
	 * as (i.e. the hostname in the url)
	 */
    .tls_verify_host = false,
    /**
	 * Optional: A list of ciphers for TLSv1.2 and below. This is a colon
	 * separated list of cipher strings. The format of the string is
	 * described in
	 * https://www.openssl.org/docs/man1.1.1/man1/ciphers.html
	 */
    .tls_cipher_list = NULL,
    /**
	 * Optional: A list of ciphers for TLSv1.3. This is a colon separated
	 * list of TLSv1.3 ciphersuite names in order of preference. Valid
	 * TLSv1.3 ciphersuite names are:
	 * - TLS_AES_128_GCM_SHA256
	 * - TLS_AES_256_GCM_SHA384
	 * - TLS_CHACHA20_POLY1305_SHA256
	 * - TLS_AES_128_CCM_SHA256
	 * - TLS_AES_128_CCM_8_SHA256
	 */
    .tls13_cipher_list = NULL
};

/* KMIP request structure declarations */

/*****************************************************************************/
/* Functions                                                                 */
/*****************************************************************************/

/* Utility functions */

static CK_KEY_TYPE get_p11_alg_from_kmip(enum kmip_crypto_algo kmip_alg)
{
    if (kmip_alg >= P11KMIP_KMIP_TO_P11_ALG_TABLE_LENGTH) {
        return P11KMIP_P11_UNKNOWN_ALG;
    }

    return P11KMIP_KMIP_TO_P11_ALG_TABLE[kmip_alg];
}

static enum kmip_crypto_algo get_kmip_alg_from_p11(CK_KEY_TYPE p11_alg)
{
    if (p11_alg >= P11KMIP_P11_TO_KMIP_ALG_TABLE_LENGTH) {
        return P11KMIP_KMIP_UNKNOWN_ALG;
    }

    return P11KMIP_P11_TO_KMIP_ALG_TABLE[p11_alg];
}

static CK_OBJECT_CLASS get_p11_obj_class_from_kmip(
                                                enum kmip_object_type kmip_obj)
{
    if (kmip_obj >= P11KMIP_KMIP_TO_P11_OBJ_TABLE_LENGTH) {
        return P11KMIP_P11_UNKNOWN_OBJ;
    }

    return P11KMIP_KMIP_TO_P11_OBJ_TABLE[kmip_obj];
}

static enum kmip_object_type get_kmip_obj_class_from_p11(
                                                CK_OBJECT_CLASS p11_obj)
{
    if (p11_obj >= P11KMIP_P11_TO_KMIP_OBJ_TABLE_LENGTH) {
        return P11KMIP_KMIP_UNKNOWN_OBJ;
    }

    return P11KMIP_P11_TO_KMIP_OBJ_TABLE[p11_obj];
}

static CK_MECHANISM_TYPE get_p11_hash_mech_from_kmip_hash_algo(
                                        enum kmip_hashing_algo kmip_hash_alg)
{
    CK_MECHANISM_TYPE p11_hash_mech = P11KMIP_P11_UNKNOWN_HASH;

    if (kmip_hash_alg < P11KMIP_KMIP_TO_P11_HASH_TABLE_LENGTH) {
        p11_hash_mech = P11KMIP_KMIP_TO_P11_HASH_TABLE[kmip_hash_alg];
    }

    return p11_hash_mech;
}

static enum kmip_crypto_usage_mask get_kmip_usage_mask_p11(
                                            struct p11kmip_keytype *keytype)
{
    /* Gnarly bitwise chain to turn on the appropriate flags for key usage */
    const enum kmip_crypto_usage_mask usage_mask =
        (keytype->encrypt_decrypt &
         (KMIP_CRY_USAGE_MASK_ENCRYPT | KMIP_CRY_USAGE_MASK_DECRYPT))
        | (keytype->sign_verify &
           (KMIP_CRY_USAGE_MASK_SIGN | KMIP_CRY_USAGE_MASK_VERIFY))
        | (keytype->wrap_unwrap &
           (KMIP_CRY_USAGE_MASK_WRAP_KEY | KMIP_CRY_USAGE_MASK_UNWRAP_KEY))
        | (keytype->derive & (KMIP_CRY_USAGE_MASK_DERIVE_KEY));
    return usage_mask;
}

/* Commandline interface functions */
static const struct p11kmip_cmd *find_command(const char *cmd)
{
    unsigned int i;

    for (i = 0; p11kmip_commands[i].cmd != NULL; i++) {
        if (strcasecmp(cmd, p11kmip_commands[i].cmd) == 0)
            return &p11kmip_commands[i];
        if (p11kmip_commands[i].cmd_short1 != NULL &&
            strcasecmp(cmd, p11kmip_commands[i].cmd_short1) == 0)
            return &p11kmip_commands[i];
        if (p11kmip_commands[i].cmd_short2 != NULL &&
            strcasecmp(cmd, p11kmip_commands[i].cmd_short2) == 0)
            return &p11kmip_commands[i];
    }

    return NULL;
}


static void count_opts(const struct p11kmip_opt *opts,
           unsigned int *optstring_len, unsigned int *longopts_count)
{
    const struct p11kmip_opt *opt;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->short_opt != 0) {
            (*optstring_len)++;
            if (opt->arg.type != ARG_TYPE_PLAIN) {
                (*optstring_len)++;
                if (!opt->arg.required)
                    (*optstring_len)++;
            }
        }

        if (opt->long_opt != NULL)
            (*longopts_count)++;
    }
}

static CK_RV build_opts(const struct p11kmip_opt *opts,
                        char *optstring, struct option *longopts)
{
    const struct p11kmip_opt *opt;
    unsigned int opts_idx, long_idx;

    opts_idx = strlen(optstring);

    for (long_idx = 0; longopts[long_idx].name != NULL; long_idx++);

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->short_opt != 0) {
            optstring[opts_idx++] = opt->short_opt;
            if (opt->arg.type != ARG_TYPE_PLAIN) {
                optstring[opts_idx++] = ':';
                if (!opt->arg.required)
                    optstring[opts_idx++] = ':';
            }
        }

        if (opt->long_opt != NULL) {
            longopts[long_idx].name = opt->long_opt;
            longopts[long_idx].has_arg = opt->arg.type != ARG_TYPE_PLAIN ?
                (opt->arg.required ?
                 required_argument : optional_argument) : no_argument;
            longopts[long_idx].flag = NULL;
            longopts[long_idx].val = opt->short_opt != 0 ?
                opt->short_opt : opt->long_opt_val;
            long_idx++;
        }
    }

    return CKR_OK;
}

static CK_RV build_cmd_opts(const struct p11kmip_opt *cmd_opts,
                            char **optstring, struct option **longopts)
{
    unsigned int optstring_len = 0, longopts_count = 0;
    CK_RV rc;

    count_opts(p11kmip_generic_opts, &optstring_len, &longopts_count);
    if (cmd_opts != NULL)
        count_opts(cmd_opts, &optstring_len, &longopts_count);

    *optstring = calloc(1 + optstring_len + 1, 1);
    *longopts = calloc(longopts_count + 1, sizeof(struct option));
    if (*optstring == NULL || *longopts == NULL) {
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    (*optstring)[0] = ':';      /* Let getopt return ':' on missing argument */

    rc = build_opts(p11kmip_generic_opts, *optstring, *longopts);
    if (rc != CKR_OK)
        goto error;

    if (cmd_opts != NULL) {
        rc = build_opts(cmd_opts, *optstring, *longopts);
        if (rc != CKR_OK)
            goto error;
    }

    return CKR_OK;

error:
    if (*optstring != NULL)
        free(*optstring);
    *optstring = NULL;

    if (*longopts != NULL)
        free(*longopts);
    *longopts = NULL;

    return rc;
}

static CK_RV process_plain_argument(const struct p11kmip_arg *arg)
{
    *arg->value.plain = true;

    return CKR_OK;
}

static CK_RV process_string_argument(const struct p11kmip_arg *arg, char *val)
{
    *arg->value.string = val;

    return CKR_OK;
}

static CK_RV process_enum_argument(const struct p11kmip_arg *arg, char *val)
{
    const struct p11kmip_enum_value *enum_val, *any_val = NULL;

    for (enum_val = arg->enum_values; enum_val->value != NULL; enum_val++) {

        if (enum_val->any_value != NULL) {
            any_val = enum_val;
        } else if (arg->case_sensitive ?
                   strcasecmp(val, enum_val->value) == 0 :
                   strcmp(val, enum_val->value) == 0) {

            *arg->value.enum_value = (struct p11kmip_enum_value *) enum_val;
            return CKR_OK;
        }
    }

    /* process ANY enumeration value after all others */
    if (any_val != NULL) {
        *any_val->any_value = val;
        *arg->value.enum_value = (struct p11kmip_enum_value *) any_val;
        return CKR_OK;
    }

    return CKR_ARGUMENTS_BAD;
}

static CK_RV process_number_argument(const struct p11kmip_arg *arg, char *val)
{
    char *endptr;

    *arg->value.number = strtoul(val, &endptr, 0);

    if ((errno == ERANGE && *arg->value.number == ULONG_MAX) ||
        (errno != 0 && *arg->value.number == 0) || endptr == val) {
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}

static CK_RV processs_argument(const struct p11kmip_arg *arg, char *val)
{
    switch (arg->type) {
    case ARG_TYPE_PLAIN:
        return process_plain_argument(arg);
    case ARG_TYPE_STRING:
        return process_string_argument(arg, val);
    case ARG_TYPE_ENUM:
        return process_enum_argument(arg, val);
    case ARG_TYPE_NUMBER:
        return process_number_argument(arg, val);
    default:
        return CKR_ARGUMENTS_BAD;
    }
}

static bool argument_is_set(const struct p11kmip_arg *arg)
{
    if (arg->is_set != NULL)
        return arg->is_set(arg);

    switch (arg->type) {
    case ARG_TYPE_PLAIN:
        return *arg->value.plain;
    case ARG_TYPE_STRING:
        return *arg->value.string != NULL;
    case ARG_TYPE_ENUM:
        return *arg->value.enum_value != NULL;
    case ARG_TYPE_NUMBER:
        return *arg->value.number != 0;
    default:
        return false;
    }
}

static void option_arg_error(const struct p11kmip_opt *opt, const char *arg)
{
    if (opt->short_opt != 0 && opt->long_opt != NULL)
        warnx("Invalid argument '%s' for option '-%c/--%s'", arg,
              opt->short_opt, opt->long_opt);
    else if (opt->long_opt != NULL)
        warnx("Invalid argument '%s' for option '--%s'", arg, opt->long_opt);
    else
        warnx("Invalid argument '%s' for option '-%c'", arg, opt->short_opt);
}

static void option_missing_error(const struct p11kmip_opt *opt)
{
    if (opt->short_opt != 0 && opt->long_opt != NULL)
        warnx("Option '-%c/--%s' is required but not specified", 
            opt->short_opt, opt->long_opt);
    else if (opt->long_opt != NULL)
        warnx("Option '--%s is required but not specified'", opt->long_opt);
    else
        warnx("Option '-%c' is required but not specified", opt->short_opt);
}

static CK_RV process_option(const struct p11kmip_opt *opts, int ch, char *val)
{
    const struct p11kmip_opt *opt;
    CK_RV rc;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (ch == (opt->short_opt != 0 ? opt->short_opt : opt->long_opt_val)) {
            rc = processs_argument(&opt->arg, val);
            if (rc != CKR_OK) {
                option_arg_error(opt, val);
                return rc;
            }

            return CKR_OK;
        }
    }

    return CKR_ARGUMENTS_BAD;
}

static CK_RV process_cmd_option(const struct p11kmip_opt *cmd_opts, 
                                int opt, char *arg)
{
    CK_RV rc;

    rc = process_option(p11kmip_generic_opts, opt, arg);
    if (rc == CKR_OK)
        return CKR_OK;

    if (cmd_opts != NULL) {
        rc = process_option(cmd_opts, opt, arg);
        if (rc == CKR_OK)
            return CKR_OK;
    }

    return rc;
}

static CK_RV check_required_opts(const struct p11kmip_opt *opts)
{
    const struct p11kmip_opt *opt;
    CK_RV rc = CKR_OK;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->required && opt->arg.required &&
            argument_is_set(&opt->arg) == false) {
            option_missing_error(opt);
            rc = CKR_ARGUMENTS_BAD;
            /* No break, report all missing options */
        }
    }

    return rc;
}

static CK_RV check_required_cmd_opts(const struct p11kmip_opt *cmd_opts)
{
    CK_RV rc;

    rc = check_required_opts(p11kmip_generic_opts);
    if (rc != CKR_OK)
        return rc;

    if (cmd_opts != NULL) {
        rc = check_required_opts(cmd_opts);
        if (rc != CKR_OK)
            return rc;
    }

    return CKR_OK;
}

static CK_RV parse_cmd_options(const struct p11kmip_cmd *cmd, 
                               int argc, char *argv[])
{
    char *optstring = NULL;
    struct option *longopts = NULL;
    CK_RV rc;
    int c;

    rc = build_cmd_opts(cmd != NULL ? cmd->opts : NULL, &optstring, &longopts);
    if (rc != CKR_OK)
        goto done;

    opterr = 0;
    while (1) {
        c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1)
            break;

        switch (c) {
        case ':':
            warnx("Option '%s' requires an argument", argv[optind - 1]);
            rc = CKR_ARGUMENTS_BAD;
            goto done;

        case '?':              /* An invalid option has been specified */
            if (optopt)
                warnx("Invalid option '-%c'", optopt);
            else
                warnx("Invalid option '%s'", argv[optind - 1]);
            rc = CKR_ARGUMENTS_BAD;
            goto done;

        default:
            rc = process_cmd_option(cmd != NULL ? cmd->opts : NULL, c, optarg);
            if (rc != CKR_OK)
                goto done;
            break;
        }
    }

    if (optind < argc) {
        warnx("Invalid argument '%s'", argv[optind]);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

done:
    if (optstring != NULL)
        free(optstring);
    if (longopts != NULL)
        free(longopts);

    return rc;
}

static CK_RV check_required_args(const struct p11kmip_arg *args)
{
    const struct p11kmip_arg *arg;
    CK_RV rc2, rc = CKR_OK;

    for (arg = args; arg != NULL && arg->name != NULL; arg++) {
        if (arg->required && argument_is_set(arg) == false) {
            warnx("Argument '%s' is required but not specified", arg->name);
            rc = CKR_ARGUMENTS_BAD;
            /* No break, report all missing arguments */
        }

        /* Check enumeration value specific arguments (if any) */
        if (arg->type == ARG_TYPE_ENUM && *arg->value.enum_value != NULL &&
            (*arg->value.enum_value)->args != NULL) {
            rc2 = check_required_args((*arg->value.enum_value)->args);
            if (rc2 != CKR_OK)
                rc = rc2;
            /* No break, report all missing arguments */
        }
    }

    return rc;
}

static CK_RV parse_arguments(const struct p11kmip_arg *args, 
                             int *argc, char **argv[])
{
    const struct p11kmip_arg *arg;
    CK_RV rc = CKR_OK;

    for (arg = args; arg->name != NULL; arg++) {
        if (*argc < 2 || strncmp((*argv)[1], "-", 1) == 0)
            break;

        rc = processs_argument(arg, (*argv)[1]);
        if (rc != CKR_OK) {
            if (rc == CKR_ARGUMENTS_BAD)
                warnx("Invalid argument '%s' for '%s'", (*argv)[1], arg->name);
            break;
        }

        (*argc)--;
        (*argv)++;

        /* Process enumeration value specific arguments (if any) */
        if (arg->type == ARG_TYPE_ENUM && *arg->value.enum_value != NULL &&
            (*arg->value.enum_value)->args != NULL) {
            rc = parse_arguments((*arg->value.enum_value)->args, argc, argv);
            if (rc != CKR_OK)
                break;
        }
    }

    return rc;
}

static CK_RV parse_cmd_arguments(const struct p11kmip_cmd *cmd, 
                                 int *argc, char **argv[])
{
    if (cmd == NULL)
        return CKR_OK;

    return parse_arguments(cmd->args, argc, argv);
}

static void print_indented(const char *str, int indent)
{
    char *word, *line, *desc, *desc_ptr;
    int word_len, pos = indent;

    desc = desc_ptr = strdup(str);
    if (desc == NULL)
        return;

    line = strsep(&desc, "\n");
    while (line != NULL) {
        word = strsep(&line, " ");
        pos = indent;
        while (word != NULL) {
            word_len = strlen(word);
            if (pos + word_len + 1 > MAX_PRINT_LINE_LENGTH) {
                printf("\n%*s", indent, "");
                pos = indent;
            }
            if (pos == indent)
                printf("%s", word);
            else
                printf(" %s", word);
            pos += word_len + 1;
            word = strsep(&line, " ");
        }
        if (desc)
            printf("\n%*s", indent, "");
        line = strsep(&desc, "\n");
    }

    printf("\n");
    free(desc_ptr);
}

static void print_options_help(const struct p11kmip_opt *opts)
{
    const struct p11kmip_opt *opt;
    char tmp[200];
    int len;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->short_opt != 0 && opt->long_opt != NULL)
            len = snprintf(tmp, sizeof(tmp), "-%c, --%s", opt->short_opt,
                           opt->long_opt);
        else if (opt->short_opt == 0 && opt->long_opt != NULL)
            len = snprintf(tmp, sizeof(tmp), "    --%s", opt->long_opt);
        else
            len = snprintf(tmp, sizeof(tmp), "-%c", opt->short_opt);

        if (opt->arg.type != ARG_TYPE_PLAIN) {
            if (opt->arg.required)
                snprintf(&tmp[len], sizeof(tmp) - len, " %s", opt->arg.name);
            else if (opt->long_opt == NULL)
                snprintf(&tmp[len], sizeof(tmp) - len, "[%s]", opt->arg.name);
            else
                snprintf(&tmp[len], sizeof(tmp) - len, "[=%s]", opt->arg.name);
        }

        printf("    %-40.40s ", tmp);
        print_indented(opt->description, PRINT_INDENT_POS);
    }
}

static void print_arguments_help(const struct p11kmip_cmd *cmd,
                                 const struct p11kmip_arg *args, int indent)
{
    const struct p11kmip_arg *arg;
    const struct p11kmip_enum_value *val;
    int width;
    bool newline = false;

    if (indent > 0) {
        for (arg = args; arg->name != NULL; arg++) {
            if (arg->required)
                printf(" %s", arg->name);
            else
                printf(" [%s]", arg->name);
        }
        printf("\n\n");
    }

    for (arg = args; arg->name != NULL; arg++) {
        width = 30 - indent;
        if (width < (int) strlen(arg->name))
            width = (int) strlen(arg->name);

        printf("%*s    %-*.*s ", indent, "", width, width, arg->name);
        print_indented(arg->description, PRINT_INDENT_POS);

        newline = false;

        if (arg->type != ARG_TYPE_ENUM)
            continue;

        /* Enumeration: print possible values */
        for (val = arg->enum_values; val->value != NULL; val++) {
            if (arg == cmd->args && argument_is_set(arg) &&
                *arg->value.enum_value != val)
                continue;

            newline = true;

            printf("%*s        %s", indent, "", val->value);

            if (val->args != NULL) {
                print_arguments_help(cmd, val->args, indent + 8);
                newline = false;
            } else {
                printf("\n");
            }
        }
    }

    if (indent > 0 || newline)
        printf("\n");
}

static void print_help(void)
{
    const struct p11kmip_cmd *cmd;

    printf("\n");
    printf("Usage: p11kmip COMMAND [OPTIONS]\n");
    printf("\n");
    printf("COMMANDS:\n");
    for (cmd = p11kmip_commands; cmd->cmd != NULL; cmd++) {
        printf("    %-40.40s ", cmd->cmd);
        print_indented(cmd->description, PRINT_INDENT_POS);
    }
    printf("\n");
    printf("COMMON OPTIONS\n");
    print_options_help(p11kmip_generic_opts);
    printf("\n");
    printf("For more information use 'p11kmip COMMAND --help'.\n");
    printf("\n");
}

static void print_command_help(const struct p11kmip_cmd *cmd)
{
    printf("\n");
    printf("Usage: p11kmip %s [ARGS] [OPTIONS]\n", cmd->cmd);
    printf("\n");
    printf("ARGS:\n");
    print_arguments_help(cmd, cmd->args, 0);
    printf("OPTIONS:\n");
    print_options_help(cmd->opts);
    print_options_help(p11kmip_generic_opts);
    printf("\n");
    if (cmd->help != NULL)
        cmd->help();
}

static void print_version(void)
{
    printf("p11kmip version %s\n", PACKAGE_VERSION);
}

static bool opt_slot_is_set(const struct p11kmip_arg *arg)
{
    return (*arg->value.number != (CK_ULONG) - 1);
}

static bool opt_targkey_length_is_set(const struct p11kmip_arg *arg)
{
    return (*arg->value.number != (CK_ULONG) - 1);
}

static int openssl_err_cb(const char *str, size_t len, void *u)
{
    UNUSED(u);

    if (str[len - 1] == '\n')
        len--;

    warnx("OpenSSL error: %.*s", (int) len, str);
    return 1;
}

static int p11kmip_pem_password_cb(char *buf, int size, 
                                   int rwflag, void *userdata)
{
    const char *pem_password = opt_pem_password;
    char *buf_pem_password = NULL;
    char *pem_path = (char *) userdata;
    char *msg = NULL;
    int len;

    UNUSED(rwflag);
    UNUSED(userdata);

    if (pem_password == NULL)
        pem_password = getenv(KMIP_PEM_PASSWORD_ENV_NAME);

    if (opt_force_pem_pwd_prompt || pem_password == NULL) {
        if (asprintf(&msg, "Please enter PEM password for '%s': ",
                     pem_path) <= 0) {
            warnx("Failed to allocate memory for message");
            return -1;
        }
        pem_password = pin_prompt(&buf_pem_password, msg);
        free(msg);
        if (pem_password == NULL) {
            warnx("Failed to prompt for PEM password");
            return -1;
        }
    }

    len = strlen(pem_password);
    if (len > size) {
        warnx("PEM password is too long");
        return -1;
    }

    strncpy(buf, pem_password, size);

    pin_free(&buf_pem_password);

    return len;
}

/*****************************************************************************/
/* Environment Variable Functions                                            */
/*****************************************************************************/

static CK_RV parse_env_vars(void)
{
    char *loc_env_pkcs_slot;

    loc_env_pkcs_slot = getenv(PKCS11_SLOT_ID_ENV_NAME);
    if (loc_env_pkcs_slot != NULL) {
        /* * 
         * ATOI gives 0 on an invalid string, but 0 is a valid
         * slot ID, so no error checking to be done 
         */
        env_pkcs_slot = atoi(loc_env_pkcs_slot);
    }

    env_pkcs_pin = getenv(PKCS11_USER_PIN_ENV_NAME);
    env_kmip_hostname = getenv(KMIP_HOSTNAME_ENV_NAME);
    env_kmip_client_cert = getenv(KMIP_CLIENT_CERT_ENV_NAME);
    env_kmip_client_key = getenv(KMIP_CLIENT_KEY_ENV_NAME);

    return CKR_OK;
}


/*****************************************************************************/
/* Configuration File Functions                                              */
/*****************************************************************************/

static void parse_config_file_error_hook(int line, int col, const char *msg)
{
    warnx("Parse error: %d:%d: %s", line, col, msg);
}

static CK_RV parse_config_file(void)
{
    FILE *fp = NULL;
    char *file_loc = getenv(P11KMIP_CONF_FILE_ENV_NAME);
    char pathname[PATH_MAX];
    struct passwd *pw;

    if (file_loc != NULL) {
        fp = fopen(file_loc, "r");
        if (fp == NULL) {
            warnx("Cannot read config file '%s' "
                  "(specified via env variable %s): %s",
                  file_loc, P11KMIP_CONF_FILE_ENV_NAME, strerror(errno));
            return CKR_GENERAL_ERROR;
        }
    } else {
        pw = getpwuid(geteuid());
        if (pw != NULL) {
            snprintf(pathname, sizeof(pathname), "%s/.%s", pw->pw_dir,
                     P11KMIP_CONFIG_FILE_NAME);
            file_loc = pathname;
            fp = fopen(file_loc, "r");
        }
        if (fp == NULL) {
            file_loc = P11KMIP_DEFAULT_CONFIG_FILE;
            fp = fopen(file_loc, "r");
            if (fp == NULL) {
                warnx("Cannot read config file '%s': %s",
                      file_loc, strerror(errno));
                return CKR_GENERAL_ERROR;
            }
        }
    }

    if (parse_configlib_file(fp, &p11kmip_cfg, 
                             parse_config_file_error_hook, 0)) {
        warnx("Failed to parse config file '%s'", file_loc);
        fclose(fp);
        return CKR_DATA_INVALID;
    }

    fclose(fp);

    return CKR_OK;
}

/*****************************************************************************/
/* KMIP Connection Functions                                                 */
/*****************************************************************************/

/**
 * @brief Uses the contents of the config file and the
 * commandline arguments to construct the configuration
 * for the KMIP connection. For optional fields it will
 * use default values if none are found; for required fields
 * it will throw an error if they are missing.
 * 
 * global       p11kmip_cfg             (input)
 * global       kmip_conf               (output)
 * global       kmip_wrap_key_format    (output)
 * global       kmip_wrap_key_alg       (output)
 * global       kmip_wrap_key_size      (output)
 * global       kmip_padding_method     (output)
 * global       kmip_hashing_algo       (output)
 * 
 * @return CK_RV 
 */
static CK_RV build_kmip_config(void)
{
    CK_RV rc;
    int f;
    struct ConfigBaseNode *c = NULL, *host = NULL,
        *tls_client_cert = NULL, *tls_client_key = NULL,
        *wrap_key_format = NULL, *wrap_key_algorithm = NULL, *wrap_key_size =
        NULL, *wrap_pad_method = NULL, *wrap_hash_algo = NULL;
    struct ConfigStructNode *structnode = NULL;
    bool found = false;
    char *tls_client_key_path = NULL;
    BIO *tls_client_key_bio = NULL;

    rc = CKR_OK;

    /* Populate the kmip_config global with static defaults */
    kmip_conf = &kmip_default_config;

    /**
     * The lack of a config file, by itself, is not fatal,  
     * because all the required information can potentially 
     * be provided through commandline arguements           
     */
    if (p11kmip_cfg != NULL) {
        /* Iterate the configuration node(s) */
        confignode_foreach(c, p11kmip_cfg, f) {
            if (!confignode_hastype(c, CT_STRUCT) ||
                strcmp(c->key, P11KMIP_CONFIG_KEYWORD_KMIP) != 0) {
                continue;
            } else if (found) {
                warnx("Syntax error in config file:"
                      "'%s' specified multiple times\n",
                      P11KMIP_CONFIG_KEYWORD_KMIP);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }

            structnode = confignode_to_struct(c);
            host = confignode_find(structnode->value,
                                   P11KMIP_CONFIG_KEYWORD_HOST);
            tls_client_cert = confignode_find(structnode->value,
                                        P11KMIP_CONFIG_KEYWORD_CLIENT_CERT);
            tls_client_key = confignode_find(structnode->value,
                                        P11KMIP_CONFIG_KEYWORD_CLIENT_KEY);
            wrap_key_format = confignode_find(structnode->value,
                                        P11KMIP_CONFIG_KEYWORD_WRAP_KEY_FMT);
            wrap_key_algorithm = confignode_find(structnode->value,
                                        P11KMIP_CONFIG_KEYWORD_WRAP_KEY_ALG);
            wrap_key_size = confignode_find(structnode->value,
                                        P11KMIP_CONFIG_KEYWORD_WRAP_KEY_SIZE);
            wrap_pad_method = confignode_find(structnode->value,
                                        P11KMIP_CONFIG_KEYWORD_WRAP_PAD_MTHD);
            wrap_hash_algo = confignode_find(structnode->value,
                                        P11KMIP_CONFIG_KEYWORD_WRAP_HASH_ALG);

            /**
             *  Ensure all the fields are the right type and were specificied
             *  with the right combinations 
             */ 
            if (host != NULL && !confignode_hastype(host, CT_STRINGVAL)) {
                warnx("Syntax error in config file: "
                      "Missing '%s' in attribute at line %hu\n",
                      P11KMIP_CONFIG_KEYWORD_HOST, c->line);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
            if (tls_client_cert != NULL
                && !confignode_hastype(tls_client_cert, CT_STRINGVAL)) {
                warnx("Syntax error in config file:"
                      " Missing '%s' in attribute at line %hu\n",
                      P11KMIP_CONFIG_KEYWORD_CLIENT_CERT, c->line);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
            if (tls_client_key != NULL
                && !confignode_hastype(tls_client_key, CT_STRINGVAL)) {
                warnx("Syntax error in config file:"
                      " Missing '%s' in attribute at line %hu\n",
                      P11KMIP_CONFIG_KEYWORD_CLIENT_KEY, c->line);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
            if (wrap_key_format != NULL
                && !confignode_hastype(wrap_key_format, CT_STRINGVAL)) {
                warnx("Syntax error in config file:"
                      " Missing '%s' in attribute at line %hu\n",
                      P11KMIP_CONFIG_KEYWORD_WRAP_KEY_FMT, c->line);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
            if (wrap_key_algorithm != NULL
                && !confignode_hastype(wrap_key_algorithm, CT_STRINGVAL)) {
                warnx("Syntax error in config file:"
                      " Missing '%s' in attribute at line %hu\n",
                      P11KMIP_CONFIG_KEYWORD_WRAP_KEY_ALG, c->line);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
            if (wrap_key_size != NULL
                && !confignode_hastype(wrap_key_size, CT_INTVAL)) {
                warnx("Syntax error in config file:"
                      " Missing '%s' in attribute at line %hu\n",
                      P11KMIP_CONFIG_KEYWORD_WRAP_KEY_SIZE, c->line);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
            if (wrap_pad_method != NULL
                && !confignode_hastype(wrap_pad_method, CT_STRINGVAL)) {
                warnx("Syntax error in config file:"
                      " Missing '%s' in attribute at line %hu\n",
                      P11KMIP_CONFIG_KEYWORD_WRAP_PAD_MTHD, c->line);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
            if (wrap_hash_algo != NULL
                && !confignode_hastype(wrap_hash_algo, CT_STRINGVAL)) {
                warnx("Syntax error in config file:"
                      " Missing '%s' in attribute at line %hu\n",
                      P11KMIP_CONFIG_KEYWORD_WRAP_HASH_ALG, c->line);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
        }

        if (host != NULL) {
            kmip_conf->server = confignode_to_stringval(host)->value;
        }

        if (tls_client_cert != NULL) {
            kmip_conf->tls_client_cert =
                confignode_to_stringval(tls_client_cert)->value;
        }

        if (tls_client_key != NULL) {
            tls_client_key_path =
                confignode_to_stringval(tls_client_key)->value;
        }

        if (wrap_key_format != NULL) {
            if (strcmp(confignode_to_stringval(wrap_key_format)->value,
                       P11KMIP_CONFIG_VALUE_FMT_PKCS1) == 0) {
                kmip_wrap_key_format = KMIP_KEY_FORMAT_TYPE_PKCS_1;
            } else if (strcmp(confignode_to_stringval(wrap_key_format)->value,
                              P11KMIP_CONFIG_VALUE_FMT_PKCS8) == 0) {
                kmip_wrap_key_format = KMIP_KEY_FORMAT_TYPE_PKCS_8;
            } else if (strcmp(confignode_to_stringval(wrap_key_format)->value,
                              P11KMIP_CONFIG_VALUE_FMT_TRANSPARENT) == 0) {
                kmip_wrap_key_format =
                    KMIP_KEY_FORMAT_TYPE_TRANSPARENT_RSA_PUBLIC_KEY;
            } else {
                warnx("Syntax error in config file:"
                      " Invalid value '%s' specified for key word '%s's\n", 
                      confignode_to_stringval(wrap_key_format)->value,
                      P11KMIP_CONFIG_KEYWORD_WRAP_KEY_FMT);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
        } else {
            warnx("Wrapping key format not found in config file");
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        if (wrap_key_algorithm != NULL) {
            if (strcmp(confignode_to_stringval(wrap_key_algorithm)->value,
                       P11KMIP_CONFIG_VALUE_KEY_ALG_RSA) == 0) {
                kmip_wrap_key_alg = KMIP_CRYPTO_ALGO_RSA;
            } else {
                warnx("Syntax error in config file:"
                      " Invalid value '%s' specified for key word '%s's\n", 
                      confignode_to_stringval(wrap_key_algorithm)->value,
                      P11KMIP_CONFIG_KEYWORD_WRAP_KEY_ALG);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
        } else {
            warnx("Wrapping key algorithm not found in config file");
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        if (wrap_key_size != NULL) {
            kmip_wrap_key_size = confignode_to_intval(wrap_key_size)->value;
        } else {
            warnx("Wrapping key length not found in config file");
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        if (wrap_pad_method != NULL) {
            if (strcmp(confignode_to_stringval(wrap_pad_method)->value,
                       P11KMIP_CONFIG_VALUE_METHD_PKCS15) == 0) {
                kmip_wrap_padding_method = KMIP_PADDING_METHOD_PKCS_1_5;
            } else if (strcmp(confignode_to_stringval(wrap_pad_method)->value,
                              P11KMIP_CONFIG_VALUE_METHD_OAEP) == 0) {
                kmip_wrap_padding_method = KMIP_PADDING_METHOD_OAEP;
            } else {
                warnx("Syntax error in config file:"
                      " Invalid value '%s' specified for key word '%s's\n", 
                      confignode_to_stringval(wrap_pad_method)->value,
                      P11KMIP_CONFIG_KEYWORD_WRAP_PAD_MTHD);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
        } else {
            warnx("Wrap padding method not found in config file");
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        if (wrap_hash_algo != NULL) {
            if (strcmp(confignode_to_stringval(wrap_hash_algo)->value,
                       P11KMIP_CONFIG_VALUE_HSH_ALG_SHA_1) == 0) {
                kmip_wrap_hash_alg = KMIP_HASHING_ALGO_SHA_1;
            } else if (strcmp(confignode_to_stringval(wrap_hash_algo)->value,
                              P11KMIP_CONFIG_VALUE_HSH_ALG_SHA_256) == 0) {
                kmip_wrap_hash_alg = KMIP_HASHING_ALGO_SHA_256;
            } else {
                warnx("Syntax error in config file:"
                      " Invalid value '%s' specified for key word '%s's\n", 
                      confignode_to_stringval(wrap_hash_algo)->value,
                      P11KMIP_CONFIG_KEYWORD_WRAP_HASH_ALG);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
        } else {
            // Wrap hashing method is only required with padding method OAEP
            if (kmip_wrap_padding_method == KMIP_PADDING_METHOD_OAEP) {
                warnx("Wrap hashing algorithm not found in config file");
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
        }
    }

    /* Environment variables have priority over configuration file settings */
    if (env_kmip_hostname != NULL)
        kmip_conf->server = env_kmip_hostname;

    if (env_kmip_client_cert != NULL)
        kmip_conf->tls_client_cert = env_kmip_client_cert;

    if (env_kmip_client_key != NULL)
        tls_client_key_path = env_kmip_client_key;

    /**
     * Command line options have priority over environment 
     * variables and configuration options
     */
    if (opt_kmip_hostname != NULL)
        kmip_conf->server = opt_kmip_hostname;

    if (opt_kmip_client_cert != NULL)
        kmip_conf->tls_client_cert = opt_kmip_client_cert;

    if (opt_kmip_client_key != NULL)
        tls_client_key_path = opt_kmip_client_key;

    if (opt_tls_no_verify_cert)
        kmip_conf->tls_verify_peer = false;

    if (opt_tls_verify_hostname)
        kmip_conf->tls_verify_host = true;

    /**
     * Now that we have the final path for the tls_client_key, 
     * read in the contents 
     */
    tls_client_key_bio = BIO_new_file(tls_client_key_path, "r");

    if (tls_client_key_bio == NULL) {
        warnx("Unable to open '%s' for TLS client key", tls_client_key_path);
        return CKR_FUNCTION_FAILED;
    }

    kmip_conf->tls_client_key =
        PEM_read_bio_PrivateKey(tls_client_key_bio, NULL,
                                p11kmip_pem_password_cb, tls_client_key_path);

    if (kmip_conf->tls_client_key == NULL) {
        warnx("Unable to extract TLS client key from '%s'",
              tls_client_key_path);
    }

    BIO_free(tls_client_key_bio);

    if (kmip_conf->tls_client_key == NULL && 
        kmip_conf->tls_client_cert == NULL) {
        warnx("TLS client key or client certificate was not"
              " provided through configuration or commandline options");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

done:

    return rc;
}

static void free_kmip_config(void)
{
    if (kmip_conf->tls_client_key != NULL)
        EVP_PKEY_free(kmip_conf->tls_client_key);
}

/**
 * Check if the certificate is a self signed certificate, and if it is expired
 * or not yet valid.
 *
 * @param cert_file         the file name of the PEM file containing the cert
 * @param self_signed       on return: true if the cetr is a self signed cert
 * @param valid             on return: false if the cert is expired or not yet
 *                          valid
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
int p11kmip_check_certificate(const char *cert_file, 
                              bool *self_signed, 
                              bool *valid)
{
    X509 *cert;
    FILE *fp;
    int rc;

    fp = fopen(cert_file, "r");
    if (fp == NULL) {
        rc = CKR_GENERAL_ERROR;
        warnx("Failed to open certificate PEM file '%s': "
              "%s", cert_file, strerror(-rc));
        return rc;
    }

    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (cert == NULL) {
        warnx("Failed to read certificate PEM file '%s'", cert_file);
        return -EIO;
    }

    *self_signed = (X509_NAME_cmp(X509_get_subject_name(cert),
                                  X509_get_issuer_name(cert)) == 0);

    *valid = (X509_cmp_current_time(X509_get0_notBefore(cert)) < 0 &&
              X509_cmp_current_time(X509_get0_notAfter(cert)) > 0);

    X509_free(cert);

    return 0;
}

/**
 * Print the certificate(s) contained in the specified PEM file.
 *
 * @param cert_pem          the file name of the PEM file to print
 *
 * @returns -EIO if the file could not be opened. -ENOENT if the PEM file
 *          does not contain any certificates. 0 if success.
 */
int p11kmip_print_certificates(const char *cert_pem)
{
    int rc = -ENOENT;
    X509 *cert;
    FILE *fp;

    if (cert_pem == NULL)
        return -EINVAL;

    fp = fopen(cert_pem, "r");
    if (fp == NULL) {
        warnx("File '%s': %s", cert_pem, strerror(errno));
        return -EIO;
    }

    while (1) {
        cert = PEM_read_X509(fp, NULL, NULL, NULL);
        if (cert == NULL)
            break;

        X509_print_ex_fp(stdout, cert, 0, X509_FLAG_NO_EXTENSIONS);

        X509_free(cert);
        rc = 0;
    }

    fclose(fp);
    return rc;
}

/*
 * Prompts for yes or no. Returns true if 'y' or 'yes' was entered.
 */
static bool prompt_for_yes(void)
{
    char str[20];

    if (fgets(str, sizeof(str), stdin) == NULL)
        return false;

    if (str[strlen(str) - 1] == '\n')
        str[strlen(str) - 1] = '\0';

    if (strcasecmp(str, "y") == 0 || strcasecmp(str, "yes") == 0)
        return true;

    return false;
}

/**
 * @brief Builds the configuration for the KMIP connection,
 * opens the KMIP connection, and determines the version of
 * the server.
 * 
 * global       kmip_conf   (output)
 * global       kmip_conn   (output)
 * global       kmip_vers   (output)
 * 
 * @return CK_RV 
 */
static CK_RV init_kmip(void)
{
    int rc = 0;
    CK_RV rv = CKR_OK;
    bool verified = false, self_signed = false, valid = false;
    
    rc = build_kmip_config();

    if (rc != CKR_OK)
        goto done;

    rc = kmip_connection_get_server_cert(kmip_conf->server,
                                         kmip_conf->transport,
                                         kmip_conf->tls_ca,
                                         kmip_conf->tls_client_key,
                                         kmip_conf->tls_client_cert,
                                         P11KMIP_SERVER_CERT_PATH,
                                         P11KMIP_SERVER_PKEY_PATH,
                                         NULL, &verified, opt_verbose);

    if (rc != 0) {
        warnx("Failed to retrieve KMIP server certificate");
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rc = p11kmip_check_certificate(P11KMIP_SERVER_CERT_PATH, &self_signed,
                                   &valid);

    if (rc != 0) {
        warnx("Failed to check KMIP server certificate '%s'",
              P11KMIP_SERVER_CERT_PATH);
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    if (!valid)
        printf("ATTENTION: The certificate is expired or not yet " "valid.\n");
    if (self_signed)
        printf("ATTENTION: The certificate is self-signed "
               "and thus could not be verified.\n");

    if (!verified) {
        if (!opt_tls_no_verify_cert) {
            warnx("The certificate could not be "
                  "verified using the system's "
                  "CA certificates. Use option "
                  "'--tls-no-verify-server-cert' to "
                  "connect to this server anyway.");
            rv = CKR_GENERAL_ERROR;;
            goto done;
        }
    }

    if (opt_tls_trust_server == false) {
        rc = p11kmip_print_certificates(P11KMIP_SERVER_CERT_PATH);

        if (rc != 0) {
            warnx("Failed to print KMIP server certificate '%s'",
                  P11KMIP_SERVER_CERT_PATH);
            rv = CKR_GENERAL_ERROR;
            goto done;
        }

        printf("Is this the KMIP server you intend to connect to? [y/N] ");
        if (!prompt_for_yes()) {
            warnx("Operation aborted by user");
            rv = CKR_CANCEL;
            goto done;
        }
    }

    rc = kmip_connection_new(kmip_conf, &kmip_conn, opt_verbose);

    if (rc != 0) {
        warnx("Failed to initialize connection to KMIP server");
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rc = discover_kmip_versions(&kmip_vers);
    if (rc != 0) {
        warnx("DISCOVER-VERSION failed, retry " "with KMIP v1.2");

        kmip_vers.major = 1;
        kmip_vers.minor = 2;
        kmip_set_default_protocol_version(&kmip_version_1_2);

        rc = discover_kmip_versions(&kmip_vers);
        if (rc != 0) {
            warnx("KMIP server version <1.2 not supported");
            rv = CKR_GENERAL_ERROR;
            goto done;
        }
    }

    kmip_set_default_protocol_version(&kmip_vers);
    printf("KMIP server version: %d.%d\n", kmip_vers.major, kmip_vers.minor);

done:
    return rv;
}

/**
 * @brief Closes and frees the KMIP connection and the
 * KMIP configuration structure
 * 
 */
static void term_kmip(void)
{
    if (kmip_conn != NULL)
        kmip_connection_free(kmip_conn);

    if (kmip_conf != NULL)
        free_kmip_config();
}

/*****************************************************************************/
/* KMIP Compatibility Functions                                              */
/*****************************************************************************/

/**
 * Discovers the KMIP protocol versions that the KMIP server supports
 *
 * @param version           On return : the highest KMIP version that the server
 *                          and the KMIP client supports
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int discover_kmip_versions(struct kmip_version *version)
{
    struct kmip_node *req_pl = NULL, *resp_pl = NULL;
    enum kmip_result_status discover_status = 0;
    enum kmip_result_reason discover_reason = 0;
    int rc = 0;

    req_pl = kmip_new_discover_versions_payload(-1, NULL);
    if (req_pl == NULL) {
        rc = CKR_HOST_MEMORY;
        warnx("Allocate KMIP node failed");
        goto out;
    }

    rc = perform_kmip_request(KMIP_OPERATION_DISCOVER_VERSIONS,
                              req_pl, &resp_pl, &discover_status,
                              &discover_reason);
    if (rc) {
        warnx("Failed to request KMIP version from server");
        goto out;
    }

    rc = kmip_get_discover_versions_response_payload(resp_pl, NULL, 0, version);
    if (rc != 0) {
        warnx("Failed to get discover version response");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

out:
    kmip_node_free(req_pl);
    kmip_node_free(resp_pl);

    return rc;
}

/**
 * Returns true if the KMIP server supports the 'Sensitive' attribute.
 * This is dependent on the profile settings, and the used KMIP protocol
 * version (>= v1.4).
 *
 * @param ph                the plugin handle
 *
 * @return true or false
 */
static bool supports_sensitive_attr(void)
{
    if (kmip_vers.major <= 1)
        return false;

    if (kmip_vers.major == 1 && kmip_vers.minor < 4)
        return false;

    return true;
}

/**
 * Returns the name of the enumeration value.
 *
 * @param values            the list of enumeration values
 * @param value             the value
 *
 * @returns a constant string
 */
static const char *_enum_value_to_str(const struct kmip_enum_name *values,
                                      uint32_t value)
{
    unsigned int i;

    for (i = 0; values[i].name != NULL; i++) {
        if (values[i].value == value)
            return values[i].name;
    }

    return "UNKNOWN";
}

/*****************************************************************************/
/* KMIP Request Functions                                                    */
/*****************************************************************************/

/**
 * Build Custom/Vendor attribute according to the Custom attribute style of the
 * profile.
 *
 * @param name              the attribute name
 * @param value             the attribute value
 *
 * @returns the attribute node or NULL in case of an error.
 */
static struct kmip_node *build_custom_attr(const char *name, const char *value)
{
    struct kmip_node *attr = NULL, *text;
    char *v1_name = NULL;

    text = kmip_node_new_text_string(KMIP_TAG_ATTRIBUTE_VALUE, NULL, value);

    if(asprintf(&v1_name, "kmip-%s", name) <= 0) {
        warnx("asprintf failed");
        goto out;
    }
    attr = kmip_new_vendor_attribute("x", v1_name, text);
    free(v1_name);

out:
    kmip_node_free(text);
    return attr;
}

static struct kmip_node *build_description_attr(const char *description)
{
    /**
     * So on the one hand, we don't support KMIP version <1.2 at all 
     * but on the other hand, SKLM doesn't appear to support description 
     * or comment attributes. Only making a custom description attribute 
     * is valid
     */
    return build_custom_attr("description", description);
}

/**
 * Check a KMIP response and extract information from it.
 *
 * @param resp              the response KMIP node
 * @param batch_item        the batch item index (staring at 0)
 * @param operation         the operation (to verify the batch item)
 * @param payload           On return : the payload of this batch item
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int check_kmip_response(struct kmip_node *resp, int32_t batch_item,
                               enum kmip_operation operation,
                               struct kmip_node **payload,
                               enum kmip_result_status *status,
                               enum kmip_result_reason *reason)
{
    struct kmip_node *resp_hdr = NULL, *resp_bi = NULL;
    const char *message = NULL;
    int32_t batch_count;
    int rc;

    rc = kmip_get_response(resp, &resp_hdr, 0, NULL);
    if (rc != 0) {
        warnx("Get KMIP response header failed");
        goto out;
    }

    rc = kmip_get_response_header(resp_hdr, NULL, NULL, NULL, NULL,
                                  &batch_count);
    if (rc != 0) {
        warnx("Get KMIP response header infos failed");
        goto out;
    }
    if (batch_item >= batch_count) {
        rc = -EBADMSG;
        warnx("Response contains less batch items than expected");
        goto out;
    }

    rc = kmip_get_response(resp, NULL, batch_item, &resp_bi);
    if (rc != 0) {
        warnx("Get KMIP response batch item failed");
        goto out;
    }

    rc = kmip_get_response_batch_item(resp_bi, NULL, NULL, NULL, status,
                                      reason, &message, NULL, NULL, payload);
    if (rc != 0) {
        warnx("Get KMIP response status infos failed");
        goto out;
    }

    if (status[0] != KMIP_RESULT_STATUS_SUCCESS) {
        warnx("KMIP Request failed: Operation: '%s', "
              "Status: '%s', Reason: '%s', Message: '%s'",
              _enum_value_to_str(required_operations, operation),
              _enum_value_to_str(kmip_result_statuses, status[0]),
              _enum_value_to_str(kmip_result_reasons, reason[0]),
              message ? message : "(none)");
        rc = -EBADMSG;
        goto out;
    }
out:
    kmip_node_free(resp_hdr);
    kmip_node_free(resp_bi);

    return rc;
}


/**
 * Build a KMIP request with the up to 2 operations and payloads
 *
 * @param operation1        The 1st operation to perform
 * @param req_pl1           the request payload of the 1st operation
 * @param operation2        The 2nd operation to perform (or 0)
 * @param req_pl2           the request payload of the 2nd operation (or NULL)
 * @param req               On return: the created request.
 * @param batch_err_opt     Batch error option
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int build_kmip_request2(enum kmip_operation operation1,
                               struct kmip_node *req_pl1,
                               enum kmip_operation operation2,
                               struct kmip_node *req_pl2,
                               struct kmip_node **req,
                               enum kmip_batch_error_cont_option batch_err_opt)
{
    struct kmip_node *req_bi1 = NULL, *req_bi2 = NULL, *req_hdr = NULL;
    int rc = 0;

    req_bi1 = kmip_new_request_batch_item(operation1, NULL, 0, req_pl1);
    if (req_bi1 == NULL) {
        rc = CKR_HOST_MEMORY;
        warnx("Allocate KMIP node failed");
        goto out;
    }

    if (operation2 != 0) {
        req_bi2 = kmip_new_request_batch_item(operation2, NULL, 0, req_pl2);
        if (req_bi2 == NULL) {
            rc = CKR_HOST_MEMORY;
            warnx("Allocate KMIP node failed");
            goto out;
        }
    }

    req_hdr = kmip_new_request_header(NULL, 0, NULL, NULL, false, NULL,
                                      batch_err_opt, true,
                                      operation2 != 0 ? 2 : 1);
    if (req_hdr == NULL) {
        rc = CKR_HOST_MEMORY;
        warnx("Allocate KMIP node failed");
        goto out;
    }

    *req = kmip_new_request_va(req_hdr, 2, req_bi1, req_bi2);
    if (*req == NULL) {
        rc = CKR_HOST_MEMORY;
        warnx("Allocate KMIP node failed");
        goto out;
    }

out:
    kmip_node_free(req_bi1);
    kmip_node_free(req_bi2);
    kmip_node_free(req_hdr);

    return rc;
}


/**
 * Perform a KMIP request with up to 2 operations and payloads.
 * Returns the response payloads.
 *
 * @param operation1        The 1st operation to perform
 * @param req_pl1           the request payload if the 1st operation
 * @param resp_pl 1         On return: the response payload.
 * @param operation2        The 2nd operation to perform (or zero)
 * @param req_pl2           the request payload of the 2nd operation (or NULL)
 * @param resp_pl2          On return: the response payload.
 * @param batch_err_opt     Batch error option
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int perform_kmip_request2(enum kmip_operation operation1,
                            struct kmip_node *req_pl1,
                            struct kmip_node **resp_pl1,
                            enum kmip_result_status *status1,
                            enum kmip_result_reason *reason1,
                            enum kmip_operation operation2,
                            struct kmip_node *req_pl2,
                            struct kmip_node **resp_pl2,
                            enum kmip_result_status *status2,
                            enum kmip_result_reason *reason2,
                            enum kmip_batch_error_cont_option batch_err_opt)
{
    struct kmip_node *req = NULL, *resp = NULL;
    int rc;

    rc = build_kmip_request2(operation1, req_pl1, operation2, req_pl2,
                             &req, batch_err_opt);
    if (rc != 0)
        goto out;

    rc = kmip_connection_perform(kmip_conn, req, &resp, opt_verbose);
    if (rc != 0) {
        goto out;
    }

    rc = check_kmip_response(resp, 0, operation1, resp_pl1, status1, reason1);
    if (rc != 0 && batch_err_opt == KMIP_BATCH_ERR_CONT_CONTINUE &&
        operation2 != 0) {
        rc = 0;
    }
    if (rc != 0)
        goto out;

    if (operation2 != 0) {
        rc = check_kmip_response(resp, 1, operation2, resp_pl2,
                                 status2, reason2);
        if (rc != 0)
            goto out;
    }

out:
    kmip_node_free(req);
    kmip_node_free(resp);

    return rc;
}

/**
 * Perform a KMIP request with the specified operation and payload. Returns the
 * response payload.
 *
 * @param operation         The operation to perform
 * @param req_pl            the request payload
 * @param resp_pl           On return: the response payload.
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int perform_kmip_request(enum kmip_operation operation,
                                struct kmip_node *req_pl,
                                struct kmip_node **resp_pl,
                                enum kmip_result_status *status,
                                enum kmip_result_reason *reason)
{
    return perform_kmip_request2(operation, req_pl, resp_pl, status, reason,
                                 0, NULL, NULL, NULL, NULL,
                                 KMIP_BATCH_ERR_CONT_STOP);
}

/*****************************************************************************/
/* PKCS Library Functions                                                    */
/*****************************************************************************/

static CK_RV load_pkcs11_lib(void)
{
    CK_RV rc;
    CK_RV(*getfunclist) (CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    const char *libname;

    libname = secure_getenv(P11KMIP_PKCSLIB_ENV_NAME);

    if (libname == NULL || strlen(libname) < 1)
        libname = P11KMIP_DEFAULT_PKCS11_LIB;

    pkcs11_lib = dlopen(libname, RTLD_NOW);
    if (pkcs11_lib == NULL) {
        warnx("Failed to load PKCS#11 library '%s': %s", libname, dlerror());
        return CKR_FUNCTION_FAILED;
    }

    *(void **) (&getfunclist) = dlsym(pkcs11_lib, "C_GetFunctionList");
    if (getfunclist == NULL) {
        warnx("Failed to resolve symbol '%s' from PKCS#11 library '%s': %s",
              "C_GetFunctionList", libname, dlerror());
        return CKR_FUNCTION_FAILED;
    }

    rc = getfunclist(&pkcs11_funcs);
    if (rc != CKR_OK) {
        warnx("C_GetFunctionList() on "
              "PKCS#11 library '%s' failed with 0x%lX: %s)\n",
              libname, rc, p11_get_ckr(rc));
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV open_pkcs11_session(CK_SLOT_ID slot, CK_FLAGS flags, 
                                 const char *pin)
{
    CK_RV rc;

    rc = pkcs11_funcs->C_GetInfo(&pkcs11_info);
    if (rc != CKR_OK) {
        warnx("Failed to getPKCS#11 info: C_GetInfo: 0x%lX: %s",
              rc, p11_get_ckr(rc));
        return rc;
    }

    rc = pkcs11_funcs->C_GetSlotInfo(slot, &pkcs11_slotinfo);
    if (rc != CKR_OK) {
        warnx("Slot %lu is not available: C_GetSlotInfo: 0x%lX: %s", slot,
              rc, p11_get_ckr(rc));
        return rc;
    }

    rc = pkcs11_funcs->C_GetTokenInfo(slot, &pkcs11_tokeninfo);
    if (rc != CKR_OK) {
        warnx("Token at slot %lu is not available: C_GetTokenInfo: 0x%lX: %s",
              slot, rc, p11_get_ckr(rc));
        return rc;
    }

    rc = pkcs11_funcs->C_OpenSession(slot, flags, NULL, NULL, &pkcs11_session);
    if (rc != CKR_OK) {
        warnx("Opening a session failed: C_OpenSession: 0x%lX: %s)", rc,
              p11_get_ckr(rc));
        return rc;
    }

    rc = pkcs11_funcs->C_Login(pkcs11_session, CKU_USER, (CK_CHAR *) pin,
                               strlen(pin));
    if (rc != CKR_OK) {
        warnx("Login failed: C_Login: 0x%lX: %s", rc, p11_get_ckr(rc));
        return rc;
    }

    return CKR_OK;
}

static void close_pkcs11_session(void)
{
    CK_RV rc;

    rc = pkcs11_funcs->C_Logout(pkcs11_session);
    if (rc != CKR_OK && rc != CKR_USER_NOT_LOGGED_IN)
        warnx("C_Logout failed: 0x%lX: %s", rc, p11_get_ckr(rc));

    rc = pkcs11_funcs->C_CloseSession(pkcs11_session);
    if (rc != CKR_OK)
        warnx("C_CloseSession failed: 0x%lX: %s", rc, p11_get_ckr(rc));

    pkcs11_session = CK_INVALID_HANDLE;
}

static CK_RV init_pkcs11(const struct p11kmip_cmd *command)
{
    CK_RV rc;
    int f;
    struct ConfigBaseNode *c, *cfg_slot;
    struct ConfigStructNode *structnode;
    bool found = false;
    char *buf_user_pin = NULL;
    const char *pin = opt_pin;
    CK_SLOT_ID slot = opt_slot;

    if (command == NULL || command->session_flags == 0)
        return CKR_OK;

    if (pin == NULL)
        pin = env_pkcs_pin;
    if (opt_force_pin_prompt || pin == NULL)
        pin = pin_prompt(&buf_user_pin, "Please enter user PIN: ");
    if (pin == NULL)
        return CKR_FUNCTION_FAILED;

    /* If not set by option, fallback to env variable */
    if (slot == (CK_SLOT_ID) - 1)
        slot = env_pkcs_slot;
    /* If not set by env variable, fallback to conf file */
    if (slot == (CK_SLOT_ID) - 1) {
        if (p11kmip_cfg != NULL) {
            /* Iterate the configuration node(s) */
            confignode_foreach(c, p11kmip_cfg, f) {
                if (!confignode_hastype(c, CT_STRUCT) ||
                    strcmp(c->key, P11KMIP_CONFIG_KEYWORD_PKCS11) != 0) {
                    continue;
                } else if (found) {
                    warnx("Syntax error in config file:"
                          " '%s' specified multiple times\n",
                          P11KMIP_CONFIG_KEYWORD_PKCS11);
                    rc = CKR_ARGUMENTS_BAD;
                    goto done;
                }

                structnode = confignode_to_struct(c);
                cfg_slot = confignode_find(structnode->value,
                                           P11KMIP_CONFIG_KEYWORD_PKCS_SLOT);

                if (cfg_slot != NULL
                    && !confignode_hastype(cfg_slot, CT_INTVAL)) {
                    warnx("Syntax error in config file:"
                          " Missing '%s' in attribute at line %hu\n",
                          P11KMIP_CONFIG_KEYWORD_WRAP_KEY_SIZE, c->line);
                    rc = CKR_ARGUMENTS_BAD;
                    goto done;
                }

                if (cfg_slot != NULL) {
                    slot = confignode_to_intval(cfg_slot)->value;
                }
            }
        }
    }

    rc = load_pkcs11_lib();
    if (rc != CKR_OK)
        goto done;

    rc = pkcs11_funcs->C_Initialize(NULL);
    if (rc != CKR_OK) {
        warnx("C_Initialize failed: 0x%lX: %s", rc, p11_get_ckr(rc));
        goto done;
    }

    pkcs11_initialized = true;

    rc = open_pkcs11_session(slot, command->session_flags, pin);
    if (rc != CKR_OK)
        goto done;

done:
    pin_free(&buf_user_pin);

    return rc;
}

static void term_pkcs11(void)
{
    CK_RV rc;

    if (pkcs11_session != CK_INVALID_HANDLE)
        close_pkcs11_session();

    if (pkcs11_funcs != NULL && pkcs11_initialized) {
        rc = pkcs11_funcs->C_Finalize(NULL);
        if (rc != CKR_OK)
            warnx("C_Finalize failed: 0x%lX: %s", rc, p11_get_ckr(rc));
    }

    if (pkcs11_lib != NULL)
        dlclose(pkcs11_lib);

    pkcs11_lib = NULL;
    pkcs11_funcs = NULL;
}

/*****************************************************************************/
/* PKCS#11 Key Attribute Functions                                           */
/*****************************************************************************/

static void print_bool_attr_short(const CK_ATTRIBUTE *val, bool applicable)
{
    if (val->ulValueLen == CK_UNAVAILABLE_INFORMATION ||
        val->ulValueLen != sizeof(CK_BBOOL))
        applicable = false;
    printf("%c ", applicable ? (*(CK_BBOOL *) (val->pValue) ? '1' : '0') : '-');
}

static void print_bool_attr_long(const char *attr, const CK_ATTRIBUTE *val,
                                 int indent, bool sensitive)
{
    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        val->ulValueLen != sizeof(CK_BBOOL))
        return;

    printf("%*s%s: %s\n", indent, "", attr,
           sensitive ? "[sensitive]" :
           *(CK_BBOOL *) (val->pValue) ? "CK_TRUE" : "CK_FALSE");
}

static CK_RV add_attribute(CK_ATTRIBUTE_TYPE type, 
                           const void *value,
                           CK_ULONG value_len, 
                           CK_ATTRIBUTE **attrs, 
                           CK_ULONG *num_attrs)
{
    CK_ATTRIBUTE *tmp;

    tmp = realloc(*attrs, (*num_attrs + 1) * sizeof(CK_ATTRIBUTE));
    if (tmp == NULL) {
        warnx("Failed to allocate memory for attribute list");
        return CKR_HOST_MEMORY;
    }

    *attrs = tmp;

    tmp[*num_attrs].type = type;
    tmp[*num_attrs].ulValueLen = value_len;
    tmp[*num_attrs].pValue = malloc(value_len);
    if (tmp[*num_attrs].pValue == NULL) {
        warnx("Failed to allocate memory attribute to add to list");
        return CKR_HOST_MEMORY;
    }
    memcpy(tmp[*num_attrs].pValue, value, value_len);

    (*num_attrs)++;

    return CKR_OK;
}

static const struct p11kmip_attr *find_attr_by_letter(char letter)
{
    const struct p11kmip_attr *attr;

    for (attr = p11kmip_bool_attrs; attr->name != NULL; attr++) {
        if (attr->letter == toupper(letter))
            return attr;
    }

    return NULL;
}

static CK_RV parse_boolean_attrs(
                    const struct p11kmip_keytype *keytype,
                    const char *attr_string, CK_ATTRIBUTE **attrs,
                    CK_ULONG *num_attrs, bool check_settable,
                    bool (*attr_aplicable)(
                        const struct p11kmip_keytype *keytype,
                        const struct p11kmip_attr *attr))
{
    const struct p11kmip_attr *attr;
    unsigned int i = 0;
    CK_BBOOL val;
    CK_RV rc;

    if (attr_string == NULL)
        return CKR_OK;

    for (i = 0; attr_string[i] != '\0'; i++) {
        attr = find_attr_by_letter(attr_string[i]);
        if (attr == NULL) {
            warnx("Attribute '%c' is not valid", attr_string[i]);
            return CKR_ARGUMENTS_BAD;
        }

        /* silently ignore attributes that are not settable or not applicable */
        if ((check_settable && !attr->settable) ||
            (attr_aplicable != NULL && keytype != NULL &&
             !attr_aplicable(keytype, attr)))
            continue;

        val = isupper(attr_string[i]) ? CK_TRUE : CK_FALSE;

        rc = add_attribute(attr->type, &val, sizeof(val), attrs, num_attrs);
        if (rc != CKR_OK)
            return rc;
    }

    return CKR_OK;
}

static CK_RV parse_id(const char *id_string, 
                      CK_ATTRIBUTE **attrs, 
                      CK_ULONG *num_attrs)
{
    unsigned char *buf = NULL;
    BIGNUM *b = NULL;
    int len;
    CK_RV rc = CKR_OK;

    len = BN_hex2bn(&b, id_string);
    if (len < (int) strlen(id_string)) {
        warnx("Hex string '%s' is not valid", id_string);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    len = len / 2 + (len % 2 > 0 ? 1 : 0);
    buf = calloc(1, len);
    if (buf == NULL) {
        warnx("Failed to allocate memory for CKA_ID attribute");
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (BN_bn2binpad(b, buf, len) != len) {
        warnx("Failed to prepare the value for CKA_ID attribute");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = add_attribute(CKA_ID, buf, len, attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to add attribute CKA_ID: 0x%lX: %s", rc, p11_get_ckr(rc));
        goto done;
    }

done:
    if (buf != NULL)
        free(buf);
    if (b != NULL)
        BN_free(b);

    return rc;
}


static bool is_attr_array_attr(CK_ATTRIBUTE *attr)
{
    switch (attr->type) {
    case CKA_WRAP_TEMPLATE:
    case CKA_UNWRAP_TEMPLATE:
    case CKA_DERIVE_TEMPLATE:
        return true;

    default:
        return false;
    }
}

static CK_RV alloc_attr_array_attr(CK_ATTRIBUTE *attr, bool *allocated)
{
    CK_ULONG i, num;
    CK_ATTRIBUTE *elem;
    CK_RV rc;

    *allocated = false;

    num = attr->ulValueLen / sizeof(CK_ATTRIBUTE);
    for (i = 0, elem = attr->pValue; i < num; i++, elem++) {
        if (elem->ulValueLen > 0 && elem->pValue == NULL) {
            elem->pValue = calloc(elem->ulValueLen, 1);
            if (elem->pValue == NULL) {
                free_attr_array_attr(attr);
                return CKR_HOST_MEMORY;
            }

            *allocated = true;
            continue;
        }

        if (is_attr_array_attr(elem)) {
            rc = alloc_attr_array_attr(elem, allocated);
            if (rc != CKR_OK) {
                free_attr_array_attr(attr);
                return CKR_HOST_MEMORY;
            }
        }
    }

    return CKR_OK;
}

static void free_attr_array_attr(CK_ATTRIBUTE *attr)
{
    CK_ULONG i, num;
    CK_ATTRIBUTE *elem;

    num = attr->ulValueLen / sizeof(CK_ATTRIBUTE);
    for (i = 0, elem = attr->pValue; elem != NULL && i < num; i++, elem++) {
        if (elem->pValue != NULL) {
            if (is_attr_array_attr(elem))
                free_attr_array_attr(elem);
            free(elem->pValue);
            elem->pValue = NULL;
        }
    }
}

static CK_RV get_attribute(CK_OBJECT_HANDLE key, CK_ATTRIBUTE *attr)
{
    bool allocated;
    CK_RV rc;

    rc = pkcs11_funcs->C_GetAttributeValue(pkcs11_session, key, attr, 1);
    if (rc != CKR_OK)
        return rc;

    if (attr->pValue == NULL && attr->ulValueLen > 0) {
        attr->pValue = calloc(attr->ulValueLen, 1);
        if (attr->pValue == NULL)
            return CKR_HOST_MEMORY;

        rc = pkcs11_funcs->C_GetAttributeValue(pkcs11_session, key, attr, 1);
    }

    if (is_attr_array_attr(attr) && rc == CKR_OK &&
        attr->pValue != NULL && attr->ulValueLen > 0) {
        do {
            allocated = false;
            rc = alloc_attr_array_attr(attr, &allocated);
            if (rc != CKR_OK)
                return rc;

            if (!allocated)
                break;

            rc = pkcs11_funcs->C_GetAttributeValue(pkcs11_session, key,
                                                   attr, 1);
        } while (rc == CKR_OK);
    }

    return rc;
}

static CK_RV add_bignum_attr(CK_ATTRIBUTE_TYPE type, const BIGNUM *bn,
                             CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs)
{
    int len;
    CK_BYTE *buff = NULL;
    CK_RV rc;

    len = BN_num_bytes(bn);
    buff = calloc(len, 1);
    if (buff == NULL || len == 0) {
        warnx("Failed to allocate a buffer for a bignum");
        if (buff != NULL)
            free(buff);
        return CKR_HOST_MEMORY;
    }

    if (BN_bn2bin(bn, buff) != len) {
        warnx("Failed to get a bignum.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        free(buff);
        return CKR_FUNCTION_FAILED;
    }

    rc = add_attribute(type, buff, len, attrs, num_attrs);
    free(buff);

    return rc;
}

static CK_RV get_bignum_attr(CK_OBJECT_HANDLE key, 
                             CK_ATTRIBUTE_TYPE type, 
                             BIGNUM **bn)
{
    CK_ATTRIBUTE attr;
    CK_RV rc;

    attr.type = type;
    attr.pValue = NULL;
    attr.ulValueLen = 0;

    if (is_attr_array_attr(&attr))
        return CKR_ATTRIBUTE_TYPE_INVALID;

    rc = get_attribute(key, &attr);
    if (rc != CKR_OK)
        return rc;

    if (attr.ulValueLen == 0 || attr.pValue == NULL)
        return CKR_ATTRIBUTE_VALUE_INVALID;

    *bn = BN_new();
    if (*bn == NULL) {
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (BN_bin2bn((unsigned char *) attr.pValue, 
                  attr.ulValueLen, *bn) == NULL) {
        rc = CKR_FUNCTION_FAILED;
        BN_free(*bn);
        *bn = NULL;
        goto done;
    }

done:
    free(attr.pValue);

    return rc;
}

static void free_attributes(CK_ATTRIBUTE *attrs, CK_ULONG num_attrs)
{
    CK_ULONG i;

    if (attrs == NULL)
        return;

    for (i = 0; i < num_attrs; i++) {
        if (attrs[i].pValue != NULL)
            free(attrs[i].pValue);
    }

    free(attrs);
}

/*****************************************************************************/
/* PKCS#11 Key Type Functions                                                */
/*****************************************************************************/

static CK_RV get_key_size(const struct p11kmip_keytype *keytype,
                          void *private, CK_ULONG *keysize)
{
    CK_OBJECT_HANDLE key_handle;
    CK_ATTRIBUTE keysize_attr;
    CK_RV rc = CKR_OK;

    if (private == NULL) {
        /*
         * If we are not provided with a key handle, we have to rely on the
         * keysize set in the keytype structure itself
         */
        *keysize = keytype->keysize_value;
        return CKR_OK;
    
    }

    key_handle = (CK_OBJECT_HANDLE)private;

    keysize_attr.type = keytype->keysize_attr;
    keysize_attr.ulValueLen = sizeof(*keysize);
    keysize_attr.pValue = keysize;
    
    rc = pkcs11_funcs->C_GetAttributeValue(pkcs11_session, key_handle,
                                           &keysize_attr, 1);
    if (rc != CKR_OK) {
        warnx("Attribute not found in PKCS#11 object");
        return rc;
    }

    *keysize = (CK_ULONG)keysize_attr.pValue;

    return CKR_OK;
}

static bool aes_is_attr_applicable(const struct p11kmip_keytype *keytype, 
                                   const struct p11kmip_attr *attr)
{
    UNUSED(keytype);
    if (attr->type == CKA_TOKEN)
        return false;

    return true;
}

/*****************************************************************************/
/* PKCS#11 Crypto Adapter Utility Functions                                  */
/*****************************************************************************/

/* Commands */

/**
 * Registers a public key with a KMIP server, retrieves a secret key from
 * the KMIP server wrapped with that public key, and then unwraps and imports
 * the secret key locally
 * 
 * global opt_wrap_label        wrapping key label
 * global opt_send_wrapkey      flag to register wrapping key
 *                              with KMIP server (optional)
 * global opt_unwrap_label      unwrapping key label (optional)
 * global opt_target_label      target key label
 * global opt_target_id         CKA_ID for target key (optional)
 * global opt_target_attrs      boolean attributes for target key (optional)
 * global opt_gen_targkey       flag for KMIP server to generate 
 *                              target key (optional)
 * 
 * @return CK_RV 
 */
static CK_RV p11kmip_import_key(void)
{
    CK_RV rc;
    CK_OBJECT_HANDLE wrapping_pubkey, wrapping_privkey, unwrapped_key_handle;
    struct p11kmip_keytype pubkey_keytype, privkey_keytype, secret_keytype;
    struct kmip_node *wrap_pubkey_uid = NULL, *secret_key_uid = NULL;
    CK_BYTE *wrapped_key_blob = NULL;
    unsigned long wrapped_key_length = 0;
    CK_ATTRIBUTE *wrapped_key_attrs = NULL;
    CK_ULONG wrapped_key_num_attrs = 0, local_key_digest_len = 0;
    u_int32_t remote_key_digest_len = 0;
    CK_BYTE_PTR local_key_digest = NULL, remote_key_digest = NULL;
    enum kmip_hashing_algo digest_alg = 0;
    struct CK_MECHANISM digest_mech = { 0 };

    /**
     * Until we support algorithms beyond RSA and AES, using these hard-coded
     * key types are sufficient 
     */
    pubkey_keytype = p11kmip_rsa_keytype;

    privkey_keytype = p11kmip_rsa_keytype;
    privkey_keytype.class = CKO_PRIVATE_KEY;

    secret_keytype = p11kmip_aes_keytype;
    
    /* Validate and set secret key length */
    if (opt_target_length == (CK_ULONG)-1) {
        secret_keytype.keysize_value = P11KMIP_DEFAULT_AES_KEY_LENGTH;
    } else {
        switch (opt_target_length)
        {
            case 128:
            case 192:
            case 256:
                break;
            default:
                warnx("Invalid length set for target key:"
                      " %ld\n", opt_target_length);
                rc = CKR_GENERAL_ERROR;
                goto done;
        }
        secret_keytype.keysize_value = (opt_target_length/8);
    }

    /* Parse the attrs and id options up front to fail fast */
    if (opt_target_attrs != NULL) {
        rc = parse_boolean_attrs(&secret_keytype, opt_target_attrs,
                                 &wrapped_key_attrs, &wrapped_key_num_attrs,
                                 false, aes_is_attr_applicable);

        if (rc != CKR_OK) {
            warnx("Failed to parse boolean attributes for target key\n");
            goto done;
        }
    }

    if (opt_target_id != NULL) {
        rc = parse_id(opt_target_id, &wrapped_key_attrs,
                      &wrapped_key_num_attrs);

        if (rc != CKR_OK) {
            warnx("Failed to parse ID for target key\n");
            goto done;
        }
    }

    rc = p11kmip_find_local_key(&pubkey_keytype, opt_wrap_label, NULL,
                                &wrapping_pubkey);

    if (rc != CKR_OK) {
        warnx("Failed to wrapping key with label '%s'\n", opt_wrap_label);
        goto done;
    }

    if (opt_unwrap_label != NULL) {
        rc = p11kmip_find_local_key(&privkey_keytype, opt_unwrap_label, NULL,
                                    &wrapping_privkey);

        if (rc != CKR_OK) {
            warnx("Failed to find unwrapping key with label '%s'\n",
                  opt_unwrap_label);
            goto done;
        }
    } else {
        rc = p11kmip_find_local_key(&privkey_keytype, opt_wrap_label, NULL,
                                    &wrapping_privkey);

        if (rc != CKR_OK) {
            warnx("Failed to find unwrapping key with label '%s'\n",
                  opt_unwrap_label);
            goto done;
        }
    }

    /* If we were unable to locate the key on the server,  */
    if (wrap_pubkey_uid == NULL) {
        /* If we were told to send the wrapkey, send it */
        if (opt_send_wrapkey) {
            /* Next we send the public key to the server */
            rc = p11kmip_register_remote_public_key(&pubkey_keytype,
                                                    wrapping_pubkey,
                                                    opt_wrap_label,
                                                    &wrap_pubkey_uid);

            if (rc != CKR_OK) {
                warnx("Failed to register wrapping key '%s' on server\n",
                      opt_wrap_label);
                goto done;
            }
        } else {
            rc = p11kmip_locate_remote_key(opt_wrap_label, &pubkey_keytype,
                                           &wrap_pubkey_uid);

            if (rc != CKR_OK) {
                warnx("Error while locating wrapping key on KMIP server\n");
                goto done;
            }
        }
    }

    if (opt_gen_targkey) {
        /* If we were told to generate a new key, do so */
        rc = p11kmip_generate_remote_secret_key(&secret_keytype,
                                                opt_target_label,
                                                &secret_key_uid);

        if (rc != CKR_OK) {
            warnx("Error creating target key on KMIP server");
            goto done;
        }
    } else {
        /* Else attempt to find the one we were given */
        rc = p11kmip_locate_remote_key(opt_target_label, &secret_keytype,
                                       &secret_key_uid);

        if (rc != CKR_OK) {
            warnx("Error while locating target key on KMIP server\n");
            goto done;
        }
        /* If we didn't find it, throw an error */
        if (secret_key_uid == NULL) {
            warnx("Did not find target key '%s' on server\n", opt_target_label);
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }
    }

    rc = p11kmip_retrieve_remote_wrapped_key(wrap_pubkey_uid,
                                             &secret_keytype, secret_key_uid,
                                             &wrapped_key_length,
                                             &wrapped_key_blob);

    if (wrapped_key_blob == NULL) {
        warnx("Failed to retrieve wrapped key\n");
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    /* Lastly we unwrap and import the retrieved key */
    rc = p11kmip_unwrap_local_secret_key(wrapping_privkey,
                                         &secret_keytype, wrapped_key_length,
                                         wrapped_key_blob, opt_target_label,
                                         wrapped_key_attrs,
                                         wrapped_key_num_attrs,
                                         &unwrapped_key_handle);

    if (rc != CKR_OK) {
        warnx("Failed to unwrap and import key");
        goto done;
    }
    /* Display digests of the retrieved keys */
    if (!opt_quiet) {
        remote_key_digest_len = 32;
        remote_key_digest = malloc(remote_key_digest_len);

        rc = p11kmip_digest_remote_key(secret_key_uid,
                                       &digest_alg, remote_key_digest,
                                       &remote_key_digest_len);

        if (rc != CKR_OK) {
            warnx("Obtaining digest of KMIP key failed");
            goto done;
        }
        /* The same hashing algorithm should produce a digest of the same len */
        local_key_digest_len = remote_key_digest_len;
        local_key_digest = malloc(local_key_digest_len);
        digest_mech.mechanism =
            get_p11_hash_mech_from_kmip_hash_algo(digest_alg);

        rc = p11kmip_digest_local_key(local_key_digest, &local_key_digest_len,
                                      unwrapped_key_handle, &digest_mech);

        if (rc != CKR_OK && rc != CKR_KEY_INDIGESTIBLE) {
            warnx("Obtaining digest of PKCS#11 key failed");
            goto done;
        }

        if (opt_short) {
            printf("%s:", opt_target_label);
            if (rc == CKR_KEY_INDIGESTIBLE) {
                printf("<key digest not available>");
                rc = CKR_OK;
            } else {
                print_hex(local_key_digest, (int) local_key_digest_len);
            }
            printf("\n");

            printf("%s:", kmip_node_get_text_string(secret_key_uid));
            print_hex(remote_key_digest, (int) remote_key_digest_len);
            printf("\n");
        } else {
            printf("  Secret Key\n");
            printf("     PKCS#11 Label...%s\n", opt_target_label);
            printf("     PKCS#11 Digest..");
            if (rc == CKR_KEY_INDIGESTIBLE) {
                printf("<key digest not available>");
                rc = CKR_OK;
            } else {
                print_hex(local_key_digest, (int) local_key_digest_len);
            }
            printf("\n");
            printf("     KMIP UID........%s\n",
                   kmip_node_get_text_string(secret_key_uid));
            printf("     KMIP Digest.....");
            print_hex(remote_key_digest, (int) remote_key_digest_len);
            printf("\n");

            printf("  Public Key\n");
            printf("     PKCS#11 Label...%s\n", opt_wrap_label);
            printf("     KMIP UID........%s\n",
                   kmip_node_get_text_string(wrap_pubkey_uid));
        }

    }

done:
    kmip_node_free(wrap_pubkey_uid);
    kmip_node_free(secret_key_uid);
    if (local_key_digest != NULL)
        free(local_key_digest);
    if (remote_key_digest != NULL)
        free(remote_key_digest);
    if (wrapped_key_blob != NULL)
        free(wrapped_key_blob);
    free_attributes(wrapped_key_attrs, wrapped_key_num_attrs);

    return rc;
}


static CK_RV p11kmip_export_key(void)
{
    CK_RV rc;
    CK_OBJECT_HANDLE wrapping_pubkey, secret_key_handle;
    struct p11kmip_keytype pubkey_keytype, secret_keytype;
    struct kmip_node *wrap_pubkey_uid = NULL, *secret_key_uid = NULL;
    CK_BYTE *wrapped_key_blob = NULL;
    unsigned long wrapped_key_length;
    EVP_PKEY *pub_key = NULL;
    CK_ATTRIBUTE *wrapping_key_attrs = NULL;
    CK_ULONG wrapping_key_num_attrs = 0, local_key_digest_len = 0;
    u_int32_t remote_key_digest_len = 0;
    CK_BYTE_PTR local_key_digest = NULL, remote_key_digest = NULL;
    enum kmip_hashing_algo digest_alg = 0;
    struct CK_MECHANISM digest_mech = { 0 };

    /**
     * Until we support algorithms beyond RSA and AES, using these hard-coded
     * key types are sufficient 
     */
    pubkey_keytype = p11kmip_rsa_keytype;

    secret_keytype = p11kmip_aes_keytype;

    /* Parse the attrs and id options up front to fail fast */
    if (opt_wrap_attrs != NULL) {
        rc = parse_boolean_attrs(&secret_keytype, opt_wrap_attrs,
                                 &wrapping_key_attrs, &wrapping_key_num_attrs,
                                 false, NULL);

        if (rc != CKR_OK) {
            warnx("Failed to parse boolean attributes for wrapping key\n");
            goto done;
        }
    }

    if (opt_wrap_id != NULL) {
        rc = parse_id(opt_wrap_id, &wrapping_key_attrs,
                      &wrapping_key_num_attrs);

        if (rc != CKR_OK) {
            warnx("Failed to parse ID for wrapping key\n");
            goto done;
        }
    }
    /** 
     * We must locate the KMIP public key to obtain its UID, even if
     * we intend to utilize a local PKCS#11 public key for the actual 
     * wrapping.
     */
    rc = p11kmip_locate_remote_key(opt_wrap_label, &pubkey_keytype,
                                   &wrap_pubkey_uid);

    if (rc != CKR_OK) {
        warnx("Error while locating wrapping key on KMIP server\n");
        goto done;
    }
    /* If we didn't find it, throw an error */
    if (wrap_pubkey_uid == NULL) {
        warnx("Did not find wrapping key '%s' on server\n", opt_wrap_label);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (opt_retr_wrapkey) {
        /**
         * If we were told to retrieve the wrapping key,
         * go through the process of importing the key 
         * material into the PKCS#11 repository
         */
        rc = p11kmip_retrieve_remote_public_key(&pubkey_keytype,
                                                wrap_pubkey_uid, &pub_key);

        if (rc != CKR_OK) {
            warnx("Failed to retrieve public key from KMIP server\n");
            goto done;
        }

        rc = p11kmip_create_local_public_key(&pubkey_keytype,
                                             pub_key, opt_wrap_label,
                                             wrapping_key_attrs,
                                             wrapping_key_num_attrs,
                                             &wrapping_pubkey);

        if (rc != CKR_OK) {
            warnx("Failed to create public key '%s'\n", opt_wrap_label);
            goto done;
        }
    } else {
        /** 
         * Else we expect it to already exist in the repository with
         * the same label as the remote key
         */
        rc = p11kmip_find_local_key(&pubkey_keytype,
                                    opt_wrap_label,
                                    opt_wrap_id, &wrapping_pubkey);

        if (rc != CKR_OK) {
            warnx("Failed to locate public key '%s'\n", opt_wrap_label);
            goto done;
        }
    }

    rc = p11kmip_find_local_key(&secret_keytype, opt_target_label,
                                opt_target_id, &secret_key_handle);

    if (rc != CKR_OK) {
        warnx("Failed to find local secret key '%s'\n", opt_target_label);
        goto done;
    }

    rc = p11kmip_wrap_local_secret_key(wrapping_pubkey,
                                       secret_key_handle, &wrapped_key_length,
                                       &wrapped_key_blob);

    if (rc != CKR_OK) {
        warnx("Failed to wrap local secret key\n");
        goto done;
    }

    rc = p11kmip_register_remote_wrapped_key(&secret_keytype,
                                             wrapped_key_length,
                                             wrapped_key_blob,
                                             opt_target_label,
                                             wrap_pubkey_uid, &secret_key_uid);

    if (rc != CKR_OK) {
        warnx("Failed to register wrapped secret key with server\n");
        goto done;
    }
    /* Display digests of the retrieved keys */
    if (!opt_quiet) {
        remote_key_digest_len = 32;
        remote_key_digest = malloc(remote_key_digest_len);

        rc = p11kmip_digest_remote_key(secret_key_uid,
                                       &digest_alg, remote_key_digest,
                                       &remote_key_digest_len);

        if (rc != CKR_OK) {
            warnx("Obtaining digest of KMIP key failed");
            goto done;
        }
        /* The same hashing algorithm should produce a digest of the same len */
        local_key_digest_len = remote_key_digest_len;
        local_key_digest = malloc(local_key_digest_len);
        digest_mech.mechanism =
            get_p11_hash_mech_from_kmip_hash_algo(digest_alg);

        rc = p11kmip_digest_local_key(local_key_digest, &local_key_digest_len,
                                      secret_key_handle, &digest_mech);

        if (rc != CKR_OK && rc != CKR_KEY_INDIGESTIBLE) {
            warnx("Obtaining digest of PKCS#11 key failed");
            goto done;
        }

        if (opt_short) {
            printf("%s:", opt_target_label);
            if (rc == CKR_KEY_INDIGESTIBLE) {
                printf("<key digest not available>");
                rc = CKR_OK;
            } else {
                print_hex(local_key_digest, (int) local_key_digest_len);
            }
            printf("\n");

            printf("%s:", kmip_node_get_text_string(secret_key_uid));
            print_hex(remote_key_digest, (int) remote_key_digest_len);
            printf("\n");
        } else {
            printf("  Secret Key\n");
            printf("     PKCS#11 Label...%s\n", opt_target_label);
            printf("     PKCS#11 Digest..");
            if (rc == CKR_KEY_INDIGESTIBLE) {
                printf("<key digest not available>");
                rc = CKR_OK;
            } else {
                print_hex(local_key_digest, (int) local_key_digest_len);
            }
            printf("\n");
            printf("     KMIP UID........%s\n",
                   kmip_node_get_text_string(secret_key_uid));
            printf("     KMIP Digest.....");
            print_hex(remote_key_digest, (int) remote_key_digest_len);
            printf("\n");

            printf("  Public Key\n");
            printf("     PKCS#11 Label...%s\n", opt_wrap_label);
            printf("     KMIP UID........%s\n",
                   kmip_node_get_text_string(wrap_pubkey_uid));
        }
    }

done:
    kmip_node_free(wrap_pubkey_uid);
    kmip_node_free(secret_key_uid);
    if (wrapped_key_blob != NULL)
        free(wrapped_key_blob);
    if (local_key_digest != NULL)
        free(local_key_digest);
    if (remote_key_digest != NULL)
        free(remote_key_digest);
    if (pub_key != NULL)
        EVP_PKEY_free(pub_key);
    free_attributes(wrapping_key_attrs, wrapping_key_num_attrs);

    return rc;
}

/***************************************************************************/
/* Functions for Manipulating Local PKCS#11 Adapter                        */
/***************************************************************************/

static CK_RV p11kmip_export_local_rsa_pkey(
                                        const struct p11kmip_keytype *keytype, 
                                        EVP_PKEY **pkey, bool private, 
                                        CK_OBJECT_HANDLE key,
                                        const char *label)
{
    BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d = NULL, *bn_iqmp = NULL;
    BIGNUM *bn_p = NULL, *bn_q = NULL, *bn_dmp1 = NULL, *bn_dmq1 = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
#else
    RSA *rsa = NULL;
#endif
    CK_RV rc;

    rc = get_bignum_attr(key, CKA_MODULUS, &bn_n);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto done;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_MODULUS from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto done;
    }

    rc = get_bignum_attr(key, CKA_PUBLIC_EXPONENT, &bn_e);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto done;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_PUBLIC_EXPONENT from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto done;
    }

    if (private) {
        rc = get_bignum_attr(key, CKA_PRIVATE_EXPONENT, &bn_d);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;

        rc = get_bignum_attr(key, CKA_PRIME_1, &bn_p);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;

        rc = get_bignum_attr(key, CKA_PRIME_2, &bn_q);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;

        rc = get_bignum_attr(key, CKA_EXPONENT_1, &bn_dmp1);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;

        rc = get_bignum_attr(key, CKA_EXPONENT_2, &bn_dmq1);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;

        rc = get_bignum_attr(key, CKA_COEFFICIENT, &bn_iqmp);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;
    }
#if !OPENSSL_VERSION_PREREQ(3, 0)
    rsa = RSA_new();
    if (rsa == NULL) {
        warnx("RSA_new failed.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    if (RSA_set0_key(rsa, bn_n, bn_e, bn_d) != 1) {
        warnx("RSA_set0_key failed.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    bn_n = bn_e = bn_d = NULL;

    if (private) {
        if (RSA_set0_factors(rsa, bn_p, bn_q) != 1) {
            warnx("RSA_set0_factors failed.");
            ERR_print_errors_cb(openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
        bn_p = bn_q = NULL;

        if (RSA_set0_crt_params(rsa, bn_dmp1, bn_dmq1, bn_iqmp) != 1) {
            warnx("RSA_set0_crt_params failed.");
            ERR_print_errors_cb(openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
        bn_dmp1 = bn_dmq1 = bn_iqmp = NULL;
    }

    *pkey = EVP_PKEY_new();
    if (*pkey == NULL) {
        warnx("EVP_PKEY_new failed.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (EVP_PKEY_assign_RSA(*pkey, rsa) != 1) {
        warnx("EVP_PKEY_assign_RSA failed.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    rsa = NULL;
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        warnx("OSSL_PARAM_BLD_new failed.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_N, bn_n) ||
        !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_E, bn_e)) {
        warnx("OSSL_PARAM_BLD_push_BN failed.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (private) {
        if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_D, bn_d) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_FACTOR1, bn_p) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_FACTOR2, bn_q) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_EXPONENT1,
                                    bn_dmp1) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_EXPONENT2,
                                    bn_dmq1) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                                    bn_iqmp)) {
            warnx("OSSL_PARAM_BLD_push_BN failed.");
            ERR_print_errors_cb(openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        warnx("OSSL_PARAM_BLD_to_param failed.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pctx == NULL) {
        warnx("EVP_PKEY_CTX_new_id failed.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!EVP_PKEY_fromdata_init(pctx) ||
        !EVP_PKEY_fromdata(pctx, pkey,
                           private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                           params)) {
        warnx("EVP_PKEY_fromdata_init/EVP_PKEY_fromdata failed.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif

done:
    if (bn_n != NULL)
        BN_free(bn_n);
    if (bn_e != NULL)
        BN_free(bn_e);
    if (bn_d != NULL)
        BN_free(bn_d);
    if (bn_p != NULL)
        BN_free(bn_p);
    if (bn_q != NULL)
        BN_free(bn_q);
    if (bn_dmp1 != NULL)
        BN_free(bn_dmp1);
    if (bn_dmq1 != NULL)
        BN_free(bn_dmq1);
    if (bn_iqmp != NULL)
        BN_free(bn_iqmp);
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (rsa != NULL)
        RSA_free(rsa);
#else
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
    if (params != NULL)
        OSSL_PARAM_free(params);
#endif
    if (rc != CKR_OK && *pkey != NULL) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return rc;
}


static CK_RV p11kmip_unwrap_local_secret_key(
                                CK_OBJECT_HANDLE wrapping_key_handle,
                                const struct p11kmip_keytype *wrapped_keytype,
                                unsigned long wrapped_key_length,
                                CK_BYTE *wrapped_key_blob,
                                char *wrapped_key_label,
                                CK_ATTRIBUTE_PTR wrapped_key_attrs,
                                CK_ULONG wrapped_key_num_attrs,
                                CK_OBJECT_HANDLE_PTR unwrapped_key_handle)
{
    CK_MECHANISM mech = { 0 };
    CK_RSA_PKCS_OAEP_PARAMS oaep_param = { 0 };
    CK_BBOOL ck_true = true;
    CK_RV rc;
    size_t i = 0;

    CK_OBJECT_CLASS key_class = wrapped_keytype->class;
    CK_KEY_TYPE key_type = wrapped_keytype->type;
    CK_ATTRIBUTE_PTR unwrapped_template = NULL;
    CK_ULONG unwrapped_templatecount = 0;

    /* Build the template for the default attribute */
    rc = add_attribute(CKA_TOKEN, &ck_true, sizeof(ck_true), 
                        &unwrapped_template, &unwrapped_templatecount);
    rc += add_attribute(CKA_SENSITIVE, &ck_true, sizeof(ck_true),
                        &unwrapped_template, &unwrapped_templatecount);
    rc += add_attribute(CKA_CLASS, &key_class, sizeof(key_class),
                        &unwrapped_template, &unwrapped_templatecount);
    rc += add_attribute(CKA_KEY_TYPE, &key_type, sizeof(key_type),
                        &unwrapped_template, &unwrapped_templatecount);
    rc += add_attribute(CKA_ENCRYPT, &ck_true, sizeof(ck_true),
                        &unwrapped_template, &unwrapped_templatecount);
    rc += add_attribute(CKA_DECRYPT, &ck_true, sizeof(ck_true),
                        &unwrapped_template, &unwrapped_templatecount);
    rc += add_attribute(CKA_SIGN, &ck_true, sizeof(ck_true),
                        &unwrapped_template, &unwrapped_templatecount);
    rc += add_attribute(CKA_VERIFY, &ck_true, sizeof(ck_true),
                        &unwrapped_template, &unwrapped_templatecount);
    rc += add_attribute(CKA_IBM_PROTKEY_EXTRACTABLE, &ck_true, sizeof(ck_true),
                        &unwrapped_template, &unwrapped_templatecount);
    rc += add_attribute(CKA_LABEL, wrapped_key_label, 
                        strlen((char *) wrapped_key_label),
                        &unwrapped_template, &unwrapped_templatecount);

    if (rc != CKR_OK)
        goto done;

    /** 
     * Copy in  any additional attributes passed in by caller while overwriting
     * non-default values that were specified                                  
     */
    for (i = 0; i < wrapped_key_num_attrs; i++) {
        if (wrapped_key_attrs[i].type == CKA_TOKEN) {
            memcpy(wrapped_key_attrs[0].pValue, wrapped_key_attrs[i].pValue, 
                wrapped_key_attrs[i].ulValueLen);
        } else if (wrapped_key_attrs[i].type == CKA_SENSITIVE) {
            memcpy(wrapped_key_attrs[1].pValue, wrapped_key_attrs[i].pValue, 
                wrapped_key_attrs[i].ulValueLen);
        } else {
            rc = add_attribute(wrapped_key_attrs[i].type, 
                    wrapped_key_attrs[i].pValue, 
                    wrapped_key_attrs[i].ulValueLen, &unwrapped_template,
                    &unwrapped_templatecount);
            if (rc != CKR_OK)
                goto done;
        }
    }

    switch (kmip_wrap_padding_method) {
    case KMIP_PADDING_METHOD_PKCS_1_5:
        mech.mechanism = CKM_RSA_PKCS;
        break;

    case KMIP_PADDING_METHOD_OAEP:
        mech.mechanism = CKM_RSA_PKCS_OAEP;
        mech.pParameter = &oaep_param;
        mech.ulParameterLen = sizeof(oaep_param);

        switch (kmip_wrap_hash_alg) {
        case KMIP_HASHING_ALGO_SHA_1:
            oaep_param.hashAlg = CKM_SHA_1;
            oaep_param.mgf = CKG_MGF1_SHA1;
            break;

        case KMIP_HASHING_ALGO_SHA_256:
            oaep_param.hashAlg = CKM_SHA256;
            oaep_param.mgf = CKG_MGF1_SHA256;
            break;

        default:
            warnx("Unsupported hashing algorithm: %d",
                  (int) kmip_wrap_hash_alg);
            return CKR_ARGUMENTS_BAD;
        }
        break;
    default:
        warnx("Unsupported padding method: %d", (int) kmip_wrap_padding_method);
        return CKR_ARGUMENTS_BAD;
    }

    rc = pkcs11_funcs->C_UnwrapKey(pkcs11_session, &mech,
                                   wrapping_key_handle,
                                   wrapped_key_blob, wrapped_key_length,
                                   unwrapped_template, unwrapped_templatecount,
                                   unwrapped_key_handle);

done:
    free_attributes(unwrapped_template, unwrapped_templatecount);

    return rc;
}

static CK_RV p11kmip_wrap_local_secret_key(CK_OBJECT_HANDLE wrapping_key_handle,
                                           CK_OBJECT_HANDLE secret_key_handle,
                                           CK_ULONG_PTR wrapped_key_length,
                                           CK_BYTE **wrapped_key_blob)
{
    CK_MECHANISM mech = { 0 };
    CK_RSA_PKCS_OAEP_PARAMS oaep_param = { 0 };
    CK_RV rc;

    switch (kmip_wrap_padding_method) {
    case KMIP_PADDING_METHOD_PKCS_1_5:
        mech.mechanism = CKM_RSA_PKCS;
        break;

    case KMIP_PADDING_METHOD_OAEP:
        mech.mechanism = CKM_RSA_PKCS_OAEP;
        mech.pParameter = &oaep_param;
        mech.ulParameterLen = sizeof(oaep_param);

        switch (kmip_wrap_hash_alg) {
        case KMIP_HASHING_ALGO_SHA_1:
            oaep_param.hashAlg = CKM_SHA_1;
            oaep_param.mgf = CKG_MGF1_SHA1;
            break;

        case KMIP_HASHING_ALGO_SHA_256:
            oaep_param.hashAlg = CKM_SHA256;
            oaep_param.mgf = CKG_MGF1_SHA256;
            break;

        default:
            warnx("Unsupported hashing algorithm: %d",
                  (int) kmip_wrap_hash_alg);
            return CKR_ARGUMENTS_BAD;
        }
        break;
    default:
        warnx("Unsupported padding method: %d", (int) kmip_wrap_padding_method);
        return CKR_ARGUMENTS_BAD;
    }

    /* wrap key (length only) */
    rc = pkcs11_funcs->C_WrapKey(pkcs11_session,
                                 &mech, wrapping_key_handle, secret_key_handle,
                                 NULL, wrapped_key_length);

    if (rc != CKR_OK) {
        warnx("Unable to determine length of wrapped key object");
        return CKR_GENERAL_ERROR;
    }

    *wrapped_key_blob = malloc(sizeof(CK_BYTE) * (*wrapped_key_length));
    if (wrapped_key_blob == NULL) {
        warnx("Unable to allocated storage for wrapped key blob");
        return CKR_HOST_MEMORY;
    }
    /* Wrap key blob */
    rc = pkcs11_funcs->C_WrapKey(pkcs11_session,
                                 &mech, wrapping_key_handle, secret_key_handle,
                                 *wrapped_key_blob, wrapped_key_length);

    return rc;
}

static CK_RV p11kmip_create_local_public_key(
                                const struct p11kmip_keytype *public_keytype,
                                EVP_PKEY *pub_key, char *public_key_label,
                                CK_ATTRIBUTE_PTR public_key_attrs,
                                CK_ULONG public_key_num_attrs,
                                CK_OBJECT_HANDLE_PTR public_key_handle)
{
    CK_BBOOL ck_true = true;
    CK_RV rc;
    size_t i = 0;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    const RSA *rsa;
    const BIGNUM *bn_n = NULL, *bn_e = NULL;
#else
    BIGNUM *bn_n = NULL, *bn_e = NULL;
#endif

    CK_OBJECT_CLASS key_class = public_keytype->class;
    CK_KEY_TYPE key_type = public_keytype->type;
    CK_ULONG key_size = 0;
    CK_ULONG public_templatecount = 0;
    CK_ATTRIBUTE_PTR public_template = NULL;

    rc = public_keytype->keygen_get_key_size(public_keytype, NULL, &key_size);
    if (rc) {
        warnx("Failed to key size of wrapped key");
        goto done;
    }
#if !OPENSSL_VERSION_PREREQ(3, 0)
    rsa = EVP_PKEY_get0_RSA(pub_key);
    if (rsa == NULL) {
        warnx("Failed to get public key params");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    RSA_get0_key(rsa, &bn_n, &bn_e, NULL);
    if (bn_n == NULL || bn_e == NULL) {
        warnx("Failed to get public key params");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#else
    if (!EVP_PKEY_get_bn_param(pub_key, OSSL_PKEY_PARAM_RSA_N, &bn_n) ||
        !EVP_PKEY_get_bn_param(pub_key, OSSL_PKEY_PARAM_RSA_E, &bn_e)) {
        warnx("Failed to get public key params");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif

    /* Add default attributes attributes */
    rc = add_attribute(CKA_TOKEN, &ck_true, sizeof(ck_true), 
                        &public_template, &public_templatecount);
    rc += add_attribute(CKA_CLASS, &key_class, sizeof(key_class),
                        &public_template, &public_templatecount);
    rc += add_attribute(CKA_KEY_TYPE, &key_type, sizeof(key_type),
                        &public_template, &public_templatecount);
    rc += add_attribute(CKA_LABEL, public_key_label, 
                        strlen((char *) public_key_label),
                        &public_template, &public_templatecount);
    
    if (rc != CKR_OK)
            goto done;

    /**
     * Copy in  any additional attributes passed in by caller while overwriting 
     * non-default values that were specified                                   
     */
    for (i = 0; i < public_key_num_attrs; i++) {
        /* Handle non-default value */
        if (public_key_attrs[i].type == CKA_TOKEN) {
            memcpy(public_template[0].pValue, public_key_attrs[i].pValue, 
                    public_key_attrs[i].ulValueLen);
        } else {
            rc = add_attribute(public_key_attrs[i].type,
                               public_key_attrs[i].pValue,
                               public_key_attrs[i].ulValueLen,
                               &public_template,
                               &public_templatecount);
            if (rc != CKR_OK)
                goto done;
        }
    }

    rc = add_bignum_attr(CKA_MODULUS, bn_n, &public_template,
                         &public_templatecount);
    if (rc != CKR_OK)
        goto done;

    rc = add_bignum_attr(CKA_PUBLIC_EXPONENT, bn_e, &public_template,
                         &public_templatecount);
    if (rc != CKR_OK)
        goto done;

    rc = pkcs11_funcs->C_CreateObject(pkcs11_session,
                                      public_template, public_templatecount,
                                      public_key_handle);

done:
    free_attributes(public_template, public_templatecount);

#if OPENSSL_VERSION_PREREQ(3, 0)
    BN_free(bn_n);
    BN_free(bn_e);
#endif

    return rc;
}

/**
 * Finds a key matching the label or id, or the class or filter attribute
 * of the key type, or any combination thereof. Expects to find exactly one
 * key matching these criteria, and returns it in the key parameter.
 * 
 * @param keytype       attributes and class of key
 * @param label         label of key
 * @param id            id of key
 * @param key           handle return if key is found
 * global pkcs11_funcs  used to call PKCS11 functions
 * 
 * @return CK_RV 
 */
static CK_RV p11kmip_find_local_key(
                        const struct p11kmip_keytype *keytype,
                        const char *label,
                        const char *id, CK_OBJECT_HANDLE *key)
{
    CK_RV rc;
    CK_ATTRIBUTE *attrs = NULL;
    CK_ULONG num_attrs = 0;
    const CK_BBOOL ck_true = CK_TRUE;
    CK_OBJECT_HANDLE keys[FIND_OBJECTS_COUNT];
    CK_ULONG num_keys;

    rc = add_attribute(CKA_TOKEN, &ck_true, sizeof(ck_true), &attrs,
                       &num_attrs);
    if (rc != CKR_OK)
        goto done;

    if (keytype != NULL) {
        /* Set the filter attribute, if applicable */
        if (keytype->filter_attr != (CK_ATTRIBUTE_TYPE) - 1) {
            rc = add_attribute(keytype->filter_attr, &keytype->filter_value,
                               sizeof(keytype->filter_value), &attrs,
                               &num_attrs);
            if (rc != CKR_OK)
                goto done;
        }
        /* Set an attribute for the class to give us more granularity */
        rc = add_attribute(CKA_CLASS, &keytype->class,
                           sizeof(keytype->class), &attrs, &num_attrs);
        if (rc != CKR_OK)
            goto done;
    }

    if (label != NULL) {
        rc = add_attribute(CKA_LABEL, label, strlen((char *) label), &attrs,
                           &num_attrs);
        if (rc != CKR_OK)
            goto done;
    }

    if (id != NULL) {
        rc = parse_id((char *) id, &attrs, &num_attrs);
        if (rc != CKR_OK)
            return rc;
    }

    rc = pkcs11_funcs->C_FindObjectsInit(pkcs11_session, attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to initialize the find operation:"
              " C_FindObjectsInit: 0x%lX: %s",
              rc, p11_get_ckr(rc));
        goto done;
    }

    memset(keys, 0, sizeof(keys));
    num_keys = 0;

    rc = pkcs11_funcs->C_FindObjects(pkcs11_session, keys,
                                     FIND_OBJECTS_COUNT, &num_keys);
    if (rc != CKR_OK) {
        warnx("Failed to find objects: C_FindObjects: 0x%lX: %s",
              rc, p11_get_ckr(rc));
        goto done;
    }

    rc = pkcs11_funcs->C_FindObjectsFinal(pkcs11_session);
    if (rc != CKR_OK) {
        warnx("Failed to finalize the find operation:"
              " C_FindObjectsFinal: 0x%lX: %s",
              rc, p11_get_ckr(rc));

        goto done;
    }

    if (num_keys == 0) {
        rc = CKR_FUNCTION_FAILED;
        warnx("Failed to find key matching label '%s'\n", label);

        goto done;
    } else if (num_keys > 1) {
        rc = CKR_FUNCTION_FAILED;
        warnx("Found multiple keys matching label '%s'\n", label);

        goto done;
    }
    /* Write back the key handle */
    *key = keys[0];

done:
    free_attributes(attrs, num_attrs);

    return rc;
}

static CK_RV p11kmip_digest_local_key(CK_BYTE_PTR digest,
                                      CK_ULONG_PTR digestLen,
                                      CK_OBJECT_HANDLE key, 
                                      CK_MECHANISM_PTR digestMech)
{
    CK_RV rc;

    rc = pkcs11_funcs->C_DigestInit(pkcs11_session, digestMech);
    if (rc != CKR_OK) {
        warnx("Failed to initialize PKCS#11 digest");
        return rc;
    }

    rc = pkcs11_funcs->C_DigestKey(pkcs11_session, key);
    if (rc != CKR_OK) {
        if (rc != CKR_KEY_INDIGESTIBLE)
            warnx("Failed to digest PKCS#11 key");
        return rc;
    }

    rc = pkcs11_funcs->C_DigestFinal(pkcs11_session, digest, digestLen);

    return rc;
}

/***************************************************************************/
/* Functions for Manipulating a Remote KMIP Server                         */
/***************************************************************************/

static CK_RV p11kmip_locate_remote_key(const char *label, const struct
                                       p11kmip_keytype *keytype,
                                       struct kmip_node **obj_uid)
{
    struct kmip_node *req_pl = NULL, *resp_pl = NULL, *item_uid = NULL,
        *last_uid = NULL;
    struct kmip_node **attrs = NULL;
    enum kmip_result_status locate_status = 0;
    enum kmip_result_reason locate_reason = 0;
    enum kmip_object_type obj_type = P11KMIP_KMIP_UNKNOWN_OBJ;
    enum kmip_crypto_algo key_alg = P11KMIP_KMIP_UNKNOWN_ALG;
    size_t num_attrs, num_objs;
    size_t i, k;
    CK_RV rc = CKR_OK;

    /* Label     */
    num_attrs = 1;

    /* Reconcile constants for PKCS#11 to KMIP */
    obj_type = get_kmip_obj_class_from_p11(keytype->class);

    if (obj_type == P11KMIP_KMIP_UNKNOWN_OBJ) {
        warnx("Unknown object class");
        rc = CKR_FUNCTION_NOT_SUPPORTED;
        goto out;
    }
    num_attrs++;

    key_alg = get_kmip_alg_from_p11(keytype->type);

    if (key_alg == P11KMIP_KMIP_UNKNOWN_ALG) {
        warnx("Unknown key algorithm");
        rc = CKR_FUNCTION_NOT_SUPPORTED;
        goto out;
    }
    num_attrs++;

    attrs = malloc(num_attrs * sizeof(struct kmip_node *));
    k = 0;

    /* Set the label */
    attrs[k] =
        kmip_new_name((char *) label, KMIP_NAME_TYPE_UNINTERPRETED_TEXT_STRING);
    if (attrs[k] == NULL) {
        rc = CKR_HOST_MEMORY;
        warnx("Allocate KMIP node failed");
        goto out;
    }
    k++;

    /* Set the object type */
    attrs[k] = kmip_new_object_type(obj_type);
    if (attrs[k] == NULL) {
        rc = CKR_HOST_MEMORY;
        warnx("Allocate KMIP node failed");
        goto out;
    }
    k++;

    /* Set the key algorithm */
    attrs[k] = kmip_new_cryptographic_algorithm(key_alg);
    if (attrs[k] == NULL) {
        rc = CKR_HOST_MEMORY;
        warnx("Allocate KMIP node failed");
        goto out;
    }
    k++;

    req_pl = kmip_new_locate_request_payload(NULL, 0, 0, 0, 0,
                                             num_attrs, attrs);
    if (req_pl == NULL) {
        rc = CKR_HOST_MEMORY;
        warnx("Allocate KMIP node failed");
        goto out;
    }

    rc = perform_kmip_request(KMIP_OPERATION_LOCATE, req_pl, &resp_pl,
                              &locate_status, &locate_reason);
    if (rc != 0) {
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    num_objs = 0;
    for (i = 0;; i++) {
        rc = kmip_get_locate_response_payload(resp_pl, NULL, NULL, i,
                                              &item_uid);
        if (rc != 0)
            break;

        num_objs++;
        last_uid = item_uid;
    }

    if (num_objs == 0) {
        rc = CKR_OK;
    } else if (num_objs == 1) {
        rc = CKR_OK;
        *obj_uid = last_uid;
    } else {
        rc = CKR_FUNCTION_FAILED;
        warnx("Unable to uniquely identify wrapping key on KMIP server");
    }

out:
    if (attrs != NULL) {
        for (i = 0; i < num_attrs; i++)
            kmip_node_free(attrs[i]);
        free(attrs);
    }

    kmip_node_free(req_pl);
    kmip_node_free(resp_pl);
    kmip_node_free(item_uid);

    return rc;

}

/**
 * @brief 
 * 
 * @param wrapping_pubkey 
 * @param wrapkey_label 
 * global kmip_connection
 * 
 * @return CK_RV 
 */
static CK_RV p11kmip_register_remote_public_key(
                                        const struct p11kmip_keytype *keytype,
                                        CK_OBJECT_HANDLE wrapping_pubkey,
                                        const char *wrapping_key_label,
                                        struct kmip_node **key_uid)
{
    EVP_PKEY *pkey = NULL;
    struct kmip_node *kobj = NULL, *name_attr = NULL, *unique_id = NULL;
    struct kmip_node *reg_req = NULL, *reg_resp = NULL, *descr_attr = NULL;
    struct kmip_node *key = NULL, *kval = NULL, *kblock = NULL;
    struct kmip_node *umask_attr = NULL, *cparams_attr = NULL;
    struct kmip_node *act_req = NULL, *act_resp = NULL;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    const BIGNUM *modulus = NULL, *pub_exp = NULL;
#else
    BIGNUM *modulus = NULL, *pub_exp = NULL;
#endif
    char *description = NULL;
    struct utsname utsname;
    enum kmip_result_status reg_status = 0, act_status = 0;
    enum kmip_result_reason reg_reason = 0, act_reason = 0;
    int rc;

    /* Export the public key from PKCS#11 into an OpenSSL EVP Key */
    if (keytype->export_asym_pkey != NULL) {
        rc = keytype->export_asym_pkey(keytype, &pkey, false,
                                       wrapping_pubkey, wrapping_key_label);

        if (rc != CKR_OK) {
            warnx("Failed to export '%s' to EVP key", wrapping_key_label);
            goto out;
        }
    } else {
        warnx("Function to export '%s' to EVP unavailable", wrapping_key_label);
        rc = CKR_FUNCTION_NOT_SUPPORTED;
        goto out;
    }

    switch (kmip_wrap_key_format) {
    case KMIP_KEY_FORMAT_TYPE_PKCS_1:
        key = kmip_new_pkcs1_public_key(pkey);
        break;
    case KMIP_KEY_FORMAT_TYPE_PKCS_8:
        key = kmip_new_pkcs8_public_key(pkey);
        break;
    case KMIP_KEY_FORMAT_TYPE_TRANSPARENT_RSA_PUBLIC_KEY:
#if !OPENSSL_VERSION_PREREQ(3, 0)
        modulus = RSA_get0_n(EVP_PKEY_get0_RSA(pkey));
        pub_exp = RSA_get0_e(EVP_PKEY_get0_RSA(pkey));
#else
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &modulus);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &pub_exp);
#endif
        if (modulus == NULL || pub_exp == NULL) {
            warnx("Failed to get RSA public key parts");
            rc = CKR_GENERAL_ERROR;
            goto out;
        }

        key = kmip_new_transparent_rsa_public_key(modulus, pub_exp);
        break;
    default:
        warnx("Unsupported wrapping key format: %d", kmip_wrap_key_format);
        rc = CKR_ARGUMENTS_BAD;
        goto out;
    }
    if (key == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    kval = kmip_new_key_value_va(NULL, key, 0);
    if (kval == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    kblock = kmip_new_key_block(kmip_wrap_key_format, 0, kval,
                                kmip_wrap_key_alg, kmip_wrap_key_size, NULL);
    if (kblock == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    kobj = kmip_new_public_key(kblock);
    if (kobj == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (wrapping_key_label != NULL) {
        name_attr = kmip_new_name(wrapping_key_label,
                                  KMIP_NAME_TYPE_UNINTERPRETED_TEXT_STRING);
        if (name_attr == NULL) {
            warnx("Allocate KMIP node failed");
            rc = CKR_HOST_MEMORY;
            goto out;
        }
    }

    umask_attr =
        kmip_new_cryptographic_usage_mask(KMIP_CRY_USAGE_MASK_ENCRYPT |
                                          KMIP_CRY_USAGE_MASK_WRAP_KEY);
    if (umask_attr == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    cparams_attr = kmip_new_cryptographic_parameters(
                        NULL, 0, kmip_wrap_padding_method,
                        kmip_wrap_padding_method == KMIP_PADDING_METHOD_OAEP ?
                                            kmip_wrap_hash_alg : 0,
                        KMIP_KEY_ROLE_TYPE_KEK, 0, kmip_wrap_key_alg, NULL,
                        NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                        kmip_wrap_padding_method == KMIP_PADDING_METHOD_OAEP ?
                                            KMIP_MASK_GENERATOR_MGF1 : 0,
                        kmip_wrap_padding_method == KMIP_PADDING_METHOD_OAEP ?
                                            kmip_wrap_hash_alg : 0,
                        NULL);
    if (cparams_attr == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (uname(&utsname) != 0) {
        rc = CKR_GENERAL_ERROR;
        warnx("Failed to obtain the system's " "hostname: %s", strerror(-rc));
        goto out;
    }

    if (asprintf(&description, "Wrapping key for PKCS#11 client on system %s",
                 utsname.nodename) <= 0) {
        rc = CKR_GENERAL_ERROR;
        warnx("asprintf failed");
        goto out;
    };
    descr_attr = build_description_attr(description);
    free(description);
    if (descr_attr == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    reg_req = kmip_new_register_request_payload_va(NULL,
                                                   KMIP_OBJECT_TYPE_PUBLIC_KEY,
                                                   kobj, NULL, 4, name_attr,
                                                   umask_attr, cparams_attr,
                                                   descr_attr);
    if (reg_req == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
    }

    act_req = kmip_new_activate_request_payload(NULL);  /* ID placeholder */
    if (act_req == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
    }

    rc = perform_kmip_request2(KMIP_OPERATION_REGISTER, reg_req,
                               &reg_resp, &reg_status, &reg_reason,
                               KMIP_OPERATION_ACTIVATE, act_req,
                               &act_resp, &act_status, &act_reason,
                               KMIP_BATCH_ERR_CONT_STOP);
    if (rc != 0) {
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    rc = kmip_get_register_response_payload(reg_resp, &unique_id, NULL,
                                            0, NULL);
    if (rc != 0) {
        warnx("Failed to get key unique-id");
        goto out;
    }

    *key_uid = unique_id;

out:
    kmip_node_free(key);
    kmip_node_free(kval);
    kmip_node_free(kblock);
    kmip_node_free(kobj);
    kmip_node_free(name_attr);
    kmip_node_free(umask_attr);
    kmip_node_free(cparams_attr);
    kmip_node_free(descr_attr);
    kmip_node_free(reg_req);
    kmip_node_free(reg_resp);
    kmip_node_free(act_req);
    kmip_node_free(act_resp);
    EVP_PKEY_free(pkey);

#if OPENSSL_VERSION_PREREQ(3, 0)
    if (modulus != NULL)
        BN_free(modulus);
    if (pub_exp != NULL)
        BN_free(pub_exp);
#endif

    return rc;
}

static CK_RV p11kmip_register_remote_wrapped_key(
                                const struct p11kmip_keytype *wrapped_keytype,
                                CK_ULONG wrapped_key_length,
                                const CK_BYTE *wrapped_key_blob,
                                const char *wrapped_key_label,
                                struct kmip_node *wrapkey_uid,
                                struct kmip_node **key_uid)
{
    struct kmip_node *kobj = NULL, *name_attr = NULL, *unique_id = NULL;
    struct kmip_node *reg_req = NULL, *reg_resp = NULL, *descr_attr = NULL;
    struct kmip_node *kval = NULL, *enc_cparams = NULL, 
        *enc_kinfo = NULL, *kblock = NULL, *wrap_data = NULL;
    struct kmip_node *umask_attr = NULL, *cparams_attr = NULL;
    struct kmip_node *act_req = NULL, *act_resp = NULL;
    enum kmip_crypto_algo wrapped_key_algo;
    CK_ULONG wrapped_key_size;
    char *description = NULL;
    struct utsname utsname;
    enum kmip_result_status reg_status = 0, act_status = 0;
    enum kmip_result_reason reg_reason = 0, act_reason = 0;
    int rc;

    wrapped_key_algo = get_kmip_alg_from_p11(wrapped_keytype->type);
    rc = wrapped_keytype->keygen_get_key_size(wrapped_keytype, NULL,
                                              &wrapped_key_size);
    if (rc) {
        warnx("Failed to get key size of wrapped key");
        goto out;
    }

    enc_cparams = kmip_new_cryptographic_parameters(
                    NULL, 0, kmip_wrap_padding_method,
                    kmip_wrap_padding_method == KMIP_PADDING_METHOD_OAEP ?
                                        kmip_wrap_hash_alg : 0,
                    0, 0, kmip_wrap_key_alg, NULL, NULL, NULL, NULL, NULL,
                    NULL, NULL, NULL,
                    kmip_wrap_padding_method == KMIP_PADDING_METHOD_OAEP ?
                                        KMIP_MASK_GENERATOR_MGF1 : 0,
                    kmip_wrap_padding_method == KMIP_PADDING_METHOD_OAEP ?
                                        kmip_wrap_hash_alg : 0,
                    NULL);
    if (enc_cparams == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    enc_kinfo = kmip_new_key_info(false, wrapkey_uid, enc_cparams);
    if (enc_kinfo == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    wrap_data = kmip_new_key_wrapping_data(NULL,
                                           KMIP_WRAPPING_METHOD_ENCRYPT,
                                           enc_kinfo, NULL, NULL, 0, NULL, 0,
                                           KMIP_ENCODING_OPTION_NO);
    if (wrap_data == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    kval =
        kmip_node_new_byte_string(KMIP_TAG_KEY_VALUE, NULL, wrapped_key_blob,
                                  wrapped_key_length);
    if (kval == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    kblock = kmip_new_key_block(KMIP_KEY_FORMAT_TYPE_RAW, 0, 
                                kval, wrapped_key_algo, 
                                /* Wanted in bits */
                                (int32_t) (wrapped_key_size * 8),
                                wrap_data);
    if (kblock == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    kobj = kmip_new_symmetric_key(kblock);
    if (kobj == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (wrapped_key_label != NULL) {
        name_attr = kmip_new_name(wrapped_key_label,
                                  KMIP_NAME_TYPE_UNINTERPRETED_TEXT_STRING);
        if (name_attr == NULL) {
            warnx("Allocate KMIP node failed");
            rc = CKR_HOST_MEMORY;
            goto out;
        }
    }

    umask_attr =
        kmip_new_cryptographic_usage_mask(KMIP_CRY_USAGE_MASK_ENCRYPT |
                                          KMIP_CRY_USAGE_MASK_DECRYPT);
    if (umask_attr == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    cparams_attr = kmip_new_cryptographic_parameters(
                        NULL, 0, 0, 0, 0, 0, 
                        KMIP_CRYPTO_ALGO_AES,
                        false, NULL, NULL, NULL,
                        NULL, NULL, NULL, NULL,
                        0, 0, NULL);
    if (cparams_attr == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (uname(&utsname) != 0) {
        rc = CKR_GENERAL_ERROR;
        warnx("Failed to obtain the system's " "hostname: %s", strerror(-rc));
        goto out;
    }

    if (asprintf(&description, "Secret key for PKCS#11 client on system %s",
                 utsname.nodename) <= 0) {
        rc = CKR_GENERAL_ERROR;
        warnx("asprintf failed");
        goto out;
    }
    descr_attr = build_description_attr(description);
    free(description);
    if (descr_attr == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    reg_req = kmip_new_register_request_payload_va(NULL,
                                                KMIP_OBJECT_TYPE_SYMMETRIC_KEY,
                                                kobj, NULL, 3, name_attr,
                                                umask_attr, cparams_attr);
    if (reg_req == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
    }

    act_req = kmip_new_activate_request_payload(NULL);  /* ID placeholder */
    if (act_req == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
    }

    rc = perform_kmip_request2(KMIP_OPERATION_REGISTER, reg_req,
                               &reg_resp, &reg_status, &reg_reason,
                               KMIP_OPERATION_ACTIVATE, act_req,
                               &act_resp, &act_status, &act_reason,
                               KMIP_BATCH_ERR_CONT_STOP);
    if (rc != 0) {
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    rc = kmip_get_register_response_payload(reg_resp, &unique_id, NULL,
                                            0, NULL);
    if (rc != 0) {
        warnx("Failed to get key unique-id");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    *key_uid = unique_id;

out:
    kmip_node_free(enc_cparams);
    kmip_node_free(enc_kinfo);
    kmip_node_free(wrap_data);
    kmip_node_free(kval);
    kmip_node_free(kblock);
    kmip_node_free(kobj);
    kmip_node_free(name_attr);
    kmip_node_free(umask_attr);
    kmip_node_free(cparams_attr);
    kmip_node_free(descr_attr);
    kmip_node_free(reg_req);
    kmip_node_free(reg_resp);
    kmip_node_free(act_req);
    kmip_node_free(act_resp);

    return rc;
}

/**
 * Sends a request to a KMIP server to retrieve a secret key wrapped in a
 * wrapping key. Expects the wrapping key to already be available on the server.
 * 
 * @param wrapped_key_label     label of the target key
 * @param wrapping_key_label    label of the wrapping key
 * @param wrapped_key_blob      on output, a buffer containing the wrapped
 *                              key material of the target key
 * global kmip_connection       structure for KMIP server connection
 * 
 * @return CK_RV 
 */
static CK_RV p11kmip_retrieve_remote_wrapped_key(
                                struct kmip_node *wrapping_key_uid,
                                struct p11kmip_keytype *wrapped_keytype, 
                                struct kmip_node *wrapped_key_uid, 
                                unsigned long *wrapped_key_length,
                                CK_BYTE **wrapped_key_blob)
{
    struct kmip_node *cparams = NULL, *wrap_id = NULL, *wkey_info = NULL;
    struct kmip_node *wrap_spec = NULL, *req_pl = NULL, *resp_pl = NULL;
    struct kmip_node *uid = NULL, *kobj = NULL, *kblock = NULL;
    struct kmip_node *kval = NULL, *wrap = NULL, *key = NULL;
    struct kmip_node *wkinfo = NULL, *wcparms = NULL;
    enum kmip_hashing_algo halgo, mgfhalgo;
    enum kmip_wrapping_method wmethod;
    enum kmip_key_format_type ftype;
    enum kmip_padding_method pmeth;
    enum kmip_encoding_option enc;
    enum kmip_mask_generator mgf;
    enum kmip_object_type otype;
    enum kmip_crypto_algo algo;
    const unsigned char *kdata;
    uint32_t klen;
    int32_t bits;
    CK_OBJECT_CLASS wrapped_key_class;
    CK_KEY_TYPE wrapped_key_alg;
    enum kmip_result_status status = 0;
    enum kmip_result_reason reason = 0;
    int rc = 0;

    if (wrapped_keytype->class != CKO_SECRET_KEY) {
        warnx("Unsupported object class");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    cparams = kmip_new_cryptographic_parameters(
                    NULL, 0, kmip_wrap_padding_method,
                    kmip_wrap_padding_method == KMIP_PADDING_METHOD_OAEP ?
                                        kmip_wrap_hash_alg : 0,
                    KMIP_KEY_ROLE_TYPE_KEK, 0, kmip_wrap_key_alg, NULL, NULL,
                    NULL, NULL, NULL, NULL, NULL, NULL,
                    kmip_wrap_padding_method == KMIP_PADDING_METHOD_OAEP ?
                                        KMIP_MASK_GENERATOR_MGF1 : 0,
                    kmip_wrap_padding_method == KMIP_PADDING_METHOD_OAEP ?
                                        kmip_wrap_hash_alg : 0, 
                    NULL);
    if (cparams == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
    }

    wkey_info = kmip_new_key_info(false, wrapping_key_uid, cparams);
    if (wkey_info == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
    }

    wrap_spec = kmip_new_key_wrapping_specification_va(NULL,
                                                KMIP_WRAPPING_METHOD_ENCRYPT,
                                                wkey_info, NULL,
                                                KMIP_ENCODING_OPTION_NO,
                                                0);
    if (wrap_spec == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
    }

    req_pl = kmip_new_get_request_payload(NULL, wrapped_key_uid,
                                          KMIP_KEY_FORMAT_TYPE_RAW, 0, 0,
                                          wrap_spec);
    if (req_pl == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
    }

    rc = perform_kmip_request(KMIP_OPERATION_GET, req_pl, &resp_pl,
                              &status, &reason);
    if (rc != 0) {
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    rc = kmip_get_get_response_payload(resp_pl, &otype, NULL, &kobj);
    if (rc != 0) {
        warnx("Failed to get wrapped key");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }
    wrapped_key_class = get_p11_obj_class_from_kmip(otype);

    if (wrapped_key_class != wrapped_keytype->class) {
        warnx("Key is not the correct object class");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    rc = kmip_get_symmetric_key(kobj, &kblock);

    if (rc) {
        warnx("Failed to get symmetric key");
        goto out;
    }

    rc = kmip_get_key_block(kblock, &ftype, NULL, &kval, &algo, &bits, &wrap);

    if (rc) {
        warnx("Failed to get key block");
        goto out;
    }

    if (ftype != KMIP_KEY_FORMAT_TYPE_RAW) {
        warnx("Key format is not RAW");
        rc = CKR_ARGUMENTS_BAD;
        goto out;
    }

    wrapped_key_alg = get_p11_alg_from_kmip(algo);
    if (wrapped_key_alg != wrapped_keytype->type) {
        warnx("Key algorithm is incorrect");
    }

    rc = kmip_get_key_wrapping_data(wrap, &wmethod, &wkinfo, NULL, NULL,
                                    NULL, NULL, NULL, &enc);

    if (rc) {
        warnx("Failed to get wrapping data");
        goto out;
    }

    if (wmethod != KMIP_WRAPPING_METHOD_ENCRYPT) {
        warnx("Wrapping method is not 'Encrypt'");
        rc = CKR_ARGUMENTS_BAD;
        goto out;
    }

    if (enc != KMIP_ENCODING_OPTION_NO) {
        rc = CKR_ARGUMENTS_BAD;
        warnx("Encoding is not 'No encoding'");
        goto out;
    }


    rc = kmip_get_key_info(wkinfo, NULL, &wcparms);

    if (rc) {
        warnx("Failed to get wrap key infos");
        goto out;
    }

    rc = kmip_get_cryptographic_parameter(wcparms, NULL, &pmeth, &halgo,
                                          NULL, NULL, &algo, NULL, NULL,
                                          NULL, NULL, NULL, NULL, NULL,
                                          NULL, &mgf, &mgfhalgo, NULL);
    if (rc != 0) {
        rc = rc;
        warnx("Failed to get crypto params");
        goto out;
    }

    if (algo != kmip_wrap_key_alg) {
        rc = CKR_ARGUMENTS_BAD;
        warnx("wrap algorithm is not as expected");
        goto out;
    }

    if (pmeth != kmip_wrap_padding_method) {
        rc = CKR_ARGUMENTS_BAD;
        warnx("padding method is not as expected");
        goto out;
    }
    if (kmip_wrap_padding_method == KMIP_PADDING_METHOD_OAEP) {
        if (halgo != kmip_wrap_hash_alg) {
            rc = CKR_ARGUMENTS_BAD;
            warnx("hashing algorithm is not as expected");
            goto out;
        }

        if (mgf != KMIP_MASK_GENERATOR_MGF1) {
            rc = CKR_ARGUMENTS_BAD;
            warnx("OAEP MGF is not as expected");
            goto out;
        }

        if (mgfhalgo != kmip_wrap_hash_alg) {
            rc = CKR_ARGUMENTS_BAD;
            warnx("MGF hashing algorithm is not as expected");
            goto out;
        }
    }

    rc = kmip_get_key_value(kval, &key, NULL, 0, NULL);

    if (rc) {
        warnx("Failed to get key value");
        goto out;
    }

    kdata = kmip_node_get_byte_string(key, &klen);
    if (kdata == NULL) {
        rc = CKR_HOST_MEMORY;
        warnx("Failed to get key data");
        goto out;
    }

    /**
     * 'bits' should contain the length of the unwrapped key
     * while the 'klen' contains the length of the wrapped blob
     */
    wrapped_keytype->keysize_value = (CK_ULONG)(bits/8);
    *wrapped_key_blob = malloc(klen);
    *wrapped_key_length = klen;
    memcpy(*wrapped_key_blob, kdata, klen);

out:
    kmip_node_free(cparams);
    kmip_node_free(wrap_id);
    kmip_node_free(wkey_info);
    kmip_node_free(wrap_spec);
    kmip_node_free(uid);
    kmip_node_free(req_pl);
    kmip_node_free(resp_pl);
    kmip_node_free(kobj);
    kmip_node_free(kblock);
    kmip_node_free(kval);
    kmip_node_free(wrap);
    kmip_node_free(wkinfo);
    kmip_node_free(wcparms);
    kmip_node_free(key);

    return rc;
}

/**
 * Sends a request to a KMIP server to retrieve a public key of the given
 * key type and label
 * 
 * @param keytype           used to specify the algorithm of the public key
 * @param public_key_label  the label of the public key on the remote server
 * @param pkey              an EVP format public key object which the retrieved
 *                          key is written into
 * 
 * @return CK_RV 
 */
static CK_RV p11kmip_retrieve_remote_public_key(
                                struct p11kmip_keytype *public_keytype,
                                struct kmip_node *pubkey_uid,
                                EVP_PKEY **pub_key)
{
    struct kmip_node *cparams = NULL, *wrap_id = NULL, *wkey_info = NULL;
    struct kmip_node *wrap_spec = NULL, *req_pl = NULL, *resp_pl = NULL;
    struct kmip_node *uid = NULL, *kobj = NULL, *kblock = NULL;
    struct kmip_node *kval = NULL, *wrap = NULL, *key = NULL;
    struct kmip_node *wkinfo = NULL, *wcparms = NULL;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    const BIGNUM **modulus_ptr = NULL, **pub_exp_ptr = NULL;
    BIGNUM *modulus = NULL, *pub_exp = NULL;
    RSA *rsa_key = NULL;
#else
    const BIGNUM **modulus_ptr = NULL, **pub_exp_ptr = NULL;
#endif
    enum kmip_key_format_type ftype;
    enum kmip_object_type otype;
    enum kmip_crypto_algo algo;
    int32_t bits;
    CK_OBJECT_CLASS public_key_class;
    CK_KEY_TYPE public_key_alg;
    enum kmip_result_status status = 0;
    enum kmip_result_reason reason = 0;
    int rc = 0;

    if (public_keytype->class != CKO_PUBLIC_KEY) {
        warnx("Unsupported object class");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    if (public_keytype->type != CKK_RSA) {
        warnx("Unsupported public key algorithm");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    req_pl = kmip_new_get_request_payload(NULL, pubkey_uid,
                                          kmip_wrap_key_format, 0, 0, NULL);
    if (req_pl == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
    }

    rc = perform_kmip_request(KMIP_OPERATION_GET, req_pl, &resp_pl,
                              &status, &reason);
    if (rc != 0) {
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    rc = kmip_get_get_response_payload(resp_pl, &otype, NULL, &kobj);
    if (rc != 0) {
        warnx("Failed to get wrapped key");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    public_key_class = get_p11_obj_class_from_kmip(otype);
    if (public_key_class != public_keytype->class) {
        warnx("Invalid class");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    rc = kmip_get_public_key(kobj, &kblock);

    if (rc) {
        warnx("Failed to get public key");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    rc = kmip_get_key_block(kblock, &ftype, NULL, &kval, &algo, &bits, NULL);

    if (rc) {
        warnx("Failed to get key block");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    if (ftype != kmip_wrap_key_format) {
        warnx("Key format is not RAW");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    public_key_alg = get_p11_alg_from_kmip(algo);
    if (public_key_alg != public_keytype->type) {
        warnx("Key algorithm is incorrect");
    }

    rc = kmip_get_key_value(kval, &key, NULL, 0, NULL);

    if (rc) {
        warnx("Failed to get key value");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    switch (kmip_wrap_key_format) {
    case KMIP_KEY_FORMAT_TYPE_PKCS_1:
        rc = kmip_get_pkcs1_public_key(key, algo, pub_key);
        if (rc != CKR_OK) {
            warnx("Failed to get RSA public key parts");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
        break;
    case KMIP_KEY_FORMAT_TYPE_PKCS_8:
        rc = kmip_get_pkcs8_public_key(key, pub_key);
        if (rc != CKR_OK) {
            warnx("Failed to get RSA public key parts");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
        break;
    case KMIP_KEY_FORMAT_TYPE_TRANSPARENT_RSA_PUBLIC_KEY:
        rc = kmip_get_transparent_rsa_public_key(key, modulus_ptr, pub_exp_ptr);
        if (rc != CKR_OK) {
            warnx("Failed to get RSA public key parts");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
#if !OPENSSL_VERSION_PREREQ(3, 0)
        rsa_key = RSA_new();
        if (rsa_key == NULL) {
            warnx("RSA_new failed.");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        modulus = BN_copy(modulus, *modulus_ptr);

        if (modulus == NULL) {
            warnx("Copying modulus failed");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        pub_exp = BN_copy(pub_exp, *pub_exp_ptr);

        if (pub_exp == NULL) {
            warnx("Copying public exponent failed");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        if (RSA_set0_key(rsa_key, modulus, pub_exp, NULL)) {
            warnx("RSA_set0_key failed.");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        if (EVP_PKEY_set1_RSA(*pub_key, (struct rsa_st *) rsa_key)) {
            warnx("RSA_PKEY_set1_RSA failed.");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
#else
        EVP_PKEY_set_bn_param(*pub_key, OSSL_PKEY_PARAM_RSA_N, *modulus_ptr);
        EVP_PKEY_set_bn_param(*pub_key, OSSL_PKEY_PARAM_RSA_E, *pub_exp_ptr);
#endif
        break;
    default:
        warnx("Unsupported wrapping key format: %d", kmip_wrap_key_format);
        rc = CKR_ARGUMENTS_BAD;
        goto out;
    }

    // Store the length of the retrieved key
    public_keytype->keysize_value = (CK_ULONG)(bits/8);

out:
    kmip_node_free(cparams);
    kmip_node_free(wrap_id);
    kmip_node_free(wkey_info);
    kmip_node_free(wrap_spec);
    kmip_node_free(uid);
    kmip_node_free(req_pl);
    kmip_node_free(resp_pl);
    kmip_node_free(kobj);
    kmip_node_free(kblock);
    kmip_node_free(kval);
    kmip_node_free(wrap);
    kmip_node_free(wkinfo);
    kmip_node_free(wcparms);
    kmip_node_free(key);
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (rsa_key != NULL)
        RSA_free(rsa_key);
#endif

    return rc;
}

static CK_RV p11kmip_generate_remote_secret_key(
                                            struct p11kmip_keytype *keytype,
                                            const char *secret_key_label,
                                            struct kmip_node **secret_key_uid)
{
    struct kmip_node *act_req = NULL, *act_resp = NULL, *unique_id = NULL;
    struct kmip_node **attrs = NULL, *crea_req = NULL, *crea_resp = NULL;
    enum kmip_result_status crea_status = 0, act_status = 0;
    enum kmip_result_reason crea_reason = 0, act_reason = 0;
    unsigned int num_attrs, i, idx = 0;
    CK_ULONG keysize = 0;
    enum kmip_crypto_algo secret_alg = P11KMIP_KMIP_UNKNOWN_ALG;
    int rc = 0;

    num_attrs = 4 + (supports_sensitive_attr()? 1 : 0);
    attrs = malloc(num_attrs * sizeof(struct kmip_node *));

    secret_alg = get_kmip_alg_from_p11(keytype->type);

    if (secret_alg == P11KMIP_KMIP_UNKNOWN_ALG) {
        warnx("Invalid key type being generated");
        rc = CKR_FUNCTION_NOT_SUPPORTED;
        goto out;
    }
    attrs[idx] = kmip_new_cryptographic_algorithm(secret_alg);

    if (attrs[idx] == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }
    idx++;

    rc = keytype->keygen_get_key_size(keytype, NULL, &keysize);

    if (rc != CKR_OK || keysize == 0) {
        warnx("Failed to get keysize");
        goto out;
    }
    /* Cryptographic length wants it in bits */
    attrs[idx] = kmip_new_cryptographic_length(keysize * 8);
    if (attrs[idx] == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }
    idx++;

    attrs[idx] =
        kmip_new_cryptographic_usage_mask(get_kmip_usage_mask_p11(keytype));
    if (attrs[idx] == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }
    idx++;

    if (supports_sensitive_attr()) {
        attrs[idx] = kmip_new_sensitive(true);
        if (attrs[idx] == NULL) {
            warnx("Allocate KMIP node failed");
            rc = CKR_HOST_MEMORY;
            goto out;
        }
        idx++;
    }

    attrs[idx] = kmip_new_name(secret_key_label,
                               KMIP_NAME_TYPE_UNINTERPRETED_TEXT_STRING);
    if (attrs[idx] == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }
    idx++;

    crea_req = kmip_new_create_request_payload(NULL,
                                               KMIP_OBJECT_TYPE_SYMMETRIC_KEY,
                                               NULL, num_attrs, attrs);
    if (crea_req == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    act_req = kmip_new_activate_request_payload(NULL);  /* ID placeholder */
    if (act_req == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    rc = perform_kmip_request2(KMIP_OPERATION_CREATE, crea_req,
                               &crea_resp, &crea_status, &crea_reason,
                               KMIP_OPERATION_ACTIVATE, act_req,
                               &act_resp, &act_status, &act_reason,
                               KMIP_BATCH_ERR_CONT_STOP);
    if (rc != 0) {
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    rc = kmip_get_create_response_payload(crea_resp, NULL, &unique_id,
                                          NULL, 0, NULL);
    if (rc != CKR_OK) {
        warnx("Failed to get key unique-id");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    *secret_key_uid = unique_id;

out:
    if (attrs != NULL) {
        for (i = 0; i < num_attrs; i++)
            kmip_node_free(attrs[i]);
        free(attrs);
    }
    kmip_node_free(crea_req);
    kmip_node_free(crea_resp);
    kmip_node_free(act_req);
    kmip_node_free(act_resp);

    return rc;
}

/**
 * @brief 
 * 
 * @param key_uid       the UUID of the key to retrieve the buffer
 *                      for. Required.
 * @param digest_alg    on output, the hashing algorithm used by
 *                      the digest. May be set to NULL.
 * @param digest        the buffer to write the digest
 *                      into. Must be allocated by the caller.
 *                      May be set to NULL.
 * @param digest_len    on input, the length of the digest buffer.
 *                      On output, the length of the digest
 *                      copied to the buffer.
 * 
 * Returns an error if the buffer is not large enough.
 * 
 * @return CK_RV 
 */
static CK_RV p11kmip_digest_remote_key(struct kmip_node *key_uid,
                                       enum kmip_hashing_algo *digest_alg,
                                       CK_BYTE *digest, u_int32_t *digest_len)
{
    struct kmip_node *attr_list_req = NULL, *attr_list_resp = NULL;
    struct kmip_node  *get_attr_req = NULL, *get_attr_resp = NULL;
    struct kmip_node *attr_ref = NULL, *attr_ref_copy = NULL;
    struct kmip_node *digest_attr = NULL;
    const CK_BYTE *l_digest = NULL;
    u_int32_t l_digest_len = 0;
    enum kmip_hashing_algo l_digest_alg = 0;
    unsigned int num_attr_refs = 0, i = 0;
    enum kmip_tag attr_tag = 0;
    enum kmip_result_status attr_list_status, get_attr_status = 0;
    enum kmip_result_reason attr_list_reason, get_attr_reason = 0;
    CK_RV rc = CKR_OK;

    /* Get the attribute list */
    attr_list_req = kmip_new_get_attribute_list_request_payload(key_uid);
    if (attr_list_req == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    rc = perform_kmip_request(KMIP_OPERATION_GET_ATTRIBUTE_LIST, attr_list_req,
                              &attr_list_resp, &attr_list_status,
                              &attr_list_reason);

    if (rc) {
        /* Handle Failure */
        rc = CKR_FUNCTION_FAILED;
        warnx("Failed to KMIP object get attribute list");
        goto out;
    }
    /* Confirm there's a "digest" attribute in the list */
    rc = kmip_get_get_attribute_list_response_payload(attr_list_resp, NULL,
                                                      &num_attr_refs, 0, NULL);
    if (rc != 0) {
        warnx("Retrieving KMIP attribute failed.");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    for (i = 0; i < num_attr_refs; i++) {
        kmip_node_free(attr_ref);
        rc = kmip_get_get_attribute_list_response_payload(attr_list_resp, NULL,
                                                          NULL, i, &attr_ref);
        if (rc != 0) {
            warnx("Retrieving KMIP attribute failed.");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        if (attr_ref == NULL) {
            warnx("Retrieving KMIP attribute failed.");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        rc = kmip_get_attribute_reference(attr_ref, &attr_tag, NULL, NULL);

        if (rc) {
            warnx("Retrieving KMIP attribute failed.");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        if (attr_tag == KMIP_TAG_DIGEST)
            break;
    }

    if (i == num_attr_refs) {
        warnx("Failed to get KMIP object attribute list");
        rc = CKR_ARGUMENTS_BAD;
        goto out;
    }
    /* Get the digest attribute */
    attr_ref_copy = kmip_node_clone(attr_ref);
    if (attr_ref_copy == NULL) {
        warnx("Clone KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    get_attr_req = kmip_new_get_attributes_request_payload_va(NULL, key_uid, 1,
                                                              attr_ref_copy);

    if (get_attr_req == NULL) {
        warnx("Allocate KMIP node failed");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    rc = perform_kmip_request(KMIP_OPERATION_GET_ATTRIBUTES, get_attr_req,
                              &get_attr_resp, &get_attr_status,
                              &get_attr_reason);

    if (rc) {
        /* Handle Failure */
        rc = CKR_FUNCTION_FAILED;
        warnx("Failed to get KMIP object attribute");
        goto out;
    }

    num_attr_refs = 0;
    rc = kmip_get_get_attributes_response_payload(get_attr_resp, NULL,
                                                  &num_attr_refs, 0,
                                                  &digest_attr);

    if (rc) {
        /* Handle Failure */
        rc = CKR_FUNCTION_FAILED;
        warnx("Failed to get KMIP object attribute");
        goto out;
    }
    /* We should have recieved exactly 1 attribute reference */
    if (num_attr_refs != 1) {
        rc = CKR_FUNCTION_FAILED;
        warnx("Unexpected number of attributes "
              "returned from get attributes request");
        goto out;
    }

    rc = kmip_get_digest(digest_attr, &l_digest_alg, &l_digest, &l_digest_len);

    if (rc) {
        rc = CKR_FUNCTION_FAILED;
        warnx("Failed to get digest from KMIP digest attribute");
        goto out;
    }

    if (digest != NULL) {
        /* Confirm the caller provided us a large enough buffer */
        if (l_digest_len > *digest_len) {
            rc = CKR_BUFFER_TOO_SMALL;
            warnx("Digest buffer could not contain digest value");
            goto out;
        }
        /* Now we can safely copy */
        memcpy(digest, l_digest, l_digest_len);
    }

    *digest_len = l_digest_len;
    *digest_alg = l_digest_alg;

out:
    kmip_node_free(attr_ref);
    kmip_node_free(attr_ref_copy);
    kmip_node_free(attr_list_req);
    kmip_node_free(attr_list_resp);
    kmip_node_free(get_attr_req);
    kmip_node_free(get_attr_resp);
    kmip_node_free(digest_attr);

    return rc;
}

/***************************************************************************/
/* Functions for Manipulating a Remote KMIP Server                         */
/***************************************************************************/

int main(int argc, char *argv[])
{
    const struct p11kmip_cmd *command = NULL;
    CK_RV rc = CKR_OK;

    /* Get p11kmip command (if any) */
    if (argc >= 2 && strncmp(argv[1], "-", 1) != 0) {
        command = find_command(argv[1]);
        if (command == NULL) {
            warnx("Invalid command '%s'", argv[1]);
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        argc--;
        argv = &argv[1];
    }

    /* Get command arguments (if any) */
    rc = parse_cmd_arguments(command, &argc, &argv);
    if (rc != CKR_OK)
        goto done;

    /* Get generic and command specific options (if any) */
    rc = parse_cmd_options(command, argc, argv);
    if (rc != CKR_OK)
        goto done;

    if (opt_help) {
        if (command == NULL)
            print_help();
        else
            print_command_help(command);
        goto done;
    }

    if (opt_version) {
        print_version();
        goto done;
    }

    if (command == NULL) {
        warnx("A command is required. Use '-h'/'--help' to see the list of "
              "supported commands");
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    rc = check_required_args(command->args);
    if (rc != CKR_OK)
        goto done;

    rc = check_required_cmd_opts(command->opts);
    if (rc != CKR_OK)
        goto done;

    rc = parse_env_vars();
    if (rc != CKR_OK)
        goto done;

    rc = parse_config_file();
    if (rc != CKR_OK)
        goto done;

    rc = init_kmip();
    if (rc != CKR_OK)
        goto done;

    rc = init_pkcs11(command);
    if (rc != CKR_OK)
        goto done;

    /* Run the command */
    rc = command->func();
    if (rc != CKR_OK) {
        warnx("Failed to perform the '%s' command: %s", command->cmd,
              p11_get_ckr(rc));
        goto done;
    }

done:
    term_kmip();
    term_pkcs11();

    if (p11kmip_cfg != NULL)
        confignode_deepfree(p11kmip_cfg);

    return rc;
}
