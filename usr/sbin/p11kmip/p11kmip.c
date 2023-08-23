/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define _GNU_SOURCE

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

#define P11KMIP_DECLARE_CURVES
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

/* Options */
static bool opt_help = false;
static bool opt_version = false;
static bool opt_verbose = false;
static CK_SLOT_ID opt_slot = (CK_SLOT_ID)-1;
static char *opt_pin = NULL;
static bool opt_force_pin_prompt = false;

static char *opt_wrap_label = NULL;
static char *opt_target_label = NULL;
static bool opt_generate = false;

static char *opt_file = NULL;
static char *opt_pem_password = NULL;
static bool opt_force_pem_pwd_prompt = false;

/*****************************************************************************/
/* Function Prototypes                                                       */
/*****************************************************************************/

/* Config */

/* P11 KMIP function prototypes */
static CK_RV p11kmip_locate_remote_key(const char *label, const struct
                                    p11kmip_keytype *keytype, 
                                    struct kmip_node **obj_uid);
static CK_RV p11kmip_register_remote_key(const struct p11kmip_keytype *keytype,
                                    CK_OBJECT_HANDLE wrapping_pubkey,
                                    const char *wrapping_key_label,
                                    struct kmip_node **key_uid);
static CK_RV p11kmip_retrieve_remote_wrapped_key(const char *wrapped_key_label,
                                    const char *wrapping_key_label, 
                                    const char **wrapped_key_blob);
static CK_RV p11kmip_generate_remote_secret_key(const struct p11kmip_keytype *keytype,
                const char *secret_key_label, struct kmip_node **secret_key_uid);
static CK_RV p11kmip_find_local_key(const struct p11kmip_keytype *keytype,
                                    const char *label, const char *id,
							        CK_OBJECT_HANDLE *key);

/* P11 function prototypes */
static bool opt_slot_is_set(const struct p11kmip_arg *arg);
static CK_RV p11kmip_import_key(void);
static CK_RV p11kmip_export_local_rsa_pkey(const struct p11kmip_keytype *keytype,
                                    EVP_PKEY **pkey, bool private,
                                    CK_OBJECT_HANDLE key, const char *label);

static CK_RV aes_get_key_size(const struct p11kmip_keytype *keytype,
                              void *private, CK_ULONG *keysize);
static CK_RV rsa_get_key_size(const struct p11kmip_keytype *keytype,
                              void *private, CK_ULONG *keysize);

static void free_attr_array_attr(CK_ATTRIBUTE *attr); // Was getting errors if I didn't add this


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
				enum kmip_batch_error_cont_option batch_err_opt);
static int perform_kmip_request(enum kmip_operation operation,
				 struct kmip_node *req_pl,
				 struct kmip_node **resp_pl,
                 enum kmip_result_status *status,
                 enum kmip_result_reason *reason);
static int discover_kmip_versions(struct kmip_version *version);
static bool supports_description_attr(void);
static bool supports_comment_attr(void);
static struct kmip_node *build_custom_attr(const char *name,
					    const char *value);
static struct kmip_node *build_description_attr(const char *description);

/*****************************************************************************/
/* Static Structure Declarations                                             */
/*****************************************************************************/

/* Key object structure declarations */
static const struct p11kmip_keytype p11kmip_aes_keytype = {
    .name = "AES",  .type = CKK_AES, .ckk_name = "CKK_AES",
    .class = CKO_SECRET_KEY,
    .keygen_mech = { .mechanism = CKM_AES_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = aes_get_key_size,
    // .keygen_add_secret_attrs = aes_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_AES,
    .keysize_attr = CKA_VALUE_LEN, 
	// .key_keysize_adjust = aes_keysize_adjust,
    // .secret_attrs = p11kmip_aes_attrs,
    // .import_check_sym_keysize = p11kmip_import_check_aes_keysize,
    // .import_sym_clear = p11kmip_import_sym_clear_des_3des_aes_generic,
    // .export_sym_clear = p11kmip_export_sym_clear_des_3des_aes_generic,
};

static const struct p11kmip_keytype p11kmip_rsa_keytype = {
    .name = "RSA",  .type = CKK_RSA, .ckk_name = "CKK_RSA",
    .keygen_mech = { .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN, },
    .is_asymmetric = true,
    .keygen_get_key_size = rsa_get_key_size,
    // .keygen_add_public_attrs = rsa_add_public_attrs,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = false,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_RSA,
    .keysize_attr = CKA_MODULUS, .keysize_attr_value_len = true,
    // .key_keysize_adjust = rsa_keysize_adjust,
    // .public_attrs = p11kmip_public_rsa_attrs,
    // .private_attrs = p11kmip_private_rsa_attrs,
    // .import_asym_pkey = p11kmip_import_rsa_pkey,
    .export_asym_pkey = p11kmip_export_local_rsa_pkey,
};

/* Commandline interface structure declarations */
static const struct p11kmip_opt p11kmip_generic_opts[] = {
    { .short_opt = 'h', .long_opt = "help", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_help, },
       .description = "Print this help, then exit." },
    { .short_opt = 'v', .long_opt = "version", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_version, },
      .description = "Print version information, then exit."},
    { .short_opt = 'd', .long_opt = "debug", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_verbose, },
      .description = "Increase debug information" },
    { .short_opt = 0, .long_opt = NULL, },
};

#define PKCS11_OPTS                                                            \
    { .short_opt = 's', .long_opt = "slot", .required = true,                  \
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


static const struct p11kmip_arg p11kmip_import_key_args[] = {
    { .name = NULL },
};
static const struct p11kmip_opt p11kmip_import_key_opts[] = {
	PKCS11_OPTS,
	{ .short_opt = 'w', .long_opt = "wrapper-label", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_wrap_label, .name = "WRAPPER-LABEL", },
      .description = "The label of the public key to be used for wrapping.", },
	{ .short_opt = 't', .long_opt = "target-label", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_target_label, .name = "TARGET-LABEL", },
      .description = "The label of the secret key to be imported from the "
	  				 "KMIP server.", },
	{ .short_opt = 'g', .long_opt = "generate", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_generate, },
      .description = "Generate a new secret key on the KMIP server to be"
	  				 "imported.", },	
};

static const struct p11kmip_cmd p11kmip_commands[] = {
    { .cmd = "import-key", .cmd_short1 = "import", .cmd_short2 = "imp",
      .func = p11kmip_import_key,
      .opts = p11kmip_import_key_opts, .args = p11kmip_import_key_args,
      .description = "Import a key from a KMIP server.",
      /*.help = print_generate_import_key_attr_help,*/
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = NULL, .func = NULL },
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
	.tls_verify_peer = false,
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

static const CK_KEY_TYPE get_p11_algorithm_kmip(enum kmip_crypto_algo kmip_alg)
{
    if (kmip_alg > P11KMIP_KMIP_P11_ALG_TABLE_LENGTH) {
        return P11KMIP_P11_UNKNOWN_ALG;
    }

    return P11KMIP_KMIP_P11_ALG_TABLE[kmip_alg];
}

static const enum kmip_crypto_algo get_kmip_algorithm_p11(CK_KEY_TYPE p11_alg)
{
    if (p11_alg > P11KMIP_P11_KMIP_ALG_TABLE_LENGTH) {
        return P11KMIP_KMIP_UNKNOWN_ALG;
    }

    return P11KMIP_P11_KMIP_ALG_TABLE[p11_alg];
}

static const CK_OBJECT_CLASS get_p11_object_class_kmip(enum kmip_object_type kmip_obj)
{
    if (kmip_obj > P11KMIP_KMIP_P11_OBJ_TABLE_LENGTH) {
        return P11KMIP_P11_UNKNOWN_OBJ;
    }

    return P11KMIP_KMIP_P11_OBJ_TABLE[kmip_obj];
}

static const enum kmip_object_type get_kmip_object_class_p11(CK_OBJECT_CLASS p11_obj)
{
    if (p11_obj > P11KMIP_P11_KMIP_OBJ_TABLE_LENGTH) {
        return P11KMIP_KMIP_UNKNOWN_OBJ;
    }

    return P11KMIP_P11_KMIP_OBJ_TABLE[p11_obj];
}

static const enum kmip_crypto_usage_mask get_kmip_usage_mask_p11(
                struct p11kmip_keytype *keytype){
    // Gnarly bitwise chain to turn on the appropriate flags for key usage
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

static const size_t get_p11_num_attrs(struct p11kmip_keytype *keytype){
    struct p11kmip_attr *attrs = NULL;
    int num_attrs = 0;

    switch(keytype->class){
        case CKO_PUBLIC_KEY:
            attrs = keytype->public_attrs;
            break;
        case CKO_PRIVATE_KEY:
            attrs = keytype->private_attrs;
            break;
        case CKO_SECRET_KEY:
            attrs = keytype->secret_attrs;
            break;
    }

    if(attrs == NULL){
        return 0;
    }

    while(attrs[num_attrs].name != NULL){
        num_attrs++;
    }

    return num_attrs;
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
                       unsigned int *optstring_len,
                       unsigned int *longopts_count)
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
                        char *optstring,
                        struct option *longopts)
{
    const struct p11kmip_opt *opt;
    unsigned int opts_idx, long_idx;

    opts_idx = strlen(optstring);

    for (long_idx = 0; longopts[long_idx].name != NULL; long_idx++)
        ;

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
                                      required_argument : optional_argument ) :
                              no_argument;
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

    (*optstring)[0] = ':'; /* Let getopt return ':' on missing argument */

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

            *arg->value.enum_value = (struct p11kmip_enum_value *)enum_val;
            return CKR_OK;
        }
    }

    /* process ANY enumeration value after all others */
    if (any_val != NULL) {
        *any_val->any_value = val;
        *arg->value.enum_value = (struct p11kmip_enum_value *)any_val;
        return CKR_OK;
    }

    return CKR_ARGUMENTS_BAD;
}

static CK_RV process_number_argument(const struct p11kmip_arg *arg, char *val)
{
    char *endptr;

    *arg->value.number = strtoul(val, &endptr, 0);

    if ((errno == ERANGE && *arg->value.number == ULONG_MAX) ||
        (errno != 0 && *arg->value.number == 0) ||
        endptr == val) {
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
        warnx("Option '-%c/--%s' is required but not specified", opt->short_opt,
             opt->long_opt);
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

        case '?': /* An invalid option has been specified */
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
        line =  strsep(&desc, "\n");
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
            len = snprintf(tmp, sizeof(tmp),"    --%s", opt->long_opt);
        else
            len = snprintf(tmp, sizeof(tmp),"-%c", opt->short_opt);

        if (opt->arg.type != ARG_TYPE_PLAIN) {
            if (opt->arg.required)
                snprintf(&tmp[len], sizeof(tmp) - len, " %s", opt->arg.name);
            else if (opt->long_opt == NULL)
                snprintf(&tmp[len], sizeof(tmp) - len, "[%s]", opt->arg.name);
            else
                snprintf(&tmp[len], sizeof(tmp) - len, "[=%s]", opt->arg.name);
        }

        printf("    %-30.30s ", tmp);
        print_indented(opt->description, PRINT_INDENT_POS);
    }
}

static void print_arguments_help(const struct p11kmip_cmd *cmd,
                                 const struct p11kmip_arg *args,
                                 int indent)
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
        if (width < (int)strlen(arg->name))
            width = (int)strlen(arg->name);

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
    printf("Usage: p11kmip COMMAND [ARGS] [OPTIONS]\n");
    printf("\n");
    printf("COMMANDS:\n");
    for (cmd = p11kmip_commands; cmd->cmd != NULL; cmd++) {
        printf("    %-30.30s ", cmd->cmd);
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
    return (*arg->value.number != (CK_ULONG)-1);
}

static int openssl_err_cb(const char *str, size_t len, void *u)
{
    UNUSED(u);

    if (str[len - 1] == '\n')
        len--;

    warnx("OpenSSL error: %.*s", (int)len, str);
    return 1;
}

static int p11kmip_pem_password_cb(char *buf, int size, int rwflag,
                                  void *userdata)
{
    const char *pem_password = opt_pem_password;
    char *buf_pem_password = NULL;
    char *msg = NULL;
    int len;

    UNUSED(rwflag);
    UNUSED(userdata);

    if (pem_password == NULL)
        pem_password = getenv(PKCS11_PEM_PASSWORD_ENV_NAME);

    if (opt_force_pem_pwd_prompt || pem_password == NULL) {
        if (asprintf(&msg, "Please enter PEM password for '%s': ",
                     opt_file) <= 0) {
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
/* Configuration File Functions                                              */
/*****************************************************************************/

static void parse_config_file_error_hook(int line, int col, const char *msg)
{
  warnx("Parse error: %d:%d: %s", line, col, msg);
}

static CK_RV parse_config_file(void)
{
    FILE *fp = NULL;
    char *file_loc = getenv(P11KMIP_DEFAULT_CONF_FILE_ENV_NAME);
    char pathname[PATH_MAX];
    struct passwd *pw;

    if (file_loc != NULL) {
        fp = fopen(file_loc, "r");
        if (fp == NULL) {
            warnx("Cannot read config file '%s' (specified via env variable %s): %s",
                  file_loc, P11KMIP_DEFAULT_CONF_FILE_ENV_NAME, strerror(errno));
            return CKR_OK;
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
                return CKR_OK;
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

const char *pcszPassphrase = "";

int passwd_callback(char *pcszBuff,int size,int rwflag, void *pPass)
{
    size_t unPass = strlen((char*)pPass);
    if(unPass > (size_t)size)
        unPass = (size_t)size;
    memcpy(pcszBuff, pPass, unPass);
    return (int)unPass;
}

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
    struct ConfigBaseNode *c, *host, *tls_client_cert, *tls_client_key,
        *wrap_key_format, *wrap_key_algorithm, *wrap_key_size, 
        *wrap_pad_method, *wrap_hash_algo;
    struct ConfigStructNode *structnode;
    bool found;
	BIO *tls_client_key_bio;

    rc = CKR_OK;

    /* Populate the kmip_config global with static defaults */
    kmip_conf = &kmip_default_config;

    /* The lack of a config file, by itself, is not fatal,  */
    /* because all the required information can potentially */
    /* be provided through commandline arguements           */
    if (p11kmip_cfg != NULL) {
        /* Iterate the configuration node(s) */
        confignode_foreach(c, p11kmip_cfg, f) {
            if (!confignode_hastype(c, CT_STRUCT) ||
                strcmp(c->key, P11KMIP_CONFIG_KEYWORD_SERVER) != 0){
                continue;
            } else if (found) {
                warnx("Syntax error in config file: '%s' specified multiple times\n",
                    P11KMIP_CONFIG_KEYWORD_SERVER);
                rc = CKR_GENERAL_ERROR;
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

            // Ensure all the fields are the right type and
            // were specificied with the right combinations
            if (host != NULL && !confignode_hastype(host, CT_STRINGVAL)) {
                warnx("Syntax error in config file: Missing '%s' in attribute at line %hu\n",
                    P11KMIP_CONFIG_KEYWORD_HOST, c->line);
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
            if (tls_client_cert != NULL && !confignode_hastype(tls_client_cert, CT_STRINGVAL)) {
                warnx("Syntax error in config file: Missing '%s' in attribute at line %hu\n",
                    P11KMIP_CONFIG_KEYWORD_CLIENT_CERT, c->line);
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
            if (tls_client_key != NULL && !confignode_hastype(tls_client_key, CT_STRINGVAL)) {
                warnx("Syntax error in config file: Missing '%s' in attribute at line %hu\n",
                    P11KMIP_CONFIG_KEYWORD_CLIENT_KEY, c->line);
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
            if (wrap_key_format != NULL && !confignode_hastype(wrap_key_format, CT_STRINGVAL)) {
                warnx("Syntax error in config file: Missing '%s' in attribute at line %hu\n",
                    P11KMIP_CONFIG_KEYWORD_WRAP_KEY_FMT, c->line);
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
            if (wrap_key_algorithm != NULL && !confignode_hastype(wrap_key_algorithm, CT_STRINGVAL)) {
                warnx("Syntax error in config file: Missing '%s' in attribute at line %hu\n",
                    P11KMIP_CONFIG_KEYWORD_WRAP_KEY_ALG, c->line);
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
            if (wrap_key_size != NULL && !confignode_hastype(wrap_key_size, CT_INTVAL)) {
                warnx("Syntax error in config file: Missing '%s' in attribute at line %hu\n",
                    P11KMIP_CONFIG_KEYWORD_WRAP_KEY_SIZE, c->line);
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
            if (wrap_pad_method != NULL && !confignode_hastype(wrap_pad_method, CT_STRINGVAL)) {
                warnx("Syntax error in config file: Missing '%s' in attribute at line %hu\n",
                    P11KMIP_CONFIG_KEYWORD_WRAP_PAD_MTHD, c->line);
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
            if (wrap_hash_algo != NULL && !confignode_hastype(wrap_hash_algo, CT_STRINGVAL)) {
                warnx("Syntax error in config file: Missing '%s' in attribute at line %hu\n",
                    P11KMIP_CONFIG_KEYWORD_WRAP_HASH_ALG, c->line);
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
        }
        
        if(host != NULL) {
            kmip_conf->server = confignode_to_stringval(host)->value;
        }

        if(tls_client_cert != NULL) {
            kmip_conf->tls_client_cert = 
                confignode_to_stringval(tls_client_cert)->value;
        }

        if(tls_client_key != NULL) {
            tls_client_key_bio = 
                BIO_new_file(confignode_to_stringval(tls_client_key)->value,"r");

            if(tls_client_key_bio == NULL) {
                warnx("Unable to open '%s' for TLS client certificate",
                    confignode_to_stringval(tls_client_cert)->value);
                //ERR_print_errors_cb(openssl_err_cb, NULL);
                return CKR_FUNCTION_FAILED;
            }

            kmip_conf->tls_client_key = PEM_read_bio_PrivateKey(
                tls_client_key_bio, NULL,
                passwd_callback,(void*)pcszPassphrase);
            
            if(kmip_conf->tls_client_key == NULL) {
                warnx("Unable to extract TLS client key from '%s'",
                    confignode_to_stringval(tls_client_key)->value);
            }

            BIO_free(tls_client_key_bio);
        }
    
        if(wrap_key_format != NULL) {
            if(strcmp(confignode_to_stringval(wrap_key_format)->value,
               P11KMIP_CONFIG_VALUE_FMT_PKCS1) == 0) {
                kmip_wrap_key_format = KMIP_KEY_FORMAT_TYPE_PKCS_1;
            } else if(strcmp(confignode_to_stringval(wrap_key_format)->value,
               P11KMIP_CONFIG_VALUE_FMT_PKCS8) == 0) {
                kmip_wrap_key_format = KMIP_KEY_FORMAT_TYPE_PKCS_8;
            } else if(strcmp(confignode_to_stringval(wrap_key_format)->value,
               P11KMIP_CONFIG_VALUE_FMT_TRANSPARENT) == 0) {
                kmip_wrap_key_format = 
                    KMIP_KEY_FORMAT_TYPE_TRANSPARENT_RSA_PUBLIC_KEY;
            } else {
                warnx("Syntax error in config file: Invalid value '%s' specified\
for key word '%s's\n", confignode_to_stringval(wrap_key_format)->value,
                    P11KMIP_CONFIG_KEYWORD_WRAP_KEY_FMT);
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
        } else {
            warnx("Wrapping key format not found in config file");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }

        if (wrap_key_algorithm != NULL) {
            if (strcmp(confignode_to_stringval(wrap_key_algorithm)->value,
               P11KMIP_CONFIG_VALUE_KEY_ALG_RSA) == 0) {
                kmip_wrap_key_alg = KMIP_CRYPTO_ALGO_RSA;
            } else {
                warnx("Syntax error in config file: Invalid value '%s' specified\
for key word '%s's\n", confignode_to_stringval(wrap_key_algorithm)->value,
                    P11KMIP_CONFIG_KEYWORD_WRAP_KEY_ALG);
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
        } else {
            warnx("Wrapping key algorithm not found in config file");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }

        if (wrap_key_size != NULL) {
            kmip_wrap_key_size = confignode_to_intval(wrap_key_size)->value;
        } else {
            warnx("Wrapping key length not found in config file");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }

        if (wrap_pad_method != NULL) {
            if (strcmp(confignode_to_stringval(wrap_pad_method)->value,
               P11KMIP_CONFIG_VALUE_METHD_PKCS15) == 0) {
                kmip_wrap_key_alg = KMIP_PADDING_METHOD_PKCS_1_5;
            } else if (strcmp(confignode_to_stringval(wrap_pad_method)->value,
               P11KMIP_CONFIG_VALUE_METHD_OAEP) == 0) {
                kmip_wrap_key_alg = KMIP_PADDING_METHOD_OAEP;
            } else {
                warnx("Syntax error in config file: Invalid value '%s' specified\
for key word '%s's\n", confignode_to_stringval(wrap_pad_method)->value,
                    P11KMIP_CONFIG_KEYWORD_WRAP_PAD_MTHD);
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
        } else {
            warnx("Wrap padding method not found in config file");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }

        if (wrap_hash_algo != NULL) {
            if (strcmp(confignode_to_stringval(wrap_hash_algo)->value,
               P11KMIP_CONFIG_VALUE_HSH_ALG_SHA_1) == 0) {
                kmip_wrap_key_alg = KMIP_HASHING_ALGO_SHA_1;
            } else if (strcmp(confignode_to_stringval(wrap_hash_algo)->value,
               P11KMIP_CONFIG_VALUE_HSH_ALG_SHA_256) == 0) {
                kmip_wrap_key_alg = KMIP_HASHING_ALGO_SHA_256;
            } else {
                warnx("Syntax error in config file: Invalid value '%s' specified\
for key word '%s's\n", confignode_to_stringval(wrap_hash_algo)->value,
                    P11KMIP_CONFIG_KEYWORD_WRAP_HASH_ALG);
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
        } else {
            warnx("Wrap hashing algorithm not found in config file");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }
    }

    /* Processing for other options goes here                     */
    /* it should also be possible to pass in the client cert file */
    /* through the commandline                                    */

    if(kmip_conf->tls_client_key == NULL &&
       kmip_conf->tls_client_cert == NULL){
        warnx("TLS client key or client certificate was not provided through configuration\
 or commandline options");
        rc = CKR_GENERAL_ERROR;
        goto done;
    }



done:

	return rc;
}

static void free_kmip_config(void)
{
	if(kmip_conf->tls_client_key != NULL)
        EVP_PKEY_free(kmip_conf->tls_client_key);
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
static CK_RV init_kmip(void){
    CK_RV rc;
    rc = CKR_OK;

    rc = build_kmip_config();

    if(rc != CKR_OK)
        goto done;

    rc = kmip_connection_new(kmip_conf, &kmip_conn, opt_verbose);

    if (rc != CKR_OK) {
        warnx("Failed to initialize connection to KMIP server");
        goto done;
    }

    rc = discover_kmip_versions(&kmip_vers);
    printf("KMIP server version: %d.%d\n", kmip_vers.major, kmip_vers.minor);

done: 
    return rc;
}

/**
 * @brief Closes and frees the KMIP connection and the
 * KMIP configuration structure
 * 
 */
static void term_kmip(void){
    if(kmip_conn != NULL)
        kmip_connection_free(kmip_conn);
    
    if(kmip_conf != NULL)
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
		rc = -ENOMEM;
		warnx("Allocate KMIP node failed");
		goto out;
	}

	rc = perform_kmip_request(KMIP_OPERATION_DISCOVER_VERSIONS,
				   req_pl, &resp_pl, &discover_status,
                   &discover_reason);
	if (rc != 0 && 
        discover_reason != KMIP_RESULT_REASON_ILLEGAL_OPERATION) {
        warnx("Failed to request KMIP version from server");
        goto out;
    }

    // This reason code can be returned if the DiscoverVersions
    // function is not supported on the server, which, ironically,
    // allows us to deduce it is version 1.0
    if(discover_reason == KMIP_RESULT_REASON_ILLEGAL_OPERATION) {
        rc = CKR_OK;
        version->major = 1;
        version->minor = 0;
    } else {
        rc = kmip_get_discover_versions_response_payload(resp_pl, NULL, 0,
                            version);
        if (rc != 0) {
            warnx("Failed to get discover version response");
            goto out;
        }
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
 * Returns true if the KMIP server supports the 'Description' attribute.
 * This is dependent on the profile settings, and the used KMIP protocol
 * version (>= v1.4).
 *
 * @return true or false
 */
static bool supports_description_attr(void)
{
	if (kmip_vers.major <= 1)
		return false;

	if (kmip_vers.major == 1 && kmip_vers.minor < 4)
		return false;

    if (kmip_vers.major == 2 && kmip_vers.minor == 1)
        return false;

	return true;
}

/**
 * Returns true if the KMIP server supports the 'Comment' attribute.
 * This is dependent on the profile settings, and the used KMIP protocol
 * version (>= v1.4).
 *
 * @return true or false
 */
static bool supports_comment_attr(void)
{
	if (kmip_vers.major <= 1)
		return false;

	if (kmip_vers.major == 1 && kmip_vers.minor < 4)
		return false;
    
    if (kmip_vers.major == 2 && kmip_vers.minor == 1)
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
static struct kmip_node *build_custom_attr(const char *name,
					    const char *value)
{
	struct kmip_node *attr = NULL, *text;
	char *v1_name = NULL;

	text = kmip_node_new_text_string(KMIP_TAG_ATTRIBUTE_VALUE, NULL, value);

	// switch (ph->profile->cust_attr_scheme) {
	// case KMIP_PROFILE_CUST_ATTR_V1_STYLE:
	// 	util_asprintf(&v1_name, "zkey-%s", name);
	// 	attr = kmip_new_vendor_attribute("x", v1_name, text);
	// 	free(v1_name);
	// 	break;
	// case KMIP_PROFILE_CUST_ATTR_V2_STYLE:
		attr = kmip_new_vendor_attribute("p11kmip", name, text);
	// 	break;
	// default:
	// 	_set_error(ph, "Invalid custom attribute style: %d",
	// 		   ph->profile->cust_attr_scheme);
	// 	goto out;
	// }

//out:
	kmip_node_free(text);
	return attr;
}

static struct kmip_node *build_description_attr(const char *description)
{
	if (supports_description_attr())
		return kmip_new_description(description);

	if (supports_comment_attr())
		return kmip_new_comment(description);

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
	// CHECK_ERROR(rc != 0, rc, rc, "Get KMIP response header failed",
	// 	    ph, out);

	rc = kmip_get_response_header(resp_hdr, NULL, NULL, NULL, NULL,
				      &batch_count);
	// CHECK_ERROR(rc != 0, rc, rc, "Get KMIP response header infos failed",
	// 		    ph, out);
	// CHECK_ERROR(batch_item >= batch_count, rc, -EBADMSG,
	// 	    "Response contains less batch items than expected",
	// 	    ph, out);

	rc = kmip_get_response(resp, NULL, batch_item, &resp_bi);
	// CHECK_ERROR(rc != 0, rc, rc, "Get KMIP response batch item failed",
	// 	    ph, out);

	rc = kmip_get_response_batch_item(resp_bi, NULL, NULL, NULL, status,
					  reason, &message, NULL, NULL,
					  payload);
	// CHECK_ERROR(rc != 0, rc, rc, "Get KMIP response status infos failed",
	// 		    ph, out);

	// pr_verbose(&ph->pd, "KMIP response, operation: %d, status: %d, "
	// 	   "reason: %d message: '%s'", operation, status, reason,
	// 	   message ? message : "(none)");

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
	// CHECK_ERROR(req_bi1 == NULL, rc, -ENOMEM, "Allocate KMIP node failed",
	// 	    ph, out);

	if (operation2 != 0) {
		req_bi2 = kmip_new_request_batch_item(operation2, NULL, 0,
						      req_pl2);
		// CHECK_ERROR(req_bi2 == NULL, rc, -ENOMEM,
		// 	    "Allocate KMIP node failed", ph, out);
	}

	req_hdr = kmip_new_request_header(NULL, 0, NULL, NULL, false, NULL,
					  batch_err_opt, true,
					  operation2 != 0 ? 2 : 1);
	// CHECK_ERROR(req_hdr == NULL, rc, -ENOMEM, "Allocate KMIP node failed",
	// 	    ph, out);

	*req = kmip_new_request_va(req_hdr, 2, req_bi1, req_bi2);
	// CHECK_ERROR(*req == NULL, rc, -ENOMEM, "Allocate KMIP node failed",
	// 	    ph, out);

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

	// if (operation2 != 0)
	// 	pr_verbose(&ph->pd, "Perform KMIP request, operations: %d, %d",
	// 		   operation1, operation2);
	// else
	// 	pr_verbose(&ph->pd, "Perform KMIP request, operation: %d",
	// 		   operation1);


	rc = build_kmip_request2(operation1, req_pl1, operation2, req_pl2,
				  &req, batch_err_opt);
	if (rc != 0)
		goto out;

	rc = kmip_connection_perform(kmip_conn, req, &resp,
				     opt_verbose);
	if (rc != 0) {
		// _set_error(ph, "Failed to perform KMIP request: %s",
		// 	   strerror(-rc));
	}

	rc  = check_kmip_response(resp, 0, operation1, resp_pl1,
                      status1, reason1);
	if (rc != 0 && batch_err_opt == KMIP_BATCH_ERR_CONT_CONTINUE &&
	    operation2 != 0) {
		rc = 0;
		//plugin_clear_error(&ph->pd);
	}
	if (rc != 0)
		goto out;

	if (operation2 != 0) {
		rc  = check_kmip_response(resp, 1, operation2, resp_pl2, 
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
                0, NULL, NULL, NULL, NULL, KMIP_BATCH_ERR_CONT_STOP);
}

/*****************************************************************************/
/* PKCS Library Functions                                                    */
/*****************************************************************************/

static CK_RV load_pkcs11_lib(void)
{
    CK_RV rc;
    CK_RV (*getfunclist)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    const char *libname;

    libname = secure_getenv(P11KMIP_PKCSLIB_ENV_NAME);
    if (libname == NULL || strlen(libname) < 1)
        libname = P11KMIP_DEFAULT_PKCS11_LIB;

    pkcs11_lib = dlopen(libname, RTLD_NOW);
    if (pkcs11_lib == NULL) {
        warnx("Failed to load PKCS#11 library '%s': %s", libname, dlerror());
        return CKR_FUNCTION_FAILED;
    }

    *(void**) (&getfunclist) = dlsym(pkcs11_lib, "C_GetFunctionList");
    if (getfunclist == NULL) {
        warnx("Failed to resolve symbol '%s' from PKCS#11 library '%s': %s",
              "C_GetFunctionList", libname, dlerror());
        return CKR_FUNCTION_FAILED;
    }

    rc = getfunclist(&pkcs11_funcs);
    if (rc != CKR_OK) {
        warnx("C_GetFunctionList() on PKCS#11 library '%s' failed with 0x%lX: %s)\n",
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

    rc = pkcs11_funcs->C_Login(pkcs11_session, CKU_USER, (CK_CHAR *)pin,
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
    char *buf_user_pin = NULL;
    const char *pin = opt_pin;

    if (command == NULL || command->session_flags == 0)
        return CKR_OK;

    if (pin == NULL)
        pin = getenv(PKCS11_USER_PIN_ENV_NAME);
    if (opt_force_pin_prompt || pin == NULL)
        pin = pin_prompt(&buf_user_pin, "Please enter user PIN: ");
    if (pin == NULL)
        return CKR_FUNCTION_FAILED;

    rc = load_pkcs11_lib();
    if (rc != CKR_OK)
        goto done;

    rc = pkcs11_funcs->C_Initialize(NULL);
    if (rc != CKR_OK) {
        warnx("C_Initialize failed: 0x%lX: %s", rc, p11_get_ckr(rc));
        goto done;
    }

    pkcs11_initialized = true;

    rc = open_pkcs11_session(opt_slot, command->session_flags, pin);
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

static CK_RV add_attribute(CK_ATTRIBUTE_TYPE type, const void *value,
                           CK_ULONG value_len, CK_ATTRIBUTE **attrs,
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

static CK_RV parse_id(const char *id_string, CK_ATTRIBUTE **attrs,
                      CK_ULONG *num_attrs)
{
    unsigned char *buf = NULL;
    BIGNUM *b = NULL;
    int len;
    CK_RV rc = CKR_OK;

    len = BN_hex2bn(&b, id_string);
    if (len < (int)strlen(id_string)) {
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

static CK_RV get_bignum_attr(CK_OBJECT_HANDLE key, CK_ATTRIBUTE_TYPE type,
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

    if (BN_bin2bn((unsigned char *)attr.pValue, attr.ulValueLen, *bn) == NULL) {
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

static CK_RV aes_get_key_size(const struct p11kmip_keytype *keytype,
                void *private, CK_ULONG *keysize){
    *keysize = 256;
    return CKR_OK;
}

static CK_RV rsa_get_key_size(const struct p11kmip_keytype *keytype,
                void *private, CK_ULONG *keysize){
    *keysize = 1024;
    return CKR_OK;
}

/* Commands */

/**
 * Registers a public key with a KMIP server, retrieves a secret key from
 * the KMIP server wrapped with that public key, and then unwraps and imports
 * the secret key locally
 * 
 * global opt_wrap_label        wrapping key label
 * gloabl opt_target_label      target key label
 * 
 * @return CK_RV 
 */
static CK_RV p11kmip_import_key(void){
	CK_RV rc;
    CK_OBJECT_HANDLE wrapping_pubkey, wrapping_privkey;
    struct p11kmip_keytype pubkey_keytype, privkey_keytype, 
        secret_keytype;
    struct kmip_node *wrap_pubkey_uid = NULL, *secret_key_uid = NULL;

    pubkey_keytype = p11kmip_rsa_keytype;
    pubkey_keytype.class = CKO_PUBLIC_KEY;

    privkey_keytype = p11kmip_rsa_keytype;
    privkey_keytype.class = CKO_PRIVATE_KEY;

    secret_keytype = p11kmip_aes_keytype;

    /*
    Ways to deal with wrapping key and target key

        - Wrapping key
            - public key
                - *specify the label of the local key
                - pass in the key material through the commandline
                - specify a file containing the public key
            - private key
                - *assumed to have the same label as the public key
                - specify a different label
                - specify a file containing the private key
        - Target key
            - *specify the label on the KMIP server
            - specify the local label if different
            - maybe allow generation of new key on
            KMIP server
    */

	rc = p11kmip_find_local_key(&pubkey_keytype, opt_wrap_label, NULL, &wrapping_pubkey);

    if(rc != CKR_OK)
        goto done;
    
    printf("Wrapping Public Key Handle: 0x%lX\n", wrapping_pubkey);

    rc = p11kmip_find_local_key(&privkey_keytype, opt_wrap_label, NULL, &wrapping_privkey);

    if(rc != CKR_OK)
        goto done;

    printf("Wrapping Private Key Handle: 0x%lX\n", wrapping_privkey);

    printf("Attempting to locate public key '%s' on server\n", opt_wrap_label);
    rc = p11kmip_locate_remote_key(opt_wrap_label, &pubkey_keytype, &wrap_pubkey_uid);

    if(rc != CKR_OK){
        printf("Error while locating wrapping key on KMIP server\n");
        goto done;
    }

    // If we were unable to locate the key on the server,
    // register it there
    if (wrap_pubkey_uid == NULL) {
        printf("Did not find wrapping key '%s' on server, registering it\n",
                opt_wrap_label);
        /* Next we send the public key to the server */
        rc = p11kmip_register_remote_key(&pubkey_keytype, wrapping_pubkey, 
                                        opt_wrap_label, &wrap_pubkey_uid);
        
        if (rc != CKR_OK) {
            warnx("Failed to register wrapping key '%s' on server\n",
                opt_wrap_label);
            goto done;
        }
    }

    printf("Wrapping key KMIP UID is '%x'", wrap_pubkey_uid);

    printf("Attempting to locate secret key '%s' on server\n", opt_target_label);
    rc = p11kmip_locate_remote_key(opt_target_label, &secret_keytype, &secret_key_uid);

    if(rc != CKR_OK){
        printf("Error while locating target key on KMIP server\n");
        goto done;
    }

    // If we were unable to locate the create, for now, create
    // it over there
    if(secret_key_uid == NULL){
        printf("Did not find target key '%s' on server, generating it\n",
            opt_target_label);
        rc = p11kmip_generate_remote_secret_key(&secret_keytype, opt_target_label,
                &secret_key_uid);
        
        if(rc != CKR_OK){
            printf("Error creating target key on KMIP server");
            goto done;
        }
    }

    printf("Target key KMIP UID is '%x'", secret_key_uid);

    /* Next we retrieve the wrapped key */
    // rc = p11kmip_retrieve_remote_wrapped_key(wrapped_key_pl, opt_wrap_label, opt_target_label, kmip_connection);

    /* Lastly we unwrap the retrieved key */
    // rc = p11kmip_unwrap_key(wrapped_key_pl, opt_target_label, wrapping_privkey);

done:
    kmip_node_free(wrap_pubkey_uid);

	return rc;
}

/***************************************************************************/
/* Functions for Manipulating a Local PKCS#11 Adapter                      */
/***************************************************************************/

static CK_RV p11kmip_export_local_rsa_pkey(const struct p11kmip_keytype *keytype,
                                    EVP_PKEY **pkey, bool private,
                                    CK_OBJECT_HANDLE key, const char *label)
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
    // if (rc != CKR_OK && *pkey != NULL) {
    //     EVP_PKEY_free(*pkey);
    //     *pkey = NULL;
    // }

    return rc;
}

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
    bool class_set = FALSE, alg_set = FALSE;
	const char *id;
	size_t i, k;
	CK_RV rc = CKR_OK;

    // Reconcile constants for PKCS#11 to KMIP
    if (keytype->class != NULL) {
        obj_type = get_kmip_object_class_p11(keytype->class);

        if(obj_type == P11KMIP_KMIP_UNKNOWN_OBJ){
            warnx("Unknown object class");
            rc = CKR_GENERAL_ERROR;
            goto out;
        }
        class_set = TRUE;
    }

    if (keytype->type != NULL) {
        key_alg = get_kmip_algorithm_p11(keytype->type);

        if(key_alg == P11KMIP_KMIP_UNKNOWN_ALG){
            warnx("Unknown key algorithm");
            rc = CKR_GENERAL_ERROR;
            goto out;
        }
        alg_set = TRUE;
    }

    /* Label, Object Class, Key Type */
    num_attrs = 1;
    if (class_set)
        num_attrs++;
    if (alg_set)
        num_attrs++;

    attrs = malloc(num_attrs * sizeof(struct kmip_node *));
    k = 0;

    // Set the label
    attrs[k] = kmip_new_name(label,
				KMIP_NAME_TYPE_UNINTERPRETED_TEXT_STRING);
    if (attrs[k] == NULL) {
        rc = -ENOMEM;
        warnx("Allocate KMIP node failed");
        goto out;
    }
    k++;

    // Set the object type
    if (class_set) {
        attrs[k] = kmip_new_object_type(obj_type);
        if (attrs[k] == NULL) {
            rc = -ENOMEM;
            warnx("Allocate KMIP node failed");
            goto out;
        }
        k++;
    }

    //Set the key algorithm
    if (alg_set) {
        attrs[k] = kmip_new_cryptographic_algorithm(key_alg);
        if (attrs[k] == NULL) {
            rc = -ENOMEM;
            warnx("Allocate KMIP node failed");
            goto out;
        }
        k++;
    }

    req_pl = kmip_new_locate_request_payload(NULL, 0, 0, 0, 0,
						 num_attrs, attrs);
    if (req_pl == NULL) {
        rc = -ENOMEM;
        warnx("Allocate KMIP node failed");
        goto out;
    }
    
    rc = perform_kmip_request(KMIP_OPERATION_LOCATE, req_pl, &resp_pl,
                &locate_status, &locate_reason);
    if (rc != 0)
        goto out;
    
    num_objs = 0;
    for (i = 0; ; i++) {
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
        rc = CKR_GENERAL_ERROR;
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


/***************************************************************************/
/* Functions for Manipulating a Remote KMIP Server                         */
/***************************************************************************/

/**
 * @brief 
 * 
 * @param wrapping_pubkey 
 * @param wrapkey_label 
 * global kmip_connection
 * 
 * @return CK_RV 
 */
static CK_RV p11kmip_register_remote_key(const struct p11kmip_keytype *keytype,
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
	//const char *wrap_key_id = NULL;
	char *description = NULL;
	struct utsname utsname;
    enum kmip_result_status reg_status = 0, act_status = 0;
    enum kmip_result_reason reg_reason = 0, act_reason = 0;
	int rc;

	// pr_verbose(&ph->pd, "Wrapping key format: %d",
	// 	   kmip_wrap_key_format);
	// pr_verbose(&ph->pd, "Wrap padding method: %d",
	// 	   kmip_wrap_padding_method);
	// pr_verbose(&ph->pd, "Wrap hashing algorithm: %d",
	// 	   kmip_wrap_hashing_algo);

    // Export the public key from PKCS#11 into an OpenSSL EVP Key
    if (keytype->export_asym_pkey != NULL) {
        rc = keytype->export_asym_pkey(keytype, &pkey, false, 
            wrapping_pubkey, wrapping_key_label);
        
        if (rc != CKR_OK) {
            warnx("Failed to export '%s' to EVP key", wrapping_key_label);
            goto out;
        }
    } else {
        warnx("Function to export '%s' to EVP unavailable", 
            wrapping_key_label);
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
			rc = -EIO;
			goto out;
		}

		key = kmip_new_transparent_rsa_public_key(modulus, pub_exp);
		break;
	default:
		warnx("Unsupported wrapping key format: %d",
			   kmip_wrap_key_format);
		rc = -EINVAL;
		goto out;
	}
	if (key == NULL) {
        warnx("Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }

	kval = kmip_new_key_value_va(NULL, key, 0);
	if (kval == NULL) {
        warnx("Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }

	kblock = kmip_new_key_block(kmip_wrap_key_format, 0, kval,
				    kmip_wrap_key_alg,
				    kmip_wrap_key_size, NULL);
	if (kblock == NULL) {
        warnx( "Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }

	kobj = kmip_new_public_key(kblock);
	if (kobj == NULL) {
        warnx( "Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }

	if (wrapping_key_label != NULL) {
		name_attr = kmip_new_name(wrapping_key_label,
				KMIP_NAME_TYPE_UNINTERPRETED_TEXT_STRING);
        if (name_attr == NULL) {
            warnx("Allocate KMIP node failed");
            rc = -ENOMEM;
            goto out;
        }
	}

	umask_attr = kmip_new_cryptographic_usage_mask(
						KMIP_CRY_USAGE_MASK_ENCRYPT |
						KMIP_CRY_USAGE_MASK_WRAP_KEY);
	if (umask_attr == NULL) {
        warnx("Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }

	cparams_attr = kmip_new_cryptographic_parameters(NULL, 0,
				kmip_wrap_padding_method,
				kmip_wrap_padding_method ==
					KMIP_PADDING_METHOD_OAEP ?
					kmip_wrap_hash_alg : 0,
				KMIP_KEY_ROLE_TYPE_KEK, 0,
				kmip_wrap_key_alg, NULL, NULL, NULL,
				NULL, NULL, NULL, NULL, NULL,
				kmip_wrap_padding_method ==
					KMIP_PADDING_METHOD_OAEP ?
					KMIP_MASK_GENERATOR_MGF1 : 0,
				kmip_wrap_padding_method ==
					KMIP_PADDING_METHOD_OAEP ?
					kmip_wrap_hash_alg : 0,
				NULL);
	if (cparams_attr == NULL) {
        warnx("Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }

	if (uname(&utsname) != 0) {
		rc = -errno;
		warnx("Failed to obtain the system's "
			   "hostname: %s", strerror(-rc));
		goto out;
	}

	asprintf(&description, "Wrapping key for PKCS#11 client on system %s",
		      utsname.nodename);
	descr_attr = build_description_attr(description);
	free(description);
    if (descr_attr == NULL) {
        warnx("Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }

	reg_req = kmip_new_register_request_payload_va(NULL,
					KMIP_OBJECT_TYPE_PUBLIC_KEY, kobj, NULL,
					4, name_attr, umask_attr, cparams_attr,
					descr_attr);
	if (reg_req == NULL) {
        warnx( "Allocate KMIP node failed");
        rc = -ENOMEM;
    }

	act_req = kmip_new_activate_request_payload(NULL); /* ID placeholder */
	if (act_req == NULL) {
        warnx( "Allocate KMIP node failed");
        rc = -ENOMEM;
    }		

	rc = perform_kmip_request2(KMIP_OPERATION_REGISTER, reg_req,
				    &reg_resp, &reg_status, &reg_reason,
                    KMIP_OPERATION_ACTIVATE, act_req,
				    &act_resp, &act_status, &act_reason,
                    KMIP_BATCH_ERR_CONT_STOP);
	if (rc != 0)
		goto out;

	rc = kmip_get_register_response_payload(reg_resp, &unique_id, NULL,
						0, NULL);
	if (rc != 0) {
        warnx( "Failed to get key unique-id");
        goto out;
    }
	// rc = kmip_get_unique_identifier(unique_id, &wrap_key_id, NULL, NULL);
	// if (rc != 0) {
    //     warnx( "Failed to get key unique-id");  
    //     goto out;
    // }
	//pr_verbose(&ph->pd, "Wrapping key ID: '%s'", wrap_key_id);

	// rc = plugin_set_or_remove_property(&ph->pd, KMIP_CONFIG_WRAPPING_KEY_ID,
	// 				   wrap_key_id);
	// if (rc != 0)
	// 	goto out;

	// rc = plugin_set_or_remove_property(&ph->pd,
	// 				   KMIP_CONFIG_WRAPPING_KEY_LABEL,
	// 				   wrapping_key_label);
	// if (rc != 0)
	// 	goto out;
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
	//kmip_node_free(unique_id);

#if OPENSSL_VERSION_PREREQ(3, 0)
	if (modulus != NULL)
		BN_free(modulus);
	if (pub_exp != NULL)
		BN_free(pub_exp);
#endif

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
static CK_RV p11kmip_retrieve_remote_wrapped_key(const char *wrapped_key_label,
                const char *wrapping_key_label, const char **wrapped_key_blob)
{
    CK_RV rc = 0;

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
static CK_RV p11kmip_retrieve_remote_public_key(const struct p11kmip_keytype *keytype,
                const char *public_key_label, EVP_PKEY **pkey){
    CK_RV rc = 0;

    return rc;
}

static CK_RV p11kmip_generate_remote_key_pair(const struct p11kmip_keytype *keytype,
                const char *public_key_label, const char *private_key_label){
    CK_RV rc = 0;

    return rc;
}

static CK_RV p11kmip_generate_remote_secret_key(const struct p11kmip_keytype *keytype,
                const char *secret_key_label, struct kmip_node **secret_key_uid){
    struct kmip_node *act_req = NULL, *act_resp = NULL, *unique_id = NULL;
	struct kmip_node **attrs = NULL, *crea_req = NULL, *crea_resp = NULL;
    enum kmip_result_status crea_status = 0, act_status = 0;
    enum kmip_result_reason crea_reason = 0, act_reason = 0;
	unsigned int num_attrs, i, idx = 0;
    CK_ULONG keysize = 0;
    enum kmip_crypto_algo secret_alg = P11KMIP_KMIP_UNKNOWN_ALG;
	const char *uid;
	int rc = 0;

	num_attrs = 4 + (supports_sensitive_attr() ? 1 : 0);
	attrs = malloc(num_attrs * sizeof(struct kmip_node *));

    secret_alg = get_kmip_algorithm_p11(keytype->type);

    if(secret_alg == P11KMIP_KMIP_UNKNOWN_ALG){
        warnx("Invalid key type being generated");
        rc = CKR_GENERAL_ERROR;
        goto out;
    }
	attrs[idx] = kmip_new_cryptographic_algorithm(secret_alg);

    if (attrs[idx] == NULL) {
        warnx("Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }
	idx++;

    rc = keytype->keygen_get_key_size(keytype, NULL, &keysize);

    if(rc != CKR_OK || keysize == 0){
        warnx("Failed to get keysize");
        goto out;
    }

    // Cryptographic length wants it in bits
	attrs[idx] = kmip_new_cryptographic_length(keysize * 8);
	if (attrs[idx] == NULL) {
        warnx("Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }
	idx++;
    
	attrs[idx] = kmip_new_cryptographic_usage_mask(
        get_kmip_usage_mask_p11(keytype));
	if (attrs[idx] == NULL) {
        warnx("Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }
	idx++;

    // TODO: change this to just apply all the attributes
    // from the keytype structure into the request
	if (supports_sensitive_attr()) {
		attrs[idx] = kmip_new_sensitive(true);
		if (attrs[idx] == NULL) {
            warnx("Allocate KMIP node failed");
            rc = -ENOMEM;
            goto out;
        }
		idx++;
	}

    attrs[idx] = kmip_new_name(secret_key_label,
            KMIP_NAME_TYPE_UNINTERPRETED_TEXT_STRING);
    if (attrs[idx] == NULL) {
        warnx("Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }
    idx++;

	crea_req = kmip_new_create_request_payload(NULL,
					KMIP_OBJECT_TYPE_SYMMETRIC_KEY, NULL,
					num_attrs, attrs);
	if (crea_req == NULL) {
        warnx("Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }

	act_req = kmip_new_activate_request_payload(NULL); /* ID placeholder */
	if (act_req == NULL) {
        warnx("Allocate KMIP node failed");
        rc = -ENOMEM;
        goto out;
    }

	rc = perform_kmip_request2(KMIP_OPERATION_CREATE, crea_req,
				    &crea_resp, &crea_status, &crea_reason,
                    KMIP_OPERATION_ACTIVATE, act_req, 
                    &act_resp, &act_status, &act_reason,
				    KMIP_BATCH_ERR_CONT_STOP);
	if (rc != 0)
		goto out;

	rc = kmip_get_create_response_payload(crea_resp, NULL, &unique_id,
					      NULL, 0, NULL);
    if (rc != CKR_OK) {
        warnx("Failed to get key unique-id");
        goto out;
    }

	*secret_key_uid = uid;

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
static CK_RV p11kmip_find_local_key(const struct p11kmip_keytype *keytype,
                               const char *label, const char *id,
							   CK_OBJECT_HANDLE *key){
	CK_RV rc;
	CK_ATTRIBUTE *attrs = NULL;
	CK_ULONG num_attrs = 0;
	const CK_BBOOL ck_true = CK_TRUE;
	CK_OBJECT_HANDLE keys[FIND_OBJECTS_COUNT];
    CK_ULONG i, num_keys;

	rc = add_attribute(CKA_TOKEN, &ck_true, sizeof(ck_true), &attrs, &num_attrs);
    if (rc != CKR_OK)
        goto done;
	
	if (keytype != NULL) {
		// Set the filter attribute, if applicable
		if (keytype->filter_attr != (CK_ATTRIBUTE_TYPE)-1) {
			rc = add_attribute(keytype->filter_attr, &keytype->filter_value,
							sizeof(keytype->filter_value), &attrs, &num_attrs);
			if (rc != CKR_OK)
				goto done;
		}

		// Set an attribute for the class to give us more
		// granularity
		if (keytype->class != NULL) {
			rc = add_attribute(CKA_CLASS, &keytype->class,
							sizeof(keytype->class), &attrs, &num_attrs);
			if (rc != CKR_OK)
				goto done;
		}
    }

    if (label != NULL) {
		rc = add_attribute(CKA_LABEL, label, strlen(label),
							&attrs, &num_attrs);
		if (rc != CKR_OK)
			goto done;
    }

    if (id != NULL) {
        rc = parse_id(id, &attrs, &num_attrs);
        if (rc != CKR_OK)
            return rc;
    }

	rc = pkcs11_funcs->C_FindObjectsInit(pkcs11_session, attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to initialize the find operation: C_FindObjectsInit: 0x%lX: %s",
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
		//goto done;
	}

	rc = pkcs11_funcs->C_FindObjectsFinal(pkcs11_session);
    if (rc != CKR_OK) {
        warnx("Failed to finalize the find operation: C_FindObjectsFinal: 0x%lX: %s",
              rc, p11_get_ckr(rc));
        
		goto done;
    }

	if (num_keys == 0) {
		// TODO: set an RC indicating that no keys
		//	     matching that description were found
		//       let the caller decide how to error out
        rc = CKR_GENERAL_ERROR;
        warnx("Failed to find key matching label");

		goto done;
	} else if (num_keys > 1) {
		// TODO: complain about not being specific enough

		goto done;
	}

	// Write back the key handle
	*key = keys[0];

done:
	free_attributes(attrs, num_attrs);

	return rc;
}

/**
 * Retrieves an AES key from the KMIP server. The key is wrapped with the
 * RSA wrapping key.
 *
 * @param key_id            the key id of the key to get
 * @param wrapped_key       On return: an allocated buffer with the wrapped key.
 *                          Must be freed by the caller.
 * @param wrapped_key_len   On return: the size of the wrapped key.
 * @param key_bits          On return the cryptographic size of the key in bits
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _get_key_rsa_wrapped(
	struct kmip_connection *connection,
	const char *key_id,
	unsigned char **wrapped_key,
	size_t *wrapped_key_len, size_t *key_bits)
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
	char *wrap_key_id = NULL;
	uint32_t klen;
	int32_t bits;
    enum kmip_result_status status = 0;
    enum kmip_result_reason reason = 0;
	int rc = 0;

	// pr_verbose(&ph->pd, "Wrap padding method: %d",
	// 	   ph->profile->wrap_padding_method);
	// pr_verbose(&ph->pd, "Wrap hashing algorithm: %d",
	// 	   ph->profile->wrap_hashing_algo);

	wrap_key_id = "wrapping key id";
	// wrap_key_id = properties_get(ph->pd.properties,
	// 			     KMIP_CONFIG_WRAPPING_KEY_ID);
	// if (wrap_key_id == NULL) {
	// 	_set_error(ph, "Wrapping key ID is not available");
	// 	return -EINVAL;
	// }

	// pr_verbose(&ph->pd, "Wrapping key id: '%s'", wrap_key_id);

	cparams = kmip_new_cryptographic_parameters(NULL, 0,
				KMIP_PADDING_METHOD_OAEP,
				0,
				KMIP_KEY_ROLE_TYPE_KEK, 0,
				KMIP_CRYPTO_ALGO_AES, NULL, NULL, NULL,
				NULL, NULL, NULL, NULL, NULL,
				0,
				0,
				NULL);
	// CHECK_ERROR(cparams == NULL, rc, -ENOMEM, "Allocate KMIP node failed",
	// 	    ph, out);

	wrap_id = kmip_new_unique_identifier(wrap_key_id, 0, 0);
	// CHECK_ERROR(wrap_id == NULL, rc, -ENOMEM, "Allocate KMIP node failed",
	// 	    ph, out);

	wkey_info = kmip_new_key_info(false, wrap_id, cparams);
	// CHECK_ERROR(wkey_info == NULL, rc, -ENOMEM, "Allocate KMIP node failed",
	// 	    ph, out);

	wrap_spec = kmip_new_key_wrapping_specification_va(NULL,
				KMIP_WRAPPING_METHOD_ENCRYPT, wkey_info, NULL,
				KMIP_ENCODING_OPTION_NO, 0);
	// CHECK_ERROR(wrap_spec == NULL, rc, -ENOMEM, "Allocate KMIP node failed",
	// 	    ph, out);

	uid = kmip_new_unique_identifier(key_id, 0, 0);
	// CHECK_ERROR(uid == NULL, rc, -ENOMEM, "Allocate KMIP node failed",
	// 	    ph, out);

	req_pl = kmip_new_get_request_payload(NULL, uid,
					      KMIP_KEY_FORMAT_TYPE_RAW, 0, 0,
					      wrap_spec);
	// CHECK_ERROR(req_pl == NULL, rc, -ENOMEM, "Allocate KMIP node failed",
	// 	    ph, out);

	rc = perform_kmip_request(KMIP_OPERATION_GET, req_pl, &resp_pl,
                        &status, &reason);
	if (rc != 0)
		goto out;

	rc = kmip_get_get_response_payload(resp_pl, &otype, NULL, &kobj);
	// CHECK_ERROR(rc != 0, rc, rc, "Failed to get wrapped key", ph, out);
	// CHECK_ERROR(otype != KMIP_OBJECT_TYPE_SYMMETRIC_KEY, rc, -EINVAL,
	// 	    "Key is not a symmetric key", ph, out);

	rc = kmip_get_symmetric_key(kobj, &kblock);
	// CHECK_ERROR(rc != 0, rc, rc, "Failed to get symmetric key", ph, out);

	rc = kmip_get_key_block(kblock, &ftype, NULL, &kval, &algo, &bits,
				&wrap);
	// CHECK_ERROR(rc != 0, rc, rc, "Failed to get key block", ph, out);
	// CHECK_ERROR(ftype != KMIP_KEY_FORMAT_TYPE_RAW, rc, -EINVAL,
	// 	    "Key format is not RAW", ph, out);
	// CHECK_ERROR(algo != KMIP_CRYPTO_ALGO_AES, rc, -EINVAL,
	// 		    "Key algorithm is not AES", ph, out);
	// CHECK_ERROR(bits < 128 || bits > 256, rc, -EINVAL,
	// 	    "Key bit size is invalid", ph, out);

	rc = kmip_get_key_wrapping_data(wrap, &wmethod, &wkinfo, NULL, NULL,
					NULL, NULL, NULL, &enc);
	// CHECK_ERROR(rc != 0, rc, rc, "Failed to get wrapping data", ph, out);
	// CHECK_ERROR(wmethod != KMIP_WRAPPING_METHOD_ENCRYPT, rc, -EINVAL,
	// 	    "Wrapping method is not 'Encrypt'", ph, out);
	// if (ph->kmip_version.major > 1 ||
	//     (ph->kmip_version.major == 1 && ph->kmip_version.minor >= 2)) {
	// 	CHECK_ERROR(enc != KMIP_ENCODING_OPTION_NO, rc, -EINVAL,
	// 		    "Encoding is not 'No encoding'", ph, out);
	// }

	rc = kmip_get_key_info(wkinfo, NULL, &wcparms);
	// CHECK_ERROR(rc != 0, rc, rc, "Failed to get wrap key infos", ph, out);

	rc = kmip_get_cryptographic_parameter(wcparms, NULL, &pmeth, &halgo,
					      NULL, NULL, &algo, NULL, NULL,
					      NULL, NULL, NULL, NULL, NULL,
					      NULL, &mgf, &mgfhalgo, NULL);
	// CHECK_ERROR(rc != 0, rc, rc, "Failed to get crypto params", ph, out);
	// if (ph->kmip_version.major > 1 ||
	//     (ph->kmip_version.major == 1 && ph->kmip_version.minor >= 2)) {
	// 	CHECK_ERROR(algo != ph->profile->wrap_key_algo, rc, -EINVAL,
	// 		    "wrap algorithm is not as expected", ph, out);
	// }
	// CHECK_ERROR(pmeth != ph->profile->wrap_padding_method, rc, -EINVAL,
	// 	    "padding method is not as expected", ph, out);
	// if (ph->profile->wrap_padding_method == KMIP_PADDING_METHOD_OAEP) {
	// 	CHECK_ERROR(halgo != ph->profile->wrap_hashing_algo, rc,
	// 		    -EINVAL, "hashing algorithm is not as expected",
	// 		    ph, out);
	// 	if (ph->kmip_version.major > 1 ||
	// 	    (ph->kmip_version.major == 1 &&
	// 	     ph->kmip_version.minor >= 4)) {
	// 		CHECK_ERROR(mgf != KMIP_MASK_GENERATOR_MGF1, rc,
	// 			    -EINVAL, "OAEP MGF is not as expected",
	// 			    ph, out);
	// 		CHECK_ERROR(mgfhalgo != ph->profile->wrap_hashing_algo,
	// 			    rc, -EINVAL, "MGF hashing algorithm is not "
	// 			    "as expected", ph, out);
	// 	}
	// }

	rc = kmip_get_key_value(kval, &key, NULL, 0, NULL);
	// CHECK_ERROR(rc != 0, rc, rc, "Failed to get key value", ph, out);

	kdata = kmip_node_get_byte_string(key, &klen);
	// CHECK_ERROR(kdata == NULL, rc, -ENOMEM, "Failed to get key data",
	// 	    ph, out);

	// pr_verbose(&ph->pd, "Wrapped key size: %u", klen);
	*wrapped_key = malloc(klen);
	*wrapped_key_len = klen;
	memcpy(*wrapped_key, kdata, klen);

	// pr_verbose(&ph->pd, "AES key size: %u bits", bits);
	*key_bits = bits;

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

	if (wrap_key_id != NULL)
		free(wrap_key_id);

	return rc;
}




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