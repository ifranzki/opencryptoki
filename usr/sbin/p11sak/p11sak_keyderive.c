/*
 * COPYRIGHT (c) International Business Machines Corp. 2026
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#if defined(_AIX)
    const char *__progname = "p11sak";
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>

#define P11SAK_DECLARE_CURVES
#include "p11sak.h"
#include "p11util.h"
#include "mechtable.h"
#include "defs.h"

#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_PREREQ(3, 0)
    #include <openssl/core_names.h>
#endif

static struct p11tool_enum_value *opt_ecdh_kdf_alg = NULL;
static char *opt_ecdh_shared_data = NULL;

static CK_RV p11sak_ecdh_prepare_mech_param_from_opts(
                              const struct p11sak_derive_mech *derive_mech,
                              CK_MECHANISM *mech);
static void p11sak_ecdh_cleanup_mech_param(
                              const struct p11sak_derive_mech *derive_mech,
                              CK_MECHANISM *mech);
static CK_RV p11sak_dh_pkcs_prepare_mech_param_from_opts(
                              const struct p11sak_derive_mech *derive_mech,
                              CK_MECHANISM *mech);

static const struct p11sak_derive_mech p11sak_derive_mech_sha1 = {
    .name = "SHA-1",
    .mech = CKM_SHA1_KEY_DERIVATION,
    .base_class = CKO_SECRET_KEY,
    .base_key_type = (CK_KEY_TYPE)-1,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
};

static const struct p11sak_derive_mech p11sak_derive_mech_sha224 = {
    .name = "SHA224",
    .mech = CKM_SHA224_KEY_DERIVATION,
    .base_class = CKO_SECRET_KEY,
    .base_key_type = (CK_KEY_TYPE)-1,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
};

static const struct p11sak_derive_mech p11sak_derive_mech_sha256 = {
    .name = "SHA256",
    .mech = CKM_SHA256_KEY_DERIVATION,
    .base_class = CKO_SECRET_KEY,
    .base_key_type = (CK_KEY_TYPE)-1,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
};

static const struct p11sak_derive_mech p11sak_derive_mech_sha384 = {
    .name = "SHA384",
    .mech = CKM_SHA384_KEY_DERIVATION,
    .base_class = CKO_SECRET_KEY,
    .base_key_type = (CK_KEY_TYPE)-1,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
};

static const struct p11sak_derive_mech p11sak_derive_mech_sha512 = {
    .name = "SHA512",
    .mech = CKM_SHA512_KEY_DERIVATION,
    .base_class = CKO_SECRET_KEY,
    .base_key_type = (CK_KEY_TYPE)-1,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
};

static const struct p11sak_derive_mech p11sak_derive_mech_sha3_224 = {
    .name = "SHA3-224",
    .mech = CKM_SHA3_224_KEY_DERIVATION,
    .base_class = CKO_SECRET_KEY,
    .base_key_type = (CK_KEY_TYPE)-1,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
};

static const struct p11sak_derive_mech p11sak_derive_mech_sha3_256 = {
    .name = "SHA3-256",
    .mech = CKM_SHA3_256_KEY_DERIVATION,
    .base_class = CKO_SECRET_KEY,
    .base_key_type = (CK_KEY_TYPE)-1,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
};

static const struct p11sak_derive_mech p11sak_derive_mech_sha3_384 = {
    .name = "SHA3-384",
    .mech = CKM_SHA3_384_KEY_DERIVATION,
    .base_class = CKO_SECRET_KEY,
    .base_key_type = (CK_KEY_TYPE)-1,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
};

static const struct p11sak_derive_mech p11sak_derive_mech_sha3_512 = {
    .name = "SHA3-512",
    .mech = CKM_SHA3_512_KEY_DERIVATION,
    .base_class = CKO_SECRET_KEY,
    .base_key_type = (CK_KEY_TYPE)-1,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
};

static const struct p11sak_derive_mech p11sak_derive_mech_shake128 = {
    .name = "SHAKE128",
    .mech = CKM_SHAKE_128_KEY_DERIVATION,
    .base_class = CKO_SECRET_KEY,
    .base_key_type = (CK_KEY_TYPE)-1,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
};

static const struct p11sak_derive_mech p11sak_derive_mech_shake256 = {
    .name = "SHAKE256",
    .mech = CKM_SHAKE_256_KEY_DERIVATION,
    .base_class = CKO_SECRET_KEY,
    .base_key_type = (CK_KEY_TYPE)-1,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
};

static const struct p11sak_derive_mech p11sak_derive_mech_ecdh = {
    .name = "ECDH",
    .mech = CKM_ECDH1_DERIVE,
    .base_class = CKO_PRIVATE_KEY,
    .base_key_type = CKK_EC,
    .addl_base_key_type = CKK_EC_MONTGOMERY,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
    .mech_param_size = sizeof(CK_ECDH1_DERIVE_PARAMS),
    .prepare_mech_param_from_opts =
                            p11sak_ecdh_prepare_mech_param_from_opts,
    .cleanup_mech_param = p11sak_ecdh_cleanup_mech_param,
};

static const struct p11sak_derive_mech p11sak_derive_mech_ecdh_cof = {
    .name = "ECDH-COF",
    .mech = CKM_ECDH1_COFACTOR_DERIVE,
    .base_class = CKO_PRIVATE_KEY,
    .base_key_type = CKK_EC,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
    .mech_param_size = sizeof(CK_ECDH1_DERIVE_PARAMS),
    .prepare_mech_param_from_opts =
                            p11sak_ecdh_prepare_mech_param_from_opts,
    .cleanup_mech_param = p11sak_ecdh_cleanup_mech_param,
};

static const struct p11sak_derive_mech p11sak_derive_mech_dh_pkcs = {
    .name = "DH-PKCS",
    .mech = CKM_DH_PKCS_DERIVE,
    .base_class = CKO_PRIVATE_KEY,
    .base_key_type = CKK_DH,
    .addl_base_key_type = (CK_KEY_TYPE)-1,
    .derived_class = CKO_SECRET_KEY,
    .derived_key_type = (CK_KEY_TYPE)-1,
    .prepare_mech_param_from_opts =
                            p11sak_dh_pkcs_prepare_mech_param_from_opts,
};

static const struct p11tool_enum_value p11sak_ecdh_kdf_algs[] = {
    { .value = "NULL", .args = NULL, .private = { .num = CKD_NULL}, },
    { .value = "SHA-1", .args = NULL, .private = { .num = CKD_SHA1_KDF }, },
    { .value = "SHA224", .args = NULL,
      .private = { .num = CKD_SHA224_KDF }, },
    { .value = "SHA256", .args = NULL,
      .private = { .num = CKD_SHA256_KDF }, },
    { .value = "SHA384", .args = NULL,
      .private = { .num = CKD_SHA384_KDF }, },
    { .value = "SHA512", .args = NULL,
      .private = { .num = CKD_SHA512_KDF }, },
    { .value = "SHA3-224", .args = NULL,
      .private = { .num = CKD_SHA3_224_KDF }, },
    { .value = "SHA3-256", .args = NULL,
      .private = { .num = CKD_SHA3_256_KDF }, },
    { .value = "SHA3-384", .args = NULL,
      .private = { .num = CKD_SHA3_384_KDF }, },
    { .value = "SHA3-512", .args = NULL,
      .private = { .num = CKD_SHA3_512_KDF }, },
    { .value = "SHA-1-SP800", .args = NULL,
      .private = { .num = CKD_SHA1_KDF_SP800 }, },
    { .value = "SHA224-SP800", .args = NULL,
      .private = { .num = CKD_SHA224_KDF_SP800 }, },
    { .value = "SHA256-SP800", .args = NULL,
      .private = { .num = CKD_SHA256_KDF_SP800 }, },
    { .value = "SHA384-SP800", .args = NULL,
      .private = { .num = CKD_SHA384_KDF_SP800 }, },
    { .value = "SHA512-SP800", .args = NULL,
      .private = { .num = CKD_SHA512_KDF_SP800 }, },
    { .value = "SHA3-224-SP800", .args = NULL,
      .private = { .num = CKD_SHA3_224_KDF_SP800 }, },
    { .value = "SHA3-256-SP800", .args = NULL,
      .private = { .num = CKD_SHA3_256_KDF_SP800 }, },
    { .value = "SHA3-384-SP800", .args = NULL,
      .private = { .num = CKD_SHA3_384_KDF_SP800 }, },
    { .value = "SHA3-512-SP800", .args = NULL,
      .private = { .num = CKD_SHA3_512_KDF_SP800 }, },
    { .value = NULL, },
};

static const struct p11tool_opt p11sak_derive_mech_ecdh_opts[] = {
    { .short_opt = 0, .long_opt = "pub-key-file", .required = true,
      .long_opt_val = OPT_DERIVE_PUB_KEY,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_file, .name = "FILENAME", },
      .description = "The file name of an OpenSSL PEM file that contains "
                     "the foreign public key to be used with the ECDH key "
                     "derivation." , },
    { .short_opt = 0, .long_opt = "kdf-alg", .required = false,
      .long_opt_val = OPT_ECDH_KDF_ALG,
      .arg =  { .type = ARG_TYPE_ENUM, .required = true, .name = "KDF-ALG",
                .value.enum_value = &opt_ecdh_kdf_alg,
                .enum_values = p11sak_ecdh_kdf_algs, },
      .description = "The key derivation function algorithm used on the "
                     "shared secret value. The default is SHA256. Possible "
                     "algorithms are:", },
    { .short_opt = 0, .long_opt = "shared-data", .required = false,
      .long_opt_val = OPT_ECDH_SHARED_DATA,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .name = "SHARED-DATA",
                .value.string = &opt_ecdh_shared_data, },
      .description = "Some data shared between the two parties. Specify a "
                     "hex string (not prefixed with 0x) of any number of "
                     "bytes. The default is that no shared data is used.", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_opt p11sak_derive_mech_dh_pkcs_opts[] = {
    { .short_opt = 0, .long_opt = "pub-key-file", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_file, .name = "FILENAME", },
      .description = "The file name of an OpenSSL PEM file that contains "
                     "the foreign public key to be used with the DH-PKCS "
                     "key derivation." , },
    { .short_opt = 0, .long_opt = NULL, },
};

const struct p11tool_enum_value p11sak_derive_mech_values[] = {
    { .value = "sha1", .args = NULL, .opts = NULL,
      .description = "Use mechanism CKM_SHA1_KEY_DERIVATION for key "
                     "derivation. Derives a secret key by digesting the "
                     "value of the base secret key with SHA-1.",
      .private = { .ptr = &p11sak_derive_mech_sha1, }, },
    { .value = "sha224", .args = NULL, .opts = NULL,
      .description = "Use mechanism CKM_SHA224_KEY_DERIVATION for key "
                     "derivation. Derives a secret key by digesting the "
                     "value of the base secret key with SHA224.",
      .private = { .ptr = &p11sak_derive_mech_sha224, }, },
    { .value = "sha256", .args = NULL, .opts = NULL,
      .description = "Use mechanism CKM_SHA256_KEY_DERIVATION for key "
                     "derivation. Derives a secret key by digesting the "
                     "value of the base secret key with SHA256.",
      .private = { .ptr = &p11sak_derive_mech_sha256, }, },
    { .value = "sha384", .args = NULL, .opts = NULL,
      .description = "Use mechanism CKM_SHA384_KEY_DERIVATION for key "
                     "derivation. Derives a secret key by digesting the "
                     "value of the base secret key with SHA384.",
      .private = { .ptr = &p11sak_derive_mech_sha384, }, },
    { .value = "sha512", .args = NULL, .opts = NULL,
      .description = "Use mechanism CKM_SHA512_KEY_DERIVATION for key "
                     "derivation. Derives a secret key by digesting the "
                     "value of the base secret key with SHA512.",
      .private = { .ptr = &p11sak_derive_mech_sha512, }, },
    { .value = "sha3-224", .args = NULL, .opts = NULL,
      .description = "Use mechanism CKM_SHA3_224_KEY_DERIVATION for key "
                     "derivation. Derives a secret key by digesting the "
                     "value of the base secret key with SHA3_224.",
      .private = { .ptr = &p11sak_derive_mech_sha3_224, }, },
    { .value = "sha3-256", .args = NULL, .opts = NULL,
      .description = "Use mechanism CKM_SHA3_256_KEY_DERIVATION for key "
                     "derivation. Derives a secret key by digesting the "
                     "value of the base secret key with SHA3_256.",
      .private = { .ptr = &p11sak_derive_mech_sha3_256, }, },
    { .value = "sha3-384", .args = NULL, .opts = NULL,
      .description = "Use mechanism CKM_SHA3_384_KEY_DERIVATION for key "
                     "derivation. Derives a secret key by digesting the "
                     "value of the base secret key with SHA3_384.",
      .private = { .ptr = &p11sak_derive_mech_sha3_384, }, },
    { .value = "sha3-512", .args = NULL, .opts = NULL,
      .description = "Use mechanism CKM_SHA3_512_KEY_DERIVATION for key "
                     "derivation. Derives a secret key by digesting the "
                     "value of the base secret key with SHA3_512.",
      .private = { .ptr = &p11sak_derive_mech_sha3_512, }, },
    { .value = "shake128", .args = NULL, .opts = NULL,
      .description = "Use mechanism CKM_SHAKE128_KEY_DERIVATION for key "
                     "derivation. Derives a secret key by digesting the "
                     "value of the base secret key with SHAKE128.",
      .private = { .ptr = &p11sak_derive_mech_shake128, }, },
    { .value = "shake256", .args = NULL, .opts = NULL,
      .description = "Use mechanism CKM_SHAKE256_KEY_DERIVATION for key "
                     "derivation. Derives a secret key by digesting the "
                     "value of the base secret key with SHAKE256.",
      .private = { .ptr = &p11sak_derive_mech_shake256, }, },
    { .value = "ecdh", .args = NULL,
      .opts = p11sak_derive_mech_ecdh_opts,
      .description = "Use mechanism CKM_ECDH1_DERIVE for key derivation. "
                    "Derivation is done with an EC or EC-Montgomery private "
                    "base key.",
      .private = { .ptr = &p11sak_derive_mech_ecdh, }, },
    { .value = "ecdh-cof", .args = NULL,
      .opts = p11sak_derive_mech_ecdh_opts,
      .description = "Use mechanism CKM_ECDH1_COFACTOR_DERIVE for key "
                     "derivation. Derivation is done with an EC private "
                     "base key.",
      .private = { .ptr = &p11sak_derive_mech_ecdh_cof, }, },
    { .value = "dh-pkcs", .args = NULL,
      .opts = p11sak_derive_mech_dh_pkcs_opts,
      .description = "Use mechanism CKM_DH_PKCS_DERIVE for key derivation. "
                     "Derivation is done with an DH private base key.",
      .private = { .ptr = &p11sak_derive_mech_dh_pkcs, }, },
    { .value = NULL, },
};

static CK_RV p11sak_get_ec_pub_key_value(EVP_PKEY *pkey, CK_BYTE **pub_key,
                                         CK_ULONG *pub_key_len)
{
    size_t buf_len = 0, point_len = 0;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    const EC_KEY *ec;
    const EC_GROUP *ec_group = NULL;
    const EC_POINT *ec_point = NULL;
    unsigned char *point = NULL;
#endif

#if OPENSSL_VERSION_PREREQ(3, 0)
    if (EVP_PKEY_get_octet_string_param(pkey,
                                        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        NULL, 0, &point_len) != 1) {
        warnx("Failed to get the EC public key value");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    /* Leave 3 bytes space for DER encoding of OCTET-STRING */
    buf_len = 3 + point_len;
    *pub_key = malloc(buf_len);
    if (*pub_key == NULL) {
        warnx("Failed to allocate a buffer for the EC public key");
        return CKR_HOST_MEMORY;
    }

    if (EVP_PKEY_get_octet_string_param(pkey,
                                        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        (*pub_key) + 3, buf_len - 3,
                                        &point_len) != 1) {
        warnx("Failed to get the EC public key value");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        free(*pub_key);
        *pub_key = NULL;
        return CKR_FUNCTION_FAILED;
    }
#else
    ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (ec == NULL) {
        warnx("Failed to get the EC key.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    ec_group = EC_KEY_get0_group(ec);
    ec_point = EC_KEY_get0_public_key(ec);
    if (ec_group == NULL || ec_point == NULL) {
        warnx("Failed to get the EC key.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    point_len = EC_POINT_point2oct(ec_group, ec_point,
                                   POINT_CONVERSION_UNCOMPRESSED,
                                   NULL, 0, NULL);
    if (point_len == 0) {
        warnx("EC_POINT_point2oct failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    /* Leave 3 bytes space for DER encoding of OCTET-STRING */
    buf_len = 3 + point_len;
    *pub_key = malloc(buf_len);
    if (*pub_key == NULL) {
        warnx("Failed to allocate buffer for EC point.");
        return CKR_HOST_MEMORY;
    }

    if (EC_POINT_point2oct(ec_group, ec_point,
                           POINT_CONVERSION_UNCOMPRESSED,
                           (*pub_key) + 3, point_len, NULL) != point_len) {
        warnx("EC_POINT_point2oct failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        free(*pub_key);
        *pub_key = NULL;
        return CKR_FUNCTION_FAILED;
    }
#endif

    if (point_len >= 0x0100) {
        warnx("EC point is too long.");
        free(*pub_key);
        *pub_key = NULL;
        return CKR_FUNCTION_FAILED;
    }

    (*pub_key)[0] = 0x04; /* OCTET-STRING */
    (*pub_key)[1] = 0x81; /* 1 byte length field */
    (*pub_key)[2] = point_len & 0xff;

    *pub_key_len = 3 + point_len;

    return CKR_OK;
}

#if OPENSSL_VERSION_PREREQ(3, 0)
static CK_RV p11sak_get_ecx_pub_key_value(EVP_PKEY *pkey, CK_BYTE **pub_key,
                                          CK_ULONG *pub_key_len)
{
    size_t buf_len = 0;

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        NULL, 0, &buf_len) != 1) {
        warnx("Failed to get the EC-Montgomery public key value");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    *pub_key = malloc(buf_len);
    if (*pub_key == NULL) {
        warnx("Failed to allocate a buffer for the EC-Montgomery public key");
        return CKR_HOST_MEMORY;
    }

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        *pub_key, buf_len, &buf_len) != 1) {
        warnx("Failed to get the EC-Montgomery public key value");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        free(*pub_key);
        *pub_key = NULL;
        return CKR_FUNCTION_FAILED;
    }

    *pub_key_len = buf_len;

    return CKR_OK;
}
#endif

static CK_RV p11sak_get_dh_pub_key_value(EVP_PKEY *pkey, CK_BYTE **pub_key,
                                         CK_ULONG *pub_key_len)
{
#if OPENSSL_VERSION_PREREQ(3, 0)
    BIGNUM *bn_pub = NULL;
#else
    const DH *dh;
    const BIGNUM *bn_pub = NULL;
#endif
    size_t buf_len = 0;

#if OPENSSL_VERSION_PREREQ(3, 0)
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &bn_pub) != 1) {
        warnx("Failed to get the DH public key value");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }
#else
    dh = EVP_PKEY_get0_DH(pkey);
    if (dh == NULL) {
        warnx("Failed to get the DH key.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    DH_get0_key(dh, &bn_pub, NULL);
    if (bn_pub == NULL) {
        warnx("Failed to get the DH key.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }
#endif

    buf_len = BN_num_bytes(bn_pub);
    *pub_key = malloc(buf_len);
    if (*pub_key == NULL) {
        warnx("Failed to allocate a buffer for the DH public key");
        return CKR_HOST_MEMORY;
    }

    if (BN_bn2binpad(bn_pub, *pub_key, buf_len) <= 0) {
        warnx("Failed to get a bignum.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        free(*pub_key);
        *pub_key = NULL;
        return CKR_FUNCTION_FAILED;
    }

    *pub_key_len = buf_len;

    return CKR_OK;
}

static CK_RV p11sak_read_pub_key(const char *filename,
                                 CK_KEY_TYPE expected_type,
                                 CK_KEY_TYPE addl_expected_type,
                                 CK_BYTE **pub_key, CK_ULONG *pub_key_len)
{
    struct p11tool_pem_password_cb_data cb_data = { 0 };
    EVP_PKEY *pkey = NULL;
    BIO *bio;
    int type;
    CK_KEY_TYPE key_type = (CK_KEY_TYPE)-1;
    CK_RV rc = CKR_OK;

    bio = BIO_new_file(filename, "r");
    if (bio == NULL) {
        warnx("Failed to open PEM file '%s'.", filename);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    pkey = PEM_read_bio_PUBKEY(bio, NULL, p11tool_pem_password_cb, &cb_data);
    if (pkey == NULL) {
        warnx("Failed to read PEM file '%s'.", filename);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    type = EVP_PKEY_base_id(pkey);

    switch (type) {
    case EVP_PKEY_EC:
        key_type = CKK_EC;
        break;
#if OPENSSL_VERSION_PREREQ(3, 0)
    case EVP_PKEY_X25519:
    case EVP_PKEY_X448:
        key_type = CKK_EC_MONTGOMERY;
        break;
#endif
    case EVP_PKEY_DH:
        key_type = CKK_DH;
        break;
    default:
        warnx("PEM file '%s' contains a public key of the wrong type",
              filename);
        return CKR_ARGUMENTS_BAD;
    }

    if (expected_type != key_type && addl_expected_type != key_type) {
        warnx("PEM file '%s' contains a public key of the wrong type",
              filename);
        return CKR_ARGUMENTS_BAD;
    }

    switch (type) {
    case EVP_PKEY_EC:
        rc = p11sak_get_ec_pub_key_value(pkey, pub_key, pub_key_len);
        break;
#if OPENSSL_VERSION_PREREQ(3, 0)
    case EVP_PKEY_X25519:
    case EVP_PKEY_X448:
        rc = p11sak_get_ecx_pub_key_value(pkey, pub_key, pub_key_len);
        break;
#endif
    case EVP_PKEY_DH:
        rc = p11sak_get_dh_pub_key_value(pkey, pub_key, pub_key_len);
        break;
    default:
        return CKR_ARGUMENTS_BAD;
    }

    if (rc != CKR_OK) {
        warnx("Failed to get public key value from PEM file '%s'", filename);
        goto done;
    }

done:
    BIO_free(bio);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    return rc;
}

static CK_RV p11sak_ecdh_prepare_mech_param_from_opts(
                              const struct p11sak_derive_mech *derive_mech,
                              CK_MECHANISM *mech)
{

    CK_ECDH1_DERIVE_PARAMS *ecdh_param = mech->pParameter;
    CK_RV rc;

    rc = p11sak_read_pub_key(opt_file, derive_mech->base_key_type,
                             derive_mech->addl_base_key_type,
                             &ecdh_param->pPublicData,
                             &ecdh_param->ulPublicDataLen);
    if (rc != CKR_OK)
        return rc;

    if (opt_ecdh_kdf_alg != NULL)
        ecdh_param->kdf = opt_ecdh_kdf_alg->private.num;
    else
        ecdh_param->kdf = CKD_SHA256_KDF;

    if (opt_ecdh_shared_data != NULL) {
        rc = p11tool_parse_hex(opt_ecdh_shared_data,
                               (CK_BYTE **)&ecdh_param->pSharedData,
                               &ecdh_param->ulSharedDataLen);
        if (rc != CKR_OK) {
            p11sak_ecdh_cleanup_mech_param(derive_mech, mech);
            return rc;
        }
    } else {
        ecdh_param->pSharedData = NULL;
        ecdh_param->ulSharedDataLen = 0;
    }

    return CKR_OK;
}

static void p11sak_ecdh_cleanup_mech_param(
                              const struct p11sak_derive_mech *derive_mech,
                              CK_MECHANISM *mech)
{
    CK_ECDH1_DERIVE_PARAMS *ecdh_param = mech->pParameter;

    UNUSED(derive_mech);

    if (ecdh_param->pPublicData != NULL)
        free(ecdh_param->pPublicData);
    if (ecdh_param->pSharedData != NULL)
        free(ecdh_param->pSharedData);
}

static CK_RV p11sak_dh_pkcs_prepare_mech_param_from_opts(
                              const struct p11sak_derive_mech *derive_mech,
                              CK_MECHANISM *mech)
{
    return p11sak_read_pub_key(opt_file, derive_mech->base_key_type,
                               derive_mech->addl_base_key_type,
                               (CK_BYTE**)&mech->pParameter,
                               &mech->ulParameterLen);
}

static CK_RV prepare_mech_param(const struct p11sak_derive_mech *derive_mech,
                                CK_MECHANISM *mech, void **mech_param)
{
    CK_RV rc = CKR_OK;

    if (derive_mech->mech_param_size > 0) {
        *mech_param = calloc(1, derive_mech->mech_param_size);
        if (*mech_param == NULL) {
            warnx("Failed to allocate memory for mechanism parameter");
            return CKR_HOST_MEMORY;
        }
    }

    mech->mechanism = derive_mech->mech;
    mech->ulParameterLen = derive_mech->mech_param_size;
    mech->pParameter = *mech_param;

    if (derive_mech->prepare_mech_param_from_opts != NULL) {
        rc = derive_mech->prepare_mech_param_from_opts(derive_mech, mech);
        if (rc != CKR_OK) {
            free(*mech_param);
            *mech_param = NULL;
        }

        if (derive_mech->mech_param_size == 0 &&
            mech->ulParameterLen != 0 &&
            mech->pParameter != NULL)
            *mech_param = mech->pParameter;
    }

    return rc;
}

static void cleanup_mech_param(const struct p11sak_derive_mech *derive_mech,
                               CK_MECHANISM *mech, void *mech_param)
{
    if (mech_param == NULL)
        return;

    if (derive_mech->cleanup_mech_param != NULL)
        derive_mech->cleanup_mech_param(derive_mech, mech);

    free(mech_param);
}

static CK_RV p11sak_derive_key_perform(
                                const struct p11sak_derive_mech *derive_mech,
                                const struct p11tool_objtype *derived_keytype,
                                CK_OBJECT_HANDLE base_key,
                                CK_MECHANISM *mech)
{
    CK_ATTRIBUTE *attrs = NULL;
    CK_ULONG num_attrs = 0;
    CK_OBJECT_HANDLE key_handle;
    void *private = NULL;
    CK_RV rc;

    if (derived_keytype->keygen_prepare != NULL) {
        rc = derived_keytype->keygen_prepare(derived_keytype, &private);
        if (rc != CKR_OK) {
            warnx("Failed to prepare key type %s: 0x%lX: %s",
                  derived_keytype->name, rc, p11_get_ckr(rc));
            return rc;
        }
    }

    rc = p11tool_add_attribute(CKA_CLASS, &derive_mech->derived_class,
                               sizeof(derive_mech->derived_class),
                               &attrs, &num_attrs);
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_add_attribute(CKA_KEY_TYPE, &derived_keytype->type,
                               sizeof(derived_keytype->type),
                               &attrs, &num_attrs);
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_add_attributes(derived_keytype, p11sak_bool_attrs,
                                &attrs, &num_attrs,
                                opt_label, opt_attr, opt_id,
                                CK_TRUE, opt_so,
                                derive_mech->derived_class == CKO_PRIVATE_KEY ?
                                    derived_keytype->keygen_add_private_attrs :
                                    derived_keytype->keygen_add_secret_attrs,
                                private,
                                derive_mech->derived_class == CKO_PRIVATE_KEY ?
                                    p11tool_private_attr_applicable :
                                    p11tool_secret_attr_applicable);
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_pkcs11_funcs->C_DeriveKey(p11tool_pkcs11_session,
                                           mech, base_key,
                                           attrs, num_attrs,
                                           &key_handle);
    if (rc != CKR_OK) {
        warnx("Failed to derive a %s key with derive mechanism %s: 0x%lX: %s",
              derived_keytype->name, derive_mech->name, rc, p11_get_ckr(rc));
        goto done;
    }

    printf("Successfully derived a %s key with label \"%s\".\n",
           derived_keytype->name, opt_label);

done:
    p11tool_free_attributes(attrs, num_attrs);

    if (derived_keytype->keygen_cleanup != NULL)
        derived_keytype->keygen_cleanup(derived_keytype, private);

    return rc;
}

CK_RV p11sak_derive_key(void)
{
    const struct p11tool_objtype *derived_keytype = NULL;
    const struct p11sak_derive_mech *derive_mech =
                                            opt_derive_mech->private.ptr;
    CK_OBJECT_HANDLE base_key_handle = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { 0 };
    void *mech_param = NULL;
    CK_RV rc;

    if (opt_base_label == NULL && opt_base_id == NULL) {
        warnx("At least one of the following options must be specified:");
        warnx("'-B'/'--base-key-label',  or '-k'/'--base-key-id'");
        return CKR_ARGUMENTS_BAD;
    }

    if (derive_mech->derived_key_type != (CK_KEY_TYPE)-1)
        derived_keytype = find_keytype(derive_mech->derived_key_type);
    if (derived_keytype == NULL && opt_keytype != NULL)
        derived_keytype = opt_keytype->private.ptr;

    if (derive_mech->derived_key_type != (CK_KEY_TYPE)-1 &&
        derived_keytype != NULL) {
        warnx("The derive mechanism derives keys of a pre-defined type, "
              "argument 'KEYTYPE' is ignored.");
    }
    if (derived_keytype == NULL) {
        warnx("Argument 'KEYTYPE' is required.");
        return CKR_ARGUMENTS_BAD;
    }

    if (derived_keytype->is_asymmetric &&
        derive_mech->derived_class == CKO_SECRET_KEY) {
        warnx("The derive mechanism can only derive symmetric keys, but the "
              "specified key type is an asymmetric key type.");
        return CKR_ARGUMENTS_BAD;
    }
    if (!derived_keytype->is_asymmetric &&
        derive_mech->derived_class != CKO_SECRET_KEY) {
        warnx("The derive mechanism can only derive asymmetric keys, but the "
              "specified key type is a symmetric key type.");
        return CKR_ARGUMENTS_BAD;
    }

    rc = p11tool_check_derive_mech_supported(opt_slot, derive_mech->mech);
    if (rc != CKR_OK)
        return rc;

    rc = p11tool_select_key(derive_mech->base_class,
                            derive_mech->base_key_type,
                            derive_mech->addl_base_key_type,
                            opt_base_label, opt_base_id, opt_force,
                            "base key", "base key",
                            &base_key_handle);
    if (rc != CKR_OK)
        goto done;

    rc = prepare_mech_param(derive_mech, &mech, &mech_param);
    if (rc != CKR_OK)
        goto done;

    rc = p11sak_derive_key_perform(derive_mech, derived_keytype,
                                   base_key_handle, &mech);
    if (rc != CKR_OK)
        goto done;

done:
    cleanup_mech_param(derive_mech, &mech, mech_param);

    return rc;
}

void print_derive_key_help(void)
{
    const struct p11tool_attr *attr;

    printf("ATTRIBUTES:\n");
    for (attr = p11sak_bool_attrs; attr->name != NULL; attr++) {
        if (attr->settable)
            printf("    '%c':   %s%s\n", attr->letter, attr->name,
                   attr->so_set_to_true ?
                           " (can be set to TRUE by SO only)" : "");
    }
    printf("\n");

    printf("    ");
    p11tool_print_indented("An uppercase letter sets the corresponding "
                           "attribute to CK_TRUE, a lower case letter to "
                           "CK_FALSE.\n"
                           "If an attribute is not set explicitly, its "
                           "default value is used.\n"
                           "Not all attributes may be accepted for all key "
                           "types.\n"
                           "Attribute CKA_TOKEN is always set to CK_TRUE.",
                           4);
    printf("\n");
}
