/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2023
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <regex.h>
#include <dirent.h>
#include <libgen.h>

#define OCK_NO_EP11_DEFINES
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "errno.h"
#include "tok_specific.h"
#include "tok_struct.h"
#include "stdll.h"
#include "attributes.h"
#include "trace.h"
#include "ock_syslog.h"
#include "ec_defs.h"
#include "pqc_defs.h"
#include "p11util.h"
#include "events.h"
#include "cfgparser.h"
#include "configuration.h"
#include "hsm_mk_change.h"
#include "constant_time.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <dlfcn.h>
#include <lber.h>
#include <grp.h>
#include <sys/time.h>
#include <time.h>
#include <err.h>

#ifdef DEBUG
#include <ctype.h>
#endif

#include <openssl/crypto.h>
#include <openssl/ec.h>

#include "ep11_specific.h"
#ifndef NO_PKEY
#include "pkey_utils.h"
#endif

CK_RV ep11tok_get_mechanism_list(STDLL_TokData_t * tokdata,
                                 CK_MECHANISM_TYPE_PTR mlist,
                                 CK_ULONG_PTR count);
CK_RV ep11tok_get_mechanism_info(STDLL_TokData_t * tokdata,
                                 CK_MECHANISM_TYPE type,
                                 CK_MECHANISM_INFO_PTR pInfo);
CK_RV ep11tok_is_mechanism_supported(STDLL_TokData_t *tokdata,
                                     CK_MECHANISM_TYPE type);
CK_RV ep11tok_is_mechanism_supported_ex(STDLL_TokData_t *tokdata,
                                        CK_MECHANISM_PTR mech);
static CK_RV ep11tok_pkcs11_mech_translate(STDLL_TokData_t *tokdata,
                                           CK_MECHANISM_TYPE type,
                                           CK_MECHANISM_TYPE* ep11_type);
static CK_RV ep11tok_pkcs11_mgf_translate(STDLL_TokData_t *tokdata,
                                          CK_RSA_PKCS_MGF_TYPE mgf,
                                          CK_RSA_PKCS_MGF_TYPE* ep11_mgf);
static CK_RV ep11tok_pkcs11_keytype_translate(STDLL_TokData_t *tokdata,
                                              CK_KEY_TYPE keytype,
                                              CK_KEY_TYPE* ep11_keytype);

static m_GenerateRandom_t dll_m_GenerateRandom;
static m_SeedRandom_t dll_m_SeedRandom;

static m_Digest_t dll_m_Digest;
static m_DigestInit_t dll_m_DigestInit;
static m_DigestUpdate_t dll_m_DigestUpdate;
static m_DigestKey_t dll_m_DigestKey;
static m_DigestFinal_t dll_m_DigestFinal;
m_DigestSingle_t dll_m_DigestSingle;

static m_Encrypt_t dll_m_Encrypt;
static m_EncryptInit_t dll_m_EncryptInit;
static m_EncryptUpdate_t dll_m_EncryptUpdate;
static m_EncryptFinal_t dll_m_EncryptFinal;
static m_EncryptSingle_t dll_m_EncryptSingle;

static m_Decrypt_t dll_m_Decrypt;
static m_DecryptInit_t dll_m_DecryptInit;
static m_DecryptUpdate_t dll_m_DecryptUpdate;
static m_DecryptFinal_t dll_m_DecryptFinal;
static m_DecryptSingle_t dll_m_DecryptSingle;

static m_ReencryptSingle_t dll_m_ReencryptSingle;
static m_GenerateKey_t dll_m_GenerateKey;
static m_GenerateKeyPair_t dll_m_GenerateKeyPair;

static m_Sign_t dll_m_Sign;
static m_SignInit_t dll_m_SignInit;
static m_SignUpdate_t dll_m_SignUpdate;
static m_SignFinal_t dll_m_SignFinal;
static m_SignSingle_t dll_m_SignSingle;

static m_Verify_t dll_m_Verify;
static m_VerifyInit_t dll_m_VerifyInit;
static m_VerifyUpdate_t dll_m_VerifyUpdate;
static m_VerifyFinal_t dll_m_VerifyFinal;
static m_VerifySingle_t dll_m_VerifySingle;

static m_WrapKey_t dll_m_WrapKey;
static m_UnwrapKey_t dll_m_UnwrapKey;
static m_DeriveKey_t dll_m_DeriveKey;

static m_GetMechanismList_t dll_m_GetMechanismList;
static m_GetMechanismInfo_t dll_m_GetMechanismInfo;
static m_GetAttributeValue_t dll_m_GetAttributeValue;
static m_SetAttributeValue_t dll_m_SetAttributeValue;

m_Login_t dll_m_Login;
m_Logout_t dll_m_Logout;
m_LoginExtended_t dll_m_LoginExtended;
m_LogoutExtended_t dll_m_LogoutExtended;
m_admin_t dll_m_admin;
static m_add_backend_t dll_m_add_backend;
static m_init_t dll_m_init;
static m_shutdown_t dll_m_shutdown;
static m_add_module_t dll_m_add_module;
static m_rm_module_t dll_m_rm_module;

xcpa_cmdblock_t dll_xcpa_cmdblock;
static xcpa_queryblock_t dll_xcpa_queryblock;
xcpa_internal_rv_t dll_xcpa_internal_rv;

m_get_xcp_info_t dll_m_get_xcp_info;

const char manuf[] = "IBM";
const char model[] = "EP11";
const char descr[] = "IBM EP11 token";
const char label[] = "ep11tok";

static CK_BBOOL ep11tok_ec_curve_supported2(STDLL_TokData_t *tokdata,
                                            TEMPLATE *template,
                                            const struct _ec **curve);

static void free_cp_config(cp_config_t * cp);
#ifdef DEBUG
static const char *ep11_get_cp(unsigned int cp);
#endif
static CK_ULONG ep11_get_cp_by_name(const char *name);
static CK_RV check_cps_for_mechanism(STDLL_TokData_t *tokdata,
                                     cp_config_t * cp_config,
                                     CK_MECHANISM_TYPE mech,
                                     unsigned char *cp, size_t cp_len,
                                     size_t max_cp_index);
static CK_RV get_control_points(STDLL_TokData_t * tokdata,
                                unsigned char *cp, size_t * cp_len,
                                size_t *max_cp_index);

static CK_RV ep11tok_get_ep11_library_version(CK_VERSION *lib_version);
static void free_card_versions(ep11_card_version_t *card_version);
static int check_card_version(STDLL_TokData_t *tokdata, CK_ULONG card_type,
                              const CK_VERSION *ep11_lib_version,
                              const CK_VERSION *firmware_version,
                              const CK_ULONG *firmware_API_version);
static int compare_ck_version(const CK_VERSION *v1, const CK_VERSION *v2);

static int check_required_versions(STDLL_TokData_t *tokdata,
                                   const version_req_t req[],
                                   CK_ULONG num_req);

static CK_RV h_opaque_2_blob(STDLL_TokData_t * tokdata, CK_OBJECT_HANDLE handle,
                             CK_BYTE ** blob, size_t * blob_len,
                             OBJECT ** kobj, OBJ_LOCK_TYPE lock_type);

static CK_RV obj_opaque_2_blob(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                               CK_BYTE **blob, size_t *blobsize);
static CK_RV obj_opaque_2_reenc_blob(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                                     CK_BYTE **blob, size_t *blobsize);

static CK_RV file_fgets(const char *fname, char *buf, size_t buflen);

/* EP11 Firmware levels that contain the HMAC min/max keysize fix */
static const CK_VERSION cex4p_hmac_fix = { .major = 4, .minor = 20 };
static const CK_VERSION cex5p_hmac_fix = { .major = 6, .minor = 3 };
static const CK_VERSION cex6p_hmac_fix = { .major = 6, .minor = 9 };

static const version_req_t hmac_req_versions[] = {
        { .card_type = 4, .min_firmware_version = &cex4p_hmac_fix },
        { .card_type = 5, .min_firmware_version = &cex5p_hmac_fix },
        { .card_type = 6, .min_firmware_version = &cex6p_hmac_fix }
};
#define NUM_HMAC_REQ (sizeof(hmac_req_versions) / sizeof(version_req_t))

static const CK_VERSION cex7p_ibm_sha3_support = { .major = 7, .minor = 11 };

static const version_req_t ibm_sha3_req_versions[] = {
        { .card_type = 7, .min_firmware_version = &cex7p_ibm_sha3_support }
};
#define NUM_IBM_SHA3_REQ (sizeof(ibm_sha3_req_versions) / sizeof(version_req_t))

static const CK_VERSION cex7p_cmac_support = { .major = 7, .minor = 11 };

static const version_req_t cmac_req_versions[] = {
        { .card_type = 7, .min_firmware_version = &cex7p_cmac_support }
};
#define NUM_CMAC_REQ (sizeof(cmac_req_versions) / sizeof(version_req_t))

static const CK_VERSION cex7p_oaep_sha2_support = { .major = 7, .minor = 13 };

static const version_req_t oaep_sha2_req_versions[] = {
        { .card_type = 7, .min_firmware_version = &cex7p_oaep_sha2_support }
};
#define NUM_OAEP_SHA2_REQ (sizeof(oaep_sha2_req_versions) / sizeof(version_req_t))

static const CK_VERSION cex6p_oaep_support = { .major = 6, .minor = 7 };

static const version_req_t oaep_req_versions[] = {
        { .card_type = 6, .min_firmware_version = &cex6p_oaep_support }
};
#define NUM_OAEP_REQ (sizeof(oaep_req_versions) / sizeof(version_req_t))

static const CK_VERSION cex7p_edwards_support = { .major = 7, .minor = 15 };

static const version_req_t edwards_req_versions[] = {
        { .card_type = 7, .min_firmware_version = &cex7p_edwards_support }
};
#define NUM_EDWARDS_REQ (sizeof(edwards_req_versions) / sizeof(version_req_t))

static const CK_VERSION ibm_cex7p_dilithium_support = { .major = 7, .minor = 15 };

static const version_req_t ibm_dilithium_req_versions[] = {
        { .card_type = 7, .min_firmware_version = &ibm_cex7p_dilithium_support }
};
#define NUM_DILITHIUM_REQ (sizeof(ibm_dilithium_req_versions) / sizeof(version_req_t))

static const CK_VERSION ibm_cex8p_kyber_support = { .major = 8, .minor = 9 };

static const version_req_t ibm_kyber_req_versions[] = {
        { .card_type = 8, .min_firmware_version = &ibm_cex8p_kyber_support }
};
#define NUM_KYBER_REQ (sizeof(ibm_kyber_req_versions) / sizeof(version_req_t))

static const CK_VERSION ibm_cex6p_reencrypt_single_support =
                                                    { .major = 6, .minor = 15 };
static const CK_VERSION ibm_cex7p_reencrypt_single_support =
                                                    { .major = 7, .minor = 21 };

static const version_req_t reencrypt_single_req_versions[] = {
        { .card_type = 6, .min_firmware_version =
                                        &ibm_cex6p_reencrypt_single_support },
        { .card_type = 7, .min_firmware_version =
                                        &ibm_cex7p_reencrypt_single_support }
};
#define NUM_REENCRYPT_SINGLE_REQ (sizeof(reencrypt_single_req_versions) / \
                                                sizeof(version_req_t))

#ifndef NO_PKEY
static const CK_VERSION ibm_cex7p_cpacf_wrap_support = { .major = 7, .minor = 15 };
static const version_req_t ibm_cpacf_wrap_req_versions[] = {
        { .card_type = 7, .min_firmware_version = &ibm_cex7p_cpacf_wrap_support }
};
#define NUM_CPACF_WRAP_REQ (sizeof(ibm_cpacf_wrap_req_versions) / sizeof(version_req_t))
#endif /* NO_PKEY */

static const CK_ULONG ibm_cex_ab_ecdh_api_version = 3;
static const version_req_t ibm_ab_ecdh_req_versions[] = {
        { .card_type = 7, .min_firmware_API_version = &ibm_cex_ab_ecdh_api_version}
};
#define NUM_AB_ECDH_REQ (sizeof(ibm_ab_ecdh_req_versions) / sizeof(version_req_t))

static const CK_VERSION ibm_cex6p_btc_support = { .major = 6, .minor = 15 };
static const CK_VERSION ibm_cex7p_btc_support = { .major = 7, .minor = 21 };

static const version_req_t ibm_btc_req_versions[] = {
        { .card_type = 6, .min_firmware_version = &ibm_cex6p_btc_support },
        { .card_type = 7, .min_firmware_version =  &ibm_cex7p_btc_support }
};
#define NUM_BTC_REQ (sizeof(ibm_btc_req_versions) / sizeof(version_req_t))

static const CK_VERSION ibm_cex6p_ecdsa_other_support =
                                                { .major = 6, .minor = 15 };
static const CK_VERSION ibm_cex7p_ecdsa_other_support =
                                                { .major = 7, .minor = 21 };

static const version_req_t ibm_ecdsa_other_req_versions[] = {
        { .card_type = 6, .min_firmware_version =
                                            &ibm_cex6p_ecdsa_other_support },
        { .card_type = 7, .min_firmware_version =
                                            &ibm_cex7p_ecdsa_other_support }
};
#define NUM_ECDSA_OTHER_REQ (sizeof(ibm_ecdsa_other_req_versions) / \
                                            sizeof(version_req_t))

static CK_RV update_ep11_attrs_from_blob(STDLL_TokData_t *tokdata,
                                         SESSION *session, OBJECT *key_obj,
                                         CK_BBOOL aes_xts);

/* defined in the makefile, ep11 library can run standalone (without HW card),
   crypto algorithms are implemented in software then (no secure key) */


typedef struct const_info {
    unsigned const int code;
    const char *name;
} const_info_t;

#define CONSTINFO(_X) { (_X), (#_X) }

static void trace_attributes(const char *func, const char *heading,
                             CK_ATTRIBUTE_PTR attrs, CK_ULONG num_attrs)
{
    CK_ULONG i;

#ifndef DEBUG
    UNUSED(func);
    UNUSED(heading);
    UNUSED(attrs);
    UNUSED(num_attrs);
#endif

    if (trace.level < TRACE_LEVEL_DEBUG)
        return;

    TRACE_DEBUG("%s: %s\n", func, heading);
    for (i = 0; i < num_attrs; i++) {
        TRACE_DEBUG_DUMPATTR(&attrs[i]);
    }
}

static CK_RV cleanse_attribute(TEMPLATE *template,
                               CK_ATTRIBUTE_TYPE attr_type)
{
    CK_ATTRIBUTE *attr;

    if (template_attribute_get_non_empty(template, attr_type, &attr) != CKR_OK)
        return CKR_FUNCTION_FAILED;

    OPENSSL_cleanse(attr->pValue, attr->ulValueLen);

    return CKR_OK;
}

static CK_RV check_expected_mkvp(STDLL_TokData_t *tokdata, CK_BYTE *blob,
                                 size_t blobsize, CK_BBOOL *new_wk)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_BYTE *wkid;
    CK_RV rc;

    if (new_wk != NULL)
        *new_wk = FALSE;

    rc = ep11tok_extract_blob_info(blob, blobsize, NULL, &wkid, NULL, NULL);
    if (rc != CKR_OK || wkid == NULL) {
        TRACE_ERROR("ep11tok_extract_blob_info failed\n");
        return CKR_FUNCTION_FAILED;
    }

    if (memcmp(wkid, ep11_data->expected_wkvp, XCP_WKID_BYTES) != 0) {
        /* If an MK change operation is active, also allow the new WK */
        if (ep11_data->mk_change_active &&
            memcmp(wkid, ep11_data->new_wkvp, XCP_WKID_BYTES) == 0) {

            TRACE_DEBUG("The key is wrapped by the new WK\n");
            if (new_wk != NULL)
                *new_wk = TRUE;
           return CKR_OK;
        }

        TRACE_ERROR("The key's wrapping key verification pattern does not "
                    "match the expected EP11 wrapping key\n");
        TRACE_DEBUG_DUMP("WKVP of key:   ", wkid, XCP_WKID_BYTES);
        TRACE_DEBUG_DUMP("Expected WKVP: ", (CK_BYTE *)ep11_data->expected_wkvp,
                         XCP_WKID_BYTES);
        OCK_SYSLOG(LOG_ERR, "The key's wrapping key verification pattern does "
                   "not match the expected EP11 wrapping key\n");
        return CKR_DEVICE_ERROR;
    }

    return CKR_OK;
}

static CK_BBOOL ep11_pqc_strength_supported(ep11_target_info_t *target_info,
                                            CK_MECHANISM_TYPE mech,
                                            const struct pqc_oid *oid)
{
    CK_ULONG strength;

    switch (mech) {
    case CKM_IBM_DILITHIUM:
        switch (oid->keyform) {
        case CK_IBM_DILITHIUM_KEYFORM_ROUND2_65:
            strength = XCP_PQC_S_DILITHIUM_R2_65;
            break;
        case CK_IBM_DILITHIUM_KEYFORM_ROUND2_87:
            strength = XCP_PQC_S_DILITHIUM_R2_87;
            break;
        case CK_IBM_DILITHIUM_KEYFORM_ROUND3_44:
            strength = XCP_PQC_S_DILITHIUM_R3_44;
            break;
        case CK_IBM_DILITHIUM_KEYFORM_ROUND3_65:
            strength = XCP_PQC_S_DILITHIUM_R3_65;
            break;
        case CK_IBM_DILITHIUM_KEYFORM_ROUND3_87:
            strength = XCP_PQC_S_DILITHIUM_R3_87;
            break;
        default:
            TRACE_DEVEL("Dilithium keyform %lu not supported by EP11\n",
                        oid->keyform);
            return FALSE;
        }
        break;
    case CKM_IBM_KYBER:
        switch (oid->keyform) {
        case CK_IBM_KYBER_KEYFORM_ROUND2_768:
            strength = XCP_PQC_S_KYBER_R2_768;
            break;
        case CK_IBM_KYBER_KEYFORM_ROUND2_1024:
            strength = XCP_PQC_S_KYBER_R2_1024;
            break;
        default:
            TRACE_DEVEL("Kyber keyform %lu not supported by EP11\n",
                        oid->keyform);
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }

    if ((target_info->pqc_strength[PQC_BYTE_NO(strength)] &
                                        PQC_BIT_MASK(strength)) == 0) {
        TRACE_DEVEL("Keyform %lu not supported by configured APQNs\n",
                    oid->keyform);
        return FALSE;
    }

    return TRUE;
}

static CK_BBOOL ep11_pqc_obj_strength_supported(ep11_target_info_t *target_info,
                                                CK_MECHANISM_TYPE mech,
                                                OBJECT *key_obj)
{
    const struct pqc_oid *oid;

    switch (mech) {
    case CKM_IBM_DILITHIUM:
    case CKM_IBM_KYBER:
        break;
    default:
        return TRUE;
    }

    oid = ibm_pqc_get_keyform_mode(key_obj->template, mech);
    if (oid == NULL) {
        TRACE_DEVEL("No keyform/mode found in key object\n");
        return FALSE;
    }

    return ep11_pqc_strength_supported(target_info, mech, oid);
}

/**
 * Return true if PKEY_MODE DISABLED is set in the token specific
 * config file, false otherwise.
 */
static CK_BBOOL ep11tok_pkey_option_disabled(STDLL_TokData_t *tokdata)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

    if (ep11_data->pkey_mode == PKEY_MODE_DISABLED)
        return CK_TRUE;

    return CK_FALSE;
}

#ifndef NO_PKEY
/**
 * Callback function used by handle_all_ep11_cards() for creating a protected
 * key via the given APQN (adaper,domain).
 * Note that this function only works with an ep11 host lib v3 or later,
 * because since v3 the target is a numeric value and we can OR the
 * XCP_TGTFL_SET_SCMD flag with it. Before calling this function, it has been
 * checked if running with v3 or later and the CPACF_WRAP mechanism is
 * supported by the hw.
 */
static CK_RV ep11tok_pkey_wrap_handler(uint_32 adapter, uint_32 domain,
                                       void *handler_data)
{
    CK_BYTE iv[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    CK_MECHANISM mech = { CKM_IBM_CPACF_WRAP, &iv, sizeof(iv) };
    pkey_wrap_handler_data_t *data = (pkey_wrap_handler_data_t *) handler_data;
    ep11_private_data_t *ep11_data;
    target_t target = 0;
    CK_RV ret = CKR_OK;
    CK_BBOOL retry = FALSE;
    CK_BYTE *blob;
    CK_ULONG bloblen;
    CK_BBOOL blobretry = FALSE;
    login_logout_data_t lldata;
    const CK_VERSION ver40 = { .major = 4, .minor = 0 };
    uint64_t flags = 0;

    if (data->wrap_was_successful)
        goto done;

    ep11_data = data->tokdata->private_data;

    if (compare_ck_version(&ep11_data->ep11_lib_version, &ver40) <= 0)
        flags |= XCP_MFL_PROBE;

    ret = get_ep11_target_for_apqn(adapter, domain, &target, flags);
    if (ret != CKR_OK)
        goto done;

    /* Create the protected key via CKM_IBM_CPACF_WRAP */
    blob = data->secure_key;
    bloblen = data->secure_key_len;
repeat:
    ret = dll_m_WrapKey(blob, bloblen,
                        NULL, 0, NULL, 0, &mech,
                        data->pkey_buf, data->pkey_buflen_p,
                        target | XCP_TGTFL_SET_SCMD);
    if ((ret == CKR_SESSION_CLOSED || ret == CKR_PIN_INCORRECT) &&
        retry == FALSE && data->ep11_session != NULL) {
        /* Re-login the EP11 session and retry once */
        lldata.tokdata = data->tokdata;
        lldata.ep11_session = data->ep11_session;
        ret = ep11_login_handler(adapter, domain, &lldata);
        if (ret == CKR_OK) {
            retry = TRUE;
            goto repeat;
        }
    }

    if (ep11_data->mk_change_active && blobretry == FALSE &&
        ret == CKR_IBM_WKID_MISMATCH && data->secure_key_reenc != NULL) {
        blob =  data->secure_key_reenc;
        bloblen = data->secure_key_reenc_len;
        blobretry = TRUE;
        goto repeat;
    }

    if (data->aes_xts && ret == CKR_OK) {
        /* Create the protected key via CKM_IBM_CPACF_WRAP */
        retry = FALSE;
        blobretry = FALSE;
        blob = data->secure_key2;
        bloblen = data->secure_key_len2;
repeat2:
        ret = dll_m_WrapKey(blob, bloblen,
                            NULL, 0, NULL, 0, &mech,
                            data->pkey_buf2, data->pkey_buflen_p2,
                            target | XCP_TGTFL_SET_SCMD);
        if ((ret == CKR_SESSION_CLOSED || ret == CKR_PIN_INCORRECT) &&
            retry == FALSE && data->ep11_session != NULL) {
            /* Re-login the EP11 session and retry once */
            lldata.tokdata = data->tokdata;
            lldata.ep11_session = data->ep11_session;
            ret = ep11_login_handler(adapter, domain, &lldata);
            if (ret == CKR_OK) {
                retry = TRUE;
                goto repeat2;
            }
        }

        if (ep11_data->mk_change_active && blobretry == FALSE &&
            ret == CKR_IBM_WKID_MISMATCH && data->secure_key_reenc2 != NULL) {
            blob =  data->secure_key_reenc2;
            bloblen = data->secure_key_reenc_len2;
            blobretry = TRUE;
            goto repeat2;
        }
    }

    if (ret == CKR_OK)
        data->wrap_was_successful = CK_TRUE;

    free_ep11_target_for_apqn(target);

done:

    /* Always return ok, calling function loops over this handler until
     * data->wrap_was_successful = true, or no more APQN left.
     * Pass back error in handler data anyway. */
    data->wrap_error = ret;
    return CKR_OK;
}

/**
 * Creates a protected key from the given secure key object via the ep11 lib
 * CKM_IBM_CPACF_WRAP mechanism.
 */
static CK_RV ep11tok_pkey_skey2pkey(STDLL_TokData_t *tokdata, SESSION *session,
                                    CK_ATTRIBUTE *skey_attr,
                                    CK_ATTRIBUTE *skey_reenc_attr,
                                    CK_ATTRIBUTE **pkey_attr,
                                    CK_BBOOL aes_xts)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_ATTRIBUTE *tmp_attr = NULL;
    CK_BYTE ep11_buf[sizeof(wrapped_key_t)];
    size_t ep11_buflen = sizeof(ep11_buf);
    CK_BYTE ep11_buf2[sizeof(wrapped_key_t)];
    size_t ep11_buflen2 = sizeof(ep11_buf2);
    pkey_wrap_handler_data_t pkey_wrap_handler_data;
    wrapped_key_t *wk, *wk2;
    uint64_t token_size = 0;
    uint8_t wrapped_key[EP11_MAX_WRAPPED_KEY_SIZE * 2];
    ep11_target_info_t *target_info = NULL;
    CK_RV ret;

    target_info = get_target_info(tokdata);
    if (target_info == NULL)
        return CKR_FUNCTION_FAILED;

    /* Create the protected key via CKM_IBM_CPACF_WRAP */
    memset(&pkey_wrap_handler_data, 0, sizeof(pkey_wrap_handler_data_t));
    pkey_wrap_handler_data.tokdata = tokdata;
    if (session != NULL)
        pkey_wrap_handler_data.ep11_session =
                                    (ep11_session_t *)session->private_data;
    pkey_wrap_handler_data.secure_key = skey_attr->pValue;
    pkey_wrap_handler_data.secure_key_len = skey_attr->ulValueLen;
    if (skey_reenc_attr != NULL) {
        pkey_wrap_handler_data.secure_key_reenc = skey_reenc_attr->pValue;
        pkey_wrap_handler_data.secure_key_reenc_len =
                                                skey_reenc_attr->ulValueLen;
    }
    pkey_wrap_handler_data.pkey_buf = (CK_BYTE *)&ep11_buf;
    pkey_wrap_handler_data.pkey_buflen_p = &ep11_buflen;
    pkey_wrap_handler_data.aes_xts = FALSE;

    if (aes_xts) {
        pkey_wrap_handler_data.secure_key_len = skey_attr->ulValueLen / 2;
        pkey_wrap_handler_data.secure_key2 =
                    (CK_BYTE *)skey_attr->pValue + skey_attr->ulValueLen / 2;
        pkey_wrap_handler_data.secure_key_len2 = skey_attr->ulValueLen / 2;
        if (skey_reenc_attr != NULL) {
            pkey_wrap_handler_data.secure_key_reenc_len =
                                        skey_reenc_attr->ulValueLen / 2;
            pkey_wrap_handler_data.secure_key_reenc2 =
                    (CK_BYTE *)skey_reenc_attr->pValue +
                                        skey_reenc_attr->ulValueLen / 2;
            pkey_wrap_handler_data.secure_key_reenc_len2 =
                                        skey_reenc_attr->ulValueLen / 2;
        }
        pkey_wrap_handler_data.pkey_buf2 = (CK_BYTE *)&ep11_buf2;
        pkey_wrap_handler_data.pkey_buflen_p2 = &ep11_buflen2;
        pkey_wrap_handler_data.aes_xts = TRUE;
    }

    if (target_info->single_apqn) {
        /* If in single APQN mode, call handler for that single APQN only */
        RETRY_SINGLE_APQN_START(tokdata, ret)
            pkey_wrap_handler_data.wrap_error = CKR_OK;
            ep11tok_pkey_wrap_handler(target_info->adapter, target_info->domain,
                                      &pkey_wrap_handler_data);
            ret = pkey_wrap_handler_data.wrap_error;
        RETRY_SINGLE_APQN_END(ret, tokdata, target_info)
    } else {
        ret = handle_all_ep11_cards(&ep11_data->target_list,
                                    ep11tok_pkey_wrap_handler,
                                    &pkey_wrap_handler_data);
    }
    if (ret != CKR_OK || !pkey_wrap_handler_data.wrap_was_successful) {
        TRACE_ERROR("handle_all_ep11_cards failed or no APQN could do the wrap.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check ep11 wrapped key struct version and length. We currently only
     * support/expect version 0x0001 structs. */
    wk = (wrapped_key_t *) &ep11_buf;
    if (ep11_buflen != sizeof(wrapped_key_t) || wk->version != EP11_WRAPPED_KEY_VERSION_1) {
        TRACE_ERROR("invalid ep11 wrapped key struct length %ld\n", ep11_buflen);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if returned key type is what we expect:
     *  - 0x1 = AES with bit length 128, 192 and 256
     *  - 0x2 = 2DES and 3DES
     *  - 0x3 = EC-P with bit length 192, 224, 256, 384 and 521
     *  - 0x4 = ED25519 and ED448
     */
    switch (wk->wrapped_key_type) {
    case EP11_WRAPPED_KEY_TYPE_AES:
    case EP11_WRAPPED_KEY_TYPE_EC:
    case EP11_WRAPPED_KEY_TYPE_ED:
        break;
    default:
        TRACE_ERROR("Got unexpected CPACF key type %d from firmware\n", wk->wrapped_key_type);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (wk->token_size > sizeof(wrapped_key)) {
        TRACE_ERROR("Buffer too small\n");
        ret = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    token_size = wk->token_size;
    /* copy wrapped key to wrapped_key variable to create CKA_IBM_OPAQUE_PKEY */
    memcpy(wrapped_key, wk->wrapped_key, wk->token_size);

    if (aes_xts) {
        /* Check ep11 wrapped key struct version and length. We currently only
         * support/expect version 0x0001 structs. */
        wk2 = (wrapped_key_t *) &ep11_buf2;
        if (ep11_buflen2 != sizeof(wrapped_key_t) ||
            wk2->version != EP11_WRAPPED_KEY_VERSION_1) {
            TRACE_ERROR("invalid ep11 wrapped key struct length %ld\n", ep11_buflen2);
            ret = CKR_FUNCTION_FAILED;
            goto done;
        }
        /* Check if returned key type is what we expect:
         *  - 0x1 = AES with bit length 128 and 256
         */
        switch (wk2->wrapped_key_type) {
        case EP11_WRAPPED_KEY_TYPE_AES:
            break;
        default:
            TRACE_ERROR("Got unexpected CPACF key type %d from firmware\n",
                        wk->wrapped_key_type);
            ret = CKR_FUNCTION_FAILED;
            goto done;
        }

        if (wk2->token_size > sizeof(wrapped_key) - wk->token_size) {
            TRACE_ERROR("Wrapped key size too big\n");
            ret = CKR_BUFFER_TOO_SMALL;
            goto done;
        }

        token_size += wk2->token_size;
        memcpy(wrapped_key + wk->token_size, wk2->wrapped_key, wk2->token_size);
    }

    /* Build new attribute for protected key */
    ret = build_attribute(CKA_IBM_OPAQUE_PKEY, wrapped_key,
                          token_size, &tmp_attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("build_attribute failed with rc=0x%lx\n", ret);
        ret = CKR_FUNCTION_FAILED;;
        goto done;
    }

    ret = CKR_OK;

done:

    *pkey_attr = tmp_attr;

    put_target_info(tokdata, target_info);

    return ret;
}

/**
 * Save the current firmware master key verification pattern in the tokdata:
 * create a dummy test key, transform it into a protected key, and store the MK
 * verification pattern in the tokdata.
 */
static CK_RV ep11tok_pkey_get_firmware_mk_vp(STDLL_TokData_t *tokdata,
                                             SESSION *session)
{
    CK_BBOOL btrue = CK_TRUE;
    CK_ULONG len = AES_KEY_SIZE_256;
    CK_MECHANISM mech = {CKM_AES_KEY_GEN, NULL_PTR, 0};
    CK_ATTRIBUTE tmpl[] = {
        {CKA_VALUE_LEN, &len, sizeof(CK_ULONG)},
        {CKA_IBM_PROTKEY_EXTRACTABLE, &btrue, sizeof(btrue)},
    };
    CK_ULONG tmpl_len = sizeof(tmpl) / sizeof(CK_ATTRIBUTE);
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_session_t *ep11_session;
    CK_BYTE csum[MAX_CSUMSIZE];
    size_t csum_l = sizeof(csum);
    CK_BYTE blob[MAX_BLOBSIZE];
    size_t blobsize = sizeof(blob);
    CK_BYTE blob_reenc[MAX_BLOBSIZE];
    CK_ATTRIBUTE *pkey_attr = NULL, *blob_attr = NULL, *blob_reenc_attr = NULL;
    ep11_target_info_t* target_info = NULL;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    CK_RV ret = CKR_OK;

    if (ep11tok_pkey_option_disabled(tokdata))
        return CKR_OK;

    if (pthread_mutex_lock(&ep11_data->pkey_mutex)) {
        TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
        return CKR_CANT_LOCK;
    }

    if (ep11_data->pkey_wrap_support_checked)
        goto unlock;

    if (session == NULL) {
        target_info = get_target_info(tokdata);
        if (target_info == NULL) {
            ret = CKR_FUNCTION_FAILED;
            goto unlock;
        }
    }

    /* Check if CPACF_WRAP mech supported */
    if (ep11tok_is_mechanism_supported(tokdata, CKM_IBM_CPACF_WRAP) != CKR_OK) {
        TRACE_INFO("CKM_IBM_CPACF_WRAP not supported on this system.\n");
        ret = CKR_FUNCTION_NOT_SUPPORTED;
        goto done;
    }

    memset(&ep11_data->pkey_mk_vp, 0, PKEY_MK_VP_LENGTH);

    trace_attributes(__func__, "Generate prot. test key:", tmpl, tmpl_len);

    if (session != NULL) {
        ep11_session = (ep11_session_t *)session->private_data;

        ep11_get_pin_blob(tokdata, ep11_session, FALSE, FALSE,
                          &ep11_pin_blob, &ep11_pin_blob_len);
    }

    /* Create an AES testkey with CKA_IBM_PROTKEY_EXTRACTABLE */
    if (session != NULL) {
        RETRY_SESSION_SINGLE_APQN_START(ret, tokdata)
        RETRY_REENC_CREATE_KEY_START()
            ret = dll_m_GenerateKey(&mech, tmpl, tmpl_len,
                                    ep11_pin_blob, ep11_pin_blob_len,
                                    blob, &blobsize, csum, &csum_l,
                                    target_info->target);
        RETRY_REENC_CREATE_KEY_END(tokdata, NULL, target_info,
                                   blob, blob_reenc, blobsize, ret)
        RETRY_SESSION_SINGLE_APQN_END(ret, tokdata, session)
    } else {
        RETRY_SINGLE_APQN_START(tokdata, ret)
        RETRY_REENC_CREATE_KEY_START()
            ret = dll_m_GenerateKey(&mech, tmpl, tmpl_len,
                                    ep11_pin_blob, ep11_pin_blob_len,
                                    blob, &blobsize, csum, &csum_l,
                                    target_info->target);
        RETRY_REENC_CREATE_KEY_END(tokdata, NULL, target_info,
                                   blob, blob_reenc, blobsize, ret)
        RETRY_SINGLE_APQN_END(ret, tokdata, target_info)
    }
    if (ret != CKR_OK) {
        TRACE_ERROR("dll_m_GenerateKey failed with rc=0x%lx\n",ret);
        goto done;
    }

    if (check_expected_mkvp(tokdata, blob, blobsize, NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        ret = CKR_DEVICE_ERROR;
        goto done;
    }

    /* Build attribute for secure key blob */
    ret = build_attribute(CKA_IBM_OPAQUE, blob, blobsize, &blob_attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("build_attribute CKA_IBM_OPAQUE failed with rc=0x%lx\n", ret);
        goto done;
    }

    if (ep11_data->mk_change_active) {
        ret = build_attribute(CKA_IBM_OPAQUE_REENC, blob_reenc, blobsize,
                              &blob_reenc_attr);
        if (ret != CKR_OK) {
            TRACE_ERROR("build_attribute CKA_IBM_OPAQUE_REENC failed with rc=0x%lx\n", ret);
            goto done;
        }
    }

    /*
     * Create a protected key from this blob to obtain the LPAR MK vp. When
     * this function returns ok, we have a 64 byte pkey value: 32 bytes
     * encrypted key + 32 bytes vp.
     */
    ret = ep11tok_pkey_skey2pkey(tokdata, NULL, blob_attr, blob_reenc_attr,
                                 &pkey_attr, FALSE);
    if (ret != CKR_OK) {
        /*
         * Could not transform secure key into protected key, pkey support is
         * not available.
         * We are just running without protected key support, i.e. the
         * pkey_wrap_supported flag in tokdata remains off, but the
         * pkey_wrap_support_checked flag is turned on
         */
        OCK_SYSLOG(LOG_WARNING,
                   "%s: Warning: Could not get mk_vp, protected key support is "
                   "not available.\n", __func__);
        TRACE_WARNING("%s: Could not get mk_vp, protected key support is not "
                      "available.\n", __func__);
        ret = CKR_OK;
        goto done;
    }

    memcpy(&ep11_data->pkey_mk_vp,
           (CK_BYTE *)pkey_attr->pValue + AES_KEY_SIZE_256,
           PKEY_MK_VP_LENGTH);
    __sync_or_and_fetch(&ep11_data->pkey_wrap_supported, 1);

done:
    if (blob_attr)
        free(blob_attr);
    if (blob_reenc_attr)
        free(blob_reenc_attr);
    if (pkey_attr)
        free(pkey_attr);

    put_target_info(tokdata, target_info);

    __sync_or_and_fetch(&ep11_data->pkey_wrap_support_checked, 1);

unlock:
    if (pthread_mutex_unlock(&ep11_data->pkey_mutex)) {
        TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
    }

    return ret;
}

/**
 * Return true, if the given key obj has a valid protected key, i.e. its
 * verification pattern matches the one of the current master key.
 */
static CK_BBOOL ep11tok_pkey_is_valid(STDLL_TokData_t *tokdata, OBJECT *key_obj)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_ATTRIBUTE *pkey_attr = NULL;
    int vp_offset;
    CK_BBOOL ret = CK_FALSE;

    if (template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE_PKEY,
                                         &pkey_attr) == CKR_OK) {
        if (pkey_attr->ulValueLen >= AES_KEY_SIZE_128 + PKEY_MK_VP_LENGTH) {
            vp_offset = pkey_attr->ulValueLen - PKEY_MK_VP_LENGTH;
            if (pthread_mutex_lock(&ep11_data->pkey_mutex)) {
                TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
                goto done;
            }
            if (memcmp((CK_BYTE *)pkey_attr->pValue + vp_offset,
                       &ep11_data->pkey_mk_vp,
                       PKEY_MK_VP_LENGTH) == 0) {
                ret = CK_TRUE;
            }
            if (pthread_mutex_unlock(&ep11_data->pkey_mutex)) {
                TRACE_ERROR("%s Failed to unlock pkey lock\n", __func__);
            }
        }
    }

done:
    return ret;
}

/**
 * Create a new protected key for the given key obj and update attribute
 * CKA_IBM_OPAQUE with the new pkey.
 */
static CK_RV ep11tok_pkey_update(STDLL_TokData_t *tokdata, SESSION *session,
                                 OBJECT *key_obj, CK_BBOOL aes_xts)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_ATTRIBUTE *skey_attr = NULL;
    CK_ATTRIBUTE *skey_reenc_attr = NULL;
    CK_ATTRIBUTE *pkey_attr = NULL;
    CK_RV ret;
    int vp_offset;
    int num_retries = 0;

    /* Get secure key from obj */
    if (template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                         &skey_attr) != CKR_OK) {
        TRACE_ERROR("This key has no blob: should not occur!\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (ep11_data->mk_change_active) {
        /* Try to get CKA_IBM_OPAQUE_REENC, ignore if it fails */
        template_attribute_get_non_empty(key_obj->template,
                                         CKA_IBM_OPAQUE_REENC,
                                         &skey_reenc_attr);
    }

retry:
    /* Transform the secure key into a protected key */
    ret = ep11tok_pkey_skey2pkey(tokdata, session, skey_attr, skey_reenc_attr,
                                 &pkey_attr, aes_xts);
    if (ret != CKR_OK) {
        TRACE_ERROR("protected key creation failed with rc=0x%lx\n",ret);
        goto done;
    }

    if (pthread_mutex_lock(&ep11_data->pkey_mutex)) {
        TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
        ret = CKR_CANT_LOCK;
        goto done;
    }

    /*
     * Check if the new pkey's verification pattern matches the one in
     * ep11_data. This should always be the case, except there was a live
     * guest relocation (LGR) in the middle of the process.
     */
    vp_offset = pkey_attr->ulValueLen - PKEY_MK_VP_LENGTH;
    if (memcmp(&ep11_data->pkey_mk_vp, (CK_BYTE *)pkey_attr->pValue + vp_offset,
               PKEY_MK_VP_LENGTH) != 0) {
        TRACE_ERROR("vp of this pkey does not match with the one in ep11_data\n");
        ret = CKR_FUNCTION_FAILED;
    }

    if (aes_xts) {
        /*
         * Check if the new pkey's verification pattern matches the one in
         * ep11_data. This should always be the case, except there was a live
         * guest relocation (LGR) in the middle of the process.
         * AES XTS has two keys, two keys are concatenated.
         * Second key is checked above and the first key is checked here
         */
        vp_offset = pkey_attr->ulValueLen / 2 - PKEY_MK_VP_LENGTH;
        if (memcmp(&ep11_data->pkey_mk_vp, (CK_BYTE *)pkey_attr->pValue + vp_offset,
                   PKEY_MK_VP_LENGTH) != 0) {
            TRACE_ERROR("vp of this pkey does not match with the one in ep11_data\n");
            ret = CKR_FUNCTION_FAILED;
        }
    }

    /*
     * Recreating the firmware mkvp via ep11tok_pkey_get_firmware_mk_vp below
     * does only work when pkey_wrap_support_checked is 0. Set it to 0 while
     * the mutex lock is still obtained.
     */
    if (ret != CKR_OK)
        __sync_and_and_fetch(&ep11_data->pkey_wrap_support_checked, 0);

    if (pthread_mutex_unlock(&ep11_data->pkey_mutex)) {
        TRACE_ERROR("%s Failed to unlock pkey lock\n", __func__);
    }

    if (ret != CKR_OK)  {
        /*
         * Verification pattern does not match. Create it again and retry.
         * If there was an LGR, this op now takes place on the new system
         * and should succeed.
         */
        ret = ep11tok_pkey_get_firmware_mk_vp(tokdata, session);
        if (ret != CKR_OK)
            goto done;

        num_retries++;
        if (num_retries < PKEY_CONVERT_KEY_RETRIES) {
            if (pkey_attr != NULL)
                free(pkey_attr);
            TRACE_DEVEL("%s VP mismatch probably due to LGR, retry %d of %d ...\n",
                        __func__, num_retries, PKEY_CONVERT_KEY_RETRIES);
            goto retry;
        }
    }

    if (ret != CKR_OK)
        goto done;

    /*
     * Now update the key obj. If it's a token obj, it will be also updated
     * in the repository.
     */
    ret = pkey_update_and_save(tokdata, key_obj, &pkey_attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("pkey_update_and_save failed with rc=0x%lx\n", ret);
        goto done;
    }

    ret = CKR_OK;

done:
    if (pkey_attr != NULL)
        free(pkey_attr);

    return ret;
}

/**
 * Returns true if the session is ok for creating protected keys, false
 * otherwise. The session must be read/write for token objects, and not public
 * nor SO for private objects.
 */
static CK_BBOOL ep11tok_pkey_session_ok_for_obj(SESSION *session,
                                                OBJECT *key_obj)
{
    if (object_is_token_object(key_obj) &&
        (session->session_info.flags & CKF_RW_SESSION) == 0)
        return CK_FALSE;

    if (object_is_private(key_obj)) {
        switch (session->session_info.state) {
        case CKS_RO_PUBLIC_SESSION:
        case CKS_RW_PUBLIC_SESSION:
        case CKS_RW_SO_FUNCTIONS:
            return CK_FALSE;
        default:
            break;
        }
    }

    return CK_TRUE;
}

/*
 * Returns true if the given key object is eligible to get a protected key
 * attribute, false otherwise.
 */
static CK_RV ep11tok_pkey_obj_eligible_for_pkey_support(
                                                ep11_private_data_t *ep11_data,
                                                OBJECT *key_obj)
{
    if (object_is_attr_bound(key_obj) || !ep11_data->pkey_wrap_supported ||
        !object_is_pkey_extractable(key_obj)) {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    if (!ep11_data->pkey_combined_extract_supported &&
        object_is_extractable(key_obj)) {
        TRACE_ERROR("Combined extract not supported, but CKA_EXTRACTABLE "
                    "and CKA_IBM_PROTKEY_EXTRACTABLE are both TRUE\n");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    return CKR_OK;
}

/**
 * Checks if the preconditions for using the related protected key of
 * the given secure key object are met. The caller of this routine must
 * have a READ_LOCK on the key object.
 *
 * The routine internally creates a protected key and adds it to the key_obj,
 * if the machine supports pkeys, the key is eligible for pkey support, does
 * not already have a valid pkey, and other conditions, like r/w session, are
 * fulfilled. As adding a protected key to the key_obj involves unlocking and
 * re-locking, the key blob, or any other attribute of the key, that was
 * retrieved via h_opaque_2_blob before calling this function might be no more
 * valid in a parallel environment.
 *
 * Therefore, the following return codes tell the calling function how to
 * proceed:
 *
 * @return CKR_OK:
 *            a protected key was possibly created successfully and everything
 *            is fine to use pkey support. In this case the protected key
 *            shall be used, but a previously obtained key blob or other attr
 *            might be invalid, because of a possible unlock/re-lock of the
 *            key_obj.
 *
 *         CKR_FUNCTION_NOT_SUPPORTED:
 *            The system, session or key do not allow to use pkey support, but
 *            no attempt was made to create a protected key. So the key blob,
 *            or any other attr, is still valid and a fallback into the ep11
 *            path is ok.
 *
 *         all others:
 *            An internal error occurred and it was possibly attempted to create
 *            a protected key for the object. In this case, the key blob, or
 *            any other attr, might be no longer valid in a parallel environment
 *            and the ep11 fallback is not possible anymore. The calling
 *            function shall return with an error in this case.
 */
CK_RV ep11tok_pkey_check(STDLL_TokData_t *tokdata, SESSION *session,
                         OBJECT *key_obj, CK_MECHANISM *mech)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_ATTRIBUTE *opaque_attr = NULL;
    CK_RV ret = CKR_FUNCTION_NOT_SUPPORTED;

    /* Check if CPACF supports the operation implied by this key and mech */
    if (!pkey_op_supported_by_cpacf(ep11_data->msa_level, mech->mechanism,
                                    key_obj->template))
        goto done;

    /* Check config option */
    switch (ep11_data->pkey_mode) {
    case PKEY_MODE_DISABLED:
        goto done;
        break;
    case PKEY_MODE_DEFAULT:
    case PKEY_MODE_ENABLE4NONEXTR:
    case PKEY_MODE_ENABLE4EXTR:
    case PKEY_MODE_ENABLE4ALL:
        /* Use existing pkeys, re-create invalid pkeys, and also create new
         * pkeys for secret/private keys that do not already have one. EC
         * public keys that are pkey-extractable, can always be used via CPACF
         * as there is no protected key involved.*/
        if (pkey_is_ec_public_key(key_obj->template) &&
            object_is_pkey_extractable(key_obj)) {
            ret = CKR_OK;
            goto done;
        }

        /* Ensure the firmware master key verification pattern is available */
        if (ep11tok_pkey_get_firmware_mk_vp(tokdata, session) != CKR_OK)
            goto done;

        ret = ep11tok_pkey_obj_eligible_for_pkey_support(ep11_data, key_obj);
        if (ret != CKR_OK)
            goto done;

        if (template_attribute_get_non_empty(key_obj->template,
                                             CKA_IBM_OPAQUE_PKEY,
                                             &opaque_attr) != CKR_OK ||
            !ep11tok_pkey_is_valid(tokdata, key_obj)) {
            /* this key has either no pkey attr, or it is not valid,
             * try to create one, if the session state allows it */
            if (!ep11tok_pkey_session_ok_for_obj(session, key_obj))
                goto done;

            ret = ep11tok_pkey_update(tokdata, session, key_obj,
                                      mech->mechanism == CKM_AES_XTS);
            if (ret != CKR_OK) {
                TRACE_ERROR("error updating the %s protected key, rc=0x%lx\n",
                            mech->mechanism == CKM_AES_XTS ? "AES XTS" : "AES",
                            ret);
                if (ret == CKR_FUNCTION_NOT_SUPPORTED)
                    ret = CKR_FUNCTION_FAILED;
                goto done;
            }
        }
        break;
    default:
        /* should not occur */
        TRACE_ERROR("PKEY_MODE %i unsupported.\n", ep11_data->pkey_mode);
        ret = CKR_FUNCTION_FAILED;
        goto done;
        break;
    }

    ret = CKR_OK;

done:

    return ret;
}

/**
 * Wrapper function around ep11tok_pkey_check for the case where we don't
 * have a key object. This function is called externally from new_host.c.
 * Returns CKR_OK if pkey usage is OK, CKR_FUNCTION_NOT_SUPPORTED if pkey
 * is not supported, or any other return code in case of an error. In such
 * cases the calling function should itself return with an error, because
 * neither the secure key nor the protected key path will work.
 */
CK_RV ep11tok_pkey_usage_ok(STDLL_TokData_t *tokdata, SESSION *session,
                            CK_OBJECT_HANDLE hkey, CK_MECHANISM *mech)
{
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj;
    CK_RV ret;

    ret = h_opaque_2_blob(tokdata, hkey, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (ret != CKR_OK) {
        TRACE_ERROR("%s no blob ret=0x%lx\n", __func__, ret);
        return ret;
    }

    ret = ep11tok_pkey_check(tokdata, session, key_obj, mech);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return ret;
}

CK_RV ep11tok_pkey_check_aes_xts(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                                 CK_MECHANISM_TYPE type)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

    if (ep11tok_is_mechanism_supported(tokdata, type) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    if (ep11tok_pkey_obj_eligible_for_pkey_support(ep11_data,
                                                   key_obj) != CKR_OK) {
        TRACE_ERROR("Key not eligible for pkey support\n");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    return CKR_OK;
}

CK_RV ep11tok_pkey_add_protkey_attr_to_tmpl(TEMPLATE *tmpl)
{
    CK_ATTRIBUTE *pkey_attr = NULL;
    CK_BBOOL btrue = CK_TRUE, bfalse = CK_FALSE;
    CK_RV ret;

    if (!template_attribute_find(tmpl, CKA_IBM_PROTKEY_EXTRACTABLE, &pkey_attr)) {
        ret = build_attribute(CKA_IBM_PROTKEY_EXTRACTABLE, &btrue,
                              sizeof(CK_BBOOL), &pkey_attr);
        if (ret != CKR_OK) {
            TRACE_ERROR("build_attribute failed with ret=0x%lx\n", ret);
            goto done;
        }
        ret = template_update_attribute(tmpl, pkey_attr);
        if (ret != CKR_OK) {
            TRACE_ERROR("update_attribute failed with ret=0x%lx\n", ret);
            free(pkey_attr);
            goto done;
        }
        ret = build_attribute(CKA_IBM_PROTKEY_NEVER_EXTRACTABLE, &bfalse,
                              sizeof(CK_BBOOL), &pkey_attr);
        if (ret != CKR_OK) {
            TRACE_ERROR("build_attribute failed with ret=0x%lx\n", ret);
            goto done;
        }
        ret = template_update_attribute(tmpl, pkey_attr);
        if (ret != CKR_OK) {
            TRACE_ERROR("update_attribute failed with ret=0x%lx\n", ret);
            free(pkey_attr);
            goto done;
        }
    }

    ret = CKR_OK;

done:
    return ret;
}

static CK_RV ep11tok_pkey_convert_key(STDLL_TokData_t *tokdata, SESSION *session,
                                     OBJECT *key_obj, CK_BBOOL xts_mode,
                                     CK_BYTE *protkey, CK_ULONG *protkey_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    int num_retries = 0, vp_offset1, vp_offset2;
    CK_ATTRIBUTE *skey_reenc_attr = NULL;
    CK_ATTRIBUTE *skey_attr = NULL;
    CK_ATTRIBUTE *pkey_attr = NULL;
    CK_RV rc, rc2;

    /* Try to obtain a write lock on the key_obj */
    rc = object_unlock(key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("object_unlock failed, rc=0x%lx\n", rc);
        goto done;
    }

    rc = object_lock(key_obj, WRITE_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not obtain write lock.\n");
        goto done;
    }

    /*
     * The key_obj could be modified between unlock and lock. Therefore get
     * the attribute when we have the write lock here.
     */
    if (template_attribute_get_non_empty(key_obj->template,
                                         CKA_IBM_OPAQUE, &skey_attr) != CKR_OK) {
        TRACE_ERROR("This key has no blob: should not occur!\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (ep11_data->mk_change_active) {
        /* Try to get CKA_IBM_OPAQUE_REENC, ignore if it fails */
        template_attribute_get_non_empty(key_obj->template,
                                         CKA_IBM_OPAQUE_REENC, &skey_reenc_attr);
    }

retry:
    /* Convert secure key to protected key. */
    rc = ep11tok_pkey_skey2pkey(tokdata, session, skey_attr, skey_reenc_attr,
                                &pkey_attr, xts_mode);
    if (rc != CKR_OK) {
        TRACE_ERROR("protkey creation failed, rc=0x%lx\n", rc);
        goto unlock;
    }

    /*
     * In case of XTS, check if the wkvp's of the two keys are identical.
     * An LGR could have happened between the creation of the two keys.
     */
    if (xts_mode) {
        vp_offset1 = pkey_attr->ulValueLen / 2 - PKEY_MK_VP_LENGTH;
        vp_offset2 = pkey_attr->ulValueLen - PKEY_MK_VP_LENGTH;
        if (memcmp((CK_BYTE *)pkey_attr->pValue + vp_offset1,
                   (CK_BYTE *)pkey_attr->pValue + vp_offset2,
                   PKEY_MK_VP_LENGTH) != 0) {
            num_retries++;
            if (num_retries < PKEY_CONVERT_KEY_RETRIES) {
                TRACE_DEVEL("%s vp of xts key 1 does not match with vp of "
                            "xts key 2, retry %d of %d ...\n",
                            __func__, num_retries, PKEY_CONVERT_KEY_RETRIES);
                goto retry;
            }
            rc = CKR_FUNCTION_FAILED;
            goto unlock;
        }
    }

    /*
     * Save new protkey attr in key_obj. This happens only in memory,
     * works also for r/o sessions.
     */
    rc = template_update_attribute(key_obj->template, pkey_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed, rc=0x%lx\n", rc);
        goto unlock;
    }

    /* If we have an r/w session, also save obj to disk. */
    if (ep11tok_pkey_session_ok_for_obj(session, key_obj)) {
        if (object_is_token_object(key_obj)) {
            rc = object_mgr_save_token_object(tokdata, key_obj);
            if (rc != CKR_OK) {
                TRACE_ERROR("Could not save token obj to repository, rc=0x%lx.\n", rc);
                goto unlock;
            }
        }
    }

    /* Update wkvp in EP11 private data. */
    if (pthread_mutex_lock(&ep11_data->pkey_mutex)) {
        TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
        rc = CKR_CANT_LOCK;
        goto unlock;
    }
    memcpy(&ep11_data->pkey_mk_vp,
           (CK_BYTE *)pkey_attr->pValue + pkey_attr->ulValueLen - PKEY_MK_VP_LENGTH,
           PKEY_MK_VP_LENGTH);
    if (pthread_mutex_unlock(&ep11_data->pkey_mutex)) {
        TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
    }

    /* Pass back new protkey. Need to do this before unlocking the obj. */
    if (*protkey_len < pkey_attr->ulValueLen) {
        rc = CKR_BUFFER_TOO_SMALL;
        goto unlock;
    }
    memcpy(protkey, pkey_attr->pValue, pkey_attr->ulValueLen);
    *protkey_len = pkey_attr->ulValueLen;

unlock:
    rc2 = object_unlock(key_obj);
    if (rc2 != CKR_OK) {
        TRACE_ERROR("object_unlock failed, rc=0x%lx\n", rc2);
        if (rc == CKR_OK)
            rc = rc2;
        goto done;
    }

    rc2 = object_lock(key_obj, READ_LOCK);
    if (rc2 != CKR_OK) {
        TRACE_ERROR("object_lock for READ failed, rc=0x%lx\n", rc2);
        if (rc == CKR_OK)
            rc = rc2;
        goto done;
    }

done:

    return rc;
}
#endif /* NO_PKEY */

CK_RV ep11tok_extract_blob_info(CK_BYTE *blob, CK_ULONG blob_len,
                                CK_BBOOL *is_spki, CK_BYTE **wkid,
                                CK_BYTE** session_id, XCP_Attr_t **bool_attrs)
{
    CK_BYTE *data;
    CK_ULONG data_len, field_len, ofs, i;
    blob_attr_header_t *hdr;

    /* From EP11 structure document section 7.4.1 SPKI with MAC */
    const struct {
        const char* field;
        CK_ULONG min_len;
        CK_BYTE **ptr;
    } fields[] = {
        { "WKID", XCP_WKID_BYTES, wkid },
        { "SessionID", XCP_WK_BYTES, session_id },
        { "Salt", XCP_SPKISALT_BYTES, NULL },
        { "Mode", XCP_BLOBCLRMODE_BYTES, NULL },
        { "Attrs", sizeof(blob_attr_header_t) + XCP_BLOBCLRATTR_BYTES,
                                                            (CK_BYTE **)&hdr },
        { NULL, 0, NULL },
    };

    /*
     * Check if MACed SPKI or key/state blob. From the EP11 structure document:
     *    Session identifiers are guaranteed not to have 0x30 as their first
     *    byte. This allows a single-byte check to differentiate between blobs
     *    starting with session identifiers, and MACed SPKIs, which may be
     *    used as blobs under other conditions.
     * Key blobs start with the session identifier (32 bytes).
     * SPKIs start with a DER encoded SPKI, which itself starts with a SEQUENCE
     * denoted by 0x30 followed by the DER encoded length of the SPKI.
     */
    if (blob_len > 5 && blob[0] == 0x30 &&
        ber_decode_SEQUENCE(blob, &data, &data_len, &field_len) == CKR_OK) {
        /* It is a SPKI, fields follow as OCTET STRINGs right after SPKI data */
        if (blob_len < field_len) {
            TRACE_ERROR("MACed SPKI is too small\n");
            return CKR_FUNCTION_FAILED;
        }

        if (is_spki != NULL)
            *is_spki = TRUE;

        if (blob_len == field_len) {
            TRACE_DEVEL("Raw-SPKI (non-MACed), no info to return\n");
            if (wkid != NULL)
                *wkid = NULL;
            if (session_id != NULL)
                *session_id = NULL;
            if (bool_attrs != NULL)
                *bool_attrs = NULL;

            return CKR_OK;
        }

        ofs = field_len;

        for (i = 0; fields[i].field != NULL; i++) {
            if (ofs + 2 + fields[i].min_len > blob_len) {
                TRACE_ERROR("MACed SPKI is too small to contain field %s\n",
                            fields[i].field);
                return CKR_FUNCTION_FAILED;
            }

            if (ber_decode_OCTET_STRING(blob + ofs, &data, &data_len,
                                        &field_len) != CKR_OK) {
                TRACE_ERROR("Failed to decode MACed SPKI field %s\n",
                            fields[i].field);
                return CKR_FUNCTION_FAILED;
            }

            if (data_len < fields[i].min_len || ofs + field_len > blob_len) {
                TRACE_ERROR("MACed SPKI field %s is too small\n",
                            fields[i].field);
                return CKR_FUNCTION_FAILED;
            }

            if (fields[i].ptr != NULL)
                *fields[i].ptr = data;

            ofs += field_len;
        }

        if (hdr->version != EP11_BLOB_ATTR_HDR_VERSION) {
            TRACE_ERROR("MACed SPKI attributes heder is invalid\n");
            return CKR_FUNCTION_FAILED;
        }

        if (bool_attrs != NULL)
            *bool_attrs = (XCP_Attr_t*)&data[sizeof(blob_attr_header_t) + 4];
    } else {
        /* It is a key blob */
        if (blob_len < EP11_BLOB_VERSION_OFFSET + sizeof(uint16_t) ||
            *(uint16_t *)&blob[EP11_BLOB_VERSION_OFFSET] != EP11_BLOB_VERSION) {
            TRACE_ERROR("Key blob is too small or is invalid\n");
            return CKR_FUNCTION_FAILED;
        }

        if (is_spki != NULL)
            *is_spki = FALSE;
        if (wkid != NULL)
            *wkid = &blob[EP11_BLOB_WKID_OFFSET];
        if (session_id != NULL)
            *session_id = blob;
        if (bool_attrs != NULL)
            *bool_attrs = (XCP_Attr_t *)&blob[EP11_BLOB_BOOL_ATTR_OFFSET];
    }

    return CKR_OK;
}

static const struct {
    XCP_Attr_t ep11_attr;
    CK_ATTRIBUTE_TYPE pkcs11_attr;
    CK_BBOOL can_set_to_false; /* allow to restrict key usage */
    CK_BBOOL can_set_to_true; /* allow to lift key usage */
} ep11_pkcs11_attr_map[] = {
    { XCP_BLOB_EXTRACTABLE, CKA_EXTRACTABLE, TRUE, FALSE },
    { XCP_BLOB_NEVER_EXTRACTABLE, CKA_NEVER_EXTRACTABLE, FALSE, FALSE },
    { XCP_BLOB_MODIFIABLE, CKA_MODIFIABLE, TRUE, FALSE },
    { XCP_BLOB_NEVER_MODIFIABLE, CKA_IBM_NEVER_MODIFIABLE, FALSE, FALSE },
    { XCP_BLOB_RESTRICTABLE, CKA_IBM_RESTRICTABLE, FALSE, FALSE },
    { XCP_BLOB_ATTRBOUND, CKA_IBM_ATTRBOUND, FALSE, FALSE },
    { XCP_BLOB_USE_AS_DATA, CKA_IBM_USE_AS_DATA, TRUE, TRUE },
    { XCP_BLOB_SIGN, CKA_SIGN, TRUE, TRUE },
    { XCP_BLOB_DECRYPT, CKA_DECRYPT, TRUE, TRUE },
    { XCP_BLOB_ENCRYPT, CKA_ENCRYPT, TRUE, TRUE },
    { XCP_BLOB_DERIVE, CKA_DERIVE, TRUE, TRUE },
    { XCP_BLOB_UNWRAP, CKA_UNWRAP, TRUE, TRUE },
    { XCP_BLOB_WRAP, CKA_WRAP, TRUE, TRUE },
    { XCP_BLOB_VERIFY, CKA_VERIFY, TRUE, TRUE },
    { XCP_BLOB_TRUSTED, CKA_TRUSTED, TRUE, FALSE },
    { XCP_BLOB_WRAP_W_TRUSTED, CKA_WRAP_WITH_TRUSTED , TRUE, TRUE},
    { XCP_BLOB_PROTKEY_EXTRACTABLE, CKA_IBM_PROTKEY_EXTRACTABLE, TRUE, FALSE },
    { XCP_BLOB_PROTKEY_NEVER_EXTRACTABLE, CKA_IBM_PROTKEY_NEVER_EXTRACTABLE,
                                                                FALSE, FALSE },
    { 0, 0, 0, 0 },
};

static CK_RV ep11tok_check_blob_import_attrs(STDLL_TokData_t *tokdata,
                                             CK_OBJECT_CLASS class,
                                             TEMPLATE *tmpl,
                                             CK_BYTE *blob, CK_ULONG blob_len)
{
    CK_ULONG keytype, i;
    XCP_Attr_t *bool_attrs = NULL, *bool_attrs2 = NULL;
    CK_ATTRIBUTE *attr;
    CK_BBOOL is_spki, blob_val, user_val;
    CK_RV rc;

    UNUSED(tokdata);

    rc = template_attribute_get_ulong(tmpl, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("CKA_KEY_TYPE not found\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    rc = ep11tok_extract_blob_info(blob, keytype == CKK_AES_XTS ?
                                                    blob_len / 2 : blob_len,
                                   &is_spki, NULL, NULL, &bool_attrs);
    if (rc != CKR_OK) {
        TRACE_ERROR("ep11tok_extract_blob_info failed\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (keytype == CKK_AES_XTS) {
        rc = ep11tok_extract_blob_info(blob + blob_len / 2, blob_len / 2,
                                       NULL, NULL, NULL, &bool_attrs2);
        if (rc != CKR_OK) {
            TRACE_ERROR("ep11tok_extract_blob_info failed\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (*bool_attrs != *bool_attrs2) {
            TRACE_ERROR("AES-XTS keys are inconsistent\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    if (is_spki) {
        /* It's a (MACed) SPKI blob */
        if (class != CKO_PUBLIC_KEY) {
            TRACE_ERROR("SPKI-blob is only allowed for public keys\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        if (bool_attrs == NULL) {
            TRACE_DEVEL("Raw-SPKI (non-MACed), no attributes to check\n");
            return CKR_OK;
        }

        TRACE_DEVEL("MACed-SPKI boolean attrs: 0x%08x\n", *bool_attrs);
    } else {
        /* It's a key blob */
        if (class != CKO_PRIVATE_KEY && class != CKO_SECRET_KEY) {
            TRACE_ERROR("Key-blob is only allowed for private or secret keys\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        TRACE_DEVEL("Key-Blob boolean attrs: 0x%08x\n", *bool_attrs);
    }

    for (i = 0; ep11_pkcs11_attr_map[i].ep11_attr != 0; i++) {
        blob_val = (*bool_attrs & ep11_pkcs11_attr_map[i].ep11_attr) != 0 ?
                                                    CK_TRUE : CK_FALSE;

        if (template_attribute_find(tmpl, ep11_pkcs11_attr_map[i].pkcs11_attr,
                                    &attr) &&
            attr->ulValueLen == sizeof(CK_BBOOL) && attr->pValue != NULL) {
            user_val = *((CK_BBOOL *)attr->pValue);
            if (blob_val != user_val) {
                /* User supplied attribute is different than in blob */
                if ((*bool_attrs & XCP_BLOB_MODIFIABLE) == 0) {
                    TRACE_ERROR("Attribute %s=%s in template can not be "
                                "applied to the blob because the blob has "
                                "CKA_MODIFIABLE=FALSE\n",
                               p11_get_cka(ep11_pkcs11_attr_map[i].pkcs11_attr),
                               user_val ? "TRUE" : "FALSE");
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                if ((user_val == FALSE &&
                                    ep11_pkcs11_attr_map[i].can_set_to_false) ||
                    (user_val == TRUE &&
                                    ep11_pkcs11_attr_map[i].can_set_to_true)) {
                    /* Update of attr is allowed */
                    blob_val = user_val;
                } else {
                    TRACE_ERROR("Attribute %s=%s in template conflicts with "
                               "blob attribute setting %s\n",
                               p11_get_cka(ep11_pkcs11_attr_map[i].pkcs11_attr),
                               user_val ? "TRUE" : "FALSE",
                               blob_val ? "TRUE" : "FALSE");
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
            }
        }

        rc = template_build_update_attribute(tmpl,
                                             ep11_pkcs11_attr_map[i].pkcs11_attr,
                                             &blob_val, sizeof(blob_val));
        if (rc != CKR_OK) {
            TRACE_ERROR("template_build_update_attribute failed for %s\n",
                        p11_get_cka(ep11_pkcs11_attr_map[i].pkcs11_attr));
            return rc;
        }
    }

    return CKR_OK;
}

/**
 * This function is called whenever a new object is created. It sets
 * attribute CKA_IBM_PROTKEY_EXTRACTABLE according to the PKEY_MODE token
 * option.
 * If the FORCE_SENSITIVE token option is enabled, it sets attribute
 * CKA_SENSITIVE to TRUE for secret keys (CKO_SECRET_KEY) if it is not
 * specified in the template. For private keys (CKO_PRIVATE_KEY) it always
 * sets CKA_SENSITIVE to TRUE if it is not specified in the template,
 * regardless of the FORCE_SENSITIVE option.
 */
CK_RV token_specific_set_attrs_for_new_object(STDLL_TokData_t *tokdata,
                                              CK_OBJECT_CLASS class,
                                              CK_ULONG mode, TEMPLATE *tmpl)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_ATTRIBUTE *sensitive_attr = NULL, *opaque = NULL;
    CK_BBOOL sensitive, extractable, pkey_extractable, btrue = CK_TRUE;
#ifndef NO_PKEY
    CK_ATTRIBUTE *ecp_attr = NULL;
    CK_BBOOL add_pkey_extractable = CK_FALSE;
#endif
    CK_RV ret;

    UNUSED(mode);

    if (class != CKO_SECRET_KEY && class != CKO_PRIVATE_KEY &&
        class != CKO_PUBLIC_KEY)
        return CKR_OK;

    if (mode == MODE_CREATE &&
        template_attribute_find(tmpl, CKA_IBM_OPAQUE, &opaque) == TRUE &&
        opaque->ulValueLen > 0 && opaque->pValue != NULL) {
        /* Check for conflicting attrs in to-be-imported blob and template */
        ret = ep11tok_check_blob_import_attrs(tokdata, class, tmpl,
                                              (CK_BYTE*)opaque->pValue,
                                              opaque->ulValueLen);
        if (ret != CKR_OK) {
            TRACE_ERROR("ep11tok_check_blob_import_attrs failed ret=0x%lx\n",
                        ret);
            goto done;
        }
    }

    if (class == CKO_PRIVATE_KEY ||
        (class == CKO_SECRET_KEY && ep11_data->cka_sensitive_default_true)) {
        /* private key, or secret key and FORCE_SENSITIVE is enabled */
        ret = template_attribute_get_bool(tmpl, CKA_SENSITIVE, &sensitive);
        if (ret == CKR_TEMPLATE_INCOMPLETE) {
            /* Not in template, supply default (TRUE) */
            ret = build_attribute(CKA_SENSITIVE, &btrue, sizeof(CK_BBOOL),
                                  &sensitive_attr);
            if (ret != CKR_OK) {
                TRACE_ERROR("build_attribute failed with ret=0x%lx\n", ret);
                goto done;
            }
            ret = template_update_attribute(tmpl, sensitive_attr);
            if (ret != CKR_OK) {
                TRACE_ERROR("update_attribute failed with ret=0x%lx\n", ret);
                free(sensitive_attr);
                goto done;
            }
        }
    }

    if (!ep11_data->pkey_combined_extract_supported) {
        ret = template_attribute_get_bool(tmpl, CKA_EXTRACTABLE, &extractable);
        if (ret != CKR_OK)
            extractable = FALSE;

        ret = template_attribute_get_bool(tmpl, CKA_IBM_PROTKEY_EXTRACTABLE,
                                          &pkey_extractable);
        if (ret != CKR_OK)
            pkey_extractable = FALSE;

        if (extractable && pkey_extractable) {
            /* The EP11 call would return CKR_FUNCTION_CANCELED in that case */
            TRACE_ERROR("Combined extract not supported, but CKA_EXTRACTABLE "
                        "and CKA_IBM_PROTKEY_EXTRACTABLE are both TRUE\n");
            ret = CKR_TEMPLATE_INCONSISTENT;
            goto done;
        }
    }

#ifndef NO_PKEY
    switch (ep11_data->pkey_mode) {
    case PKEY_MODE_DISABLED:
        /* Nothing to do */
        break;
    case PKEY_MODE_DEFAULT:
        /* If the application did not specify pkey-extractable, all keys get
         * pkey-extractable=false. This was already set by default, so
         * nothing to do here. */
        break;
    case PKEY_MODE_ENABLE4NONEXTR:
        /* If the application did not specify pkey-extractable, all
         * non-extractable secret/private keys and all EC public keys where
         * CPACF supports the related curve, get pkey-extractable=true */
        switch (class) {
        case CKO_PUBLIC_KEY:
            if (template_attribute_get_non_empty(tmpl, CKA_EC_PARAMS, &ecp_attr) == CKR_OK &&
                pkey_op_supported_by_cpacf(ep11_data->msa_level, CKM_ECDSA, tmpl))
                add_pkey_extractable = CK_TRUE;
                /* Note that the explicit parm CKM_ECDSA just tells the
                 * function that it's not AES here. It covers all EC and ED
                 * mechs */
            break;
        default:
            ret = template_attribute_get_bool(tmpl, CKA_EXTRACTABLE, &extractable);
            if (ret == CKR_OK && !extractable)
                add_pkey_extractable = CK_TRUE;
            break;
        }
        break;
    case PKEY_MODE_ENABLE4EXTR:
        /* If the application did not specify CKA_IBM_PROTKEY_EXTRACTABLE in
         * its template, new keys of any type with CKA_EXTRACTABLE=true get
         * CKA_IBM_PROTKEY_EXTRACTABLE=true and a protected key is automatically
         * created at first use of the key.
         */
        switch (class) {
        case CKO_PUBLIC_KEY:
            if (template_attribute_get_non_empty(tmpl, CKA_EC_PARAMS, &ecp_attr) == CKR_OK &&
                pkey_op_supported_by_cpacf(ep11_data->msa_level, CKM_ECDSA, tmpl))
                add_pkey_extractable = CK_TRUE;
                /* Note that the explicit parm CKM_ECDSA just tells the
                 * function that it's not AES here. It covers all EC and ED
                 * mechs */
            break;
        default:
            ret = template_attribute_get_bool(tmpl, CKA_EXTRACTABLE, &extractable);
            if (ret == CKR_OK && extractable)
                add_pkey_extractable = CK_TRUE;
            break;
        }
        break;
    case PKEY_MODE_ENABLE4ALL:
        /* If the application did not specify CKA_IBM_PROTKEY_EXTRACTABLE in
         * its template, new keys of any type, regardless of CKA_EXTRACTABLE,
         * get CKA_IBM_PROTKEY_EXTRACTABLE=true and a protected key is
         * automatically created at first use of the key.
         */
        switch (class) {
        case CKO_PUBLIC_KEY:
            if (template_attribute_get_non_empty(tmpl, CKA_EC_PARAMS, &ecp_attr) == CKR_OK &&
                pkey_op_supported_by_cpacf(ep11_data->msa_level, CKM_ECDSA, tmpl))
                add_pkey_extractable = CK_TRUE;
                /* Note that the explicit parm CKM_ECDSA just tells the
                 * function that it's not AES here. It covers all EC and ED
                 * mechs */
            break;
        default:
            add_pkey_extractable = CK_TRUE;
            break;
        }
        break;
    default:
        TRACE_ERROR("PKEY_MODE %i unsupported.\n", ep11_data->pkey_mode);
        ret = CKR_FUNCTION_FAILED;
        goto done;
        break;
    }

    if (add_pkey_extractable) {
        ret = ep11tok_pkey_add_protkey_attr_to_tmpl(tmpl);
        if (ret != CKR_OK)
            goto done;
    }
#endif /* NO_PKEY */

    ret = CKR_OK;

done:

    return ret;
}

#ifdef NO_PKEY
CK_RV ep11tok_pkey_usage_ok(STDLL_TokData_t *tokdata, SESSION *session,
                            CK_OBJECT_HANDLE hkey, CK_MECHANISM *mech)
{
    UNUSED(tokdata);
    UNUSED(session);
    UNUSED(hkey);
    UNUSED(mech);

    return CKR_FUNCTION_NOT_SUPPORTED;
}
#endif /* NO_PKEY */

static CK_RV check_ab_supported(CK_KEY_TYPE type) {
    switch(type) {
    case CKK_AES:
    case CKK_DES2:
    case CKK_DES3:
    case CKK_GENERIC_SECRET:
    case CKK_RSA:
    case CKK_EC:
    case CKK_DSA:
    case CKK_DH:
        return CKR_OK;
    default:
        TRACE_ERROR("%s key type not supported for ab: 0x%lx\n", __func__, type);
        return CKR_TEMPLATE_INCONSISTENT;
    }
}

static CK_RV check_ab_pair(CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                           CK_ULONG ulPublicKeyAttributeCount,
                           CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                           CK_ULONG ulPrivateKeyAttributeCount)
{
    CK_RV rc;
    CK_BBOOL abpub = FALSE, abpriv = FALSE;

    rc = get_bool_attribute_by_type(pPublicKeyTemplate, ulPublicKeyAttributeCount,
                                    CKA_IBM_ATTRBOUND, &abpub);
    if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE) {
        TRACE_ERROR("Failed to retrieve CKA_IBM_ATTRBOUND attribute from public template. rc=0x%lx\n", rc);
        return rc;
    }
    rc = get_bool_attribute_by_type(pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                    CKA_IBM_ATTRBOUND, &abpriv);
    if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE) {
        TRACE_ERROR("Failed to retrieve CKA_IBM_ATTRBOUND attribute from private template. rc=0x%lx\n", rc);
        return rc;
    }
    if (abpub != abpriv) {
        TRACE_ERROR("Only one of the key pair is attribute bound.\n");
        return CKR_TEMPLATE_INCONSISTENT;
    }
    return CKR_OK;
}

static CK_RV check_ab_kek_type(TEMPLATE *tmpl, CK_RV errval)
{
    CK_KEY_TYPE kektype;
    CK_OBJECT_CLASS class;
    CK_RV rc;

    rc = template_attribute_get_ulong(tmpl, CKA_KEY_TYPE, &kektype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Invalid key type attribute\n");
        return rc;
    }
    rc = template_attribute_get_ulong(tmpl, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Invalid object class attribute\n");
        return rc;
    }
    if (kektype != CKK_RSA && class != CKO_SECRET_KEY) {
        TRACE_ERROR("KEK key type %ld not supported for AB wrap/unwrap\n",
                    kektype);
        return errval;
    }
    return rc;
}

static CK_RV check_ab_attributes(CK_ATTRIBUTE *attrs,
                                 CK_ULONG attrs_len,
                                 CK_OBJECT_CLASS kc)
{
    CK_RV rc;
    CK_BBOOL attrbound = FALSE, sensitive = FALSE;

    if (kc != CKO_PUBLIC_KEY) {
        rc = get_bool_attribute_by_type(attrs, attrs_len, CKA_IBM_ATTRBOUND,
                                        &attrbound);
        if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE)
            return rc;
        rc = get_bool_attribute_by_type(attrs, attrs_len, CKA_SENSITIVE,
                                        &sensitive);
        if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE)
            return rc;
        if (attrbound && !sensitive) {
            TRACE_ERROR("Attribute bound key not sensitive!");
            return CKR_TEMPLATE_INCONSISTENT;
        }
    }
    return CKR_OK;
}

static CK_RV check_ab_wrap(STDLL_TokData_t * tokdata,
                           CK_BYTE **sblob, size_t *sblob_len,
                           OBJECT **sobj,
                           OBJECT *key_obj, OBJECT *wrap_key_obj,
                           CK_MECHANISM_PTR mech, SESSION *sess)
{
    CK_RV rc;
    CK_BBOOL abkey, abwrapkey, absignkey, signsignkey;

    *sobj = 0;
    *sblob = 0;
    *sblob_len = ~0;
    rc = template_attribute_get_bool(key_obj->template, CKA_IBM_ATTRBOUND, &abkey);
    if (rc == CKR_TEMPLATE_INCOMPLETE) {
        abkey = FALSE;
        rc = CKR_OK;
    } else if (rc != CKR_OK) {
        TRACE_ERROR("Invalid CKA_IBM_ATTRBOUND attribute on key to wrap\n");
        return rc;
    }
    rc = template_attribute_get_bool(wrap_key_obj->template, CKA_IBM_ATTRBOUND, &abwrapkey);
    if (rc == CKR_TEMPLATE_INCOMPLETE) {
        abwrapkey = FALSE;
        rc = CKR_OK;
    } else if (rc != CKR_OK) {
        TRACE_ERROR("Invalid CKA_IBM_ATTRBOUND attribute on wrapping key\n");
        return rc;
    }
    if (abwrapkey) {
        if (!abkey) {
            TRACE_ERROR("Wrapping key is AB, but target key not\n");
            return CKR_KEY_NOT_WRAPPABLE;
        }
        /* Here, only AB wrapping can be used.  Check mechanism and parameters. */
        if (mech->mechanism != CKM_IBM_ATTRIBUTEBOUND_WRAP){
            TRACE_ERROR("AB key wrapping attempt without CKM_IBM_ATTRIBUTEBOUND_WRAP");
            return CKR_MECHANISM_INVALID;
        }
        if (sizeof(CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS) != mech->ulParameterLen) {
            TRACE_ERROR("AB key wrapping attempt with invalid mechanism parameter");
            return CKR_MECHANISM_PARAM_INVALID;
        }
        rc = check_ab_kek_type(wrap_key_obj->template, CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
        if (rc != CKR_OK)
            return rc;
        rc = h_opaque_2_blob(tokdata,
                             ((CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS *)mech->pParameter)->hSignVerifyKey,
                             sblob, sblob_len, sobj, READ_LOCK);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to get sign key for AB wrapping\n");
            return rc;
        }
        rc = tokdata->policy->is_key_allowed(tokdata->policy, &(*sobj)->strength, sess);
        if (rc != CKR_OK) {
            TRACE_ERROR("POLICY VIOLATION: AB wrap signing key too weak\n");
            goto out;
        }
        rc = template_attribute_get_bool((*sobj)->template, CKA_IBM_ATTRBOUND, &absignkey);
        if (rc != CKR_OK || !absignkey) {
            TRACE_ERROR("AB-Wrap: sign key not AB\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto out;
        }
        rc = template_attribute_get_bool((*sobj)->template, CKA_SIGN, &signsignkey);
        if (rc != CKR_OK || !signsignkey) {
            TRACE_ERROR("AB-Wrap: sign key not able to sign\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto out;
        }
    } else if (abkey) {
        TRACE_ERROR("Target key is AB, but wrapping key is not\n");
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }
 out:
    if (rc != CKR_OK && *sobj) {
        object_put(tokdata, *sobj, TRUE);
        *sobj = 0;
        *sblob = 0;
        *sblob_len = ~0;
    }
    return rc;
}

static CK_RV check_ab_unwrap(STDLL_TokData_t * tokdata,
                             CK_BYTE **vblob, size_t *vblob_len,
                             OBJECT **vobj, OBJECT *unwrap_key_obj,
                             CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
                             CK_MECHANISM_PTR mech, CK_BBOOL *isab,
                             SESSION *sess)
{
    CK_RV rc;
    CK_BBOOL abkey, abunwrapkey, abverifykey, verifyverifykey;

    *vobj = 0;
    *vblob = 0;
    *vblob_len = ~0;
    *isab = FALSE;
    rc = template_attribute_get_bool(unwrap_key_obj->template, CKA_IBM_ATTRBOUND,
                                     &abunwrapkey);
    if (rc == CKR_TEMPLATE_INCOMPLETE) {
        abunwrapkey = FALSE;
        rc = CKR_OK;
    } else if (rc != CKR_OK) {
        return rc;
    }
    rc = get_bool_attribute_by_type(attrs, attrs_len, CKA_IBM_ATTRBOUND, &abkey);
    if (rc == CKR_TEMPLATE_INCOMPLETE) {
        abkey = FALSE;
        rc = CKR_OK;
    } else if (rc != CKR_OK) {
        return rc;
    }
    if (mech->mechanism == CKM_IBM_ATTRIBUTEBOUND_WRAP) {
        *isab = TRUE;
        if (mech->ulParameterLen != sizeof(CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS)) {
            TRACE_ERROR("Unwrapping AB key with invalid mechanism\n");
            return CKR_MECHANISM_PARAM_INVALID;
        }
        if (!abkey) {
            TRACE_ERROR("CKM_IBM_ATTRIBUTEBOUND_WRAP with non-AB target\n");
            return CKR_MECHANISM_INVALID;
        }
        if (!abunwrapkey) {
            TRACE_ERROR("CKM_IBM_ATTRIBUTEBOUND_WRAP with non-AB unwrap key\n");
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        /* extract verification key */
        rc = h_opaque_2_blob(tokdata,
                             ((CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS *)mech->pParameter)->hSignVerifyKey,
                             vblob, vblob_len, vobj, READ_LOCK);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to get verification key for AB wrapping\n");
            return rc;
        }
        rc = tokdata->policy->is_key_allowed(tokdata->policy, &(*vobj)->strength, sess);
        if (rc != CKR_OK) {
            TRACE_ERROR("POLICY VIOLATION: AB verification key too weak\n");
            goto out;
        }
        rc = template_attribute_get_bool((*vobj)->template, CKA_IBM_ATTRBOUND, &abverifykey);
        if (rc != CKR_OK || !abverifykey) {
            TRACE_ERROR("AB-Wrap: verification key not AB\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto out;
        }
        rc = template_attribute_get_bool((*vobj)->template, CKA_VERIFY, &verifyverifykey);
        if (rc != CKR_OK || !verifyverifykey) {
            TRACE_ERROR("AB-Unwrap: verification key not able to verify\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto out;
        }
    } else {
        if (abkey) {
            TRACE_ERROR("Unwrapping AB key without CKM_IBM_ATTRIBUTEBOUND_WRAP\n");
            return CKR_MECHANISM_INVALID;
        }
        if (abunwrapkey) {
            TRACE_ERROR("Unwrap key AB key without CKM_IBM_ATTRIBUTEBOUND_WRAP\n");
            return CKR_MECHANISM_INVALID;
        }
    }
 out:
    if (rc != CKR_OK && *vobj) {
        object_put(tokdata, *vobj, TRUE);
        *vobj = 0;
        *vblob = 0;
        *vblob_len = ~0;
    }
    return rc;
}

/* Has to be called either with WRITE_LOCK on @obj, or before the object is
 * made publicly available via object_mgr_create_final.  Since this function
 * updates the attributes of the object, we would get race conditions
 * otherwise.
 */
static CK_RV ab_unwrap_update_template(STDLL_TokData_t * tokdata,
                                       SESSION * session,
                                       CK_BYTE *blob, size_t blob_len,
                                       OBJECT *obj,
                                       CK_KEY_TYPE keytype)
{
    CK_RV rc;
    CK_BBOOL trusted, encrypt, decrypt, wrap, unwrap, sign, sign_recover,
             verify, verify_recover, derive, extractable, local,
             never_extractable, modifiable, wrap_with_trusted;
    CK_ULONG valuelen;
    CK_KEY_TYPE template_keytype;
    CK_ATTRIBUTE attrs[] = {
        {CKA_TRUSTED,           &trusted,           sizeof(trusted)},
        {CKA_ENCRYPT,           &encrypt,           sizeof(encrypt)},
        {CKA_DECRYPT,           &decrypt,           sizeof(decrypt)},
        {CKA_WRAP,              &wrap,              sizeof(wrap)},
        {CKA_UNWRAP,            &unwrap,            sizeof(unwrap)},
        {CKA_SIGN,              &sign,              sizeof(sign)},
        {CKA_SIGN_RECOVER,      &sign_recover,      sizeof(sign_recover)},
        {CKA_VERIFY,            &verify,            sizeof(verify)},
        {CKA_VERIFY_RECOVER,    &verify_recover,    sizeof(verify_recover)},
        {CKA_DERIVE,            &derive,            sizeof(derive)},
        {CKA_EXTRACTABLE,       &extractable,       sizeof(extractable)},
        {CKA_LOCAL,             &local,             sizeof(local)},
        {CKA_NEVER_EXTRACTABLE, &never_extractable, sizeof(extractable)},
        {CKA_MODIFIABLE,        &modifiable,        sizeof(modifiable)},
        {CKA_WRAP_WITH_TRUSTED, &wrap_with_trusted, sizeof(wrap_with_trusted)},
        {CKA_KEY_TYPE,          &template_keytype,  sizeof(template_keytype)},
        {CKA_VALUE_LEN,         &valuelen,          sizeof(valuelen)},
    };
    CK_ULONG i;
    CK_ATTRIBUTE *attr;
    CK_BBOOL cktrue = TRUE;
    CK_BYTE *useblob;
    size_t useblob_len;

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, obj, blob, blob_len,
                           useblob, useblob_len, rc)
        rc = dll_m_GetAttributeValue(useblob, useblob_len, attrs,
                                     sizeof(attrs) / sizeof(CK_ATTRIBUTE),
                                     target_info->target);
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblob_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        TRACE_ERROR("Retrieving attributes from AB unwrapped key failed, rc=0x%lx\n",
                    rc);
        return rc;
    }
    if (template_keytype != keytype) {
        TRACE_ERROR("Template specifies different key type than the AB key (0x%08lx vs 0x%08lx)\n",
                    template_keytype, keytype);
        return CKR_TEMPLATE_INCONSISTENT;
    }
    for (i = 0; i < sizeof(attrs) / sizeof(CK_ATTRIBUTE); ++i) {
        if (attrs[i].type == CKA_VALUE_LEN) {
            switch (keytype) {
            case CKK_GENERIC_SECRET:
            case CKK_AES:
                break;
            default:
                continue;
            }
        }

        rc = build_attribute(attrs[i].type, attrs[i].pValue,
                             attrs[i].ulValueLen, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("failed to build attribute (rc=0x%lx)\n", rc);
            return rc;
        }
        rc = template_update_attribute(obj->template, attr);
        if (rc != CKR_OK) {
            free(attr);
            attr = NULL;
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            return rc;
        }
    }
    /* force sensitive */
    rc = build_attribute(CKA_SENSITIVE, &cktrue, sizeof(CK_BBOOL), &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("failed to build attribute (rc=0x%lx)\n", rc);
        return rc;
    }    
    rc = template_update_attribute(obj->template, attr);
    if (rc != CKR_OK) {
        free(attr);
        attr = NULL;
        TRACE_ERROR("%s failed to force template sensitive; rc=0x%08lx\n", __func__, rc);
    }
    return rc;
} 

static CK_RV force_ab_sensitive(CK_ATTRIBUTE_PTR *p_attrs, CK_ULONG *p_attrs_len,
                                CK_KEY_TYPE type)
{
    CK_RV rc;
    CK_BBOOL cktrue = TRUE, abvalue, sensitive;

    rc = get_bool_attribute_by_type(*p_attrs, *p_attrs_len,
                                    CKA_IBM_ATTRBOUND, &abvalue);
    if (rc == CKR_OK && abvalue) {
        rc = check_ab_supported(type);
        if (rc != CKR_OK)
            return rc;
        /* An AB key => make sure it is sensitive */
        rc = get_bool_attribute_by_type(*p_attrs, *p_attrs_len,
                                        CKA_SENSITIVE, &sensitive);
        if (rc == CKR_OK) {
            if (!sensitive) {
                /* Template specifies CKA_SENSITIVE == CKA_FALSE so is
                 * inconsistent for AB keys */
                rc = CKR_TEMPLATE_INCONSISTENT;
            }
        } else if (rc == CKR_TEMPLATE_INCOMPLETE) {
            /* CKA_SENSITIVE not in template */
            rc = add_to_attribute_array(p_attrs, p_attrs_len,
                                        CKA_SENSITIVE, &cktrue, sizeof(cktrue));
        }
    } else if (rc == CKR_TEMPLATE_INCOMPLETE) {
        /* Not an AB key */
        rc = CKR_OK;
    }   
    return rc;
}

static CK_RV check_ab_derive_attributes(STDLL_TokData_t *tokdata,
                                        TEMPLATE *tmpl,
                                        CK_ATTRIBUTE_PTR *attrs,
                                        CK_ULONG *attrs_len)
{
    CK_BBOOL abgoal, abbase;
    CK_RV rc;

    rc = template_attribute_get_bool(tmpl, CKA_IBM_ATTRBOUND, &abbase);
    if (rc == CKR_TEMPLATE_INCOMPLETE) {
        abbase = FALSE;
        rc = CKR_OK;
    } else if (rc != CKR_OK) {
        TRACE_ERROR("Invalid CKA_IBM_ATTRBOUND attribute on base key (rc=0x%lx)\n",
                    rc);
        return rc;
    }
    if (abbase && check_required_versions(tokdata, ibm_ab_ecdh_req_versions,
                                          NUM_AB_ECDH_REQ) < 1)
        return CKR_MECHANISM_INVALID;
    rc = get_bool_attribute_by_type(*attrs, *attrs_len,
                                    CKA_IBM_ATTRBOUND, &abgoal);
    if (rc == CKR_OK && abgoal) {
        /* We want to derive an AB key */
        if (!abbase) {
            TRACE_ERROR("Attempt to derive AB key from non-AB key\n");
            rc = CKR_TEMPLATE_INCONSISTENT;
        }
    } else if (rc == CKR_TEMPLATE_INCOMPLETE) {
        rc = CKR_OK;
        /* AB setting defaulted => if AB base key, derive AB key */
        if (abbase) {
            rc = add_to_attribute_array(attrs, attrs_len,
                                        CKA_IBM_ATTRBOUND,
                                        (CK_BYTE *) &abbase,
                                        sizeof(abbase));
        }
    }
    return rc;
}

static CK_RV check_key_attributes(STDLL_TokData_t * tokdata,
                                  CK_KEY_TYPE kt, CK_OBJECT_CLASS kc,
                                  CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
                                  CK_ATTRIBUTE_PTR * p_attrs,
                                  CK_ULONG * p_attrs_len, int curve_type)
{

    CK_RV rc;
    CK_ULONG i;
    CK_BBOOL cktrue = TRUE;
    CK_ULONG check_types_pub[] = { CKA_VERIFY, CKA_ENCRYPT, CKA_WRAP };
    CK_ULONG check_types_priv[] = { CKA_SIGN, CKA_DECRYPT, CKA_UNWRAP };
    CK_ULONG check_types_sec[] =
        { CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP };
    CK_ULONG check_types_sec_sensitive[] =
        { CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP, CKA_SENSITIVE };
    CK_ULONG check_types_gen_sec[] =
        { CKA_SIGN, CKA_VERIFY };
    CK_ULONG check_types_gen_sec_sensitive[] =
        { CKA_SIGN, CKA_VERIFY, CKA_SENSITIVE };
    CK_ULONG check_types_derive[] = { CKA_DERIVE };
    CK_ULONG *check_types = NULL;
    CK_BBOOL *check_values[] = { &cktrue, &cktrue, &cktrue, &cktrue, &cktrue };
    CK_ULONG attr_cnt = 0;
    ep11_private_data_t *ep11_data = tokdata->private_data;

    /* check/add attributes for public key template */
    if ((rc = dup_attribute_array(attrs, attrs_len, p_attrs, p_attrs_len)))
        return rc;

    switch (kc) {
    case CKO_SECRET_KEY:
        switch (kt) {
        case CKK_GENERIC_SECRET:
        case CKK_SHA_1_HMAC:
        case CKK_SHA224_HMAC:
        case CKK_SHA256_HMAC:
        case CKK_SHA384_HMAC:
        case CKK_SHA512_HMAC:
        case CKK_SHA3_224_HMAC:
        case CKK_SHA3_256_HMAC:
        case CKK_SHA3_384_HMAC:
        case CKK_SHA3_512_HMAC:
        case CKK_SHA512_224_HMAC:
        case CKK_SHA512_256_HMAC:
            if (ep11_data->cka_sensitive_default_true) {
                check_types = &check_types_gen_sec_sensitive[0];
                attr_cnt =
                    sizeof(check_types_gen_sec_sensitive) / sizeof(CK_ULONG);

            } else {
                check_types = &check_types_gen_sec[0];
                attr_cnt = sizeof(check_types_gen_sec) / sizeof(CK_ULONG);
            }
            break;
        default:
            if (ep11_data->cka_sensitive_default_true) {
                check_types = &check_types_sec_sensitive[0];
                attr_cnt = sizeof(check_types_sec_sensitive) / sizeof(CK_ULONG);
            } else {
                check_types = &check_types_sec[0];
                attr_cnt = sizeof(check_types_sec) / sizeof(CK_ULONG);
            }
            break;
        }
        break;
    case CKO_PUBLIC_KEY:
        if ((kt == CKK_EC) || (kt == CKK_ECDSA) || (kt == CKK_DSA)) {
            check_types = &check_types_pub[0];
            attr_cnt = 1;       /* only CKA_VERIFY */
            if (kt == CKK_EC && curve_type == MONTGOMERY_CURVE)
                attr_cnt = 0;
        } else if (kt == CKK_RSA) {
            check_types = &check_types_pub[0];
            attr_cnt = sizeof(check_types_pub) / sizeof(CK_ULONG);
        }
        /* do nothing for CKM_DH_PKCS_KEY_PAIR_GEN, CKK_IBM_PQC_DILITHIUM,
           and CKK_IBM_PQC_KYBER */
        break;
    case CKO_PRIVATE_KEY:
        if ((kt == CKK_EC) || (kt == CKK_ECDSA) || (kt == CKK_DSA)) {
            check_types = &check_types_priv[0];
            attr_cnt = 1;       /* only CKA_SIGN */
            if (kt == CKK_EC && curve_type == MONTGOMERY_CURVE)
                attr_cnt = 0;
        } else if (kt == CKK_RSA) {
            check_types = &check_types_priv[0];
            attr_cnt = sizeof(check_types_priv) / sizeof(CK_ULONG);
        } else if (kt == CKK_DH) {
            check_types = &check_types_derive[0];
            attr_cnt = sizeof(check_types_derive) / sizeof(CK_ULONG);
        }
        /* Do nothing for CKK_IBM_PQC_DILITHIUM and CKK_IBM_PQC_KYBER */
        break;
    default:
        return CKR_OK;
    }

    for (i = 0; i < attr_cnt; i++, check_types++) {
        CK_ATTRIBUTE_PTR attr = get_attribute_by_type(*p_attrs,
                                                      *p_attrs_len,
                                                      *check_types);
        if (!attr) {
            rc = add_to_attribute_array(p_attrs, p_attrs_len,
                                        *check_types,
                                        (CK_BYTE *) check_values[i],
                                        sizeof(*check_values[i]));
            if (rc)
                goto cleanup;
        }
    }
    return check_ab_attributes(*p_attrs, *p_attrs_len, kc);
cleanup:
    if (rc) {
        free_attribute_array(*p_attrs, *p_attrs_len);
        *p_attrs = NULL;
        *p_attrs_len = 0;
    }
    return rc;
}

static CK_RV check_key_restriction(OBJECT *key_obj, CK_ATTRIBUTE_TYPE type)
{
    CK_RV rc;
    CK_BBOOL flag;

    rc = template_attribute_get_bool(key_obj->template, type, &flag);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID)
        return rc;
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find attribute 0x%lx for the key.\n", type);
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    if (flag != TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_FUNCTION_NOT_PERMITTED));
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    return CKR_OK;
}

#define UNKNOWN_MECHANISM   0xFFFFFFFF

/* for logging, debugging */
static const char *ep11_get_ckm(STDLL_TokData_t *tokdata, CK_ULONG mechanism)
{
    const struct mechrow *row;

    switch (mechanism) {
    case CKM_IBM_CPACF_WRAP:
        /*
         * CKM_IBM_CPACF_WRAP is only supported/known inside the EP11 token
         * code, but not externally, thus it is not in the mechtable.
         */
        return "CKM_IBM_CPACF_WRAP";
    default:
        break;
    }

    row = tokdata->mechtable_funcs->p_row_from_num(mechanism);
    if (row)
        return row->string;

    TRACE_WARNING("%s unknown mechanism %lx\n", __func__, mechanism);
    return "UNKNOWN";
}

static CK_ULONG ep11_get_mechanisms_by_name(STDLL_TokData_t *tokdata,
                                            const char *name)
{
    const struct mechrow *row;

    row = tokdata->mechtable_funcs->p_row_from_str(name);
    if (row)
        return row->numeric;

    TRACE_WARNING("%s unknown mechanism name '%s'\n", __func__, name);
    return UNKNOWN_MECHANISM;
}

static CK_RV read_adapter_config_file(STDLL_TokData_t * tokdata,
                                      const char *conf_name);
static CK_RV read_cp_filter_config_file(STDLL_TokData_t *tokdata,
                                        const char *conf_name,
                                        cp_config_t ** cp_config);

CK_RV ep11_error_to_pkcs11_error(CK_RV rc, SESSION *session)
{
    if (rc < CKR_VENDOR_DEFINED)
        return rc;

    TRACE_ERROR("%s ep11 specific error: rc=0x%lx\n", __func__, rc);

    if (session != NULL)
        session->session_info.ulDeviceError = rc;

    switch (rc) {
    case CKR_IBM_INTERNAL_ERROR:
    case CKR_IBM_TRANSPORT_ERROR:
    case CKR_IBM_OA_API_ERROR:
    case CKR_IBM_TRANSPORT_LIMIT:
    case CKR_IBM_REQ_TIMEOUT:
        return CKR_FUNCTION_FAILED;
    case CKR_IBM_WKID_MISMATCH:
    case CKR_IBM_WK_NOT_INITIALIZED:
        return CKR_DEVICE_ERROR;
    case CKR_IBM_STATIC_POLICY:
        return CKR_KEY_SIZE_RANGE;
    case CKR_IBM_READONLY:
        return CKR_ARGUMENTS_BAD;
    case CKR_IBM_BLOB_ERROR:
    case CKR_IBM_BLOBKEY_CONFLICT:
        return CKR_ENCRYPTED_DATA_INVALID;
    case CKR_IBM_MODE_CONFLICT:
    case CKR_IBM_NONCRT_KEY_SIZE:
        return CKR_ARGUMENTS_BAD;
    default:
        return CKR_FUNCTION_FAILED;
    }
}

/**
 * This function covers some specific restrictions of the ep11 hostlib, i.e.
 * passing these attrs to the ep11 hostlib would cause an error.
 */
static CK_BBOOL attr_applicable_for_ep11(STDLL_TokData_t * tokdata,
                                         CK_ATTRIBUTE *attr, CK_KEY_TYPE ktype,
                                         CK_OBJECT_CLASS class, int curve_type,
                                         CK_MECHANISM_PTR mech)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

    /* On older cards, CKA_IBM_PROTKEY_EXTRACTABLE might cause errors, so filter
     * it out when the CPACF_WRAP mechanism is not supported on this system */
    if (attr->type == CKA_IBM_PROTKEY_EXTRACTABLE &&
        ep11_data->pkey_wrap_supported == 0)
        return CK_FALSE;

    /* EP11 does not support sign/verify recover */
    if (attr->type == CKA_SIGN_RECOVER || attr->type == CKA_VERIFY_RECOVER)
        return CK_FALSE;

    switch (ktype) {
    case CKK_RSA:
        if (class == CKO_PRIVATE_KEY && attr->type == CKA_PUBLIC_EXPONENT)
            return CK_FALSE;
        if (attr->type == CKA_DERIVE)
            return CK_FALSE;
        break;
    case CKK_EC:
        if (class == CKO_PRIVATE_KEY && attr->type == CKA_EC_PARAMS &&
            mech->mechanism != CKM_IBM_BTC_DERIVE)
            return CK_FALSE;
        if (attr->type == CKA_ENCRYPT || attr->type == CKA_DECRYPT ||
            attr->type == CKA_WRAP || attr->type == CKA_UNWRAP)
            return CK_FALSE;
        /* Montgomery curves cannot be used for sign/verify */
        if (class == CKO_PRIVATE_KEY && curve_type == MONTGOMERY_CURVE && attr->type == CKA_SIGN)
            return CK_FALSE;
        if (class == CKO_PUBLIC_KEY && curve_type == MONTGOMERY_CURVE && attr->type == CKA_VERIFY)
            return CK_FALSE;
        /* Edwards curves cannot be used for derive (except for CKM_IBM_BTC_DERIVE) */
        if (curve_type == EDWARDS_CURVE && attr->type == CKA_DERIVE &&
            mech->mechanism != CKM_IBM_BTC_DERIVE)
            return CK_FALSE;
        break;
    case CKK_DSA:
        if (attr->type == CKA_ENCRYPT || attr->type == CKA_DECRYPT ||
            attr->type == CKA_WRAP || attr->type == CKA_UNWRAP ||
            attr->type == CKA_DERIVE)
            return CK_FALSE;
        if (attr->type == CKA_PRIME || attr->type == CKA_SUBPRIME ||
            attr->type == CKA_BASE)
            return CK_FALSE;
        break;
    case CKK_DH:
        if (attr->type == CKA_ENCRYPT || attr->type == CKA_DECRYPT ||
            attr->type == CKA_WRAP || attr->type == CKA_UNWRAP ||
            attr->type == CKA_SIGN || attr->type == CKA_VERIFY)
            return CK_FALSE;
        if (attr->type == CKA_BASE || attr->type == CKA_PRIME)
            return CK_FALSE;
        break;
    case CKK_IBM_PQC_DILITHIUM:
        if (attr->type == CKA_ENCRYPT || attr->type == CKA_DECRYPT ||
            attr->type == CKA_WRAP || attr->type == CKA_UNWRAP ||
            attr->type == CKA_DERIVE || 
            attr->type == CKA_IBM_DILITHIUM_KEYFORM ||
            attr->type == CKA_IBM_DILITHIUM_MODE)
            return CK_FALSE;
        break;
    case CKK_IBM_PQC_KYBER:
        if (attr->type == CKA_SIGN || attr->type == CKA_VERIFY ||
            attr->type == CKA_WRAP || attr->type == CKA_UNWRAP ||
            attr->type == CKA_IBM_KYBER_KEYFORM ||
            attr->type == CKA_IBM_KYBER_MODE)
            return CK_FALSE;
        break;
    default:
        break;
    }

    return CK_TRUE;
}

/*
 * Build an array of attributes to be passed to EP11. Some attributes are
 * handled 'read-only' by EP11, and would cause an error if passed to EP11.
 */
static CK_RV build_ep11_attrs(STDLL_TokData_t * tokdata, TEMPLATE *template,
                              CK_ATTRIBUTE_PTR *p_attrs, CK_ULONG_PTR p_attrs_len,
                              CK_KEY_TYPE ktype, CK_OBJECT_CLASS class,
                              int curve_type, CK_MECHANISM_PTR mech)
{
    DL_NODE *node;
    CK_ATTRIBUTE_PTR attr;
    CK_RV rc;
    CK_ULONG value_len = 0;
    CK_KEY_TYPE key_type;

    node = template->attribute_list;
    while (node != NULL) {
        attr = node->data;

        /* EP11 handles this as 'read only' and reports an error if specified */
        switch (attr->type) {
        case CKA_NEVER_EXTRACTABLE:
        case CKA_IBM_PROTKEY_NEVER_EXTRACTABLE:
        case CKA_LOCAL:
            break;
        case CKA_KEY_TYPE:
            if (attr->ulValueLen != sizeof(CK_KEY_TYPE) || attr->pValue == NULL)
                return CKR_ATTRIBUTE_VALUE_INVALID;

            key_type = *(CK_KEY_TYPE *)attr->pValue;
            ep11tok_pkcs11_keytype_translate(tokdata, key_type, &key_type);

            if (key_type == CKK_AES_XTS && ktype == CKK_AES)
                key_type = CKK_AES;

            rc = add_to_attribute_array(p_attrs, p_attrs_len, attr->type,
                                        (CK_BYTE *)&key_type, sizeof(key_type));
            if (rc != CKR_OK) {
                TRACE_ERROR("Adding attribute failed type=0x%lx rc=0x%lx\n",
                            attr->type, rc);
                return rc;
            }
            break;
        case CKA_VALUE_LEN:
            if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL)
                return CKR_ATTRIBUTE_VALUE_INVALID;

            value_len = *(CK_ULONG *)attr->pValue;
            if (ktype == CKK_AES_XTS)
                value_len /= 2;

            rc = add_to_attribute_array(p_attrs, p_attrs_len, attr->type,
                                        (CK_BYTE *)&value_len,
                                        sizeof(value_len));
            if (rc != CKR_OK) {
                TRACE_ERROR("Adding attribute failed type=0x%lx rc=0x%lx\n",
                            attr->type, rc);
                return rc;
            }
            break;
        /* EP11 does not like empty (zero length) attributes of that types */
        case CKA_PUBLIC_KEY_INFO:
            if (attr->ulValueLen == 0)
                break;
            /* Fallthrough */
        default:
            if (attr->ulValueLen > 0 && attr->pValue == NULL)
                return CKR_ATTRIBUTE_VALUE_INVALID;

            if (attr_applicable_for_ep11(tokdata, attr, ktype, class,
                                         curve_type, mech)) {
                rc = add_to_attribute_array(p_attrs, p_attrs_len, attr->type,
                                            attr->pValue, attr->ulValueLen);
                if (rc != CKR_OK) {
                    TRACE_ERROR("Adding attribute failed type=0x%lx rc=0x%lx\n",
                                attr->type, rc);
                    return rc;
                }
            }
        }

        node = node->next;
    }

    return CKR_OK;
}

/* import a DES/AES key, that is, make a blob for a DES/AES key
 * that was not created by EP11 hardware, encrypt the key by the wrap key,
 * unwrap it by the wrap key
 */
static CK_RV rawkey_2_blob(STDLL_TokData_t * tokdata, SESSION * sess,
                           unsigned char *key,
                           CK_ULONG ksize, CK_KEY_TYPE ktype,
                           unsigned char *blob, unsigned char *blobreenc,
                           size_t *blen, OBJECT *key_obj)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_BYTE cipher[MAX_BLOBSIZE];
    CK_ULONG clen = sizeof(cipher);
    CK_BYTE csum[MAX_CSUMSIZE];
    size_t cslen = sizeof(csum);
    CK_BYTE iv[AES_BLOCK_SIZE];
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
    CK_RV rc;
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    CK_ATTRIBUTE_PTR new_p_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_ATTRIBUTE *chk_attr = NULL;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;
    CK_BYTE *wrap_blob;

    /* tell ep11 the attributes the user specified */
    rc = build_ep11_attrs(tokdata, key_obj->template, &p_attrs, &attrs_len,
                          ktype, CKO_SECRET_KEY, -1, &mech);
    if (rc != CKR_OK)
        goto rawkey_2_blob_end;

    memset(cipher, 0, sizeof(cipher));
    memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

    /*
     * calls the ep11 lib (which in turns sends the request to the card),
     * all m_ function are ep11 functions
     */
    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
        rc = dll_m_EncryptSingle(wrap_blob, ep11_data->raw2key_wrap_blob_l,
                                 &mech, key, ksize, cipher, &clen,
                                 target_info->target);
    RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s encrypt ksize=0x%lx clen=0x%lx rc=0x%lx\n",
                    __func__, ksize, clen, rc);
        goto rawkey_2_blob_end;
    }
    TRACE_INFO("%s encrypt ksize=0x%lx clen=0x%lx rc=0x%lx\n",
               __func__, ksize, clen, rc);

    rc = check_key_attributes(tokdata, ktype, CKO_SECRET_KEY, p_attrs,
                              attrs_len, &new_p_attrs, &new_attrs_len, -1);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s RSA/EC check private key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto rawkey_2_blob_end;
    }

    trace_attributes(__func__, "Import sym.:", new_p_attrs, new_attrs_len);

    ep11_get_pin_blob(tokdata, ep11_session, object_is_session_object(key_obj),
                      object_is_private(key_obj),
                      &ep11_pin_blob, &ep11_pin_blob_len);

    /* the encrypted key is decrypted and a blob is build,
     * card accepts only blobs as keys
     */
    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
    RETRY_REENC_CREATE_KEY_START()
        rc = dll_m_UnwrapKey(cipher, clen, wrap_blob,
                             ep11_data->raw2key_wrap_blob_l, NULL, ~0,
                             ep11_pin_blob, ep11_pin_blob_len, &mech,
                             new_p_attrs, new_attrs_len, blob, blen, csum,
                             &cslen, target_info->target);
    RETRY_REENC_CREATE_KEY_END(tokdata, sess, target_info, blob, blobreenc,
                               *blen, rc)
    RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s unwrap blen=%zd rc=0x%lx\n", __func__, *blen, rc);
        goto rawkey_2_blob_end;
    } else {
        TRACE_INFO("%s unwrap blen=%zd rc=0x%lx\n", __func__, *blen, rc);

        if (cslen >= EP11_CSUMSIZE) {
            /* First 3 bytes of csum is the check value */
            rc = build_attribute(CKA_CHECK_VALUE, csum, EP11_CSUMSIZE,
                                 &chk_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                            __func__, rc);
                goto rawkey_2_blob_end;
            }

            rc = template_update_attribute(key_obj->template, chk_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s template_update_attribute failed with "
                            "rc=0x%lx\n", __func__, rc);
                goto rawkey_2_blob_end;
            }
            chk_attr = NULL;
        }
    }

rawkey_2_blob_end:
    if (p_attrs != NULL)
        free_attribute_array(p_attrs, attrs_len);
    if (new_p_attrs)
        free_attribute_array(new_p_attrs, new_attrs_len);
    if (chk_attr != NULL)
        free(chk_attr);
    return rc;
}

/* random number generator */
CK_RV token_specific_rng(STDLL_TokData_t * tokdata, CK_BYTE * output,
                         CK_ULONG bytes)
{
    ep11_target_info_t* target_info;
    CK_RV rc;

    target_info = get_target_info(tokdata);
    if (target_info == NULL)
        return CKR_FUNCTION_FAILED;

    RETRY_SINGLE_APQN_START(tokdata, rc)
        rc = dll_m_GenerateRandom(output, bytes, target_info->target);
    RETRY_SINGLE_APQN_END(rc, tokdata, target_info)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s output=%p bytes=%lu rc=0x%lx\n",
                    __func__, (void *)output, bytes, rc);
    }

    put_target_info(tokdata, target_info);
    return rc;
}

/*
 * for importing keys we need to encrypt the keys and build the blob by
 * m_UnwrapKey, use one wrap key for this purpose, can be any key,
 * we use an AES key
 */
static CK_RV make_wrapblob(STDLL_TokData_t *tokdata, SESSION *sess)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_session_t *ep11_session = (ep11_session_t *)sess->private_data;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_BYTE csum[MAX_CSUMSIZE];
    size_t csum_l = sizeof(csum);
    CK_ULONG len = 32;
    CK_BBOOL cktrue = 1;
    CK_ATTRIBUTE wrap_tmpl[] = {
        { CKA_VALUE_LEN, &len, sizeof(CK_ULONG) },
        { CKA_WRAP, &cktrue, sizeof(cktrue) },
        { CKA_UNWRAP, &cktrue, sizeof(cktrue) },
        { CKA_ENCRYPT, &cktrue, sizeof(cktrue) },
        { CKA_DECRYPT, &cktrue, sizeof(cktrue) },
        { CKA_EXTRACTABLE, &cktrue, sizeof(cktrue) },
    };
    CK_ULONG wrap_tmpl_len = sizeof(wrap_tmpl) / sizeof(CK_ATTRIBUTE);
    CK_RV rc = CKR_OK;

    if (pthread_mutex_lock(&ep11_data->raw2key_wrap_blob_mutex)) {
        TRACE_ERROR("%s Failed to lock Wrap-Blob lock\n", __func__);
        return CKR_CANT_LOCK;
    }

    if (ep11_data->raw2key_wrap_blob_l != 0) {
        TRACE_INFO("%s blob already exists raw2key_wrap_blob_l=0x%zx\n",
                   __func__, ep11_data->raw2key_wrap_blob_l);
        goto out_unlock;
    }

    trace_attributes(__func__, "Generate wrap blog key:",
                     wrap_tmpl, wrap_tmpl_len);

    ep11_get_pin_blob(tokdata, ep11_session, FALSE, FALSE,
                      &ep11_pin_blob, &ep11_pin_blob_len);

    ep11_data->raw2key_wrap_blob_l = sizeof(ep11_data->raw2key_wrap_blob);

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_CREATE_KEY_START()
        rc = dll_m_GenerateKey(&mech, wrap_tmpl, wrap_tmpl_len,
                               ep11_pin_blob, ep11_pin_blob_len,
                               ep11_data->raw2key_wrap_blob,
                               &ep11_data->raw2key_wrap_blob_l, csum, &csum_l,
                               target_info->target);
    RETRY_REENC_CREATE_KEY_END(tokdata, NULL, target_info,
                               ep11_data->raw2key_wrap_blob,
                               ep11_data->raw2key_wrap_blob_reenc,
                               ep11_data->raw2key_wrap_blob_l, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        TRACE_ERROR("%s end raw2key_wrap_blob_l=0x%zx rc=0x%lx\n",
                    __func__, ep11_data->raw2key_wrap_blob_l, rc);
        goto out;
    } else {
        TRACE_INFO("%s end raw2key_wrap_blob_l=0x%zx rc=0x%lx\n",
                   __func__, ep11_data->raw2key_wrap_blob_l, rc);
    }

    if (check_expected_mkvp(tokdata, ep11_data->raw2key_wrap_blob,
                            ep11_data->raw2key_wrap_blob_l, NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
    }

out:
    if (rc == CKR_IBM_WK_NOT_INITIALIZED) {
        TRACE_ERROR("%s rc is CKR_IBM_WK_NOT_INITIALIZED, "
                    "no master key set ?\n", __func__);
        OCK_SYSLOG(LOG_ERR,
                   "%s: Error: CKR_IBM_WK_NOT_INITIALIZED occurred, no "
                   "master key set ?\n", __func__);
        rc = CKR_DEVICE_ERROR;
    }
    if (rc == CKR_FUNCTION_CANCELED) {
        TRACE_ERROR("%s rc is CKR_FUNCTION_CANCELED, "
                    "control point 13 (generate or derive symmetric "
                    "keys including DSA parameters) disabled ?\n",
                    __func__);
        OCK_SYSLOG(LOG_ERR,
                   "%s: Error: CKR_FUNCTION_CANCELED occurred, "
                   "control point 13 (generate or derive symmetric "
                   "keys including DSA parameters) disabled ?\n", __func__);
        rc = CKR_DEVICE_ERROR;
    }

out_unlock:
    if (pthread_mutex_unlock(&ep11_data->raw2key_wrap_blob_mutex)) {
        TRACE_ERROR("%s Failed to unlock Wrap-Blob lock\n", __func__);
    }

    if (rc != CKR_OK)
        ep11_data->raw2key_wrap_blob_l = 0;

    return rc;
}

#ifdef EP11_HSMSIM
#define DLOPEN_FLAGS        RTLD_NOW | RTLD_DEEPBIND
#else
#define DLOPEN_FLAGS        RTLD_NOW
#endif

static void *ep11_load_host_lib(void)
{
    void *lib_ep11;
    char *ep11_lib_name;
    char *errstr;

    ep11_lib_name = secure_getenv(EP11SHAREDLIB_NAME);
    if (ep11_lib_name != NULL) {
        lib_ep11 = dlopen(ep11_lib_name, DLOPEN_FLAGS);

        if (lib_ep11 == NULL) {
            errstr = dlerror();
            OCK_SYSLOG(LOG_ERR,
                       "%s: Error loading shared library '%s' [%s]\n",
                       __func__, ep11_lib_name, errstr);
            TRACE_ERROR("%s Error loading shared library '%s' [%s]\n",
                        __func__, ep11_lib_name, errstr);
            return NULL;
        }
        return lib_ep11;
    }

    ep11_lib_name = EP11SHAREDLIB_V4;
    lib_ep11 = dlopen(ep11_lib_name, DLOPEN_FLAGS);

    if (lib_ep11 == NULL) {
        TRACE_DEVEL("%s Error loading shared library '%s', trying '%s'\n",
                    __func__, EP11SHAREDLIB_V4, EP11SHAREDLIB_V3);
        /* Try version 3 instead */
        ep11_lib_name = EP11SHAREDLIB_V3;
        lib_ep11 = dlopen(ep11_lib_name, DLOPEN_FLAGS);
    }

    if (lib_ep11 == NULL) {
        TRACE_DEVEL("%s Error loading shared library '%s', trying '%s'\n",
                    __func__, EP11SHAREDLIB_V3, EP11SHAREDLIB_V2);
        /* Try version 2 instead */
        ep11_lib_name = EP11SHAREDLIB_V2;
        lib_ep11 = dlopen(ep11_lib_name, DLOPEN_FLAGS);
    }

    if (lib_ep11 == NULL) {
        TRACE_DEVEL("%s Error loading shared library '%s', trying '%s'\n",
                    __func__, EP11SHAREDLIB_V2, EP11SHAREDLIB_V1);
        /* Try version 1 instead */
        ep11_lib_name = EP11SHAREDLIB_V1;
        lib_ep11 = dlopen(ep11_lib_name, DLOPEN_FLAGS);
    }

    if (lib_ep11 == NULL) {
        TRACE_DEVEL("%s Error loading shared library '%s', trying '%s'\n",
                    __func__, EP11SHAREDLIB_V1, EP11SHAREDLIB);
        /* Try unversioned library instead */
        ep11_lib_name = EP11SHAREDLIB;
        lib_ep11 = dlopen(ep11_lib_name, DLOPEN_FLAGS);
    }

    if (lib_ep11 == NULL) {
        errstr = dlerror();
        OCK_SYSLOG(LOG_ERR,
                   "%s: Error loading shared library '%s[.4][.3|.2|.1]' [%s]\n",
                   __func__, EP11SHAREDLIB, errstr);
        TRACE_ERROR("%s Error loading shared library '%s[.4][.3|.2|.1]' [%s]\n",
                    __func__, EP11SHAREDLIB, errstr);
        return NULL;
    }

    return lib_ep11;
}

static CK_RV ep11_resolve_lib_sym(void *hdl)
{
    char *error = NULL;

    dlerror();                  /* Clear existing error */

    *(void **)(&dll_m_GenerateRandom) = dlsym(hdl, "m_GenerateRandom");
    *(void **)(&dll_m_SeedRandom) = dlsym(hdl, "m_SeedRandom");

    *(void **)(&dll_m_Digest) = dlsym(hdl, "m_Digest");
    *(void **)(&dll_m_DigestInit) = dlsym(hdl, "m_DigestInit");
    *(void **)(&dll_m_DigestUpdate) = dlsym(hdl, "m_DigestUpdate");
    *(void **)(&dll_m_DigestFinal) = dlsym(hdl, "m_DigestFinal");
    *(void **)(&dll_m_DigestKey) = dlsym(hdl, "m_DigestKey");
    *(void **)(&dll_m_DigestSingle) = dlsym(hdl, "m_DigestSingle");

    *(void **)(&dll_m_Encrypt) = dlsym(hdl, "m_Encrypt");
    *(void **)(&dll_m_EncryptInit) = dlsym(hdl, "m_EncryptInit");
    *(void **)(&dll_m_EncryptUpdate) = dlsym(hdl, "m_EncryptUpdate");
    *(void **)(&dll_m_EncryptFinal) = dlsym(hdl, "m_EncryptFinal");
    *(void **)(&dll_m_EncryptSingle) = dlsym(hdl, "m_EncryptSingle");

    *(void **)(&dll_m_Decrypt) = dlsym(hdl, "m_Decrypt");
    *(void **)(&dll_m_DecryptInit) = dlsym(hdl, "m_DecryptInit");
    *(void **)(&dll_m_DecryptUpdate) = dlsym(hdl, "m_DecryptUpdate");
    *(void **)(&dll_m_DecryptFinal) = dlsym(hdl, "m_DecryptFinal");
    *(void **)(&dll_m_DecryptSingle) = dlsym(hdl, "m_DecryptSingle");

    *(void **)(&dll_m_ReencryptSingle) = dlsym(hdl, "m_ReencryptSingle");
    *(void **)(&dll_m_GenerateKey) = dlsym(hdl, "m_GenerateKey");
    *(void **)(&dll_m_GenerateKeyPair) = dlsym(hdl, "m_GenerateKeyPair");

    *(void **)(&dll_m_Sign) = dlsym(hdl, "m_Sign");
    *(void **)(&dll_m_SignInit) = dlsym(hdl, "m_SignInit");
    *(void **)(&dll_m_SignUpdate) = dlsym(hdl, "m_SignUpdate");
    *(void **)(&dll_m_SignFinal) = dlsym(hdl, "m_SignFinal");
    *(void **)(&dll_m_SignSingle) = dlsym(hdl, "m_SignSingle");

    *(void **)(&dll_m_Verify) = dlsym(hdl, "m_Verify");
    *(void **)(&dll_m_VerifyInit) = dlsym(hdl, "m_VerifyInit");
    *(void **)(&dll_m_VerifyUpdate) = dlsym(hdl, "m_VerifyUpdate");
    *(void **)(&dll_m_VerifyFinal) = dlsym(hdl, "m_VerifyFinal");
    *(void **)(&dll_m_VerifySingle) = dlsym(hdl, "m_VerifySingle");

    *(void **)(&dll_m_WrapKey) = dlsym(hdl, "m_WrapKey");
    *(void **)(&dll_m_UnwrapKey) = dlsym(hdl, "m_UnwrapKey");
    *(void **)(&dll_m_DeriveKey) = dlsym(hdl, "m_DeriveKey");

    *(void **)(&dll_m_GetMechanismList) = dlsym(hdl, "m_GetMechanismList");
    *(void **)(&dll_m_GetMechanismInfo) = dlsym(hdl, "m_GetMechanismInfo");
    *(void **)(&dll_m_GetAttributeValue) = dlsym(hdl, "m_GetAttributeValue");
    *(void **)(&dll_m_SetAttributeValue) = dlsym(hdl, "m_SetAttributeValue");

    *(void **)(&dll_m_Login) = dlsym(hdl, "m_Login");
    *(void **)(&dll_m_Logout) = dlsym(hdl, "m_Logout");
    *(void **)(&dll_m_admin) = dlsym(hdl, "m_admin");

    *(void **)(&dll_m_init) = dlsym(hdl, "m_init");
    *(void **)(&dll_m_add_backend) = dlsym(hdl, "m_add_backend");
    *(void **)(&dll_m_shutdown) = dlsym(hdl, "m_shutdown");

    *(void **)(&dll_xcpa_cmdblock) = dlsym(hdl, "xcpa_cmdblock");
    *(void **)(&dll_xcpa_queryblock) = dlsym(hdl, "xcpa_queryblock");
    *(void **)(&dll_xcpa_internal_rv) = dlsym(hdl, "xcpa_internal_rv");

    *(void **)(&dll_m_get_xcp_info) = dlsym(hdl, "m_get_xcp_info");

    if ((error = dlerror()) != NULL) {
        TRACE_ERROR("%s Error: %s\n", __func__, error);
        OCK_SYSLOG(LOG_ERR, "%s: Error: %s\n", __func__, error);
        return CKR_FUNCTION_FAILED;
    }

    /*
     * The following are only available since EP11 host library version 2.
     * Ignore if they fail to load, the code will fall back to the old target
     * handling in this case.
     */
    *(void **)(&dll_m_add_module) = dlsym(hdl, "m_add_module");
    *(void **)(&dll_m_rm_module) = dlsym(hdl, "m_rm_module");
    if (dll_m_add_module == NULL || dll_m_rm_module == NULL) {
        dll_m_add_module = NULL;
        dll_m_rm_module = NULL;
    }

    /*
     * The following are only available since EP11 host library version 4.1.
     * Ignore if they fail to load.
     */
    *(void **)(&dll_m_LoginExtended) = dlsym(hdl, "m_LoginExtended");
    *(void **)(&dll_m_LogoutExtended) = dlsym(hdl, "m_LogoutExtended");
    if (dll_m_LoginExtended == NULL || dll_m_LogoutExtended == NULL) {
        dll_m_LoginExtended = NULL;
        dll_m_LogoutExtended = NULL;
    }

    return CKR_OK;
}

static CK_RV ep11tok_load_libica(STDLL_TokData_t *tokdata)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    libica_t *libica = &ep11_data->libica;
    int default_libica = 0;
    char *errstr;

    if (ep11_data->digest_libica == 0)
        return CKR_OK;

    if (strcmp(ep11_data->digest_libica_path, "") == 0) {
        strcpy(ep11_data->digest_libica_path, ICASHAREDLIB_V4);
        default_libica = 1;
        libica->library = dlopen(ep11_data->digest_libica_path, RTLD_NOW);
        if (libica->library == NULL) {
            strcpy(ep11_data->digest_libica_path, ICASHAREDLIB_V3);
            libica->library = dlopen(ep11_data->digest_libica_path, RTLD_NOW);
        }
    } else {
        libica->library = dlopen(ep11_data->digest_libica_path, RTLD_NOW);
    }
    if (libica->library == NULL) {
        errstr = dlerror();
        OCK_SYSLOG(default_libica ? LOG_WARNING : LOG_ERR,
               "%s: Error loading shared library '%s' [%s]\n",
               __func__, ep11_data->digest_libica_path, errstr);
        TRACE_ERROR("%s Error loading shared library '%s' [%s]\n",
                __func__, ep11_data->digest_libica_path, errstr);
        ep11_data->digest_libica = 0;
        return default_libica ? CKR_OK : CKR_FUNCTION_FAILED;
    }

    *(void **)(&libica->ica_fips_status) = dlsym(libica->library, "ica_fips_status");
    if (libica->ica_fips_status != NULL &&
        libica->ica_fips_status() > ICA_FIPS_MODE) {
        TRACE_WARNING("%s: libica FIPS selftests failed, disable use of libica\n",
                       __func__);
    } else {
        *(void **)(&libica->ica_sha1) = dlsym(libica->library, "ica_sha1");
        *(void **)(&libica->ica_sha224) = dlsym(libica->library, "ica_sha224");
        *(void **)(&libica->ica_sha256) = dlsym(libica->library, "ica_sha256");
        *(void **)(&libica->ica_sha384) = dlsym(libica->library, "ica_sha384");
        *(void **)(&libica->ica_sha512) = dlsym(libica->library, "ica_sha512");
        *(void **)(&libica->ica_sha512_224) =
            dlsym(libica->library, "ica_sha512_224");
        *(void **)(&libica->ica_sha512_256) =
            dlsym(libica->library, "ica_sha512_256");
#ifdef SHA3_224
        *(void **)(&libica->ica_sha3_224) = dlsym(libica->library, "ica_sha3_224");
        *(void **)(&libica->ica_sha3_256) = dlsym(libica->library, "ica_sha3_256");
        *(void **)(&libica->ica_sha3_384) = dlsym(libica->library, "ica_sha3_384");
        *(void **)(&libica->ica_sha3_512) = dlsym(libica->library, "ica_sha3_512");
#endif
    }
    *(void **)(&libica->ica_cleanup) = dlsym(libica->library, "ica_cleanup");
    /* No error checking, each of the libica functions is allowed to be NULL */

    TRACE_DEVEL("%s: Loaded libica from '%s'\n", __func__,
                ep11_data->digest_libica_path);
    return CKR_OK;
}

static CK_BBOOL ep11tok_is_sel_guest(void)
{
    char buf[20];
    CK_RV rc;

    if (access(SYSFS_SEL_GUEST, R_OK) != 0)
        return FALSE;

    rc = file_fgets(SYSFS_SEL_GUEST, buf, sizeof(buf));
    if (rc != CKR_OK)
        return FALSE;

    return (buf[0] == '1');
}

CK_RV ep11tok_init(STDLL_TokData_t * tokdata, CK_SLOT_ID SlotNumber,
                   char *conf_name)
{
    CK_RV rc;
    ep11_private_data_t *ep11_data;
#ifndef EP11_HSMSIM
    const CK_VERSION ver4_1 = { .major = 4, .minor = 1 };
#endif

    TRACE_INFO("ep11 %s slot=%lu running\n", __func__, SlotNumber);

    /* Request the API layer to lock against HSM-MK-change state changes. */
    rc = init_hsm_mk_change_lock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("init_hsm_mk_change_lock failed.\n");
        goto error;
    }

    ep11_data = calloc(1, sizeof(ep11_private_data_t));
    if (ep11_data == NULL)
        return CKR_HOST_MEMORY;

    if (pthread_rwlock_init(&ep11_data->target_rwlock, NULL) != 0) {
        TRACE_DEVEL("Target Lock init failed.\n");
        OCK_SYSLOG(LOG_ERR, "%s: Failed to initialize the target lock\n",
                   __func__);
        rc = CKR_CANT_LOCK;
        free(ep11_data);
        goto error;
    }

    tokdata->private_data = ep11_data;

    /* read ep11 specific config file with user specified
     * adapter/domain pairs */
    rc = read_adapter_config_file(tokdata, conf_name);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ep11 config file error rc=0x%lx\n", __func__, rc);
        goto error;
    }

    /* dynamically load in the ep11 shared library */
    ep11_data->lib_ep11 = ep11_load_host_lib();
    if (ep11_data->lib_ep11 == NULL) {
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    rc = ep11_resolve_lib_sym(ep11_data->lib_ep11);
    if (rc != CKR_OK)
        goto error;

#ifndef XCP_STANDALONE
    /* call ep11 shared lib init */
    if (dll_m_init() < 0) {
        TRACE_ERROR("%s ep11 lib init failed\n", __func__);
        OCK_SYSLOG(LOG_ERR,
                   "%s: Error: EP 11 library initialization failed\n",
                   __func__);
        rc = CKR_DEVICE_ERROR;
        goto error;
    }
#endif

    rc = ep11tok_get_ep11_library_version(&ep11_data->ep11_lib_version);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to get the Ep11 library version "
                    "(ep11tok_get_ep11_library_version rc=0x%lx)\n", __func__,
                    rc);
        OCK_SYSLOG(LOG_ERR, "%s: Failed to get the EP11 library version "
                   "rc=0x%lx\n", __func__, rc);
        goto error;
    }

    TRACE_INFO("%s Host library version: %d.%d.%d\n", __func__,
               ep11_data->ep11_lib_version.major,
               (ep11_data->ep11_lib_version.minor & 0xF0) >> 4,
               (ep11_data->ep11_lib_version.minor & 0x0F));

#ifndef EP11_HSMSIM
    if (ep11_data->fips_session_mode) {
        if (compare_ck_version(&ep11_data->ep11_lib_version, &ver4_1) < 0 ||
            dll_m_LoginExtended == NULL || dll_m_LogoutExtended == NULL) {
            TRACE_ERROR("%s EP11 host library does not support LoginExtended "
                        "but this is required for FIPS-session mode\n",
                        __func__);
            OCK_SYSLOG(LOG_ERR,
                       "The EP11 host library does not support LoginExtended "
                       "but this is required for FIPS-session mode\n");
            rc = CKR_DEVICE_ERROR;
            goto error;
        }
    }
#endif

    rc = ep11tok_mk_change_check_pending_ops(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to check for pending HSM MK change operations "
                    "rc=0x%lx\n", __func__, rc);
        OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to check for pending HSM MK "
                   "change operations rc=0x%lx\n", tokdata->slot_id, rc);
        goto error;
    }

    rc = refresh_target_info(tokdata, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to get the target info (refresh_target_info "
                    "rc=0x%lx)\n", __func__, rc);
        OCK_SYSLOG(LOG_ERR, "%s: Failed to get the target info rc=0x%lx\n",
                   __func__, rc);
        goto error;
    }

    if (ep11_data->digest_libica) {
        rc = ep11tok_load_libica(tokdata);
        if (rc != CKR_OK)
            goto error;
    }

#ifndef NO_PKEY
    ep11_data->msa_level = get_msa_level();
    TRACE_INFO("MSA level = %i\n", ep11_data->msa_level);
#endif

    if (pthread_mutex_init(&ep11_data->raw2key_wrap_blob_mutex, NULL) != 0) {
        TRACE_ERROR("Initializing Wrap-Blob lock failed.\n");
        rc = CKR_CANT_LOCK;
        goto error;
    }
    ep11_data->raw2key_wrap_blob_l = 0;

    if (pthread_mutex_init(&ep11_data->pkey_mutex, NULL) != 0) {
        TRACE_ERROR("Initializing PKEY lock failed.\n");
        rc = CKR_CANT_LOCK;
        goto error;
    }

#ifndef NO_PKEY
    if (!ep11tok_pkey_option_disabled(tokdata) &&
        !ep11_data->fips_session_mode) {
        rc = ep11tok_pkey_get_firmware_mk_vp(tokdata, NULL);
        if (rc != CKR_OK && rc != CKR_FUNCTION_NOT_SUPPORTED)
            goto error;
    }
#endif /* NO_PKEY */

    if (ep11_data->vhsm_mode || ep11_data->fips_session_mode) {
        if (ep11tok_is_sel_guest() && (
#ifndef EP11_HSMSIM
             compare_ck_version(&ep11_data->ep11_lib_version, &ver4_1) < 0 ||
#endif
             ep11_data->target_info->used_firmware_API_version < 6)) {
            TRACE_ERROR("Strict-session or VHSM mode requires an EP11 "
                        "host library >= v4.1 and API ordinal >= 6 when "
                        "running in a Secure Execution for Linux guest\n");
            OCK_SYSLOG(LOG_ERR, "Slot %lu: Strict-session or VHSM mode "
                       "requires an EP11 host library >= v4.1 and API ordinal "
                       ">= 6 when running in a Secure Execution for Linux "
                       "guest\n", tokdata->slot_id);
            rc = CKR_FUNCTION_FAILED;
            goto error;
        }

        if (pthread_mutex_init(&ep11_data->session_mutex, NULL) != 0) {
            TRACE_ERROR("Initializing session lock failed.\n");
            rc = CKR_CANT_LOCK;
            goto error;
        }
    }
    ep11_data->get_session_refcount = tokdata->tokspec_counter.get_tokspec_count;
    ep11_data->incr_session_refcount = tokdata->tokspec_counter.incr_tokspec_count;
    ep11_data->decr_session_refcount = tokdata->tokspec_counter.decr_tokspec_count;

    TRACE_INFO("%s init done successfully\n", __func__);
    return CKR_OK;

error:
    ep11tok_final(tokdata, FALSE);
    TRACE_INFO("%s init failed with rc: 0x%lx\n", __func__, rc);
    return rc;
}

CK_RV ep11tok_final(STDLL_TokData_t * tokdata, CK_BBOOL in_fork_initializer)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

    TRACE_INFO("ep11 %s running\n", __func__);

    if (ep11_data != NULL) {
        if (ep11_data->target_info != NULL) {
            if (dll_m_rm_module != NULL)
                dll_m_rm_module(NULL, ep11_data->target_info->target);
            free_card_versions(ep11_data->target_info->card_versions);
            free((void* )ep11_data->target_info);
        }
        pthread_rwlock_destroy(&ep11_data->target_rwlock);
        pthread_mutex_destroy(&ep11_data->raw2key_wrap_blob_mutex);
        if (ep11_data->vhsm_mode || ep11_data->fips_session_mode)
            pthread_mutex_destroy(&ep11_data->session_mutex);
        pthread_mutex_destroy(&ep11_data->pkey_mutex);
        free_cp_config(ep11_data->cp_config);
        if (ep11_data->libica.ica_cleanup != NULL && !in_fork_initializer)
            ep11_data->libica.ica_cleanup();
        if (ep11_data->libica.library != NULL && !in_fork_initializer)
            dlclose(ep11_data->libica.library);
        if (ep11_data->lib_ep11 != NULL && !in_fork_initializer)
            dlclose(ep11_data->lib_ep11);
        if (ep11_data->mk_change_apqns != NULL)
            free(ep11_data->mk_change_apqns);
        free(ep11_data);
        tokdata->private_data = NULL;
    }

    return CKR_OK;
}

static CK_RV check_add_spki_attr(STDLL_TokData_t *tokdata,
                                 CK_ATTRIBUTE_PTR attr, CK_KEY_TYPE keytype,
                                 int curve_type,
                                 CK_ATTRIBUTE_PTR *attrs, CK_ULONG *attrs_len)
{
    CK_MECHANISM mech = { CKM_IBM_TRANSPORTKEY, 0, 0 };
    CK_BBOOL bool_value;
    CK_RV rc;

    if (!attr_applicable_for_ep11(tokdata, attr, keytype,
                                  CKO_PUBLIC_KEY, curve_type, &mech))
        return CKR_OK;

    switch (attr->type) {
    case CKA_ENCRYPT:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
        if (attr->ulValueLen != sizeof(CK_BOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        /*
         * EP11 does not allow to restrict public RSA/DSA/EC keys with
         * CKA_VERIFY=FALSE and/or CKA_ENCRYPT=FALSE since it can not
         * technically enforce the restrictions. Therefore override these
         * attributes for the EP11 library, but keep the original attribute
         * values in the object.
         */
        if (keytype == CKK_EC || keytype == CKK_RSA || keytype == CKK_DSA)
            bool_value = CK_TRUE;
        else
            bool_value = *(CK_BBOOL *)attr->pValue;
        rc = add_to_attribute_array(attrs, attrs_len, attr->type,
                                    &bool_value, sizeof(bool_value));
        if (rc != CKR_OK) {
            TRACE_ERROR("%s adding attribute failed type=0x%lx rc=0x%lx\n",
                        __func__, attr->type, rc);
            return rc;
        }
        break;

    case CKA_EXTRACTABLE:
    case CKA_MODIFIABLE:
    case CKA_DERIVE:
    case CKA_WRAP:
    case CKA_TRUSTED:
    case CKA_IBM_RESTRICTABLE:
    case CKA_IBM_ATTRBOUND:
        if (attr->ulValueLen > 0 && attr->pValue == NULL) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        rc = add_to_attribute_array(attrs, attrs_len, attr->type,
                                    attr->pValue, attr->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s adding attribute failed type=0x%lx rc=0x%lx\n",
                        __func__, attr->type, rc);
            return rc;
        }
        break;

    default:
        break;
    }

    return CKR_OK;
}

/*
 * Makes a public key blob which is a MACed SPKI of the public key.
 * Either pub_key_obj or pub_key_attrs/pub_key_attrs_len must be specified
 * to supply the public key attributes.
 */
static CK_RV make_maced_spki(STDLL_TokData_t *tokdata, SESSION *sess,
                             OBJECT *pub_key_obj,
                             CK_ATTRIBUTE *pub_key_attrs,
                             CK_ULONG pub_key_attrs_len,
                             CK_BYTE *spki, CK_ULONG spki_len,
                             CK_BYTE *maced_spki, CK_BYTE *maced_spki_reenc,
                             CK_ULONG *maced_spki_len, int curve_type)
{
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;
    CK_MECHANISM mech = { CKM_IBM_TRANSPORTKEY, 0, 0 };
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    DL_NODE *node;
    CK_BYTE csum[MAX_BLOBSIZE];
    CK_ULONG cslen = sizeof(csum);
    CK_KEY_TYPE keytype;
    CK_BBOOL is_private, is_session;
    CK_BYTE *tmp;
    CK_ULONG i, tmp_len, seq_len;
    CK_RV rc;

    if (spki_len < 6 ||
        ber_decode_SEQUENCE(spki, &tmp, &tmp_len, &seq_len) != CKR_OK) {
        TRACE_ERROR("%s Its not an SPKI\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    if (seq_len < spki_len)
        spki_len = seq_len;

    if (pub_key_obj != NULL) {
        rc = template_attribute_get_ulong(pub_key_obj->template, CKA_KEY_TYPE,
                                          &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto make_maced_spki_end;
        }

        is_private = object_is_private(pub_key_obj);
        is_session = object_is_session_object(pub_key_obj);

        /*
         * m_UnwrapKey with CKM_IBM_TRANSPORTKEY allows boolean attributes only
         * to be added to MACed-SPKIs
         */
        node = pub_key_obj->template->attribute_list;
        while (node != NULL) {
            rc = check_add_spki_attr(tokdata, node->data, keytype, curve_type,
                                     &p_attrs, &attrs_len);
            if (rc != CKR_OK)
                goto make_maced_spki_end;

            node = node->next;
        }
    } else {
        rc = get_ulong_attribute_by_type(pub_key_attrs, pub_key_attrs_len,
                                         CKA_KEY_TYPE, &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto make_maced_spki_end;
        }

        is_private = ep11_is_private_object(pub_key_attrs, pub_key_attrs_len);
        is_session = ep11_is_session_object(pub_key_attrs, pub_key_attrs_len);

        /*
         * m_UnwrapKey with CKM_IBM_TRANSPORTKEY allows boolean attributes only
         * to be added to MACed-SPKIs
         */
        for (i = 0; i < pub_key_attrs_len; i++) {
            rc = check_add_spki_attr(tokdata, &pub_key_attrs[i], keytype,
                                     curve_type, &p_attrs, &attrs_len);
            if (rc != CKR_OK)
                goto make_maced_spki_end;
        }
    }

    trace_attributes(__func__, "MACed SPKI import:", p_attrs, attrs_len);

    ep11_get_pin_blob(tokdata, ep11_session, is_session, is_private,
                      &ep11_pin_blob, &ep11_pin_blob_len);

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_CREATE_KEY_START()
        rc = dll_m_UnwrapKey(spki, spki_len, NULL, 0, NULL, 0,
                             ep11_pin_blob, ep11_pin_blob_len, &mech,
                             p_attrs, attrs_len, maced_spki, maced_spki_len,
                             csum, &cslen, target_info->target);
    RETRY_REENC_CREATE_KEY_END(tokdata, sess, target_info, maced_spki,
                               maced_spki_reenc, *maced_spki_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s unwrapping SPKI rc=0x%lx spki_len=0x%zx maced_spki_len=0x%zx\n",
                    __func__, rc, spki_len, *maced_spki_len);
    } else {
        TRACE_INFO("%s unwrapping SPKI rc=0x%lx spki_len=0x%zx maced_spki_len=0x%zx\n",
                   __func__, rc, spki_len, *maced_spki_len);
    }

make_maced_spki_end:
    if (p_attrs != NULL)
            cleanse_and_free_attribute_array(p_attrs, attrs_len);

    return rc;
}

/**
 * Determine the curve type from the given template.
 *
 * @return a valid curve_type if successful
 *         -1 if no CKA_ECDSA_PARAMS found in template
 */
static int get_curve_type_from_template(TEMPLATE *tmpl)
{
    CK_ATTRIBUTE *ec_params;
    int i, curve_type = -1;
    CK_RV ret;

    ret = template_attribute_get_non_empty(tmpl, CKA_EC_PARAMS, &ec_params);
    if (ret != CKR_OK) {
        TRACE_ERROR("Could not find CKA_EC_PARAMS for the key.\n");
        return curve_type;
    }

    for (i = 0; i < NUMEC; i++) {
        if (der_ec_supported[i].data_size == ec_params->ulValueLen &&
            memcmp(ec_params->pValue, der_ec_supported[i].data,
                   ec_params->ulValueLen) == 0) {
            curve_type = der_ec_supported[i].curve_type;
            break;
        }
    }

    return curve_type;
}

static int get_curve_type_from_spki(CK_BYTE *spki, CK_ULONG spki_len)
{
    CK_BYTE *algid = NULL;
    CK_ULONG algid_len;
    CK_BYTE *algid_ECBase = NULL;
    CK_BYTE *param = NULL;
    CK_ULONG param_len;
    CK_BYTE *pubkey = NULL;
    CK_ULONG pubkey_len;
    CK_ULONG field_len, len, i;
    CK_RV rc;

    UNUSED(spki_len);

    rc = ber_decode_SPKI(spki, &algid, &algid_len, &param, &param_len,
                         &pubkey, &pubkey_len);
    if (rc != CKR_OK) {
       TRACE_DEVEL("ber_decode_SPKI failed\n");
       return -1;
    }

    /*
     * Check if we're dealing with an EC key.
     * Extract base alg-id of DER encoded EC byte string
     * and compare against the decoded alg-id from the inner sequence
     */
    rc = ber_decode_SEQUENCE((CK_BYTE *)der_AlgIdECBase, &algid_ECBase, &len,
                             &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return -1;
    }

    if (memcmp(algid, algid_ECBase, len) != 0) {
         /* Not an EC SPKI, ignore */
        return -1;
    }

    for (i = 0; i < NUMEC; i++) {
        if (der_ec_supported[i].data_size ==  param_len &&
            memcmp(param, der_ec_supported[i].data, param_len) == 0) {
            return der_ec_supported[i].curve_type;
        }
    }

    return -1;
}

/* import a AES-XTS key, that is, make a blob for a AES XTS key
 * that was not created by EP11 hardware, encrypt the key by the wrap key,
 * unwrap it by the wrap key
 */
static CK_RV import_aes_xts_key(STDLL_TokData_t *tokdata, SESSION *sess,
                                OBJECT *aes_xts_key_obj,
                                CK_BYTE *blob, CK_BYTE *blobreenc,
                                size_t *blob_size)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_BYTE cipher[MAX_BLOBSIZE];
    CK_ULONG clen = sizeof(cipher);
    CK_BYTE csum[MAX_CSUMSIZE];
    size_t cslen = sizeof(csum);
    CK_BYTE iv[AES_BLOCK_SIZE];
    size_t blob_size2 = *blob_size;
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
    CK_RV rc;
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    CK_ATTRIBUTE_PTR new_p_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_ATTRIBUTE *attr = NULL;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t*) sess->private_data;
    CK_BYTE *wrap_blob;
    CK_BBOOL blob_new_mk = CK_FALSE, blob2_new_mk;

    rc = template_attribute_get_non_empty(aes_xts_key_obj->template, CKA_VALUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    if (memcmp(attr->pValue,
               ((CK_BYTE *)attr->pValue) + attr->ulValueLen / 2,
               attr->ulValueLen / 2) == 0) {
        TRACE_ERROR("The 2 key parts of an AES-XTS key can not be the same\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    /* tell ep11 the attributes the user specified */
    rc = build_ep11_attrs(tokdata, aes_xts_key_obj->template, &p_attrs,
                          &attrs_len, CKK_AES, CKO_SECRET_KEY, -1, &mech);
    if (rc != CKR_OK)
        goto import_aes_xts_key_end;

#ifndef NO_PKEY
    rc = ep11tok_pkey_check_aes_xts(tokdata, aes_xts_key_obj, CKM_AES_XTS);
#else
    rc = CKR_FUNCTION_NOT_SUPPORTED;
#endif
    if (rc != CKR_OK) {
        TRACE_ERROR("%s EP11 AES XTS is not supported: rc=0x%lx\n", __func__, rc);
        goto import_aes_xts_key_end;
    }

    rc = check_key_attributes(tokdata, CKK_AES, CKO_SECRET_KEY, p_attrs,
                              attrs_len, &new_p_attrs, &new_attrs_len, -1);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s AES XTS check private key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto import_aes_xts_key_end;
    }

    trace_attributes(__func__, "Import sym.:", new_p_attrs, new_attrs_len);

    ep11_get_pin_blob(tokdata, ep11_session,
                      object_is_session_object(aes_xts_key_obj),
                      object_is_private(aes_xts_key_obj),
                      &ep11_pin_blob, &ep11_pin_blob_len);

retry:
    memset(cipher, 0, sizeof(cipher));
    memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

    /*
     * calls the ep11 lib (which in turns sends the request to the card),
     * all m_ function are ep11 functions
     */
    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
        rc = dll_m_EncryptSingle(wrap_blob,
                                 ep11_data->raw2key_wrap_blob_l, &mech,
                                 attr->pValue, attr->ulValueLen / 2,
                                 cipher, &clen, target_info->target);
    RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s encrypt ksize=0x%lx clen=0x%lx rc=0x%lx\n", __func__,
                    attr->ulValueLen / 2, clen, rc);
        goto import_aes_xts_key_end;
    } else {
        TRACE_INFO("%s encrypt ksize=0x%lx clen=0x%lx rc=0x%lx\n", __func__,
                   attr->ulValueLen / 2, clen, rc);
    }

    /* the encrypted key is decrypted and a blob is built,
     * card accepts only blobs as keys
     */
    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
    RETRY_REENC_CREATE_KEY_START()
        rc = dll_m_UnwrapKey(cipher, clen, wrap_blob,
                             ep11_data->raw2key_wrap_blob_l, NULL, ~0, ep11_pin_blob,
                             ep11_pin_blob_len, &mech, new_p_attrs, new_attrs_len,
                             blob, blob_size, csum, &cslen, target_info->target);
    RETRY_REENC_CREATE_KEY_END(tokdata, sess, target_info, blob, blobreenc,
                               *blob_size, rc)
    RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s unwrap blen=%zd rc=0x%lx\n", __func__, *blob_size, rc);
        goto import_aes_xts_key_end;
    } else {
        TRACE_INFO("%s unwrap blen=%zd rc=0x%lx\n", __func__, *blob_size, rc);
    }

    if (ep11_data->mk_change_active)
        blob_new_mk = ep11tok_is_blob_new_wkid(tokdata, blob, *blob_size);

    memset(cipher, 0, sizeof(cipher));

    /*
     * calls the ep11 lib (which in turns sends the request to the card),
     * all m_ function are ep11 functions
     */
    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
        rc = dll_m_EncryptSingle(wrap_blob,
                                 ep11_data->raw2key_wrap_blob_l, &mech,
                                 ((CK_BYTE *)attr->pValue) + attr->ulValueLen / 2,
                                 attr->ulValueLen / 2, cipher, &clen,
                                 target_info->target);
    RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s encrypt ksize=0x%lx clen=0x%lx rc=0x%lx\n",
                    __func__, attr->ulValueLen / 2, clen, rc);
        goto import_aes_xts_key_end;
    } else {
        TRACE_INFO("%s encrypt ksize=0x%lx clen=0x%lx rc=0x%lx\n", __func__,
                   attr->ulValueLen / 2, clen, rc);
    }

    trace_attributes(__func__, "Import sym.:", new_p_attrs, new_attrs_len);

    /* update the remaining buffer size in blob */
    blob_size2 = blob_size2 - *blob_size;

    /* the encrypted key is decrypted and a blob is built,
     * card accepts only blobs as keys
     */
    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
    RETRY_REENC_CREATE_KEY_START()
        rc = dll_m_UnwrapKey(cipher, clen,
                             wrap_blob,
                             ep11_data->raw2key_wrap_blob_l, NULL, ~0,
                             ep11_pin_blob, ep11_pin_blob_len, &mech,
                             new_p_attrs, new_attrs_len, blob + *blob_size,
                             &blob_size2, csum, &cslen, target_info->target);
    RETRY_REENC_CREATE_KEY_END(tokdata, sess, target_info, blob + *blob_size,
                               blobreenc + *blob_size, blob_size2, rc)
    RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s unwrap blen=%zd rc=0x%lx\n", __func__, blob_size2, rc);
        goto import_aes_xts_key_end;
    } else {
        TRACE_INFO("%s unwrap blen=%zd rc=0x%lx\n", __func__, blob_size2, rc);
    }

    if (ep11_data->mk_change_active) {
        blob2_new_mk = ep11tok_is_blob_new_wkid(tokdata, blob + *blob_size,
                                                blob_size2);
        if (blob_new_mk != blob2_new_mk) {
            /*
             * New MK has been set after importing key 1 but before
             * importing key 2
             */
            if (blob2_new_mk == TRUE) {
                /*
                 * Key 2 was created with new MK, key 1 with old MK.
                 * Key 2 already has blob and reenc_blob with new MK,
                 * Key 1 has blob with old MK, and blob_reenc with new MK.
                 * Supply blob_reenc with new MK in blob also.
                 */
                memcpy(blob, blobreenc, *blob_size);
            } else {
                /*
                 * Key 1 was created with new MK, but key 2 with old MK.
                 * This can happen when the single APQN with new MK went offline
                 * and a new single APQN with old MK is selected after creating
                 * key 1 but before creating key 2. Since there is no key1 blob
                 * with old MK, we need to re-create both keys (both with old
                 * MK now).
                 */
                goto retry;
            }
        }
    }

    /* update the concatenated blobsize */
    *blob_size = *blob_size + blob_size2;

    cleanse_attribute(aes_xts_key_obj->template, CKA_VALUE);

import_aes_xts_key_end:
    if (rc != CKR_OK)
        cleanse_attribute(aes_xts_key_obj->template, CKA_VALUE);
    if (p_attrs != NULL)
        cleanse_and_free_attribute_array(p_attrs, attrs_len);
    if (new_p_attrs)
        cleanse_and_free_attribute_array(new_p_attrs, new_attrs_len);
    return rc;
}

/*
 * makes blobs for private imported RSA keys and
 * SPKIs for public imported RSA keys.
 * Similar to rawkey_2_blob, but keys must follow a standard BER encoding.
 */
static CK_RV import_RSA_key(STDLL_TokData_t *tokdata, SESSION *sess,
                            OBJECT *rsa_key_obj,
                            CK_BYTE *blob, CK_BYTE *blobreenc,
                            size_t *blob_size,
                            CK_BYTE *spki, size_t *spki_size)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE iv[AES_BLOCK_SIZE];
    CK_MECHANISM mech_w = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
    CK_BYTE cipher[MAX_BLOBSIZE];
    CK_ULONG cipher_l = sizeof(cipher);
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    CK_ATTRIBUTE_PTR new_p_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_OBJECT_CLASS class;
    CK_BYTE *data = NULL;
    CK_ULONG data_len;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;
    CK_BYTE *wrap_blob;

    memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

    /* need class for private/public key info */
    rc = template_attribute_get_ulong(rsa_key_obj->template, CKA_CLASS,
                                      &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    /* m_Unwrap builds key blob in the card,
     * tell ep11 the attributes the user specified for that key.
     */
    rc = build_ep11_attrs(tokdata, rsa_key_obj->template, &p_attrs, &attrs_len,
                          CKK_RSA, class, -1, &mech_w);
    if (rc != CKR_OK)
        goto import_RSA_key_end;

    if (class != CKO_PRIVATE_KEY) {

        /* an imported public RSA key, we need a SPKI for it. */

        CK_ATTRIBUTE *modulus;
        CK_ATTRIBUTE *publ_exp;

        rc = template_attribute_get_non_empty(rsa_key_obj->template,
                                              CKA_MODULUS, &modulus);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
            goto import_RSA_key_end;
        }

        rc = template_attribute_get_non_empty(rsa_key_obj->template,
                                              CKA_PUBLIC_EXPONENT, &publ_exp);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_PUBLIC_EXPONENT for the key.\n");
            goto import_RSA_key_end;
        }

        /* our contribution to asn1.c,
         * builds the BER encoding that is a SPKI.
         */
        rc = ber_encode_RSAPublicKey(0, &data, &data_len, modulus, publ_exp);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s public key import class=0x%lx rc=0x%lx "
                        "data_len=0x%lx\n", __func__, class, rc, data_len);
            goto import_RSA_key_end;
        } else {
            TRACE_INFO("%s public key import class=0x%lx rc=0x%lx "
                       "data_len=0x%lx\n", __func__, class, rc, data_len);
        }

        /* save the SPKI as blob although it is not a blob.
         * The card expects MACed-SPKIs as public keys.
         */
        rc = make_maced_spki(tokdata, sess, rsa_key_obj, NULL, 0,
                             data, data_len,
                             blob, blobreenc, blob_size, -1);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s failed to make a MACed-SPKI rc=0x%lx\n",
                        __func__, rc);
            goto import_RSA_key_end;
        }

        *spki_size = 0; /* common code will extract SPKI from object */

    } else {

        /* imported private RSA key goes here */

        rc = rsa_priv_check_and_swap_pq(rsa_key_obj->template);
        if (rc != CKR_OK) {
            TRACE_DEVEL("%s RSA check and swap failed\n", __func__);
            goto import_RSA_key_end;
        }

        /* extract the secret data to be wrapped
         * since this is AES_CBC_PAD, padding is done in mechanism.
         */
        rc = rsa_priv_wrap_get_data(rsa_key_obj->template, FALSE,
                                    &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("%s RSA wrap get data failed\n", __func__);
            goto import_RSA_key_end;
        }

        /* encrypt */
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
            rc = dll_m_EncryptSingle(wrap_blob, ep11_data->raw2key_wrap_blob_l,
                                     &mech_w, data, data_len, cipher, &cipher_l,
                                     target_info->target);
        RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

        TRACE_INFO("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                   __func__, rc, cipher_l);

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                        __func__, rc, cipher_l);
            goto import_RSA_key_end;
        }

        rc = check_key_attributes(tokdata, CKK_RSA, CKO_PRIVATE_KEY, p_attrs,
                                  attrs_len, &new_p_attrs, &new_attrs_len, -1);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s RSA/EC check private key attributes failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto import_RSA_key_end;
        }

        trace_attributes(__func__, "RSA import:", new_p_attrs, new_attrs_len);

        ep11_get_pin_blob(tokdata, ep11_session,
                          object_is_session_object(rsa_key_obj),
                          object_is_private(rsa_key_obj),
                          &ep11_pin_blob, &ep11_pin_blob_len);

        /* calls the card, it decrypts the private RSA key,
         * reads its BER format and builds a blob.
         */
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
        RETRY_REENC_CREATE_KEY_START()
            rc = dll_m_UnwrapKey(cipher, cipher_l, wrap_blob,
                                 ep11_data->raw2key_wrap_blob_l, NULL, ~0,
                                 ep11_pin_blob, ep11_pin_blob_len, &mech_w,
                                 new_p_attrs, new_attrs_len, blob, blob_size,
                                 spki, spki_size, target_info->target);
        RETRY_REENC_CREATE_KEY_END(tokdata, sess, target_info,
                                   blob, blobreenc, *blob_size, rc)
        RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                        __func__, rc, *blob_size);
        } else {
            TRACE_INFO("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                       __func__, rc, *blob_size);
        }

        cleanse_attribute(rsa_key_obj->template, CKA_PRIVATE_EXPONENT);
        cleanse_attribute(rsa_key_obj->template, CKA_PRIME_1);
        cleanse_attribute(rsa_key_obj->template, CKA_PRIME_2);
        cleanse_attribute(rsa_key_obj->template, CKA_EXPONENT_1);
        cleanse_attribute(rsa_key_obj->template, CKA_EXPONENT_2);
        cleanse_attribute(rsa_key_obj->template, CKA_COEFFICIENT);
    }

import_RSA_key_end:
    if (data) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }
    if (p_attrs != NULL)
        cleanse_and_free_attribute_array(p_attrs, attrs_len);
    if (new_p_attrs)
        cleanse_and_free_attribute_array(new_p_attrs, new_attrs_len);
    return rc;
}

/*
 * makes blobs for private imported EC keys and
 * SPKIs for public imported EC keys.
 * Similar to rawkey_2_blob, but keys must follow a standard BER encoding.
 */
static CK_RV import_EC_key(STDLL_TokData_t *tokdata, SESSION *sess,
                           OBJECT *ec_key_obj,
                           CK_BYTE *blob,  CK_BYTE *blobreenc,
                           size_t *blob_size,
                           CK_BYTE *spki, size_t *spki_size)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE iv[AES_BLOCK_SIZE];
    CK_MECHANISM mech_w = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
    CK_BYTE cipher[MAX_BLOBSIZE];
    CK_ULONG cipher_l = sizeof(cipher);
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    CK_ATTRIBUTE_PTR new_p_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_OBJECT_CLASS class;
    CK_BYTE *data = NULL;
    CK_ULONG data_len;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;
    CK_ULONG privkey_len, pubkey_len;
    CK_BYTE *pubkey = NULL;
    const struct _ec *curve = NULL;
    CK_BYTE *wrap_blob;

    memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

    /* need class for private/public key info */
    rc = template_attribute_get_ulong(ec_key_obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    if (!ep11tok_ec_curve_supported2(tokdata, ec_key_obj->template, &curve)) {
        TRACE_ERROR("Curve not supported.\n");
        return CKR_CURVE_NOT_SUPPORTED;
    }

    /* m_Unwrap builds key blob in the card,
     * tell ep11 the attributes the user specified for that key.
     */
    rc = build_ep11_attrs(tokdata, ec_key_obj->template, &p_attrs, &attrs_len,
                          CKK_EC, class, (int)curve->curve_type, &mech_w);
    if (rc != CKR_OK)
        goto import_EC_key_end;

    if (class != CKO_PRIVATE_KEY) {

        /* an imported public EC key, we need a SPKI for it. */

        CK_ATTRIBUTE *ec_params;
        CK_ATTRIBUTE *ec_point_attr;
        CK_ATTRIBUTE ec_point_uncompr;
        CK_BYTE *ecpoint;
        CK_ULONG ecpoint_len, field_len;

        rc = template_attribute_get_non_empty(ec_key_obj->template,
                                              CKA_EC_PARAMS, &ec_params);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_EC_PARAMS for the key.\n");
            goto import_EC_key_end;
        }

        rc = template_attribute_get_non_empty(ec_key_obj->template,
                                              CKA_EC_POINT, &ec_point_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_EC_POINT for the key.\n");
            goto import_EC_key_end;
        }

        /* CKA_EC_POINT is an BER encoded OCTET STRING. Extract it. */
        rc = ber_decode_OCTET_STRING((CK_BYTE *)ec_point_attr->pValue, &ecpoint,
                                     &ecpoint_len, &field_len);
        if (rc != CKR_OK || ec_point_attr->ulValueLen != field_len) {
            TRACE_DEVEL("%s ber_decode_OCTET_STRING failed\n", __func__);
            rc = CKR_ATTRIBUTE_VALUE_INVALID;
            goto import_EC_key_end;
        }

        /* Uncompress the public key (EC_POINT) */
        rc = get_ecsiglen(ec_key_obj, &privkey_len);
        if (rc != CKR_OK)
            goto import_EC_key_end;
        privkey_len /= 2; /* private key is half the size of an EC signature */

        pubkey_len = 1 + 2 * privkey_len;
        pubkey = (CK_BYTE *)malloc(pubkey_len);
        if (pubkey == NULL) {
            rc = CKR_HOST_MEMORY;
            goto import_EC_key_end;
        }

        rc = ec_uncompress_public_key(ec_params->pValue, ec_params->ulValueLen,
                                      ecpoint, ecpoint_len,
                                      privkey_len, pubkey, &pubkey_len);
        if (rc != CKR_OK)
            goto import_EC_key_end;

        /* build ec-point attribute as BER encoded OCTET STRING */
        rc = ber_encode_OCTET_STRING(FALSE, &ecpoint, &ecpoint_len,
                                     pubkey, pubkey_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
            goto import_EC_key_end;
        }

        ec_point_uncompr.type = ec_point_attr->type;
        ec_point_uncompr.pValue = ecpoint;
        ec_point_uncompr.ulValueLen = ecpoint_len;

        /*
         * Builds the DER encoding (ansi_x962) SPKI.
         */
        rc = ber_encode_ECPublicKey(FALSE, &data, &data_len,
                                    ec_params, &ec_point_uncompr);
        free(ecpoint);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s public key import class=0x%lx rc=0x%lx "
                        "data_len=0x%lx\n", __func__, class, rc, data_len);
            goto import_EC_key_end;
        } else {
            TRACE_INFO("%s public key import class=0x%lx rc=0x%lx "
                       "data_len=0x%lx\n", __func__, class, rc, data_len);
        }

        /* save the SPKI as blob although it is not a blob.
         * The card expects MACed-SPKIs as public keys.
         */
        rc = make_maced_spki(tokdata, sess, ec_key_obj, NULL, 0,
                             data, data_len,
                             blob, blobreenc, blob_size,
                             (int)curve->curve_type);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s failed to make a MACed-SPKI rc=0x%lx\n",
                        __func__, rc);
            goto import_EC_key_end;
        }

        *spki_size = 0; /* common code will extract SPKI from object */

    } else {

        /* imported private EC key goes here */

        /* extract the secret data to be wrapped
         * since this is AES_CBC_PAD, padding is done in mechanism.
         */
        rc = ecdsa_priv_wrap_get_data(ec_key_obj->template, FALSE,
                                      &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("%s EC wrap get data failed\n", __func__);
            goto import_EC_key_end;
        }

        /* encrypt */
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
            rc = dll_m_EncryptSingle(wrap_blob, ep11_data->raw2key_wrap_blob_l,
                                     &mech_w, data, data_len,
                                     cipher, &cipher_l, target_info->target);
        RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

        TRACE_INFO("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                   __func__, rc, cipher_l);

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                        __func__, rc, cipher_l);
            goto import_EC_key_end;
        }

        rc = check_key_attributes(tokdata, CKK_EC, CKO_PRIVATE_KEY, p_attrs,
                                  attrs_len, &new_p_attrs, &new_attrs_len,
                                  (int)curve->curve_type);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s EC check private key attributes failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto import_EC_key_end;
        }

        trace_attributes(__func__, "EC import:", new_p_attrs, new_attrs_len);

        ep11_get_pin_blob(tokdata, ep11_session,
                          object_is_session_object(ec_key_obj),
                          object_is_private(ec_key_obj),
                          &ep11_pin_blob, &ep11_pin_blob_len);

        /* calls the card, it decrypts the private EC key,
         * reads its BER format and builds a blob.
         */
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
        RETRY_REENC_CREATE_KEY_START()
            rc = dll_m_UnwrapKey(cipher, cipher_l,
                                 wrap_blob,
                                 ep11_data->raw2key_wrap_blob_l, NULL, ~0,
                                 ep11_pin_blob,
                                 ep11_pin_blob_len, &mech_w,
                                 new_p_attrs, new_attrs_len, blob,
                                 blob_size, spki, spki_size,
                                 target_info->target);
        RETRY_REENC_CREATE_KEY_END(tokdata, sess, target_info,
                                   blob, blobreenc, *blob_size, rc)
        RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                        __func__, rc, *blob_size);
        } else {
            TRACE_INFO("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                       __func__, rc, *blob_size);
        }

        cleanse_attribute(ec_key_obj->template, CKA_VALUE);
    }

import_EC_key_end:
    if (pubkey)
        free(pubkey);
    if (data) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }
    if (p_attrs != NULL)
        cleanse_and_free_attribute_array(p_attrs, attrs_len);
    if (new_p_attrs)
        cleanse_and_free_attribute_array(new_p_attrs, new_attrs_len);
    return rc;
}

/*
 * makes blobs for private imported DSA keys and
 * SPKIs for public imported DSA keys.
 * Similar to rawkey_2_blob, but keys must follow a standard BER encoding.
 */
static CK_RV import_DSA_key(STDLL_TokData_t *tokdata, SESSION *sess,
                            OBJECT *dsa_key_obj,
                            CK_BYTE *blob, CK_BYTE *blobreenc,
                            size_t *blob_size,
                            CK_BYTE *spki, size_t *spki_size)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE iv[AES_BLOCK_SIZE];
    CK_MECHANISM mech_w = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
    CK_BYTE cipher[MAX_BLOBSIZE];
    CK_ULONG cipher_l = sizeof(cipher);
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    CK_ATTRIBUTE_PTR new_p_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_OBJECT_CLASS class;
    CK_BYTE *data = NULL;
    CK_ULONG data_len;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;
    CK_BYTE *wrap_blob;

    memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

    /* need class for private/public key info */
    rc = template_attribute_get_ulong(dsa_key_obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    /* m_Unwrap builds key blob in the card,
     * tell ep11 the attributes the user specified for that key.
     */
    rc = build_ep11_attrs(tokdata, dsa_key_obj->template, &p_attrs, &attrs_len,
                          CKK_DSA, class, -1, &mech_w);
    if (rc != CKR_OK)
        goto import_DSA_key_end;

    if (class != CKO_PRIVATE_KEY) {

        /* an imported public DSA key, we need a SPKI for it. */

        CK_ATTRIBUTE *prime;
        CK_ATTRIBUTE *subprime;
        CK_ATTRIBUTE *base;
        CK_ATTRIBUTE *value;

        rc = template_attribute_get_non_empty(dsa_key_obj->template,
                                              CKA_PRIME, &prime);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_PRIME for the key.\n");
            goto import_DSA_key_end;
        }

        rc = template_attribute_get_non_empty(dsa_key_obj->template,
                                              CKA_SUBPRIME, &subprime);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_SUBPRIME for the key.\n");
            goto import_DSA_key_end;
        }

        rc = template_attribute_get_non_empty(dsa_key_obj->template, CKA_BASE,
                                              &base);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_BASE for the key.\n");
            goto import_DSA_key_end;
        }

        rc = template_attribute_get_non_empty(dsa_key_obj->template,
                                              CKA_VALUE, &value);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
            goto import_DSA_key_end;
        }

        /*
         * Builds the DER encoding (ansi_x962) SPKI.
         */
        rc = ber_encode_DSAPublicKey(FALSE, &data, &data_len,
                                     prime, subprime, base, value);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s public key import class=0x%lx rc=0x%lx "
                        "data_len=0x%lx\n", __func__, class, rc, data_len);
            goto import_DSA_key_end;
        } else {
            TRACE_INFO("%s public key import class=0x%lx rc=0x%lx "
                       "data_len=0x%lx\n", __func__, class, rc, data_len);
        }

        /* save the SPKI as blob although it is not a blob.
         * The card expects MACed-SPKIs as public keys.
         */
        rc = make_maced_spki(tokdata, sess, dsa_key_obj, NULL, 0,
                             data, data_len,
                             blob, blobreenc, blob_size, -1);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s failed to make a MACed-SPKI rc=0x%lx\n",
                        __func__, rc);
            goto import_DSA_key_end;
        }

        *spki_size = 0; /* common code will extract SPKI from object */

    } else {

        /* imported private DSA key goes here */

        /* extract the secret data to be wrapped
         * since this is AES_CBC_PAD, padding is done in mechanism.
         */
        rc = dsa_priv_wrap_get_data(dsa_key_obj->template, FALSE,
                                    &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("%s DSA wrap get data failed\n", __func__);
            goto import_DSA_key_end;
        }

        /* encrypt */
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
            rc = dll_m_EncryptSingle(wrap_blob, ep11_data->raw2key_wrap_blob_l,
                                     &mech_w, data, data_len,
                                     cipher, &cipher_l, target_info->target);
        RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)


        TRACE_INFO("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                   __func__, rc, cipher_l);

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                        __func__, rc, cipher_l);
            goto import_DSA_key_end;
        }

        rc = check_key_attributes(tokdata, CKK_DSA, CKO_PRIVATE_KEY, p_attrs,
                                  attrs_len, &new_p_attrs, &new_attrs_len, -1);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s DSA check private key attributes failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto import_DSA_key_end;
        }

        trace_attributes(__func__, "DSA import:", new_p_attrs, new_attrs_len);

        ep11_get_pin_blob(tokdata, ep11_session,
                          object_is_session_object(dsa_key_obj),
                          object_is_private(dsa_key_obj),
                          &ep11_pin_blob, &ep11_pin_blob_len);

        /* calls the card, it decrypts the private EC key,
         * reads its BER format and builds a blob.
         */
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
        RETRY_REENC_CREATE_KEY_START()
            rc = dll_m_UnwrapKey(cipher, cipher_l,
                                 wrap_blob,
                                 ep11_data->raw2key_wrap_blob_l, NULL, ~0,
                                 ep11_pin_blob,
                                 ep11_pin_blob_len, &mech_w,
                                 new_p_attrs, new_attrs_len, blob,
                                 blob_size, spki, spki_size,
                                 target_info->target);
        RETRY_REENC_CREATE_KEY_END(tokdata, sess, target_info,
                                   blob, blobreenc, *blob_size, rc)
        RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                        __func__, rc, *blob_size);
        } else {
            TRACE_INFO("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                       __func__, rc, *blob_size);
        }

        cleanse_attribute(dsa_key_obj->template, CKA_VALUE);
    }

import_DSA_key_end:
    if (data) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }
    if (p_attrs != NULL)
        cleanse_and_free_attribute_array(p_attrs, attrs_len);
    if (new_p_attrs)
        cleanse_and_free_attribute_array(new_p_attrs, new_attrs_len);
    return rc;
}

/*
 * makes blobs for private imported DH keys and
 * SPKIs for public imported DH keys.
 * Similar to rawkey_2_blob, but keys must follow a standard BER encoding.
 */
static CK_RV import_DH_key(STDLL_TokData_t *tokdata, SESSION *sess,
                           OBJECT *dh_key_obj,
                           CK_BYTE *blob, CK_BYTE *blobreenc,
                           size_t *blob_size,
                           CK_BYTE *spki, size_t *spki_size)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE iv[AES_BLOCK_SIZE];
    CK_MECHANISM mech_w = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
    CK_BYTE cipher[MAX_BLOBSIZE];
    CK_ULONG cipher_l = sizeof(cipher);
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    CK_ATTRIBUTE_PTR new_p_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_OBJECT_CLASS class;
    CK_BYTE *data = NULL;
    CK_ULONG data_len;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;
    CK_BYTE *wrap_blob;

    memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

    /* need class for private/public key info */
    rc = template_attribute_get_ulong(dh_key_obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    /* m_Unwrap builds key blob in the card,
     * tell ep11 the attributes the user specified for that key.
     */
    rc = build_ep11_attrs(tokdata, dh_key_obj->template, &p_attrs, &attrs_len,
                          CKK_DH, class, -1, &mech_w);
    if (rc != CKR_OK)
        goto import_DH_key_end;

    if (class != CKO_PRIVATE_KEY) {

        /* an imported public DH key, we need a SPKI for it. */

        CK_ATTRIBUTE *prime;
        CK_ATTRIBUTE *base;
        CK_ATTRIBUTE *value;

        rc = template_attribute_get_non_empty(dh_key_obj->template, CKA_PRIME,
                                              &prime);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_PRIME for the key.\n");
            goto import_DH_key_end;
        }

        rc = template_attribute_get_non_empty(dh_key_obj->template, CKA_BASE,
                                              &base);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_BASE for the key.\n");
            goto import_DH_key_end;
        }

        rc = template_attribute_get_non_empty(dh_key_obj->template, CKA_VALUE,
                                              &value);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
            goto import_DH_key_end;
        }

        /*
         * Builds the DER encoding (ansi_x962) SPKI.
         */
        rc = ber_encode_DHPublicKey(FALSE, &data, &data_len,
                                    prime, base, value);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s public key import class=0x%lx rc=0x%lx "
                        "data_len=0x%lx\n", __func__, class, rc, data_len);
            goto import_DH_key_end;
        } else {
            TRACE_INFO("%s public key import class=0x%lx rc=0x%lx "
                       "data_len=0x%lx\n", __func__, class, rc, data_len);
        }

        /* save the SPKI as blob although it is not a blob.
         * The card expects MACed-SPKIs as public keys.
         */
        rc = make_maced_spki(tokdata, sess, dh_key_obj, NULL, 0,
                             data, data_len,
                             blob, blobreenc, blob_size, -1);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s failed to make a MACed-SPKI rc=0x%lx\n",
                        __func__, rc);
            goto import_DH_key_end;
        }

        *spki_size = 0; /* common code will extract SPKI from object */

    } else {
        CK_ATTRIBUTE *value;
        CK_ATTRIBUTE *value_bits;
        CK_ULONG num_bits;

        /* imported private DH key goes here */

        /* extract the secret data to be wrapped
         * since this is AES_CBC_PAD, padding is done in mechanism.
         */
        rc = dh_priv_wrap_get_data(dh_key_obj->template, FALSE,
                                   &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("%s DH wrap get data failed\n", __func__);
            goto import_DH_key_end;
        }

        rc = template_attribute_get_non_empty(dh_key_obj->template, CKA_VALUE,
                                              &value);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
            goto import_DH_key_end;
        }

        num_bits = value->ulValueLen * 8;

        /* encrypt */
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
            rc = dll_m_EncryptSingle(wrap_blob, ep11_data->raw2key_wrap_blob_l,
                                     &mech_w, data, data_len,
                                     cipher, &cipher_l, target_info->target);
        RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

        TRACE_INFO("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                   __func__, rc, cipher_l);

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                        __func__, rc, cipher_l);
            goto import_DH_key_end;
        }

        rc = check_key_attributes(tokdata, CKK_DH, CKO_PRIVATE_KEY, p_attrs,
                                  attrs_len, &new_p_attrs, &new_attrs_len, -1);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s DH check private key attributes failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto import_DH_key_end;
        }

        trace_attributes(__func__, "DH import:", new_p_attrs, new_attrs_len);

        ep11_get_pin_blob(tokdata, ep11_session,
                          object_is_session_object(dh_key_obj),
                          object_is_private(dh_key_obj),
                          &ep11_pin_blob, &ep11_pin_blob_len);

        /* calls the card, it decrypts the private EC key,
         * reads its BER format and builds a blob.
         */
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
        RETRY_REENC_CREATE_KEY_START()
            rc = dll_m_UnwrapKey(cipher, cipher_l,
                                 wrap_blob,
                                 ep11_data->raw2key_wrap_blob_l, NULL, ~0,
                                 ep11_pin_blob,
                                 ep11_pin_blob_len, &mech_w,
                                 new_p_attrs, new_attrs_len, blob,
                                 blob_size, spki, spki_size,
                                 target_info->target);
        RETRY_REENC_CREATE_KEY_END(tokdata, sess, target_info,
                                   blob, blobreenc, *blob_size, rc)
        RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                        __func__, rc, *blob_size);
        } else {
            TRACE_INFO("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                       __func__, rc, *blob_size);
        }

        rc = build_attribute(CKA_VALUE_BITS, (CK_BYTE *)&num_bits,
                             sizeof(num_bits), &value_bits);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
            goto import_DH_key_end;
        }

        rc = template_update_attribute(dh_key_obj->template, value_bits);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(value_bits);
            goto import_DH_key_end;
        }

        cleanse_attribute(dh_key_obj->template, CKA_VALUE);
    }

import_DH_key_end:
    if (data) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }
    if (p_attrs != NULL)
        cleanse_and_free_attribute_array(p_attrs, attrs_len);
    if (new_p_attrs)
        cleanse_and_free_attribute_array(new_p_attrs, new_attrs_len);
    return rc;
}

/*
 * makes blobs for private imported IBM PQC keys and
 * SPKIs for public imported IBM PQC keys.
 * Similar to rawkey_2_blob, but keys must follow a standard BER encoding.
 */
static CK_RV import_IBM_pqc_key(STDLL_TokData_t *tokdata, SESSION *sess,
                                OBJECT *pqc_key_obj, CK_KEY_TYPE keytype,
                                CK_BYTE *blob, CK_BYTE *blobreenc,
                                size_t *blob_size,
                                CK_BYTE *spki, size_t *spki_size)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE iv[AES_BLOCK_SIZE];
    CK_MECHANISM mech_w = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
    CK_BYTE cipher[MAX_BLOBSIZE];
    CK_ULONG cipher_l = sizeof(cipher);
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    CK_ATTRIBUTE_PTR new_p_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_OBJECT_CLASS class;
    CK_BYTE *data = NULL;
    CK_ULONG data_len;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_BBOOL data_alloced = TRUE;
    const struct pqc_oid *oid;
    const char *key_type_str;
    CK_MECHANISM_TYPE pqc_mech;
    CK_BYTE *wrap_blob;

    switch (keytype) {
    case CKK_IBM_PQC_DILITHIUM:
        key_type_str = "Dilithium";
        pqc_mech = CKM_IBM_DILITHIUM;
        break;
    case CKK_IBM_PQC_KYBER:
        key_type_str = "Kyber";
        pqc_mech = CKM_IBM_KYBER;
        break;
    default:
        TRACE_ERROR("Invalid key type provided for %s\n ", __func__);
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

    /* need class for secret/public key info */
    rc = template_attribute_get_ulong(pqc_key_obj->template, CKA_CLASS,
                                      &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    /* m_Unwrap builds key blob in the card,
     * tell ep11 the attributes the user specified for that key.
     */
    rc = build_ep11_attrs(tokdata, pqc_key_obj->template,
                          &p_attrs, &attrs_len,
                          keytype, class, -1, &mech_w);
    if (rc != CKR_OK)
        goto done;

    if (class != CKO_PRIVATE_KEY) {
        /* Make an SPKI for the public IBM PQC key */

        /* A public IBM PQC key must either have a CKA_VALUE containing
         * the SPKI, or must have a keyform/mode value and the individual
         * attributes
         */
        if (template_attribute_find(pqc_key_obj->template,
                                    CKA_VALUE, &value_attr) &&
            value_attr->ulValueLen > 0 && value_attr ->pValue != NULL) {
            /* CKA_VALUE with SPKI */
            data = value_attr ->pValue;
            data_len = value_attr->ulValueLen;
            data_alloced = FALSE;

            /*
             * Decode SPKI and add public key attributes. This also adds the
             * keyform and mode attributes to the template.
             */
            rc = ibm_pqc_priv_unwrap_get_data(pqc_key_obj->template, keytype,
                                              data, data_len, FALSE);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to decode SPKI from CKA_VALUE.\n");
                goto done;
            }
         } else {
            /* Individual attributes */
             rc = ibm_pqc_publ_get_spki(pqc_key_obj->template, keytype,
                                        FALSE, &data, &data_len);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s public key import class=0x%lx rc=0x%lx "
                            "data_len=0x%lx\n", __func__, class, rc, data_len);
                goto done;
            } else {
                TRACE_INFO("%s public key import class=0x%lx rc=0x%lx "
                           "data_len=0x%lx\n", __func__, class, rc, data_len);
            }

            /* Ensure both, keyform and mode attributes are added */
            oid = ibm_pqc_get_keyform_mode(pqc_key_obj->template, pqc_mech);
            if (oid == NULL) {
                rc = CKR_TEMPLATE_INCOMPLETE;
                goto done;
            }

            rc = ibm_pqc_add_keyform_mode(pqc_key_obj->template, oid, pqc_mech);
            if (rc != CKR_OK) {
                TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
                goto done;
            }

            /* Add SPKI as CKA_VALUE to public key (z/OS ICSF compatibility) */
            rc = build_attribute(CKA_VALUE, data, data_len, &value_attr);
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_attribute failed\n");
                goto done;
            }

            rc = template_update_attribute(pqc_key_obj->template,
                                           value_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                            __func__, rc);
                free(value_attr);
                goto done;
            }
            value_attr = NULL;
        }

        /* save the SPKI as blob although it is not a blob.
         * The card expects MACed-SPKIs as public keys.
         */
        rc = make_maced_spki(tokdata, sess, pqc_key_obj, NULL, 0,
                             data, data_len,
                             blob, blobreenc, blob_size, -1);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s failed to make a MACed-SPKI rc=0x%lx\n",
                        __func__, rc);
            goto done;
        }

        *spki_size = 0; /* common code will extract SPKI from object */

    } else {

        /* imported private IBM PQC key goes here */

        /* A public IBM PQC key must either have a CKA_VALUE containing
         * the PKCS#8 encoded private key, or must have a keyform/mode value
         * and the individual attributes
         */
        if (template_attribute_find(pqc_key_obj->template,
                                    CKA_VALUE, &value_attr) &&
            value_attr->ulValueLen > 0 && value_attr ->pValue != NULL) {
            /* CKA_VALUE with SPKI */
            data = value_attr ->pValue;
            data_len = value_attr->ulValueLen;
            data_alloced = FALSE;

            /* Decode PKCS#8 private key and add key attributes */
            rc = ibm_pqc_priv_unwrap(pqc_key_obj->template, keytype,
                                     data, data_len, FALSE);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to decode private key from CKA_VALUE.\n");
                goto done;
            }
        } else {
            /* Extract the secret data to be wrapped since this is AES_CBC_PAD,
             * padding is done in mechanism. This also adds the keyform and mode
             * attributes to the template.
             */
            rc = ibm_pqc_priv_wrap_get_data(pqc_key_obj->template, keytype,
                                            FALSE, &data, &data_len);
            if (rc != CKR_OK) {
                TRACE_DEVEL("%s %s wrap get data failed\n", __func__,
                            key_type_str);
                goto done;
            }

            /* Ensure both, keyform and mode attributes are added */
            oid = ibm_pqc_get_keyform_mode(pqc_key_obj->template, pqc_mech);
            if (oid == NULL) {
                rc = CKR_TEMPLATE_INCOMPLETE;
                goto done;
            }

            rc = ibm_pqc_add_keyform_mode(pqc_key_obj->template, oid, pqc_mech);
            if (rc != CKR_OK) {
                TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
                goto done;
            }
        }

        /* encrypt */
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
            if (ep11_pqc_obj_strength_supported(target_info, pqc_mech,
                                                pqc_key_obj))
                rc = dll_m_EncryptSingle(wrap_blob, ep11_data->raw2key_wrap_blob_l,
                                         &mech_w, data, data_len,
                                         cipher, &cipher_l,
                                         target_info->target);
            else
                rc = CKR_KEY_SIZE_RANGE;
        RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

        TRACE_INFO("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                   __func__, rc, cipher_l);

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                        __func__, rc, cipher_l);
            goto done;
        }

        rc = check_key_attributes(tokdata, keytype, CKO_PRIVATE_KEY,
                            p_attrs, attrs_len,
                            &new_p_attrs, &new_attrs_len, -1);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s EC check private key attributes failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto done;
        }

        trace_attributes(__func__, "PQC import:", new_p_attrs, new_attrs_len);

        ep11_get_pin_blob(tokdata, ep11_session,
                          object_is_session_object(pqc_key_obj),
                          object_is_private(pqc_key_obj),
                          &ep11_pin_blob, &ep11_pin_blob_len);

        /* calls the card, it decrypts the private PQC key,
         * reads its BER format and builds a blob.
         */
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_WRAPBLOB_START(tokdata, target_info, wrap_blob)
        RETRY_REENC_CREATE_KEY_START()
            rc = dll_m_UnwrapKey(cipher, cipher_l,
                                 wrap_blob,
                                 ep11_data->raw2key_wrap_blob_l, NULL, ~0,
                                 ep11_pin_blob,
                                 ep11_pin_blob_len, &mech_w,
                                 new_p_attrs, new_attrs_len, blob,
                                 blob_size, spki, spki_size,
                                 target_info->target);
        RETRY_REENC_CREATE_KEY_END(tokdata, sess, target_info,
                                   blob, blobreenc, *blob_size, rc)
        RETRY_REENC_WRAPBLOB_END(tokdata, target_info, wrap_blob, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                        __func__, rc, *blob_size);
        } else {
            TRACE_INFO("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                       __func__, rc, *blob_size);
        }

        cleanse_attribute(pqc_key_obj->template, CKA_VALUE);

        switch (keytype) {
        case CKK_IBM_PQC_DILITHIUM:
            cleanse_attribute(pqc_key_obj->template, CKA_IBM_DILITHIUM_SEED);
            cleanse_attribute(pqc_key_obj->template, CKA_IBM_DILITHIUM_TR);
            cleanse_attribute(pqc_key_obj->template, CKA_IBM_DILITHIUM_S1);
            cleanse_attribute(pqc_key_obj->template, CKA_IBM_DILITHIUM_S2);
            cleanse_attribute(pqc_key_obj->template, CKA_IBM_DILITHIUM_T0);
            break;
        case CKK_IBM_PQC_KYBER:
            cleanse_attribute(pqc_key_obj->template, CKA_IBM_KYBER_SK);
            break;
        }
    }

done:
    if (data_alloced && data) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }
    if (p_attrs != NULL)
        cleanse_and_free_attribute_array(p_attrs, attrs_len);
    if (new_p_attrs)
        cleanse_and_free_attribute_array(new_p_attrs, new_attrs_len);

    return rc;
}

static CK_RV import_blob_private_public(STDLL_TokData_t *tokdata, SESSION *sess,
                                        OBJECT *obj, CK_KEY_TYPE keytype,
                                        CK_BYTE *spki, CK_ULONG spki_len,
                                        CK_BBOOL is_public)
{
    CK_ULONG data_len, raw_spki_len;
    CK_BYTE *data;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(sess);

    /* Decode SPKI and add the respective public key attributes */
    switch (keytype) {
    case CKK_EC:
        rc = ecdsa_priv_unwrap_get_data(obj->template, spki, spki_len,
                                        is_public);
        break;
    case CKK_RSA:
        rc = rsa_priv_unwrap_get_data(obj->template, spki, spki_len, is_public);
        break;
    case CKK_DSA:
        rc = dsa_priv_unwrap_get_data(obj->template, spki, spki_len, is_public);
        break;
    case CKK_DH:
        rc = dh_priv_unwrap_get_data(obj->template, spki, spki_len, is_public);
        break;
    case CKK_IBM_PQC_DILITHIUM:
        rc = ibm_dilithium_priv_unwrap_get_data(obj->template, spki, spki_len,
                                                is_public);
        break;
    case CKK_IBM_PQC_KYBER:
        rc = ibm_kyber_priv_unwrap_get_data(obj->template, spki, spki_len,
                                            is_public);
        break;
    default:
        TRACE_ERROR("%s Key type 0x%lx not supported\n", __func__, keytype);
        return CKR_FUNCTION_FAILED;
    }

    if (rc != 0) {
        TRACE_ERROR("%s xxx_priv_unwrap_get_data rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    /* SPKI is a MACed SPKI, get length of SPKI part only */
    rc = ber_decode_SEQUENCE(spki, &data, &data_len, &raw_spki_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_decode_SEQUENCE failed rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    /* Add SPKI as CKA_PUBLIC_KEY_INFO */
    rc = template_build_update_attribute(obj->template, CKA_PUBLIC_KEY_INFO,
                                         spki, raw_spki_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_build_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    return CKR_OK;
}

static CK_RV import_blob_secret(STDLL_TokData_t *tokdata, SESSION *sess,
                                OBJECT *obj, CK_KEY_TYPE keytype,
                                CK_ULONG value_len)
{
    CK_BYTE *zero;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(sess);

    switch (keytype) {
    case CKK_AES:
    case CKK_AES_XTS:
    case CKK_GENERIC_SECRET:
    case CKK_SHA_1_HMAC:
    case CKK_SHA224_HMAC:
    case CKK_SHA256_HMAC:
    case CKK_SHA384_HMAC:
    case CKK_SHA512_HMAC:
    case CKK_SHA3_224_HMAC:
    case CKK_SHA3_256_HMAC:
    case CKK_SHA3_384_HMAC:
    case CKK_SHA3_512_HMAC:
    case CKK_SHA512_224_HMAC:
    case CKK_SHA512_256_HMAC:
        rc = template_build_update_attribute(obj->template, CKA_VALUE_LEN,
                                             (CK_BYTE *)&value_len,
                                             sizeof(value_len));
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_build_update_attribute failed with "
                        "rc=0x%lx\n", __func__, rc);
            return rc;
        }

        /* Add all zero CKA_VALUE (needed by object_mgr_add) */
        zero = calloc(1, value_len);
        if (zero == NULL) {
            TRACE_ERROR("%s Failed to allocate dummy buffer of %lu bytes\n",
                        __func__, value_len);
            return CKR_HOST_MEMORY;
        }

        rc = template_build_update_attribute(obj->template, CKA_VALUE,
                                             zero, value_len);
        free(zero);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_build_update_attribute failed with "
                        "rc=0x%lx\n", __func__, rc);
            return rc;
        }
        break;
    }

    return CKR_OK;
}

static CK_RV import_blob_update_attrs(STDLL_TokData_t *tokdata, SESSION *sess,
                                      OBJECT *obj, XCP_Attr_t *bool_attrs,
                                      CK_OBJECT_CLASS class,
                                      CK_KEY_TYPE keytype)
{
    CK_ATTRIBUTE *attr;
    CK_ULONG i;
    CK_BBOOL blob_val, user_val;
    TEMPLATE *tmpl;
    CK_RV rc = CKR_OK;

    tmpl = calloc(1, sizeof(TEMPLATE));
    if (tmpl == NULL) {
        TRACE_ERROR("%s allocate template failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    for (i = 0; ep11_pkcs11_attr_map[i].ep11_attr != 0; i++) {
        blob_val = (*bool_attrs & ep11_pkcs11_attr_map[i].ep11_attr) != 0 ?
                                                    CK_TRUE : CK_FALSE;

        if (template_attribute_find(obj->template,
                                    ep11_pkcs11_attr_map[i].pkcs11_attr,
                                    &attr) &&
            attr->ulValueLen == sizeof(CK_BBOOL) && attr->pValue != NULL) {
            user_val = *((CK_BBOOL *)attr->pValue);
            if (blob_val != user_val &&
                ((user_val == FALSE &&
                                 ep11_pkcs11_attr_map[i].can_set_to_false) ||
                 (user_val == TRUE &&
                                 ep11_pkcs11_attr_map[i].can_set_to_true))) {
                /* Attribute was updated, add it */
                rc = template_build_update_attribute(tmpl, attr->type,
                                                     (CK_BYTE *)attr->pValue,
                                                     attr->ulValueLen);
                if (rc != CKR_OK) {
                    TRACE_ERROR("%s template_build_update_attribute failed "
                                "rc=0x%lx\n", __func__, rc);
                    goto out;
                }
            }
        }
    }

    if (tmpl->attribute_list != NULL) {
        if ((*bool_attrs & XCP_BLOB_MODIFIABLE) == 0) {
            TRACE_ERROR("%s The blob has CKA_MODIFIABLE=FALSE, attributes can not "
                        "be modified\n", __func__);
            rc = CKR_ATTRIBUTE_VALUE_INVALID;
            goto out;
        }

        /* Check if the attributes are allowed to be modified that way */
        rc = template_validate_attributes(tokdata, tmpl, class, keytype,
                                          MODE_MODIFY);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_validate_attributes failed rc=0x%lx\n",
                        __func__, rc);
            goto out;
        }

        rc = token_specific_set_attribute_values(tokdata, sess, obj, tmpl);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s token_specific_set_attribute_values failed "
                       "rc=0x%lx\n", __func__, rc);
            goto out;
        }

        rc = template_merge(obj->template, &tmpl);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_merge failed rc=0x%lx\n",
                        __func__, rc);
            goto out;
        }
    }

out:
    if (tmpl != NULL)
        template_free(tmpl);

    return rc;
}

struct check_uv_session_data {
    STDLL_TokData_t *tokdata;
    CK_BYTE *session_id;
    CK_BBOOL found;
};

static CK_RV check_uv_session_handler(uint_32 adapter, uint_32 domain,
                                      void *handler_data)
{
    struct check_uv_session_data *data = handler_data;
    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_BYTE blob[MAX_BLOBSIZE];
    CK_BYTE csum[MAX_CSUMSIZE];
    size_t csum_l = sizeof(csum), blob_l = sizeof(blob);
    CK_ULONG len = 32;
    CK_BBOOL cktrue = 1;
    CK_ATTRIBUTE wrap_tmpl[] = {
        { CKA_VALUE_LEN, &len, sizeof(CK_ULONG) },
        { CKA_WRAP, &cktrue, sizeof(cktrue) },
        { CKA_UNWRAP, &cktrue, sizeof(cktrue) },
        { CKA_ENCRYPT, &cktrue, sizeof(cktrue) },
        { CKA_DECRYPT, &cktrue, sizeof(cktrue) },
        { CKA_EXTRACTABLE, &cktrue, sizeof(cktrue) },
    };
    CK_ULONG wrap_tmpl_len = sizeof(wrap_tmpl) / sizeof(CK_ATTRIBUTE);
    target_t target = 0;
    CK_BYTE *uv_session = NULL;
    CK_RV rc;

    if (data->found) /* Already found a matching UV session */
        return CKR_OK;

    rc = get_ep11_target_for_apqn(adapter, domain, &target, 0);
    if (rc != CKR_OK)
        return rc;

    /* Generate a temporary key on this APQN to get its UV session */
    rc = dll_m_GenerateKey(&mech, wrap_tmpl, wrap_tmpl_len, NULL, 0,
                           blob, &blob_l, csum, &csum_l, target);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s Failed to generate temporary AES key on APQN %02X.%04X "
                    "rc=0x%lx\n", __func__, adapter, domain, rc);
        /* Ignore the error, APQN might be offline, etc */
        rc = CKR_OK;
        goto out;
    }

    if (check_expected_mkvp(data->tokdata, blob, blob_l, NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto out;
    }

    rc = ep11tok_extract_blob_info(blob, blob_l, NULL, NULL,
                                   &uv_session, NULL);
    if (rc != CKR_OK) {
        TRACE_ERROR("ep11tok_extract_blob_info failed\n");
        goto out;
    }

    if (uv_session != NULL && data->session_id != NULL &&
        memcmp(data->session_id, uv_session, XCP_WK_BYTES) == 0) {
        TRACE_DEVEL("Session matches the UV session of APQN %02X.%04X\n",
                    adapter, domain);
        data->found = TRUE;
    }

out:
    free_ep11_target_for_apqn(target);

    return rc;
}

static CK_RV import_blob(STDLL_TokData_t *tokdata, SESSION *sess, OBJECT *obj,
                         CK_OBJECT_CLASS class, CK_KEY_TYPE keytype,
                         CK_BYTE *blob, CK_ULONG blob_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_session_t *ep11_session = (ep11_session_t *)sess->private_data;
    CK_BYTE *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    CK_BBOOL is_new_mk, is_new_mk2, is_spki;
    XCP_Attr_t *bool_attrs = NULL;
    CK_BYTE *session_id = NULL, *session_id2 = NULL, *exp_session = NULL;
    const CK_BYTE zero_session[XCP_WK_BYTES] = { 0 };
    CK_BYTE maced_spki[MAX_BLOBSIZE];
    CK_BYTE blob_reenc[MAX_BLOBSIZE];
    CK_ULONG maced_spki_len = sizeof(maced_spki);
    ep11_target_info_t* target_info;
    int curve_type;
    CK_BYTE *useblob, *blob2;
    size_t useblob_len, blob1_len, blob2_len;
    CK_KEY_TYPE blob_type = CK_UNAVAILABLE_INFORMATION;
    CK_KEY_TYPE blob_type2 = CK_UNAVAILABLE_INFORMATION;
    CK_KEY_TYPE exp_keytype;
    CK_ULONG value_len, value_len2, stdcomp, stdcomp2;
    CK_BYTE buf[MAX_BLOBSIZE];
    CK_ATTRIBUTE get_attr[] = {
        { CKA_KEY_TYPE, &blob_type, sizeof(blob_type) }, /* must be first */
        { CKA_VALUE_LEN, &value_len, sizeof(value_len) },
        { CKA_IBM_STD_COMPLIANCE1, &stdcomp, sizeof(stdcomp) },
        { CKA_PUBLIC_KEY_INFO, &buf, sizeof(buf) } /* SPKI must be last */
    };
    CK_ULONG get_attr_num = sizeof(get_attr) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE get_attr2[] = {
        { CKA_KEY_TYPE, &blob_type2, sizeof(blob_type2) },
        { CKA_VALUE_LEN, &value_len2, sizeof(value_len2) },
        { CKA_IBM_STD_COMPLIANCE1, &stdcomp2, sizeof(stdcomp2) },
    };
    CK_ULONG get_attr2_num = sizeof(get_attr2) / sizeof(CK_ATTRIBUTE);
    CK_BBOOL in_sel_guest = FALSE;
    struct check_uv_session_data uv_data;
    CK_RV rc;

    rc = ep11tok_extract_blob_info(blob, keytype == CKK_AES_XTS ?
                                                blob_len / 2 : blob_len,
                                   &is_spki, NULL, &session_id, &bool_attrs);
    if (rc != CKR_OK) {
        TRACE_ERROR("ep11tok_extract_blob_info failed\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (keytype == CKK_AES_XTS) {
        rc = ep11tok_extract_blob_info(blob + blob_len / 2, blob_len / 2,
                                       NULL, NULL, &session_id2, NULL);
        if (rc != CKR_OK) {
            TRACE_ERROR("ep11tok_extract_blob_info failed\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

#ifndef NO_PKEY
        rc = ep11tok_pkey_check_aes_xts(tokdata, obj, CKM_AES_XTS);
#else
        rc = CKR_FUNCTION_NOT_SUPPORTED;
#endif
        if (rc != CKR_OK) {
            TRACE_ERROR("%s EP11 AES XTS is not supported: rc=0x%lx\n",
                        __func__, rc);
            return rc;
        }
    }

    if (is_spki && class != CKO_PUBLIC_KEY) {
        TRACE_ERROR("Key blob is an SPKI but import is not for a public key\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (!is_spki && class == CKO_PUBLIC_KEY) {
        TRACE_ERROR("Public key import requres a SPKI.\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (is_spki && session_id == NULL) {
        /* Raw (un-MACed) SPKI: MAC it */
        curve_type = get_curve_type_from_spki(blob, blob_len);

        rc = make_maced_spki(tokdata, sess, obj, NULL, 0, blob, blob_len,
                             maced_spki, blob_reenc, &maced_spki_len,
                             curve_type);
        if (rc != CKR_OK) {
            TRACE_ERROR("make_maced_spki failed\n");
            return rc;
        }

        rc = template_build_update_attribute(obj->template, CKA_IBM_OPAQUE,
                                             maced_spki, maced_spki_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_build_update_attribute failed for "
                        "CKA_IBM_OPAQUE\n");
            return rc;
        }

        blob = maced_spki;
        blob_len = maced_spki_len;
    }

    ep11_get_pin_blob(tokdata, ep11_session,
                      object_is_session_object(obj),
                      object_is_private(obj),
                      &ep11_pin_blob, &ep11_pin_blob_len);

    if (ep11_pin_blob == NULL) {
        /*
         * In a secure execution guest keys might be bound to the ultravisor
         * session. Get the UV session ID (if any) from the wrap blob.
         * Note that if multipe domains of the same card(s) are available,
         * then each domain uses its own ultravisor session.
         */
        rc = ep11tok_extract_blob_info(ep11_data->raw2key_wrap_blob,
                                       ep11_data->raw2key_wrap_blob_l,
                                       NULL, NULL,
                                       &exp_session, NULL);
        if (rc != CKR_OK) {
            TRACE_ERROR("extract_blob_info failed for wrap blob\n");
            return rc;
        }

        if (memcmp(exp_session, zero_session, XCP_WK_BYTES) == 0)
            exp_session = NULL; /* No UV session, not running in an SEL guest */
        else
            in_sel_guest = TRUE; /* Running in an SEL guest */
    } else {
        exp_session = ep11_pin_blob;
    }

    /* Check if session bound and if so for valid session */
    if (memcmp(session_id, zero_session, XCP_WK_BYTES) == 0)
        session_id = NULL;
    if (keytype == CKK_AES_XTS &&
        memcmp(session_id2, zero_session, XCP_WK_BYTES) == 0)
        session_id2 = NULL;

    if (keytype == CKK_AES_XTS) {
        /*
         * AES-XTS key pair: either both are not session bound,
         * or both are bound to the same session.
         */
        if ((session_id == NULL && session_id2 != NULL) ||
            (session_id != NULL && session_id2 == NULL)) {
            TRACE_ERROR("AES-XTS key blob is inconsistent\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (session_id != NULL && session_id2 != NULL && !in_sel_guest &&
            memcmp(session_id, session_id2, XCP_WK_BYTES) != 0) {
            TRACE_ERROR("AES-XTS key blob is inconsistent\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    if (exp_session == NULL && session_id != NULL) {
        TRACE_ERROR("Key blob must not be session bound\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (exp_session != NULL && session_id == NULL) {
        TRACE_ERROR("Key blob must be session bound, but it is not\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (exp_session != NULL && session_id != NULL && !in_sel_guest &&
        memcmp(exp_session, session_id, XCP_WK_BYTES) != 0) {
        TRACE_ERROR("Key blob is bound to an unexpected session\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (exp_session != NULL && session_id != NULL && in_sel_guest) {
        uv_data.tokdata = tokdata;
        uv_data.session_id = session_id;
        uv_data.found = FALSE;
        rc = handle_all_ep11_cards(&ep11_data->target_list,
                                   check_uv_session_handler, &uv_data);
        if (rc != CKR_OK) {
            TRACE_ERROR("handle_all_ep11_cards failed for check UV session\n");
            return rc;
        }
        if (!uv_data.found) {
            TRACE_ERROR("Key blob is not bound to an expected UV session\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (keytype == CKK_AES_XTS && session_id2 != NULL) {
            uv_data.tokdata = tokdata;
            uv_data.session_id = session_id2;
            uv_data.found = FALSE;
            rc = handle_all_ep11_cards(&ep11_data->target_list,
                                       check_uv_session_handler, &uv_data);
            if (rc != CKR_OK) {
                TRACE_ERROR("handle_all_ep11_cards failed for check UV "
                            "session (2nd AES-XTS key)\n");
                return rc;
            }
            if (!uv_data.found) {
                TRACE_ERROR("2nd key of AES-XTS key blob is not bound to an "
                            "expected UV session\n");
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
        }
    }

    /* Check for valid master key */
    if (check_expected_mkvp(tokdata, blob, keytype == CKK_AES_XTS ?
                                                    blob_len / 2 : blob_len,
                            &is_new_mk) != CKR_OK) {
        TRACE_ERROR("Key blob has an invalid WKVP\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (keytype == CKK_AES_XTS) {
        if (check_expected_mkvp(tokdata, blob + blob_len / 2, blob_len / 2,
                                &is_new_mk2) != CKR_OK) {
            TRACE_ERROR("Key blob has an invalid WKVP\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (is_new_mk != is_new_mk2) {
            TRACE_ERROR("AES-XTS key blob is inconsistent\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    if (ep11_data->mk_change_active) {
        if (is_new_mk) {
            /* Blob has new WK already: supply it in reencblob as well */
            TRACE_DEVEL("%s Key blob has new WK\n", __func__);
            memcpy(blob_reenc, blob, blob_len);
        } else {
            target_info = get_target_info(tokdata);
            if (target_info == NULL)
                return CKR_FUNCTION_FAILED;

            /* Key has old WK, re-encipher it */
            TRACE_DEVEL("%s Key blob has old WK, reencipher it\n", __func__);
            rc = ep11tok_reencipher_blob(tokdata, sess, &target_info,
                                         blob, keytype == CKK_AES_XTS ?
                                                     blob_len / 2 : blob_len,
                                         blob_reenc);

            if (rc == CKR_OK && keytype == CKK_AES_XTS) {
                rc = ep11tok_reencipher_blob(tokdata, sess, &target_info,
                                             blob + blob_len / 2,blob_len / 2,
                                             blob_reenc + blob_len / 2);
            }

            put_target_info(tokdata, target_info);

            if (rc != CKR_OK) {
                put_target_info(tokdata, target_info);
                TRACE_ERROR("%s new WK has just been activated, can not "
                            "reencipher key blob\n", __func__);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
        }

        rc = template_build_update_attribute(obj->template,
                                             CKA_IBM_OPAQUE_REENC,
                                             blob_reenc, blob_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_build_update_attribute failed for "
                        "CKA_IBM_OPAQUE_REENC\n");
            return rc;
        }
    }

    if (class == CKO_PUBLIC_KEY)
        get_attr_num = 1; /* get only key type for public key */
    if (class == CKO_SECRET_KEY)
        get_attr_num--; /* don't get SPKI for secret key */

    /* Get Key type and SPKI for private keys */
    blob1_len = keytype == CKK_AES_XTS ? blob_len / 2 : blob_len;
    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, obj, blob, blob1_len,
                           useblob, useblob_len, rc)
        rc = dll_m_GetAttributeValue(useblob, useblob_len, get_attr,
                                     get_attr_num, target_info->target);
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblob_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

    if (rc == CKR_OK && keytype == CKK_AES_XTS) {
        blob2 = blob + blob_len / 2;
        blob2_len = blob_len / 2;
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_BLOB_START(tokdata, target_info, obj, blob2, blob2_len,
                               useblob, useblob_len, rc)
            rc = dll_m_GetAttributeValue(useblob, useblob_len, get_attr2,
                                         get_attr2_num, target_info->target);
        RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblob_len, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)
    }

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s m_GetAttributeValue failed rc=0x%lx\n", __func__, rc);

        if (class == CKO_PRIVATE_KEY && rc != CKR_SESSION_CLOSED) {
            /* This is most likely due to a missing EP11 firmware fix */
            TRACE_DEVEL("%s possibly caused by missing EP11 firmware fix?\n",
                        __func__);
            return CKR_PUBLIC_KEY_INVALID; /* Indicate this situation */
        }
        return rc;
    }

    exp_keytype = keytype;
    ep11tok_pkcs11_keytype_translate(tokdata, exp_keytype, &exp_keytype);
    if (keytype != CKK_AES_XTS && blob_type != exp_keytype) {
        TRACE_ERROR("%s Key blob is not of the expected type: 0x%lx expectd "
                    "0x%lx\n", __func__, blob_type, exp_keytype);

        if (blob_type == 0x80ffffff || blob_type == CK_UNAVAILABLE_INFORMATION)
            return CKR_PUBLIC_KEY_INVALID; /* Old firmware indication */

        return CKR_KEY_TYPE_INCONSISTENT;
    }

    if (keytype == CKK_AES_XTS) {
        if ((blob_type != blob_type2 || value_len != value_len2 ||
             stdcomp != stdcomp2)) {
            TRACE_ERROR("AES-XTS key blob is inconsistent\n");

            if (blob_type2 == 0x80ffffff ||
                blob_type2 == CK_UNAVAILABLE_INFORMATION)
                return CKR_PUBLIC_KEY_INVALID; /* Old firmware indication */

            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        value_len *= 2;

        if (blob_type != CKK_AES) {
             TRACE_ERROR("%s Key blob is not of the expected type: 0x%lx "
                         "expectd 0x%x\n", __func__, blob_type, CKK_AES);
             return CKR_KEY_TYPE_INCONSISTENT;
         }
    }

    switch (class) {
    case CKO_PUBLIC_KEY:
        rc = import_blob_private_public(tokdata, sess, obj, keytype,
                                        blob, blob_len, TRUE);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import_blob_public failed rc=0x%lx\n",
                        __func__, rc);
            return rc;
        }
        break;

    case CKO_PRIVATE_KEY:
        rc = import_blob_private_public(tokdata, sess, obj, keytype,
                                        get_attr[get_attr_num - 1].pValue,
                                        get_attr[get_attr_num - 1].ulValueLen,
                                        FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import_blob_public failed rc=0x%lx\n",
                        __func__, rc);
            return rc;
        }
        break;

    case CKO_SECRET_KEY:
        rc = import_blob_secret(tokdata, sess, obj, keytype, value_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import_blob_secret failed rc=0x%lx\n",
                        __func__, rc);
            return rc;
        }
        break;
    }

    rc = template_build_update_attribute(obj->template, CKA_IBM_STD_COMPLIANCE1,
                                         (CK_BYTE *)&stdcomp, sizeof(stdcomp));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_build_update_attribute failed rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    if (class != CKO_PUBLIC_KEY) {
        /* Set CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE */
        rc = key_mgr_apply_always_sensitive_never_extractable_attrs(tokdata,
                                                                    obj);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s key_mgr_apply_always_sensitive_never_extractable_attrs "
                        "failed with rc=0x%lx\n", __func__, rc);
            return rc;
        }
    }

    /* check if bool attrs are changed during import, and apply if so */
    rc = import_blob_update_attrs(tokdata, sess, obj, bool_attrs,
                                  class, keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s import_blob_update_attrs failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    return CKR_OK;
}

CK_RV token_specific_object_add(STDLL_TokData_t * tokdata, SESSION * sess,
                                OBJECT * obj)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_KEY_TYPE keytype;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE blob[MAX_BLOBSIZE];
    CK_BYTE blobreenc[MAX_BLOBSIZE];
    size_t blobsize = sizeof(blob);
    CK_BYTE spki[MAX_BLOBSIZE];
    size_t spkisize = sizeof(spki);
    CK_RV rc;
    CK_ULONG class;
    CK_BBOOL attrbound;
    CK_BYTE *temp;
    CK_ULONG temp_len;

    /* get key type */
    rc = template_attribute_get_ulong(obj->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK) {
        /* not a key, so nothing to do. Just return. */
        return CKR_OK;
    }

    /* Check that we do not try to create an attribute bound private key. */
    /* need class for private/public key info */
    rc = template_attribute_get_ulong(obj->template, CKA_CLASS,
                                      &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }
    rc = template_attribute_get_bool(obj->template, CKA_IBM_ATTRBOUND,
                                    &attrbound);
    if (rc == CKR_TEMPLATE_INCOMPLETE) {
        attrbound = false;
    } else if (rc != CKR_OK) {
        TRACE_ERROR("Incomplete CKA_IBM_ATTRBOUND attribute for the key.\n");
        return rc;
    }
    if (class != CKO_PUBLIC_KEY && attrbound) {
        TRACE_ERROR("Cannot create attribute bound private key via C_CreateObject.\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    /* Ensure the wrap blob is available */
    rc = make_wrapblob(tokdata, sess);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s make_wrapblob rc=0x%lx\n", __func__, rc);
        return rc;
    }

#ifndef NO_PKEY
    /* Ensure the firmware master key verification pattern is available */
    rc = ep11tok_pkey_get_firmware_mk_vp(tokdata, sess);
    if (rc != CKR_OK && rc != CKR_FUNCTION_NOT_SUPPORTED)
        return rc;
#endif /* NO_PKEY */

    memset(blob, 0, sizeof(blob));
    memset(blobreenc, 0, sizeof(blobreenc));

    /* Check for key blob import */
    if (template_attribute_find(obj->template, CKA_IBM_OPAQUE, &attr) &&
        attr->ulValueLen > 0 && attr->pValue != NULL) {
        rc = import_blob(tokdata, sess, obj, class, keytype,
                         (CK_BYTE *)attr->pValue, attr->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import_blob rc=0x%lx\n", __func__, rc);
            return rc;
        }

        return CKR_OK;
    }

    /* only these keys can be imported */
    switch (keytype) {
    case CKK_RSA:
        rc = import_RSA_key(tokdata, sess, obj, blob, blobreenc, &blobsize,
                            spki, &spkisize);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import RSA key rc=0x%lx blobsize=0x%zx\n",
                        __func__, rc, blobsize);
            return rc;
        }
        TRACE_INFO("%s import RSA key rc=0x%lx blobsize=0x%zx\n",
                   __func__, rc, blobsize);
        break;
    case CKK_EC:
        rc = import_EC_key(tokdata, sess, obj, blob, blobreenc, &blobsize,
                           spki, &spkisize);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import EC key rc=0x%lx blobsize=0x%zx\n",
                        __func__, rc, blobsize);
            return rc;
        }
        TRACE_INFO("%s import EC key rc=0x%lx blobsize=0x%zx\n",
                   __func__, rc, blobsize);
        break;
    case CKK_DSA:
        rc = import_DSA_key(tokdata, sess, obj, blob, blobreenc, &blobsize,
                            spki, &spkisize);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import DSA key rc=0x%lx blobsize=0x%zx\n",
                        __func__, rc, blobsize);
            return rc;
        }
        TRACE_INFO("%s import DSA key rc=0x%lx blobsize=0x%zx\n",
                   __func__, rc, blobsize);
        break;
    case CKK_DH:
        rc = import_DH_key(tokdata, sess, obj, blob, blobreenc, &blobsize,
                           spki, &spkisize);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import DH key rc=0x%lx blobsize=0x%zx\n",
                        __func__, rc, blobsize);
            return rc;
        }
        TRACE_INFO("%s import DH key rc=0x%lx blobsize=0x%zx\n",
                   __func__, rc, blobsize);
        break;
    case CKK_IBM_PQC_DILITHIUM:
    case CKK_IBM_PQC_KYBER:
        rc = import_IBM_pqc_key(tokdata, sess, obj, keytype, blob, blobreenc,
                                &blobsize, spki, &spkisize);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import IBM PQC key kytype=0x%lx rc=0x%lx blobsize=0x%zx\n",
                        __func__, keytype, rc, blobsize);
            return rc;
        }
        TRACE_INFO("%s import IBM PQC key kytype=0x%lx rc=0x%lx blobsize=0x%zx\n",
                   __func__, keytype, rc, blobsize);
        break;
    case CKK_DES2:
    case CKK_DES3:
    case CKK_AES:
    case CKK_GENERIC_SECRET:
    case CKK_SHA_1_HMAC:
    case CKK_SHA224_HMAC:
    case CKK_SHA256_HMAC:
    case CKK_SHA384_HMAC:
    case CKK_SHA512_HMAC:
    case CKK_SHA3_224_HMAC:
    case CKK_SHA3_256_HMAC:
    case CKK_SHA3_384_HMAC:
    case CKK_SHA3_512_HMAC:
    case CKK_SHA512_224_HMAC:
    case CKK_SHA512_256_HMAC:
        /* get key value */
        rc = template_attribute_get_non_empty(obj->template, CKA_VALUE, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
            return rc;
        }
        /* attr holds key value specified by user,
         * import that key (make a blob)
         */
        rc = rawkey_2_blob(tokdata, sess, attr->pValue, attr->ulValueLen,
                           keytype, blob, blobreenc, &blobsize, obj);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s rawkey_2_blob rc=0x%lx "
                        "blobsize=0x%zx\n", __func__, rc, blobsize);
            return rc;
        }

        /* clear value attribute */
        OPENSSL_cleanse(attr->pValue, attr->ulValueLen);

        TRACE_INFO("%s rawkey_2_blob rc=0x%lx blobsize=0x%zx\n",
                   __func__, rc, blobsize);
        break;
    case CKK_AES_XTS:
        rc = import_aes_xts_key(tokdata, sess, obj, blob, blobreenc, &blobsize);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import AES XTS key rc=0x%lx blobsize=0x%zx\n",
                        __func__, rc, blobsize);
            return rc;
        }
        TRACE_INFO("%s import AES XTS key rc=0x%lx blobsize=0x%zx\n",
                    __func__, rc, blobsize);
        break;
    default:
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    if (check_expected_mkvp(tokdata, blob, keytype == CKK_AES_XTS ?
                            blobsize / 2 : blobsize, NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }
    if (keytype == CKK_AES_XTS) {
        if (check_expected_mkvp(tokdata, blob + blobsize / 2,
                                blobsize / 2, NULL) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }
    }

    /* store the blob in the key obj */
    rc = build_attribute(CKA_IBM_OPAQUE, blob, blobsize, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }

    rc = template_update_attribute(obj->template, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(attr);
        return rc;
    }

    if (ep11_data->mk_change_active) {
        rc = build_attribute(CKA_IBM_OPAQUE_REENC, blobreenc, blobsize, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__,
                        rc);
            return rc;
        }

        rc = template_update_attribute(obj->template, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(attr);
            return rc;
        }
    }

    if (spkisize > 0 && (class == CKO_PRIVATE_KEY || class == CKO_PUBLIC_KEY)) {
        /* spki may be a MACed SPKI, get length of SPKI part only */
        rc = ber_decode_SEQUENCE(spki, &temp, &temp_len, &spkisize);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s ber_decode_SEQUENCE failed rc=0x%lx\n",
                        __func__, rc);
            return rc;
        }

        rc = build_attribute(CKA_PUBLIC_KEY_INFO, spki, spkisize, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__,
                        rc);
            return rc;
        }

        rc = template_update_attribute(obj->template, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(attr);
            return rc;
        }
    }

    rc = update_ep11_attrs_from_blob(tokdata, sess, obj,
                                     (keytype == CKK_AES_XTS));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s update_ep11_attrs_from_blob failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    return CKR_OK;
}

CK_RV ep11tok_generate_key(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR attrs,
                           CK_ULONG attrs_len, CK_OBJECT_HANDLE_PTR handle)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_BYTE blob[MAX_BLOBSIZE], blob2[MAX_BLOBSIZE];
    CK_BYTE reenc_blob[MAX_BLOBSIZE], reenc_blob2[MAX_BLOBSIZE];
    size_t blobsize = sizeof(blob);
    size_t blobsize2 = sizeof(blob2);
    CK_BYTE csum[MAX_CSUMSIZE], csum2[MAX_CSUMSIZE];;
    size_t csum_len = sizeof(csum), csum2_len = sizeof(csum2);
    CK_ATTRIBUTE *attr = NULL;
    OBJECT *key_obj = NULL;
    CK_ULONG ktype;
    CK_ULONG class;
    CK_ATTRIBUTE_PTR new_attrs = NULL;
    CK_ATTRIBUTE_PTR new_attrs2 = NULL;
    CK_ULONG new_attrs_len = 0, new_attrs2_len = 0;
    CK_RV rc;
    CK_BOOL xts = FALSE, mapped_mech = FALSE;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) session->private_data;
    CK_MECHANISM mech2 = {0, NULL, 0};
    CK_BBOOL blob_new_mk = FALSE, blob2_new_mk = FALSE;

    memset(blob, 0, sizeof(blob));
    memset(reenc_blob, 0, sizeof(reenc_blob));
    memset(csum, 0, sizeof(csum));
    memset(blob2, 0, sizeof(blob2));
    memset(csum2, 0, sizeof(csum2));

    /* Get the keytype to use when creating the key object */
    rc = pkcs_get_keytype(attrs, attrs_len, mech, &ktype, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_subclass failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = check_key_attributes(tokdata, ktype, CKO_SECRET_KEY, attrs, attrs_len,
                              &new_attrs, &new_attrs_len, -1);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s check secret key attributes failed: rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

#ifndef NO_PKEY
    /* Ensure the firmware master key verification pattern is available */
    rc = ep11tok_pkey_get_firmware_mk_vp(tokdata, session);
    if (rc != CKR_OK && rc != CKR_FUNCTION_NOT_SUPPORTED)
        goto error;
#endif /* NO_PKEY */

    rc = object_mgr_create_skel(tokdata, session, new_attrs, new_attrs_len,
                                MODE_KEYGEN, CKO_SECRET_KEY, ktype, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s object_mgr_create_skel failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    rc = build_ep11_attrs(tokdata, key_obj->template,
                          &new_attrs2, &new_attrs2_len,
                          ktype, CKO_SECRET_KEY, -1, mech);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_ep11_attrs failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    switch (mech->mechanism){
    case CKM_AES_XTS_KEY_GEN:
        xts = TRUE;
        mech2.mechanism = CKM_AES_KEY_GEN;
        mapped_mech = TRUE;
#ifndef NO_PKEY
        rc = ep11tok_pkey_check_aes_xts(tokdata, key_obj, mech->mechanism);
#else
        rc = CKR_FUNCTION_NOT_SUPPORTED;
#endif
        if (rc != CKR_OK) {
            TRACE_ERROR("%s EP11 AES XTS is not supported: rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        break;
    case CKM_SHA_1_KEY_GEN:
    case CKM_SHA224_KEY_GEN:
    case CKM_SHA256_KEY_GEN:
    case CKM_SHA384_KEY_GEN:
    case CKM_SHA512_KEY_GEN:
    case CKM_SHA512_224_KEY_GEN:
    case CKM_SHA512_256_KEY_GEN:
    case CKM_SHA3_224_KEY_GEN:
    case CKM_SHA3_256_KEY_GEN:
    case CKM_SHA3_384_KEY_GEN:
    case CKM_SHA3_512_KEY_GEN:
        rc = ep11tok_pkcs11_mech_translate(tokdata, mech->mechanism,
                                           &mech2.mechanism);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s ep11tok_pkcs11_mech_translate failed: rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        mapped_mech = TRUE;
        break;
    }

    trace_attributes(__func__, "Generate key:", new_attrs2, new_attrs2_len);

    ep11_get_pin_blob(tokdata, ep11_session,
                      ep11_is_session_object(attrs, attrs_len),
                      ep11_is_private_object(attrs, attrs_len),
                      &ep11_pin_blob, &ep11_pin_blob_len);

retry:
    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_CREATE_KEY_START()
        rc = dll_m_GenerateKey(mapped_mech ? &mech2 : mech, new_attrs2, new_attrs2_len,
                               ep11_pin_blob, ep11_pin_blob_len, blob, &blobsize,
                               csum, &csum_len, target_info->target);
    RETRY_REENC_CREATE_KEY_END(tokdata, session, target_info,
                               blob, reenc_blob, blobsize, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s m_GenerateKey rc=0x%lx mech='%s' attrs_len=0x%lx\n",
                    __func__, rc, ep11_get_ckm(tokdata, mech->mechanism),
                    attrs_len);
        goto error;
    }

    TRACE_INFO("%s m_GenerateKey rc=0x%lx mech='%s' attrs_len=0x%lx\n",
               __func__, rc, ep11_get_ckm(tokdata, mech->mechanism), attrs_len);

    if (check_expected_mkvp(tokdata, blob, blobsize, &blob_new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto error;
    }

    if (xts) {
retry_xts:
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_CREATE_KEY_START()
            rc = dll_m_GenerateKey(&mech2, new_attrs2, new_attrs2_len,
                                   ep11_pin_blob, ep11_pin_blob_len, blob2,
                                   &blobsize2, csum2, &csum2_len,
                                   target_info->target);
        RETRY_REENC_CREATE_KEY_END(tokdata, session, target_info,
                                   blob2, reenc_blob2, blobsize2, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, session);
            TRACE_ERROR("%s m_GenerateKey rc=0x%lx mech='%s' attrs_len=0x%lx\n",
                        __func__, rc, ep11_get_ckm(tokdata, mech->mechanism),
                        attrs_len);
            goto error;
        }

        TRACE_INFO("%s m_GenerateKey rc=0x%lx mech='%s' attrs_len=0x%lx\n",
               __func__, rc, ep11_get_ckm(tokdata, mech->mechanism), attrs_len);

        if (check_expected_mkvp(tokdata, blob2, blobsize2,
                                &blob2_new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            rc = CKR_DEVICE_ERROR;
            goto error;
        }

        if (ep11_data->mk_change_active && blob_new_mk != blob2_new_mk) {
            /*
             * New MK has been set after generating key 1 but before
             * generating key 2
             */
            if (blob2_new_mk == TRUE) {
                /*
                 * Key 2 was created with new MK, key 1 with old MK.
                 * Key 2 already has blob and reenc_blob with new MK,
                 * Key 1 has blob with old MK, and blob_reenc with new MK.
                 * Supply blob_reenc with new MK in blob also.
                 */
                memcpy(blob, reenc_blob, blobsize);
            } else {
                /*
                 * Key 1 was created with new MK, but key 2 with old MK.
                 * This can happen when the single APQN with new MK went offline
                 * and a new single APQN with old MK is selected after creating
                 * key 1 but before creating key 2. Since there is no key1 blob
                 * with old MK, we need to re-create both keys (both with old
                 * MK now).
                 */
                goto retry;
            }
        }

        /* Compare check sums to ensure the 2 key parts are not the same */
        if (csum_len == csum2_len && memcmp(csum, csum2, csum_len) == 0)
            goto retry_xts;

        if (blobsize + blobsize2 > MAX_BLOBSIZE) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto error;
        }

        memcpy(blob + blobsize, blob2, blobsize2);
        if (ep11_data->mk_change_active)
            memcpy(reenc_blob + blobsize, reenc_blob2, blobsize2);
        blobsize = blobsize + blobsize2;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, blob, blobsize, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = template_update_attribute(key_obj->template, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }
    attr = NULL;

    if (ep11_data->mk_change_active) {
        rc = build_attribute(CKA_IBM_OPAQUE_REENC, reenc_blob, blobsize, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__,
                        rc);
            goto error;
        }

        rc = template_update_attribute(key_obj->template, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        attr = NULL;
    }

    rc = update_ep11_attrs_from_blob(tokdata, session, key_obj, xts);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s update_ep11_attrs_from_blob failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    if (!xts && csum_len >= EP11_CSUMSIZE) {
        /* First 3 bytes of csum is the check value */
        rc = build_attribute(CKA_CHECK_VALUE, csum, EP11_CSUMSIZE, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        rc = template_update_attribute(key_obj->template, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto error;
        }
        attr = NULL;
    }

    /* add CKA_KEY_GEN_MECHANISM */
    rc = build_attribute(CKA_KEY_GEN_MECHANISM, (CK_BYTE *)&mech->mechanism,
                         sizeof(CK_MECHANISM_TYPE), &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(key_obj->template, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto error;
    }
    attr = NULL;

    /* Set CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE */
    rc = key_mgr_apply_always_sensitive_never_extractable_attrs(tokdata,
                                                                key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s key_mgr_apply_always_sensitive_never_extractable_attrs "
                    "failed  with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    /* key should be fully constructed.
     * Assign an object handle and store key.
     * Enforce policy.
     */
    rc = object_mgr_create_final(tokdata, session, key_obj, handle);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s object_mgr_create_final with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    INC_COUNTER(tokdata, session, mech, key_obj, POLICY_STRENGTH_IDX_0);

    goto done;
error:
    if (key_obj)
        object_free(key_obj);
    if (attr != NULL)
        free(attr);
    *handle = 0;
done:
    if (new_attrs)
        free_attribute_array(new_attrs, new_attrs_len);
    if (new_attrs2)
        free_attribute_array(new_attrs2, new_attrs2_len);
    return rc;
}

CK_BBOOL ep11tok_libica_digest_available(STDLL_TokData_t *tokdata,
                                         ep11_private_data_t *ep11_data,
                                         CK_MECHANISM_TYPE mech)
{
    int use_libica;

    switch (mech) {
    case CKM_SHA_1:
        use_libica = ep11_data->libica.ica_sha1 != NULL;
        break;
    case CKM_SHA224:
        use_libica = ep11_data->libica.ica_sha224 != NULL;
        break;
    case CKM_SHA256:
        use_libica = ep11_data->libica.ica_sha256 != NULL;
        break;
    case CKM_SHA384:
        use_libica = ep11_data->libica.ica_sha384 != NULL;
        break;
    case CKM_SHA512:
        use_libica = ep11_data->libica.ica_sha512 != NULL;
        break;
    case CKM_SHA512_224:
        use_libica = ep11_data->libica.ica_sha512_224 != NULL;
        break;
    case CKM_SHA512_256:
        use_libica = ep11_data->libica.ica_sha512_256 != NULL;
        break;
#ifdef SHA3_224
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        use_libica = ep11_data->libica.ica_sha3_224 != NULL;
        break;
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        use_libica = ep11_data->libica.ica_sha3_256 != NULL;
        break;
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        use_libica = ep11_data->libica.ica_sha3_384 != NULL;
        break;
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        use_libica = ep11_data->libica.ica_sha3_512 != NULL;
        break;
#endif
    default:
        use_libica = 0;
    }

    if (use_libica == 0)
        TRACE_DEVEL("%s mech=%s is not supported by libica\n", __func__,
                    ep11_get_ckm(tokdata, mech));

    return use_libica ? CK_TRUE : CK_FALSE;
}

static CK_RV ep11tok_digest_from_mech(CK_MECHANISM_TYPE mech,
                                      CK_MECHANISM_TYPE *digest_mech)
{
    switch (mech) {
    case CKM_SHA_1:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
        *digest_mech = CKM_SHA_1;
        break;

    case CKM_SHA224:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA224:
        *digest_mech = CKM_SHA224;
        break;

    case CKM_SHA256:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA256:
        *digest_mech = CKM_SHA256;
        break;

    case CKM_SHA384:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA384:
        *digest_mech = CKM_SHA384;
        break;

    case CKM_SHA512:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA512:
        *digest_mech = CKM_SHA512;
        break;

    case CKM_SHA512_224:
        *digest_mech = CKM_SHA512_224;
        break;

    case CKM_SHA512_256:
        *digest_mech = CKM_SHA512_256;
        break;

    case CKM_IBM_SHA3_224:
        *digest_mech = CKM_IBM_SHA3_224;
        break;

    case CKM_IBM_SHA3_256:
        *digest_mech = CKM_IBM_SHA3_256;
        break;

    case CKM_IBM_SHA3_384:
        *digest_mech = CKM_IBM_SHA3_384;
        break;

    case CKM_IBM_SHA3_512:
        *digest_mech = CKM_IBM_SHA3_512;
        break;

    case CKM_SHA3_224:
    case CKM_SHA3_224_RSA_PKCS:
    case CKM_ECDSA_SHA3_224:
        *digest_mech = CKM_SHA3_224;
        break;

    case CKM_SHA3_256:
    case CKM_SHA3_256_RSA_PKCS:
    case CKM_ECDSA_SHA3_256:
        *digest_mech = CKM_SHA3_256;
        break;

    case CKM_SHA3_384:
    case CKM_SHA3_384_RSA_PKCS:
    case CKM_ECDSA_SHA3_384:
        *digest_mech = CKM_SHA3_384;
        break;

    case CKM_SHA3_512:
    case CKM_SHA3_512_RSA_PKCS:
    case CKM_ECDSA_SHA3_512:
        *digest_mech = CKM_SHA3_512;
        break;

    default:
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

static CK_BBOOL ep11tok_ec_curve_supported2(STDLL_TokData_t *tokdata,
                                            TEMPLATE *template,
                                            const struct _ec **curve)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    int i, status;
    const CK_VERSION ver3 = { .major = 3, .minor = 0 };

    *curve = NULL;

    rc = template_attribute_get_non_empty(template, CKA_ECDSA_PARAMS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_ECDSA_PARAMS for the key.\n");
        return CK_FALSE;
    }

    for (i = 0; i < NUMEC; i++) {
        if (der_ec_supported[i].data_size == attr->ulValueLen &&
            (memcmp(attr->pValue, der_ec_supported[i].data,
             attr->ulValueLen) == 0)) {
            *curve = &der_ec_supported[i];
            break;
        }
    }

    if (*curve == NULL) {
        TRACE_DEVEL("%s EC curve not supported\n", __func__);
        return CK_FALSE;
    }

    switch ((*curve)->curve_type) {
    case PRIME_CURVE:
    case BRAINPOOL_CURVE:
    case KOBLITZ_CURVE:
        break;

    case MONTGOMERY_CURVE:
    case EDWARDS_CURVE:
        if (compare_ck_version(&ep11_data->ep11_lib_version, &ver3) < 0) {
            TRACE_INFO("%s Curve requires host library version 3 or later\n",
                       __func__);
            return CK_FALSE;
        }

        status = check_required_versions(tokdata, edwards_req_versions,
                                         NUM_EDWARDS_REQ);
        if (status != 1) {
            TRACE_INFO("%s Curve not supported due to mixed firmware versions\n",
                       __func__);
            return CK_FALSE;
        }

        break;

    default:
        TRACE_DEVEL("%s EC curve not supported\n", __func__);
        return CK_FALSE;
    }

    return CK_TRUE;
}

static CK_BBOOL ep11tok_ec_curve_supported(STDLL_TokData_t *tokdata,
                                           CK_OBJECT_HANDLE hKey)
{
    CK_RV rc;
    OBJECT *key_obj;
    CK_BBOOL ret;
    const struct _ec *curve = NULL;

    rc = object_mgr_find_in_map1(tokdata, hKey, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s key 0x%lx not mapped\n", __func__, hKey);
        return CK_FALSE;
    }

    ret = ep11tok_ec_curve_supported2(tokdata, key_obj->template, &curve);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return ret;
}

CK_BBOOL ep11tok_libica_mech_available(STDLL_TokData_t *tokdata,
                                       CK_MECHANISM_TYPE mech,
                                       CK_OBJECT_HANDLE hKey)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_MECHANISM_TYPE digest_mech;
    CK_RV rc;

    rc = ep11tok_digest_from_mech(mech, &digest_mech);
    if (rc != CKR_OK)
        return CK_FALSE;

    switch (mech) {
       case CKM_ECDSA_SHA1:
       case CKM_ECDSA_SHA224:
       case CKM_ECDSA_SHA256:
       case CKM_ECDSA_SHA384:
       case CKM_ECDSA_SHA512:
       case CKM_ECDSA_SHA3_224:
       case CKM_ECDSA_SHA3_256:
       case CKM_ECDSA_SHA3_384:
       case CKM_ECDSA_SHA3_512:
           if (!ep11tok_ec_curve_supported(tokdata, hKey))
               return CK_FALSE;
           break;
    }

    return ep11tok_libica_digest_available(tokdata, ep11_data, digest_mech);
}

CK_RV ep11tok_libica_digest(STDLL_TokData_t *tokdata,
                            ep11_private_data_t *ep11_data,
                            CK_MECHANISM_TYPE mech, libica_sha_context_t *ctx,
                            CK_BYTE *in_data, CK_ULONG in_data_len,
                            CK_BYTE *out_data, CK_ULONG *out_data_len,
                            unsigned int message_part)
{
    CK_ULONG hsize;
    CK_RV rc;

    rc = get_sha_size(mech, &hsize);
    if (rc != CKR_OK)
        return rc;

    if (*out_data_len < hsize)
        return CKR_BUFFER_TOO_SMALL;

    TRACE_DEVEL("%s mech=%s part=%u\n", __func__,
                ep11_get_ckm(tokdata, mech), message_part);

    switch (mech) {
    case CKM_SHA_1:
        rc = ep11_data->libica.ica_sha1(message_part, in_data_len, in_data,
                                        &ctx->ctx.sha1, out_data);
        break;
    case CKM_SHA224:
        rc = ep11_data->libica.ica_sha224(message_part, in_data_len, in_data,
                                          &ctx->ctx.sha256, out_data);
        break;
    case CKM_SHA256:
        rc = ep11_data->libica.ica_sha256(message_part, in_data_len, in_data,
                                          &ctx->ctx.sha256, out_data);
        break;
    case CKM_SHA384:
        rc = ep11_data->libica.ica_sha384(message_part, in_data_len, in_data,
                                          &ctx->ctx.sha512, out_data);
        break;
    case CKM_SHA512:
        rc = ep11_data->libica.ica_sha512(message_part, in_data_len, in_data,
                                          &ctx->ctx.sha512, out_data);
        break;
    case CKM_SHA512_224:
        rc = ep11_data->libica.ica_sha512_224(message_part, in_data_len, in_data,
                                              &ctx->ctx.sha512, out_data);
        break;
    case CKM_SHA512_256:
        rc = ep11_data->libica.ica_sha512_256(message_part, in_data_len, in_data,
                                              &ctx->ctx.sha512, out_data);
        break;
#ifdef SHA3_224
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        rc = ep11_data->libica.ica_sha3_224(message_part, in_data_len, in_data,
                                            &ctx->ctx.sha3_224, out_data);
        break;
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        rc = ep11_data->libica.ica_sha3_256(message_part, in_data_len, in_data,
                                            &ctx->ctx.sha3_256, out_data);
        break;
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        rc = ep11_data->libica.ica_sha3_384(message_part, in_data_len, in_data,
                                            &ctx->ctx.sha3_384, out_data);
        break;
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        rc = ep11_data->libica.ica_sha3_512(message_part, in_data_len, in_data,
                                            &ctx->ctx.sha3_512, out_data);
        break;
#endif
    default:
        TRACE_ERROR("%s Invalid mechanism: mech=%s\n", __func__,
                    ep11_get_ckm(tokdata, mech));
        return CKR_MECHANISM_INVALID;
    }

    if (rc != CKR_OK) {
        TRACE_ERROR("%s Libica SHA failed. mech=%s rc=0x%lx\n", __func__,
                    ep11_get_ckm(tokdata, mech), rc);

        switch (rc) {
        case EINVAL:
            return CKR_ARGUMENTS_BAD;
        case ENODEV:
            return CKR_DEVICE_ERROR;
        default:
            return CKR_FUNCTION_FAILED;
        }
    }

    *out_data_len = hsize;
    return CKR_OK;
}

CK_RV token_specific_sha_init(STDLL_TokData_t * tokdata, DIGEST_CONTEXT * c,
                              CK_MECHANISM * mech)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    size_t state_len = MAX(MAX_DIGEST_STATE_BYTES * 2,
                           sizeof(libica_sha_context_t));
    size_t usestate_len = 0;
    CK_BYTE *state, *usestate;
    libica_sha_context_t *libica_ctx;
    ep11_target_info_t* target_info;
    CK_MECHANISM ep11_mech = *mech;

    state = calloc(state_len, 1); /* freed by dig_mgr.c */
    if (!state) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    target_info = get_target_info(tokdata);
    if (target_info == NULL) {
        free(state);
        return CKR_FUNCTION_FAILED;
    }

    if (ep11tok_libica_digest_available(tokdata, ep11_data, mech->mechanism)) {
        libica_ctx = (libica_sha_context_t *)state;
        state_len = sizeof(libica_sha_context_t);
        libica_ctx->first = CK_TRUE;
        rc = get_sha_block_size(mech->mechanism, &libica_ctx->block_size);
    } else {
        ep11tok_pkcs11_mech_translate(tokdata, mech->mechanism,
                                      &ep11_mech.mechanism);
        /*
         * state is allocated large enough to hold 2 times the max state blob.
         * Initially use the first half only. The second half is for the
         * re-enciphered state blob (if mk change is active).
         */
        state_len /= 2;

        RETRY_SINGLE_APQN_START(tokdata, rc)
        RETRY_UPDATE_BLOB_START(tokdata, target_info, state, state_len,
                                state + state_len, state_len,
                                usestate, usestate_len)
            rc = dll_m_DigestInit(usestate, &usestate_len, &ep11_mech,
                                  target_info->target);
            if (rc == CKR_OK && retry == 1) {
                /*
                 * Initially, the real state_len is unknown, and is set to
                 * allocated state size / 2. When the state was created on
                 * an APQN with new WK set already, move the state to the
                 * final place, which is state + usestate_len, where
                 * usestate_len now is the real state size.
                 */
                memmove(state + usestate_len, state + state_len, usestate_len);
            }
            state_len = usestate_len;
        RETRY_UPDATE_BLOB_END(tokdata, NULL, target_info, state, state_len,
                              state + state_len, state_len,
                              usestate, usestate_len, rc)
        RETRY_SINGLE_APQN_END(rc, tokdata, target_info)
    }

    put_target_info(tokdata, target_info);

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
        free(state);
    } else {
        /* DIGEST_CONTEXT will show up with following
         *  requests (sha_update), 'state' is build by the card
         * and holds all to continue, even by another adapter
         */
        c->mech.ulParameterLen = mech->ulParameterLen;
        c->mech.mechanism = mech->mechanism;
        c->mech.pParameter = NULL;
        c->context = state;
        c->context_len = state_len * 2; /* current and re-enciphered state */

        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV token_specific_sha(STDLL_TokData_t * tokdata, DIGEST_CONTEXT * c,
                         CK_BYTE * in_data,
                         CK_ULONG in_data_len, CK_BYTE * out_data,
                         CK_ULONG * out_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    ep11_target_info_t* target_info;
    CK_BYTE *state;
    size_t state_len;

    target_info = get_target_info(tokdata);
    if (target_info == NULL)
        return CKR_FUNCTION_FAILED;

    if (ep11tok_libica_digest_available(tokdata, ep11_data, c->mech.mechanism)) {
        rc = ep11tok_libica_digest(tokdata, ep11_data, c->mech.mechanism,
                                   (libica_sha_context_t *)c->context,
                                   in_data, in_data_len,
                                   out_data, out_data_len,
                                   SHA_MSG_PART_ONLY);
    } else {
        RETRY_SINGLE_APQN_START(tokdata, rc)
        RETRY_UPDATE_BLOB_START(tokdata, target_info,
                                c->context, c->context_len / 2,
                                c->context + (c->context_len / 2),
                                c->context_len / 2, state, state_len)
            rc = dll_m_Digest(state, state_len,
                              in_data, in_data_len,
                              out_data, out_data_len, target_info->target);
        RETRY_UPDATE_BLOB_END(tokdata, NULL, target_info,
                              c->context, c->context_len / 2,
                              c->context + (c->context_len / 2),
                              c->context_len / 2, state, state_len, rc)
        RETRY_SINGLE_APQN_END(rc, tokdata, target_info)
    }

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    put_target_info(tokdata, target_info);
    return rc;
}


CK_RV token_specific_sha_update(STDLL_TokData_t * tokdata, DIGEST_CONTEXT * c,
                                CK_BYTE * in_data, CK_ULONG in_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    libica_sha_context_t *libica_ctx = (libica_sha_context_t *)c->context;
    CK_BYTE temp_out[MAX_SHA_HASH_SIZE];
    CK_ULONG out_len = sizeof(temp_out);
    CK_ULONG len;
    CK_RV rc = CKR_OK;
    ep11_target_info_t* target_info;
    CK_BYTE *state;
    size_t state_len;

    target_info = get_target_info(tokdata);
    if (target_info == NULL)
        return CKR_FUNCTION_FAILED;

    if (ep11tok_libica_digest_available(tokdata, ep11_data, c->mech.mechanism)) {
        if (libica_ctx->offset > 0 || in_data_len < libica_ctx->block_size) {
            len = MIN(libica_ctx->block_size - libica_ctx->offset,
                      in_data_len);
            memcpy(&libica_ctx->buffer[libica_ctx->offset], in_data, len);
            libica_ctx->offset += len;

            in_data += len;
            in_data_len -= len;

            if (libica_ctx->offset == libica_ctx->block_size) {
                rc = ep11tok_libica_digest(tokdata,
                                           ep11_data, c->mech.mechanism,
                                           libica_ctx, libica_ctx->buffer,
                                           libica_ctx->offset, temp_out,
                                           &out_len, libica_ctx->first ?
                                                        SHA_MSG_PART_FIRST :
                                                        SHA_MSG_PART_MIDDLE);
                if (rc != CKR_OK)
                    goto out;

                libica_ctx->first = CK_FALSE;

                libica_ctx->offset = 0;
            }
        }

        if (in_data_len > 0) {
            len = (in_data_len / libica_ctx->block_size) * libica_ctx->block_size;
            rc = ep11tok_libica_digest(tokdata, ep11_data, c->mech.mechanism,
                                       libica_ctx, in_data, len, temp_out,
                                       &out_len, libica_ctx->first ?
                                                    SHA_MSG_PART_FIRST :
                                                    SHA_MSG_PART_MIDDLE);
            if (rc != CKR_OK)
                goto out;

            libica_ctx->first = CK_FALSE;

            in_data += len;
            in_data_len -= len;

            if (in_data_len > 0) {
                memcpy(libica_ctx->buffer, in_data, in_data_len);
                libica_ctx->offset = in_data_len;
            }
        }
    } else {
        RETRY_SINGLE_APQN_START(tokdata, rc)
        RETRY_UPDATE_BLOB_START(tokdata, target_info,
                                c->context, c->context_len / 2,
                                c->context + (c->context_len / 2),
                                c->context_len / 2, state, state_len)
            rc = dll_m_DigestUpdate(state, state_len,
                                    in_data, in_data_len, target_info->target);
        RETRY_UPDATE_BLOB_END(tokdata, NULL, target_info,
                              c->context, c->context_len / 2,
                              c->context + (c->context_len / 2),
                              c->context_len / 2, state, state_len, rc)
        RETRY_SINGLE_APQN_END(rc, tokdata, target_info)
    }

out:
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    put_target_info(tokdata, target_info);
    return rc;
}


CK_RV token_specific_sha_final(STDLL_TokData_t * tokdata, DIGEST_CONTEXT * c,
                               CK_BYTE * out_data, CK_ULONG * out_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    libica_sha_context_t *libica_ctx = (libica_sha_context_t *)c->context;
    CK_RV rc;
    ep11_target_info_t* target_info;
    CK_BYTE *state;
    size_t state_len;

    target_info = get_target_info(tokdata);
    if (target_info == NULL)
        return CKR_FUNCTION_FAILED;

    if (ep11tok_libica_digest_available(tokdata, ep11_data, c->mech.mechanism)) {
        rc = ep11tok_libica_digest(tokdata, ep11_data, c->mech.mechanism,
                                   libica_ctx, libica_ctx->buffer,
                                   libica_ctx->offset,
                                   out_data, out_data_len,
                                   libica_ctx->first ?
                                        SHA_MSG_PART_ONLY :
                                        SHA_MSG_PART_FINAL);
    } else {
        RETRY_SINGLE_APQN_START(tokdata, rc)
        RETRY_UPDATE_BLOB_START(tokdata, target_info,
                                c->context, c->context_len / 2,
                                c->context + (c->context_len / 2),
                                c->context_len / 2, state, state_len)
            rc = dll_m_DigestFinal(state, state_len,
                                   out_data, out_data_len, target_info->target);
        RETRY_UPDATE_BLOB_END(tokdata, NULL, target_info,
                              c->context, c->context_len / 2,
                              c->context + (c->context_len / 2),
                              c->context_len / 2, state, state_len, rc)
        RETRY_SINGLE_APQN_END(rc, tokdata, target_info)
    }

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    put_target_info(tokdata, target_info);
    return rc;
}

CK_RV token_specific_rsa_sign(STDLL_TokData_t *tokdata, SESSION *session,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len,
                              OBJECT *key_obj)
{
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    CK_MECHANISM mech;
    CK_BYTE *useblob;
    size_t useblobsize;

    rc = obj_opaque_2_blob(tokdata, key_obj, &keyblob, &keyblobsize);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    mech.mechanism = CKM_RSA_PKCS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, key_obj, keyblob, keyblobsize,
                           useblob, useblobsize, rc)
        rc = dll_m_SignSingle(useblob, useblobsize, &mech,
                              in_data, in_data_len,
                              out_data, out_data_len, target_info->target);
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblobsize, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV token_specific_rsa_verify(STDLL_TokData_t *tokdata, SESSION *session,
                                CK_BYTE *in_data, CK_ULONG in_data_len,
                                CK_BYTE *signature, CK_ULONG sig_len,
                                OBJECT *key_obj)
{
    CK_RV rc;
    CK_BYTE *spki;
    size_t spki_len = 0;
    CK_MECHANISM mech;
    CK_BYTE *useblob;
    size_t useblob_len;

    rc = obj_opaque_2_blob(tokdata, key_obj, &spki, &spki_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    mech.mechanism = CKM_RSA_PKCS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, key_obj, spki, spki_len,
                           useblob, useblob_len, rc)
        rc = dll_m_VerifySingle(useblob, useblob_len, &mech,
                                in_data, in_data_len,
                                signature, sig_len, target_info->target);
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblob_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV token_specific_rsa_pss_sign(STDLL_TokData_t *tokdata, SESSION *session,
                                  SIGN_VERIFY_CONTEXT *ctx,
                                  CK_BYTE *in_data, CK_ULONG in_data_len,
                                  CK_BYTE *sig, CK_ULONG *sig_len)
{
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj;
    CK_MECHANISM mech;
    CK_BYTE *useblob;
    size_t useblobsize;

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    mech.mechanism = CKM_RSA_PKCS_PSS;
    mech.ulParameterLen = ctx->mech.ulParameterLen;
    mech.pParameter = ctx->mech.pParameter;

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, key_obj, keyblob, keyblobsize,
                           useblob, useblobsize, rc)
        rc = dll_m_SignSingle(useblob, useblobsize, &mech, in_data, in_data_len,
                              sig, sig_len, target_info->target);
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblobsize, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV token_specific_rsa_pss_verify(STDLL_TokData_t *tokdata, SESSION *session,
                                    SIGN_VERIFY_CONTEXT *ctx,
                                    CK_BYTE *in_data, CK_ULONG in_data_len,
                                    CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_RV rc;
    CK_BYTE *spki;
    size_t spki_len = 0;
    OBJECT *key_obj;
    CK_MECHANISM mech;
    CK_BYTE *useblob;
    size_t useblob_len;

    rc = h_opaque_2_blob(tokdata, ctx->key, &spki, &spki_len, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    mech.mechanism = CKM_RSA_PKCS_PSS;
    mech.ulParameterLen = ctx->mech.ulParameterLen;
    mech.pParameter = ctx->mech.pParameter;

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, key_obj, spki, spki_len,
                           useblob, useblob_len, rc)
        rc = dll_m_VerifySingle(useblob, useblob_len, &mech,
                                in_data, in_data_len,
                                signature, sig_len, target_info->target);
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblob_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV token_specific_ec_sign(STDLL_TokData_t *tokdata, SESSION  *session,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key_obj )
{
#ifndef NO_PKEY
    SIGN_VERIFY_CONTEXT *ctx = &(session->sign_ctx);
#endif
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    CK_MECHANISM mech;
    CK_BYTE *useblob;
    size_t useblobsize;

    rc = obj_opaque_2_blob(tokdata, key_obj, &keyblob, &keyblobsize);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

#ifndef NO_PKEY
    rc = ep11tok_pkey_check(tokdata, session, key_obj, &ctx->mech);
    switch (rc) {
    case CKR_OK:
        rc = pkey_ec_sign(tokdata, session, key_obj, in_data, in_data_len,
                          out_data, out_data_len, NULL,
                          ep11tok_pkey_convert_key);
        goto done;
    case CKR_FUNCTION_NOT_SUPPORTED:
        break;
    default:
        goto done;
    }
#endif /* NO_PKEY */

    mech.mechanism = CKM_ECDSA;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, key_obj, keyblob, keyblobsize,
                           useblob, useblobsize, rc)
        rc = dll_m_SignSingle(useblob, useblobsize, &mech, in_data, in_data_len,
                              out_data, out_data_len, target_info->target);
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblobsize, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

#ifndef NO_PKEY
done:
#endif

    return rc;
}

CK_RV token_specific_ec_verify(STDLL_TokData_t *tokdata, SESSION  *session,
                               CK_BYTE *in_data, CK_ULONG in_data_len,
                               CK_BYTE *out_data, CK_ULONG out_data_len,
                               OBJECT *key_obj )
{
#ifndef NO_PKEY
    SIGN_VERIFY_CONTEXT *ctx = &(session->verify_ctx);
#endif
    CK_RV rc;
    CK_BYTE *spki;
    size_t spki_len = 0;
    CK_MECHANISM mech;
    CK_BYTE *useblob;
    size_t useblob_len;

    rc = obj_opaque_2_blob(tokdata, key_obj, &spki, &spki_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

#ifndef NO_PKEY
    rc = ep11tok_pkey_check(tokdata, session, key_obj, &ctx->mech);
    switch (rc) {
    case CKR_OK:
        rc = pkey_ec_verify(key_obj, in_data, in_data_len,
                            out_data, out_data_len);
        goto done;
    case CKR_FUNCTION_NOT_SUPPORTED:
        break;
    default:
        goto done;
    }
#endif /* NO_PKEY */

    mech.mechanism = CKM_ECDSA;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, key_obj, spki, spki_len,
                           useblob, useblob_len, rc)
        rc = dll_m_VerifySingle(useblob, useblob_len, &mech,
                                in_data, in_data_len,
                                out_data, out_data_len, target_info->target);
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblob_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

#ifndef NO_PKEY
done:
#endif

    return rc;
}

CK_RV token_specific_reencrypt_single(STDLL_TokData_t *tokdata,
                                     SESSION *session,
                                      ENCR_DECR_CONTEXT *decr_ctx,
                                      CK_MECHANISM *decr_mech,
                                      OBJECT *decr_key_obj,
                                      ENCR_DECR_CONTEXT *encr_ctx,
                                      CK_MECHANISM *encr_mech,
                                      OBJECT *encr_key_obj,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    CK_RV rc;
    CK_BYTE *decr_key, *encr_key;
    size_t decr_key_len = 0, encr_key_len = 0;
    int status;
    CK_BYTE *decr_useblob, *encr_useblob;
    size_t decr_useblob_len, encr_useblob_len;

    UNUSED(decr_ctx);
    UNUSED(encr_ctx);

    if (dll_m_ReencryptSingle == NULL)
        return CKR_FUNCTION_NOT_SUPPORTED;

    status = check_required_versions(tokdata, reencrypt_single_req_versions,
                                     NUM_REENCRYPT_SINGLE_REQ);
    if (status != 1)
        return CKR_FUNCTION_NOT_SUPPORTED;

    rc = obj_opaque_2_blob(tokdata, decr_key_obj, &decr_key, &decr_key_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no decr-blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    rc = obj_opaque_2_blob(tokdata, encr_key_obj, &encr_key, &encr_key_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no encrr-blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB2_START(tokdata, target_info,
                            decr_key_obj, decr_key, decr_key_len,
                            decr_useblob, decr_useblob_len,
                            encr_key_obj, encr_key, encr_key_len,
                            encr_useblob, encr_useblob_len, rc)
        rc = dll_m_ReencryptSingle(decr_useblob, decr_useblob_len,
                                   encr_useblob, encr_useblob_len,
                                   decr_mech, encr_mech, in_data, in_data_len,
                                   out_data, out_data_len, target_info->target);
    RETRY_REENC_BLOB2_END(tokdata, target_info,
                          decr_useblob, decr_useblob_len,
                          encr_useblob, encr_useblob_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

#ifndef NO_PKEY
/**
 * This routine is currently only used when the operation is performed using
 * a protected key. Therefore we don't have (and don't need) an ep11
 * fallback here.
 */
CK_RV token_specific_aes_ecb(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key_obj, CK_BYTE encrypt)
{
    return pkey_aes_ecb(tokdata, sess, key_obj, in_data, in_data_len,
                        out_data, out_data_len, encrypt,
                        ep11tok_pkey_convert_key);
}

/**
 * This routine is currently only used when the operation is performed using
 * a protected key. Therefore we don't have (and don't need) an ep11
 * fallback here.
 */
CK_RV token_specific_aes_cbc(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key_obj, CK_BYTE *init_v,
                             CK_BYTE encrypt)
{
    return pkey_aes_cbc(tokdata, sess, key_obj, init_v, in_data, in_data_len,
                        out_data, out_data_len, encrypt,
                        ep11tok_pkey_convert_key);
}

/**
 * This routine is currently only used when the operation is performed using
 * a protected key. Therefore we don't have (and don't need) an ep11
 * fallback here.
 */
CK_RV token_specific_aes_cmac(STDLL_TokData_t *tokdata, SESSION *session,
                              CK_BYTE *message, CK_ULONG message_len,
                              OBJECT *key_obj, CK_BYTE *iv,
                              CK_BBOOL first, CK_BBOOL last,
                              CK_VOID_PTR *context)
{
    CK_RV rc;

    UNUSED(context);

    if (first && last)
        rc = pkey_aes_cmac(tokdata, session, key_obj, message, message_len,
                           iv, NULL, ep11tok_pkey_convert_key);
    else if (!last)
        rc = pkey_aes_cmac(tokdata, session, key_obj, message, message_len,
                           NULL, iv, ep11tok_pkey_convert_key);
    else // last
        rc = pkey_aes_cmac(tokdata, session, key_obj, message, message_len,
                           iv, iv, ep11tok_pkey_convert_key);

    return rc;
}

/**
 * This routine is currently only used when the operation is performed using
 * a protected key. Therefore we don't have (and don't need) an ep11
 * fallback here.
 */
CK_RV token_specific_aes_xts(STDLL_TokData_t *tokdata, SESSION *session,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key_obj, CK_BYTE *init_v,
                             CK_BBOOL encrypt, CK_BBOOL initial,
                             CK_BBOOL final, CK_BYTE *iv)
{
    return pkey_aes_xts(tokdata, session, key_obj, init_v,
                        in_data, in_data_len, out_data, out_data_len,
                        encrypt, initial, final, iv,
                        ep11tok_pkey_convert_key);
}
#endif /* NO_PKEY */

struct EP11_KYBER_MECH {
    CK_MECHANISM mech;
    struct XCP_KYBER_KEM_PARAMS params;
};

static CK_RV ep11tok_kyber_mech_pre_process(STDLL_TokData_t *tokdata,
                                            CK_MECHANISM *mech,
                                            struct EP11_KYBER_MECH *mech_ep11,
                                            OBJECT **secret_key_obj,
                                            CK_BBOOL use_reenc_blob)
{
    CK_IBM_KYBER_PARAMS *kyber_params;
    CK_RV rc;

    kyber_params = mech->pParameter;
    if (mech->ulParameterLen != sizeof(CK_IBM_KYBER_PARAMS)) {
        TRACE_ERROR("Mechanism parameter length not as expected\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (kyber_params->ulVersion != CK_IBM_KYBER_KEM_VERSION) {
        TRACE_ERROR("Unsupported version in Kyber mechanism param\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    mech_ep11->mech.mechanism = mech->mechanism;
    mech_ep11->mech.pParameter = &mech_ep11->params;
    mech_ep11->mech.ulParameterLen = sizeof(mech_ep11->params);

    memset(&mech_ep11->params, 0, sizeof(mech_ep11->params));
    mech_ep11->params.version = XCP_KYBER_KEM_VERSION;
    mech_ep11->params.mode = kyber_params->mode;
    mech_ep11->params.kdf = kyber_params->kdf;
    mech_ep11->params.prepend = kyber_params->bPrepend;
    mech_ep11->params.pSharedData = kyber_params->pSharedData;
    mech_ep11->params.ulSharedDataLen = kyber_params->ulSharedDataLen;

    switch (kyber_params->mode) {
    case CK_IBM_KYBER_KEM_ENCAPSULATE:
        if (kyber_params->ulCipherLen > 0 && kyber_params->pCipher == NULL) {
            TRACE_ERROR("Unsupported cipher buffer in Kyber mechnism param "
                        "cannot be NULL\n");
            return CKR_MECHANISM_PARAM_INVALID;
        }

        mech_ep11->params.pCipher = NULL;
        mech_ep11->params.ulCipherLen = 0;
        /* Cipher is returned in 2nd output param of m_DeriveKey */
        break;

    case CK_IBM_KEM_DECAPSULATE:
        mech_ep11->params.pCipher = kyber_params->pCipher;
        mech_ep11->params.ulCipherLen = kyber_params->ulCipherLen;
        break;

    default:
        TRACE_ERROR("Unsupported mode in Kyber mechanism param\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (kyber_params->hSecret != CK_INVALID_HANDLE) {
        rc = h_opaque_2_blob(tokdata, kyber_params->hSecret,
                             &mech_ep11->params.pBlob,
                             &mech_ep11->params.ulBlobLen,
                             secret_key_obj, READ_LOCK);
        if (rc != CKR_OK) {
            TRACE_ERROR("h_opaque_2_blob failed hSecret=0x%lx\n",
                        kyber_params->hSecret);
            return rc;
        }

        if (use_reenc_blob) {
            rc = obj_opaque_2_reenc_blob(tokdata, *secret_key_obj,
                                         &mech_ep11->params.pBlob,
                                         &mech_ep11->params.ulBlobLen);
            if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE) {
                TRACE_ERROR("obj_opaque_2_reenc_blob failed hSecret=0x%lx\n",
                            kyber_params->hSecret);
                return rc;
            }
        }
    }

    return CKR_OK;
}

static CK_RV ep11tok_kyber_mech_post_process(STDLL_TokData_t *tokdata,
                                             CK_MECHANISM *mech,
                                             CK_BYTE *csum, CK_ULONG cslen)
{
    CK_IBM_KYBER_PARAMS *kyber_params;
    CK_ULONG cipher_len;

    UNUSED(tokdata);

    kyber_params = mech->pParameter;
    if (mech->ulParameterLen != sizeof(CK_IBM_KYBER_PARAMS)) {
        TRACE_ERROR("Mechanism parameter length not as expected\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (kyber_params->mode != CK_IBM_KYBER_KEM_ENCAPSULATE)
        return CKR_OK;

    /*
     * For encapsulate:
     * Generated cipher is returned in csum prepended with the checksum of
     * the generated symmetric key and its bit count (in total 7 bytes).
     */
    if (cslen < EP11_CSUMSIZE + 4) {
        TRACE_ERROR("%s returned cipher size is invalid: %lu\n",
                    __func__, cslen);
        return CKR_FUNCTION_FAILED;
    }

    cipher_len = cslen - (EP11_CSUMSIZE + 4);

    if (kyber_params->ulCipherLen < cipher_len) {
        TRACE_ERROR("%s Cipher buffer in kyber mechanism param too small, required: %lu\n",
                    __func__, cipher_len);
        kyber_params->ulCipherLen = cipher_len;
        OPENSSL_cleanse(&csum[EP11_CSUMSIZE + 4], cipher_len);
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(kyber_params->pCipher, &csum[EP11_CSUMSIZE + 4], cipher_len);
    kyber_params->ulCipherLen = cipher_len;

    OPENSSL_cleanse(&csum[EP11_CSUMSIZE + 4], cipher_len);
    return CKR_OK;
}

static CK_RV ep11tok_btc_mech_pre_process(STDLL_TokData_t *tokdata,
                                          OBJECT *key_obj,
                                          CK_ATTRIBUTE **new_attrs,
                                          CK_ULONG *new_attrs_len)
{
    CK_ATTRIBUTE *ec_params;
    CK_ULONG i, privlen;
    CK_RV rc;

    UNUSED(tokdata);

    /*
     * CKM_IBM_BTC_DERIVE requires CKA_VALUE_LEN to specify the byte length
     * of the to be derived EC key. CKA_VALUE_LEN is dependent on the
     * curve used.
     * CKA_VALUE_LEN can not be already in the user supplied template,
     * since this is not allowed by the key template check routines.
     */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_EC_PARAMS,
                                          &ec_params);
    if (rc != CKR_OK) {
        TRACE_ERROR("CKA_EC_PARAMS is required in derive template\n");
        return rc;
    }

    for (i = 0; i < NUMEC; i++) {
        if (der_ec_supported[i].data_size == ec_params->ulValueLen &&
            memcmp(ec_params->pValue, der_ec_supported[i].data,
                   ec_params->ulValueLen) == 0) {
            privlen = (der_ec_supported[i].len_bits + 7) / 8;
            rc = add_to_attribute_array(new_attrs, new_attrs_len,
                                        CKA_VALUE_LEN,
                                        (CK_BYTE_PTR)&privlen,
                                        sizeof(privlen));
            if (rc != CKR_OK) {
                TRACE_ERROR("Adding attribute failed type=CKA_VALUE_LEN "
                            "rc=0x%lx\n", rc);
                return rc;
            }
            break;
        }
    }

    return CKR_OK;
}

static CK_RV ep11tok_btc_mech_post_process(STDLL_TokData_t *tokdata,
                                           SESSION *session, CK_MECHANISM *mech,
                                           CK_ULONG class, CK_ULONG ktype,
                                           OBJECT *key_obj,
                                           CK_BYTE *blob, CK_ULONG bloblen,
                                           CK_BYTE *csum, CK_ULONG cslen)
{
    CK_IBM_BTC_DERIVE_PARAMS *btc_params = NULL;
    CK_BYTE *spki = NULL;
    CK_ULONG spki_length = 0;
    CK_BYTE buf[MAX_BLOBSIZE];
    CK_ATTRIBUTE get_attr[1] = {{ CKA_PUBLIC_KEY_INFO, &buf, sizeof(buf) }};
    CK_ATTRIBUTE *spki_attr = NULL;
    CK_BBOOL allocated = FALSE;
    CK_RV rc = CKR_OK;
    CK_BYTE *useblob;
    size_t useblob_len;

    if (mech->ulParameterLen != sizeof(CK_IBM_BTC_DERIVE_PARAMS) ||
        mech->pParameter == NULL) {
        TRACE_ERROR("%s Param NULL or len for %s wrong: %lu\n",
                    __func__, ep11_get_ckm(tokdata, mech->mechanism),
                    mech->ulParameterLen);
        return CKR_MECHANISM_PARAM_INVALID;
    }

    btc_params = (CK_IBM_BTC_DERIVE_PARAMS *)mech->pParameter;

    if (btc_params != NULL && btc_params->pChainCode != NULL &&
        cslen >= CK_IBM_BTC_CHAINCODE_LENGTH) {
        memcpy(btc_params->pChainCode, csum, CK_IBM_BTC_CHAINCODE_LENGTH);
        btc_params->ulChainCodeLen = CK_IBM_BTC_CHAINCODE_LENGTH;
    }

    switch (class) {
    case CKO_PUBLIC_KEY:
        /* Derived blob is an SPKI, extract public EC key attributes */
        rc = ecdsa_priv_unwrap_get_data(key_obj->template, blob, bloblen, TRUE);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s ecdsa_priv_unwrap_get_data failed with "
                        "rc=0x%lx\n", __func__, rc);
            return rc;
        }

        /* Extract the SPKI and add CKA_PUBLIC_KEY_INFO to key */
        rc = publ_key_get_spki(key_obj->template, ktype, FALSE,
                               &spki, &spki_length);
        if (rc != CKR_OK) {
            TRACE_DEVEL("publ_key_get_spki failed\n");
            return rc;
        }

        allocated = TRUE;
        break;

    case CKO_PRIVATE_KEY:
        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_BLOB_START(tokdata, target_info, key_obj, blob, bloblen,
                               useblob, useblob_len, rc)
            rc = dll_m_GetAttributeValue(useblob, useblob_len, get_attr, 1,
                                         target_info->target);
        RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblob_len, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

        /* Only newer EP11 libs support this, ignore if error */
        if (rc != CKR_OK)
            return CKR_OK;

        spki = get_attr[0].pValue;
        spki_length = get_attr[0].ulValueLen;
        break;

    default:
        /* do nothing */
        return CKR_OK;
    }

    rc = build_attribute(CKA_PUBLIC_KEY_INFO, spki, spki_length,
                         &spki_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto out;
    }

    rc = template_update_attribute(key_obj->template, spki_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(spki_attr);
        goto out;
    }

out:
    if (allocated && spki != NULL)
        free(spki);

    return rc;
}

static CK_RV ep11tok_sha_key_derive_mech_pre_process(STDLL_TokData_t *tokdata,
                                                     OBJECT *base_key_obj,
                                                     OBJECT *derived_key_obj,
                                                     CK_MECHANISM *mech,
                                                     CK_ULONG keytype)
{
    CK_RV rc;
    CK_ULONG hsize, value_len = 0;
    CK_ATTRIBUTE *attr;
    CK_BBOOL battr;

    UNUSED(tokdata);

    /*
     * As per PKCS#11 standard:
     * - If no length or key type is provided in the template, then the key
     *   produced by this mechanism will be a generic secret key. Its length
     *   will be the output size of the used digest.
     * - If no key type is provided in the template, but a length is, then the
     *   key produced by this mechanism will be a generic secret key of the
     *   specified length.
     * - If no length was provided in the template, but a key type is, then
     *   that key type must have a well-defined length. If it does, then the
     *   key produced by this mechanism will be of the type specified in the
     *   template. If it doesn’t, an error will be returned.
     * - If both a key type and a length are provided in the template, the
     *   length must be compatible with that key type. The key produced by
     *   this mechanism will be of the specified type and length.
     */
    switch (mech->mechanism) {
        case CKM_SHA1_KEY_DERIVATION:
            hsize = SHA1_HASH_SIZE;
            break;
        case CKM_SHA224_KEY_DERIVATION:
            hsize = SHA224_HASH_SIZE;
            break;
        case CKM_SHA256_KEY_DERIVATION:
            hsize = SHA256_HASH_SIZE;
            break;
        case CKM_SHA384_KEY_DERIVATION:
            hsize = SHA384_HASH_SIZE;
            break;
        case CKM_SHA512_KEY_DERIVATION:
            hsize = SHA512_HASH_SIZE;
            break;
        case CKM_SHA512_224_KEY_DERIVATION:
            hsize = SHA224_HASH_SIZE;
            break;
        case CKM_SHA512_256_KEY_DERIVATION:
            hsize = SHA256_HASH_SIZE;
            break;
        default:
            TRACE_ERROR("%s invalid mechanism 0x%lx\n", __func__,
                        mech->mechanism);
            return CKR_MECHANISM_INVALID;
    }

    rc = template_attribute_get_ulong(derived_key_obj->template, CKA_VALUE_LEN,
                                      &value_len);
    if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE) {
        TRACE_ERROR("%s error getting CKA_VALUE_LEN rc=0x%lx\n", __func__, rc);
        return rc;
    }

    if (value_len == 0) {
        value_len = hsize;
    } else if (value_len > hsize) {
        TRACE_ERROR("%s CKA_VALUE_LEN is too large\n", __func__);
        return CKR_TEMPLATE_INCONSISTENT;
    }

    switch (keytype) {
    case CKK_GENERIC_SECRET:
    case CKK_SHA_1_HMAC:
    case CKK_SHA224_HMAC:
    case CKK_SHA256_HMAC:
    case CKK_SHA384_HMAC:
    case CKK_SHA512_HMAC:
    case CKK_SHA3_224_HMAC:
    case CKK_SHA3_256_HMAC:
    case CKK_SHA3_384_HMAC:
    case CKK_SHA3_512_HMAC:
    case CKK_SHA512_224_HMAC:
    case CKK_SHA512_256_HMAC:
        break;
    case CKK_DES:
    case CKK_DES2:
    case CKK_DES3:
        value_len = 0;
        break;
    case CKK_AES:
        switch (value_len) {
        case 16:
        case 24:
        case 32:
            break;
        default:
            TRACE_ERROR("%s CKA_VALUE_LEN improper for AES\n", __func__);
            return CKR_TEMPLATE_INCONSISTENT;
        }
        break;
    case CKK_AES_XTS:
        switch (value_len) {
        case 32:
        case 64:
            break;
        default:
            TRACE_ERROR("%s CKA_VALUE_LEN improper for AES-XTS\n", __func__);
            return CKR_TEMPLATE_INCONSISTENT;
        }
        break;
    default:
        TRACE_ERROR("%s invalid key type 0x%lx\n", __func__, keytype);
        return CKR_TEMPLATE_INCONSISTENT;
    }

    if (value_len > 0) {
        rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE *)&value_len,
                             sizeof(value_len), &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            return rc;
        }

        rc = template_update_attribute(derived_key_obj->template, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(attr);
            return rc;
        }
    }

    /*
     * As per PKCS#11 standard:
     * - If the base key has its CKA_ALWAYS_SENSITIVE attribute set to CK_FALSE,
     *   then the derived key will as well. If the base key has its
     *   CKA_ALWAYS_SENSITIVE attribute set to CK_TRUE, then the derived key
     *   has its CKA_ALWAYS_SENSITIVE attribute set to the same value as its
     *   CKA_SENSITIVE attribute.
     * - Similarly, if the base key has its CKA_NEVER_EXTRACTABLE attribute
     *   set to CK_FALSE, then the derived key will, too. If the base key has
     *   its CKA_NEVER_EXTRACTABLE attribute set to CK_TRUE, then the derived
     *   key has its CKA_NEVER_EXTRACTABLE attribute set to the opposite value
     *   from its CKA_EXTRACTABLE attribute.
     */
    rc = template_attribute_get_bool(base_key_obj->template,
                                     CKA_ALWAYS_SENSITIVE, &battr);
    if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE) {
        TRACE_ERROR("%s error getting CKA_ALWAYS_SENSITIVE rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    if (battr == CK_TRUE) {
        rc = template_attribute_get_bool(derived_key_obj->template,
                                         CKA_SENSITIVE, &battr);
        if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE) {
            TRACE_ERROR("%s error getting CKA_SENSITIVE rc=0x%lx\n",
                        __func__, rc);
            return rc;
        }
    }

    rc = build_attribute(CKA_ALWAYS_SENSITIVE, (CK_BYTE *)&battr,
                         sizeof(battr), &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    rc = template_update_attribute(derived_key_obj->template, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(attr);
        return rc;
    }

    rc = template_attribute_get_bool(base_key_obj->template,
                                     CKA_NEVER_EXTRACTABLE, &battr);
    if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE) {
        TRACE_ERROR("%s error getting CKA_NEVER_EXTRACTABLE rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    if (battr == CK_TRUE) {
        rc = template_attribute_get_bool(derived_key_obj->template,
                                         CKA_EXTRACTABLE, &battr);
        if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE) {
            TRACE_ERROR("%s error getting CKA_EXTRACTABLE rc=0x%lx\n",
                        __func__, rc);
            return rc;
        }

        battr = !battr;
    }

    rc = build_attribute(CKA_NEVER_EXTRACTABLE, (CK_BYTE *)&battr,
                         sizeof(battr), &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    rc = template_update_attribute(derived_key_obj->template, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(attr);
        return rc;
    }

    return CKR_OK;
}

CK_RV ep11tok_derive_key(STDLL_TokData_t *tokdata, SESSION *session,
                         CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE hBaseKey,
                         CK_OBJECT_HANDLE_PTR handle, CK_ATTRIBUTE_PTR attrs,
                         CK_ULONG attrs_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE *keyblob;
    size_t keyblobsize;
    CK_BYTE newblob[MAX_BLOBSIZE];
    CK_BYTE newblobreenc[MAX_BLOBSIZE];
    size_t newblobsize = sizeof(newblob);
    CK_BYTE csum[MAX_BLOBSIZE];
    CK_ULONG cslen = sizeof(csum);
    CK_ATTRIBUTE *opaque_attr = NULL, *chk_attr = NULL, *ec_parms_attr = NULL;
    OBJECT *base_key_obj = NULL;
    OBJECT *key_obj = NULL;
    CK_ULONG ktype;
    CK_ULONG class;
    CK_ATTRIBUTE_PTR new_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) session->private_data;
    CK_ECDH1_DERIVE_PARAMS *ecdh1_parms = NULL;
    CK_ECDH1_DERIVE_PARAMS ecdh1_parms2;
    CK_MECHANISM ecdh1_mech, ecdh1_mech2;
    CK_BYTE *ecpoint = NULL;
    CK_ULONG ecpoint_len, field_len, key_len = 0;
    CK_ATTRIBUTE *new_attrs1 = NULL, *new_attrs2 = NULL;
    CK_ULONG new_attrs1_len = 0, new_attrs2_len = 0;
    CK_ULONG privlen;
    int curve_type;
    CK_BBOOL allocated = FALSE;
    ep11_target_info_t* target_info;
    CK_ULONG used_firmware_API_version;
    CK_MECHANISM_PTR mech_orig = mech;
    struct EP11_KYBER_MECH mech_ep11;
    OBJECT *kyber_secret_obj = NULL;
    CK_KEY_TYPE keytype;
    CK_BYTE *useblob;
    size_t useblobsize;
    int retry_mech_param_blob = 0;

    memset(newblob, 0, sizeof(newblob));
    memset(newblobreenc, 0, sizeof(newblobreenc));

    if (mech->mechanism == CKM_ECDH1_DERIVE ||
        mech->mechanism == CKM_IBM_EC_X25519 ||
        mech->mechanism == CKM_IBM_EC_X448) {
        if (mech->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS) ||
            mech->pParameter == NULL) {
            TRACE_ERROR("%s Param NULL or len for %s wrong: %lu\n",
                        __func__, ep11_get_ckm(tokdata, mech->mechanism),
                        mech->ulParameterLen);
            return CKR_MECHANISM_PARAM_INVALID;
        }
        ecdh1_parms = mech->pParameter;

        /* As per PKCS#11, a token MUST be able to accept this value encoded
         * as a raw octet string (as per section A.5.2 of [ANSI X9.62]).
         * A token MAY, in addition, support accepting this value as a
         * DER-encoded ECPoint (as per section E.6 of [ANSI X9.62]) i.e.
         * the same as a CKA_EC_POINT encoding.
         * The EP11 host library only accepts the raw form, thus convert
         * it to the raw format if the caller specified it in the DER-encoded
         * form.
         * Also, the EP11 host library only accepts EC points in uncompressed
         * form, so uncompress it if in compressed or hybrid form.
         */
        if (ecdh1_parms->pPublicData != NULL &&
            ecdh1_parms->ulPublicDataLen > 0) {

            ecdh1_parms2 = *ecdh1_parms;

            if (mech->mechanism == CKM_ECDH1_DERIVE) {
                rc = h_opaque_2_blob(tokdata, hBaseKey, &keyblob, &keyblobsize,
                                     &base_key_obj, READ_LOCK);
                if (rc != CKR_OK) {
                    TRACE_ERROR("%s failed hBaseKey=0x%lx\n", __func__, hBaseKey);
                    return rc;
                }

                rc = get_ecsiglen(base_key_obj, &privlen);
                privlen /= 2;

                if (rc != CKR_OK) {
                    TRACE_ERROR("%s get_ecsiglen failed\n", __func__);
                    goto error;
                }

                rc = template_attribute_get_non_empty(base_key_obj->template,
                                                      CKA_EC_PARAMS,
                                                      &ec_parms_attr);
                if (rc != CKR_OK) {
                    TRACE_ERROR("Could not find CKA_EC_PARAMS in base key\n");
                    goto error;
                }

                rc = ec_point_uncompressed_from_public_data(
                                               ecdh1_parms->pPublicData,
                                               ecdh1_parms->ulPublicDataLen,
                                               privlen,
                                               (CK_BYTE *)ec_parms_attr->pValue,
                                               ec_parms_attr->ulValueLen,
                                               TRUE, &allocated,
                                               &ecpoint, &ecpoint_len);
                if (rc != CKR_OK) {
                    TRACE_DEVEL("ec_point_from_public_data failed\n");
                    goto error;
                }

                object_put(tokdata, base_key_obj, TRUE);
                base_key_obj = NULL;
            } else {
                rc = ber_decode_OCTET_STRING(ecdh1_parms->pPublicData, &ecpoint,
                                             &ecpoint_len, &field_len);
                if (rc != CKR_OK || field_len != ecdh1_parms->ulPublicDataLen ||
                    ecpoint_len > ecdh1_parms->ulPublicDataLen - 2) {
                    /* no valid BER OCTET STRING encoding, assume raw */
                    ecpoint = ecdh1_parms->pPublicData;
                    ecpoint_len = ecdh1_parms->ulPublicDataLen;
                }
            }

            ecdh1_parms2.pPublicData = ecpoint;
            ecdh1_parms2.ulPublicDataLen = ecpoint_len;

            ecdh1_mech2.mechanism = mech->mechanism;
            ecdh1_mech2.pParameter = &ecdh1_parms2;
            ecdh1_mech2.ulParameterLen = sizeof(ecdh1_parms2);

            mech = &ecdh1_mech2;
            ecdh1_parms = mech->pParameter;
        }

        /*
         * EP11 supports CKM_ECDH1_DERIVE (and CKM_IBM_EC_C*) slightly different
         * than specified in PKCS#11 v2.11 or later. It expects the public data
         * directly as mechanism param, not via CK_ECDH1_DERIVE_PARAMS. It also
         * does not support KDFs and shared data.
         *
         * Newer EP11 crypto cards that support API version 3 support this
         * mechanism in the PKCS#11 c2.11 way. If the used API version is > 2,
         * then we can pass the mechanism parameters as-is, otherwise we still
         * need to use the old way.
         */
        target_info = get_target_info(tokdata);
        if (target_info == NULL) {
            rc = CKR_FUNCTION_FAILED;
            goto error;
        }

        used_firmware_API_version = target_info->used_firmware_API_version;

        put_target_info(tokdata, target_info);

        if (used_firmware_API_version <= 2) {
            if (ecdh1_parms->kdf != CKD_NULL) {
                TRACE_ERROR("%s KDF for CKM_ECDH1_DERIVE not supported: %lu\n",
                            __func__, ecdh1_parms->kdf);
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto error;
            }

            if (ecdh1_parms->pSharedData != NULL ||
                ecdh1_parms->ulSharedDataLen > 0) {
                TRACE_ERROR("%s Shared data for CKM_ECDH1_DERIVE not "
                            "supported\n", __func__);
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto error;
            }

            ecdh1_mech.mechanism = mech->mechanism;
            ecdh1_mech.pParameter = ecdh1_parms->pPublicData;
            ecdh1_mech.ulParameterLen = ecdh1_parms->ulPublicDataLen;
            mech = &ecdh1_mech;
        }
    }

    rc = h_opaque_2_blob(tokdata, hBaseKey, &keyblob, &keyblobsize,
                         &base_key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s failedL hBaseKey=0x%lx\n", __func__, hBaseKey);
        goto error;
    }

    rc = template_attribute_get_ulong(base_key_obj->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Invalid key type attribute\n");
        goto error;
    }

    if (mech->mechanism == CKM_AES_XTS || keytype == CKK_AES_XTS) {
        TRACE_ERROR("%s Key derive with AES-XTS is not supported\n", __func__);
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto error;
    }

    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech_orig,
                                          &base_key_obj->strength,
                                          POLICY_CHECK_DERIVE,
                                          session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: derive key\n");
        goto error;
    }

    if (!key_object_is_mechanism_allowed(base_key_obj->template,
                                         mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto error;
    }

    /* Get the keytype to use when creating the key object */
    rc = pkcs_get_keytype(attrs, attrs_len, mech, &ktype, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_subclass failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    if (ktype == CKK_AES_XTS) {
        TRACE_ERROR("%s Deriving an AES-XTS key is not supported\n", __func__);
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto error;
    }

    rc = check_key_attributes(tokdata, ktype, class, attrs, attrs_len,
                              &new_attrs, &new_attrs_len, -1);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Check key attributes for derived key failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = check_ab_derive_attributes(tokdata, base_key_obj->template,
                                    &new_attrs, &new_attrs_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Attribute bound attribute violation on derive key: rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    if (mech->mechanism == CKM_ECDH1_DERIVE ||
        mech->mechanism == CKM_IBM_EC_X25519 ||
        mech->mechanism == CKM_IBM_EC_X448) {
        /* Determine derived key length */
        rc = template_attribute_get_non_empty(base_key_obj->template,
                                              CKA_EC_PARAMS,
                                              &ec_parms_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_EC_PARAMS in base key\n");
            goto error;
        }

        /* Get CKA_VALUE_LEN if , otherwise key_len remains 0 */
        get_ulong_attribute_by_type(new_attrs, new_attrs_len, CKA_VALUE_LEN,
                                    &key_len);

        rc = ecdh_get_derived_key_size(0, ec_parms_attr->pValue,
                                       ec_parms_attr->ulValueLen,
                                       ecdh1_parms->kdf, ktype,
                                       key_len, &key_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("Can not determine the derived key length\n");
            goto error;
        }

        /* Add CKA_VALUE_LEN attribute, since EP11 needs this attribute */
        if (get_attribute_by_type(new_attrs, new_attrs_len,
                                  CKA_VALUE_LEN) == NULL) {
            rc = add_to_attribute_array(&new_attrs, &new_attrs_len,
                                        CKA_VALUE_LEN, (CK_BYTE *)&key_len,
                                        sizeof(CK_ULONG));
            if (rc != CKR_OK) {
                TRACE_ERROR("add_to_attribute_array failed\n");
                goto error;
            }
        }
    }

    rc = force_ab_sensitive(&new_attrs, &new_attrs_len, ktype);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s force attribute bound key sensitive failed: rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    rc = key_object_apply_template_attr(base_key_obj->template,
                                        CKA_DERIVE_TEMPLATE,
                                        new_attrs, new_attrs_len,
                                        &new_attrs1, &new_attrs1_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("key_object_apply_template_attr failed.\n");
        goto error;
    }

#ifndef NO_PKEY
    /* Ensure the firmware master key verification pattern is available */
    rc = ep11tok_pkey_get_firmware_mk_vp(tokdata, session);
    if (rc != CKR_OK && rc != CKR_FUNCTION_NOT_SUPPORTED)
        goto error;
#endif /* NO_PKEY */

    /* Start creating the key object */
    rc = object_mgr_create_skel(tokdata, session, new_attrs1, new_attrs1_len,
                                MODE_DERIVE, class, ktype, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s object_mgr_create_skel failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    switch (mech->mechanism) {
    case CKM_SHA1_KEY_DERIVATION:
    case CKM_SHA224_KEY_DERIVATION:
    case CKM_SHA256_KEY_DERIVATION:
    case CKM_SHA384_KEY_DERIVATION:
    case CKM_SHA512_KEY_DERIVATION:
    case CKM_SHA512_224_KEY_DERIVATION:
    case CKM_SHA512_256_KEY_DERIVATION:
        rc = ep11tok_sha_key_derive_mech_pre_process(tokdata, base_key_obj,
                                                     key_obj, mech, ktype);
        if (rc != CKR_OK)
            goto error;
        break;
    default:
        break;
    }

    curve_type = get_curve_type_from_template(key_obj->template);
    rc = build_ep11_attrs(tokdata, key_obj->template,
                          &new_attrs2, &new_attrs2_len,
                          ktype, class, curve_type, mech);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_ep11_attrs failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

do_retry:
    switch (mech_orig->mechanism) {
    case CKM_IBM_BTC_DERIVE:
        rc = ep11tok_btc_mech_pre_process(tokdata, key_obj, &new_attrs2,
                                          &new_attrs2_len);
        if (rc != CKR_OK)
            goto error;
        break;

    case CKM_IBM_KYBER:
        rc = ep11tok_kyber_mech_pre_process(tokdata, mech_orig, &mech_ep11,
                                            &kyber_secret_obj,
                                            retry_mech_param_blob != 0);
        if (rc != CKR_OK)
            goto error;
        mech = &mech_ep11.mech;
        break;

    default:
        break;
    }

    trace_attributes(__func__, "Derive:", new_attrs2, new_attrs2_len);

    ep11_get_pin_blob(tokdata, ep11_session,
                      ep11_is_session_object(attrs, attrs_len),
                      ep11_is_private_object(attrs, attrs_len),
                      &ep11_pin_blob, &ep11_pin_blob_len);

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, base_key_obj, keyblob,
                           keyblobsize, useblob, useblobsize, rc)
    RETRY_REENC_CREATE_KEY_START()
        if (ep11_pqc_obj_strength_supported(target_info, mech->mechanism,
                                            base_key_obj))
            rc = dll_m_DeriveKey(mech, new_attrs2, new_attrs2_len,
                                 useblob, useblobsize, NULL, 0,
                                 ep11_pin_blob, ep11_pin_blob_len, newblob,
                                 &newblobsize, csum, &cslen,
                                 target_info->target);
        else
            rc = CKR_KEY_SIZE_RANGE;
    RETRY_REENC_CREATE_KEY_END(tokdata, session, target_info,
                               newblob, newblobreenc, newblobsize, rc)
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblobsize, rc)
        /*
         * Special handling for mechs where mech param contains a blob:
         * If blob in mech param causes CKR_IBM_WKID_MISMATCH then retry the
         * whole operation including preprocessing. This will then cause the
         * blob in the mech param to be the reenciphered one.
         */
        if (rc == CKR_IBM_WKID_MISMATCH && mech == &mech_ep11.mech &&
            ep11_data->mk_change_active) {
            TRACE_DEVEL("Blob in mech param and WKID mismatch -> retry\n");
            retry_mech_param_blob++;
        } else {
            retry_mech_param_blob = 0;
        }
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (retry_mech_param_blob == 1) /* Retry only once */
        goto do_retry;

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s hBaseKey=0x%lx rc=0x%lx handle=0x%lx blobsize=0x%zx\n",
                    __func__, hBaseKey, rc, *handle, newblobsize);
        goto error;
    }
    TRACE_INFO("%s hBaseKey=0x%lx rc=0x%lx handle=0x%lx blobsize=0x%zx\n",
               __func__, hBaseKey, rc, *handle, newblobsize);

    if (check_expected_mkvp(tokdata, newblob, newblobsize, NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto error;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, newblob, newblobsize, &opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = template_update_attribute(key_obj->template, opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }
    opaque_attr = NULL;

    if (class == CKO_SECRET_KEY || class == CKO_PRIVATE_KEY) {
        rc = update_ep11_attrs_from_blob(tokdata, session, key_obj, FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s update_ep11_attrs_from_blob failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
    }

    switch (mech_orig->mechanism) {
    case CKM_IBM_BTC_DERIVE:
        rc = ep11tok_btc_mech_post_process(tokdata, session, mech, class, ktype,
                                           key_obj, newblob, newblobsize,
                                           csum, cslen);
        if (rc != CKR_OK)
            goto error;
        break;

    case CKM_IBM_KYBER:
        rc = ep11tok_kyber_mech_post_process(tokdata, mech_orig, csum, cslen);
        if (rc != CKR_OK)
            goto error;
        break;

    default:
        break;
    }

    if (ep11_data->mk_change_active) {
        rc = build_attribute(CKA_IBM_OPAQUE_REENC, newblobreenc, newblobsize,
                             &opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__,
                        rc);
            goto error;
        }

        rc = template_update_attribute(key_obj->template, opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        opaque_attr = NULL;
    }

    if (class == CKO_SECRET_KEY && cslen >= EP11_CSUMSIZE) {
        /* First 3 bytes of csum is the check value */
        rc = build_attribute(CKA_CHECK_VALUE, csum, EP11_CSUMSIZE, &chk_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        rc = template_update_attribute(key_obj->template, chk_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto error;
        }
        chk_attr = NULL;
    }

    /* key should be fully constructed.
     * Assign an object handle and store key.
     * Enforce policy.
     */
    rc = object_mgr_create_final(tokdata, session, key_obj, handle);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s object_mgr_create_final with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    INC_COUNTER(tokdata, session, mech_orig, base_key_obj,
                POLICY_STRENGTH_IDX_0);

    goto out;
error:
    if (key_obj)
        object_free(key_obj);
    *handle = 0;
 out:
    if (opaque_attr != NULL)
        free(opaque_attr);
    if (chk_attr != NULL)
        free(chk_attr);
    if (new_attrs)
        free_attribute_array(new_attrs, new_attrs_len);
    if (new_attrs1)
        free_attribute_array(new_attrs1, new_attrs1_len);
    if (new_attrs2)
        free_attribute_array(new_attrs2, new_attrs2_len);
    if (allocated && ecpoint != NULL)
        free(ecpoint);

    object_put(tokdata, base_key_obj, TRUE);
    base_key_obj = NULL;
    object_put(tokdata, kyber_secret_obj, TRUE);
    kyber_secret_obj = NULL;

    return rc;
}



static CK_RV dh_generate_keypair(STDLL_TokData_t *tokdata,
                                 SESSION *sess,
                                 CK_MECHANISM_PTR pMechanism,
                                 TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE publblob[MAX_BLOBSIZE];
    CK_BYTE publblobreenc[MAX_BLOBSIZE];
    size_t publblobsize = sizeof(publblob);
    CK_BYTE privblob[MAX_BLOBSIZE];
    CK_BYTE privblobreenc[MAX_BLOBSIZE];
    size_t privblobsize = sizeof(privblob);
    CK_ATTRIBUTE *prime_attr = NULL;
    CK_ATTRIBUTE *base_attr = NULL;
    CK_ATTRIBUTE *opaque_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_ATTRIBUTE_PTR dh_pPublicKeyTemplate = NULL;
    CK_ULONG dh_ulPublicKeyAttributeCount = 0;
    CK_ATTRIBUTE_PTR dh_pPrivateKeyTemplate = NULL;
    CK_ULONG dh_ulPrivateKeyAttributeCount = 0;
    CK_ULONG data_len;
    CK_ULONG field_len;
    CK_BYTE *data;
    CK_BYTE *y_start, *oid, *parm;
    CK_ULONG bit_str_len, oid_len, parm_len, value_bits = 0;
    unsigned char *priv_ep11_pin_blob = NULL;
    CK_ULONG priv_ep11_pin_blob_len = 0;
    unsigned char *publ_ep11_pin_blob = NULL;
    CK_ULONG publ_ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;
    CK_ATTRIBUTE *new_publ_attrs = NULL, *new_priv_attrs = NULL;
    CK_ULONG new_publ_attrs_len = 0, new_priv_attrs_len = 0;
    CK_ULONG spki_len;

    /* ep11 accepts CKA_PRIME and CKA_BASE parameters/attributes
     * only in this format
     */
    struct {
        size_t pg_bytes;        /* total size: 2*bytecount(P) */
        unsigned char *pg;
    } dh_pgs;

    memset(&dh_pgs, 0, sizeof(dh_pgs));
    memset(publblob, 0, sizeof(publblob));
    memset(publblobreenc, 0, sizeof(publblobreenc));
    memset(privblob, 0, sizeof(privblob));
    memset(privblobreenc, 0, sizeof(privblobreenc));

    rc = build_ep11_attrs(tokdata, publ_tmpl, &dh_pPublicKeyTemplate,
                          &dh_ulPublicKeyAttributeCount,
                          CKK_DH, CKO_PUBLIC_KEY, -1, pMechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_ep11_attrs failed with rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    rc = build_ep11_attrs(tokdata, priv_tmpl, &dh_pPrivateKeyTemplate,
                          &dh_ulPrivateKeyAttributeCount,
                          CKK_DH, CKO_PRIVATE_KEY, -1, pMechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_ep11_attrs failed with rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    rc = check_key_attributes(tokdata, CKK_DH, CKO_PUBLIC_KEY,
                              dh_pPublicKeyTemplate,
                              dh_ulPublicKeyAttributeCount,
                              &new_publ_attrs, &new_publ_attrs_len, -1);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s DH check public key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    rc = check_key_attributes(tokdata, CKK_DH, CKO_PRIVATE_KEY,
                              dh_pPrivateKeyTemplate,
                              dh_ulPrivateKeyAttributeCount,
                              &new_priv_attrs, &new_priv_attrs_len, -1);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s DH check private key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    /* card does not want CKA_PRIME/CKA_BASE in template but in dh_pgs */
    rc = template_attribute_get_non_empty(publ_tmpl, CKA_PRIME,
                                          &prime_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s DH No CKA_PRIME attribute found\n", __func__);
        goto dh_generate_keypair_end;
    }

    rc = template_attribute_get_non_empty(publ_tmpl, CKA_BASE,
                                          &base_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s DH No CKA_BASE attribute found\n", __func__);
        goto dh_generate_keypair_end;
    }

    dh_pgs.pg = malloc(prime_attr->ulValueLen * 2);
    if (!dh_pgs.pg) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        rc = CKR_HOST_MEMORY;
        goto dh_generate_keypair_end;
    }

    memset(dh_pgs.pg, 0, prime_attr->ulValueLen * 2);
    /* copy CKA_PRIME value */
    memcpy(dh_pgs.pg, prime_attr->pValue, prime_attr->ulValueLen);
    /* copy CKA_BASE value, it must have leading zeros
     * if it is shorter than CKA_PRIME
     */
    memcpy(dh_pgs.pg + prime_attr->ulValueLen +
                        (prime_attr->ulValueLen - base_attr->ulValueLen),
           base_attr->pValue, base_attr->ulValueLen);
    dh_pgs.pg_bytes = prime_attr->ulValueLen * 2;

#ifdef DEBUG
    TRACE_DEBUG("%s P:\n", __func__);
    TRACE_DEBUG_DUMP("    ", &dh_pgs.pg[0], prime_attr->ulValueLen);
    TRACE_DEBUG("%s G:\n", __func__);
    TRACE_DEBUG_DUMP("    ", &dh_pgs.pg[prime_attr->ulValueLen],
                     prime_attr->ulValueLen);
#endif

    rc = add_to_attribute_array(&new_publ_attrs, &new_publ_attrs_len,
                                CKA_IBM_STRUCT_PARAMS, dh_pgs.pg,
                                dh_pgs.pg_bytes);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s add_to_attribute_array failed with rc=0x%lx\n",
                    __func__, rc);
        goto dh_generate_keypair_end;
    }

    /* copy CKA_PRIME/CKA_BASE to private template */
    rc = build_attribute(CKA_PRIME, prime_attr->pValue,
                         prime_attr->ulValueLen, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(attr);
        goto dh_generate_keypair_end;
    }

    rc = build_attribute(CKA_BASE, base_attr->pValue,
                         base_attr->ulValueLen, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(attr);
        goto dh_generate_keypair_end;
    }

    trace_attributes(__func__, "DH public key attributes:",
                     new_publ_attrs, new_publ_attrs_len);
    trace_attributes(__func__, "DH private key attributes:",
                     new_priv_attrs, new_priv_attrs_len);

    ep11_get_pin_blob(tokdata, ep11_session,
                      ep11_is_session_object(new_priv_attrs,
                                             new_priv_attrs_len),
                      ep11_is_private_object(new_priv_attrs,
                                             new_priv_attrs_len),
                      &priv_ep11_pin_blob, &priv_ep11_pin_blob_len);
    ep11_get_pin_blob(tokdata, ep11_session,
                      ep11_is_session_object(new_publ_attrs,
                                             new_publ_attrs_len),
                      ep11_is_private_object(new_publ_attrs,
                                             new_publ_attrs_len),
                      &publ_ep11_pin_blob, &publ_ep11_pin_blob_len);

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_CREATE_KEY2_START()
        rc = dll_m_GenerateKeyPair(pMechanism,
                                   new_publ_attrs, new_publ_attrs_len,
                                   new_priv_attrs, new_priv_attrs_len,
                                   priv_ep11_pin_blob, priv_ep11_pin_blob_len,
                                   privblob, &privblobsize,
                                   publblob, &publblobsize, target_info->target);
    RETRY_REENC_CREATE_KEY2_END(tokdata, sess, target_info,
                                privblob, privblobreenc, privblobsize,
                                publblob, publblobreenc, publblobsize, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s m_GenerateKeyPair failed rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    TRACE_INFO("%s rc=0x%lx plen=%zd publblobsize=0x%zx privblobsize=0x%zx\n",
               __func__, rc, prime_attr->ulValueLen, publblobsize, privblobsize);

    if (check_expected_mkvp(tokdata, privblob, privblobsize, NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto dh_generate_keypair_end;
    }

    if (priv_ep11_pin_blob != publ_ep11_pin_blob) {
        /* Re-create the MACed SPKI with the desired EP11 session */
        spki_len = publblobsize;
        publblobsize = sizeof(publblob);
        rc = make_maced_spki(tokdata, sess, NULL,
                             new_publ_attrs, new_publ_attrs_len,
                             publblob, spki_len,
                             publblob, publblobreenc, &publblobsize, -1);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s failed to re-make a MACed-SPKI rc=0x%lx\n",
                        __func__, rc);
            goto dh_generate_keypair_end;
        }
    }

    if (check_expected_mkvp(tokdata, publblob, publblobsize, NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto dh_generate_keypair_end;
    }

    /* store the blobs */
    rc = build_attribute(CKA_IBM_OPAQUE, publblob, publblobsize, &opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    rc = template_update_attribute(publ_tmpl, opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(opaque_attr);
        goto dh_generate_keypair_end;
    }

    if (ep11_data->mk_change_active) {
        rc = build_attribute(CKA_IBM_OPAQUE_REENC, publblobreenc, publblobsize,
                             &opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__,
                        rc);
            goto dh_generate_keypair_end;
        }

        rc = template_update_attribute(publ_tmpl, opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(opaque_attr);
            goto dh_generate_keypair_end;
        }
    }

    rc = build_attribute(CKA_IBM_OPAQUE, privblob, privblobsize, &opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    rc = template_update_attribute(priv_tmpl, opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(opaque_attr);
        goto dh_generate_keypair_end;
    }

    if (ep11_data->mk_change_active) {
        rc = build_attribute(CKA_IBM_OPAQUE_REENC, privblobreenc, privblobsize,
                             &opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__,
                        rc);
            goto dh_generate_keypair_end;
        }

        rc = template_update_attribute(priv_tmpl, opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(opaque_attr);
            goto dh_generate_keypair_end;
        }
    }

#ifdef DEBUG
    TRACE_DEBUG("%s DH SPKI\n", __func__);
    TRACE_DEBUG_DUMP("   ", publblob, publblobsize);
#endif

    /* CKA_VALUE of the public key must hold 'y' */
    rc = ber_decode_SPKI(publblob, &oid, &oid_len, &parm, &parm_len,
                         &y_start, &bit_str_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_decode SKPI failed rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    /* DHPublicKey ::= INTEGER -- public key, y = g^x mod p */
    rc = ber_decode_INTEGER(y_start, &data, &data_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_decode_INTEGER failed rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    TRACE_INFO("%s DH SPKI decode INTEGER rc=0x%lx y_start=0x%x"
               " field_len=%lu data_len=%lu data=0x%hhx\n",
               __func__, rc, y_start[1], field_len, data_len, data[0]);

    /* remove leading zero, a leading zero is needed
     * (according to standard) if left most bit of first byte is 1,
     * in order to indicate a positive number.
     * ock, like many others, interpret 'y' always as positive number,
     * a leading zero is not expected by ock.
     */
    if (data[0] == 0) {
        data_len = data_len - 1;
        data = data + 1;
        TRACE_INFO("%s DH SPKI removed leading zero rc=0x%lx"
                   " y_start=0x%x field_len=%lu data_len=%lu data=0x%hhx\n",
                   __func__, rc, y_start[1], field_len, data_len, data[0]);
    }

    rc = build_attribute(CKA_VALUE, data, data_len, &value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    rc = template_update_attribute(publ_tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(value_attr);
        goto dh_generate_keypair_end;
    }

    /* Supply CKA_VALUE_BITS to private key if not present or zero */
    if (template_attribute_get_ulong(priv_tmpl, CKA_VALUE_BITS,
                                     &value_bits) != CKR_OK ||
        value_bits == 0) {
        value_bits = data_len * 8; /* private key is same length as pub key */

        rc = build_attribute(CKA_VALUE_BITS, (CK_BYTE *)&data_len,
                             sizeof(value_bits), &value_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
            goto dh_generate_keypair_end;
        }

        rc = template_update_attribute(priv_tmpl, value_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(value_attr);
            goto dh_generate_keypair_end;
        }
    }

dh_generate_keypair_end:
    if (dh_pgs.pg != NULL)
        free(dh_pgs.pg);
    if (dh_pPublicKeyTemplate)
         free_attribute_array(dh_pPublicKeyTemplate,
                              dh_ulPublicKeyAttributeCount);
     if (dh_pPrivateKeyTemplate)
         free_attribute_array(dh_pPrivateKeyTemplate,
                              dh_ulPrivateKeyAttributeCount);
     if (new_publ_attrs)
         free_attribute_array(new_publ_attrs, new_publ_attrs_len);
     if (new_priv_attrs)
         free_attribute_array(new_priv_attrs, new_priv_attrs_len);
    return rc;
}

static CK_RV dsa_generate_keypair(STDLL_TokData_t *tokdata,
                                  SESSION *sess,
                                  CK_MECHANISM_PTR pMechanism,
                                  TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE publblob[MAX_BLOBSIZE];
    CK_BYTE publblobreenc[MAX_BLOBSIZE];
    size_t publblobsize = sizeof(publblob);
    CK_BYTE privblob[MAX_BLOBSIZE];
    CK_BYTE privblobreenc[MAX_BLOBSIZE];
    size_t privblobsize = sizeof(privblob);
    CK_ATTRIBUTE *prime_attr = NULL;
    CK_ATTRIBUTE *sub_prime_attr = NULL;
    CK_ATTRIBUTE *base_attr = NULL;
    CK_ATTRIBUTE *opaque_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *key;
    CK_BYTE *data, *oid, *parm;
    CK_ULONG data_len, field_len, bit_str_len, oid_len, parm_len;
    CK_ATTRIBUTE_PTR dsa_pPublicKeyTemplate = NULL;
    CK_ULONG dsa_ulPublicKeyAttributeCount = 0;
    CK_ATTRIBUTE_PTR dsa_pPrivateKeyTemplate = NULL;
    CK_ULONG dsa_ulPrivateKeyAttributeCount = 0;
    unsigned char *priv_ep11_pin_blob = NULL;
    CK_ULONG priv_ep11_pin_blob_len = 0;
    unsigned char *publ_ep11_pin_blob = NULL;
    CK_ULONG publ_ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;
    CK_ATTRIBUTE *new_publ_attrs = NULL, *new_priv_attrs = NULL;
    CK_ULONG new_publ_attrs_len = 0, new_priv_attrs_len = 0;
    CK_ULONG spki_len;

    /* ep11 accepts CKA_PRIME,CKA_SUBPRIME,CKA_BASE only in this format */
    struct {
        size_t pqg_bytes;       /* total size: 3*bytecount(P) */
        unsigned char *pqg;
    } dsa_pqgs;

    memset(&dsa_pqgs, 0, sizeof(dsa_pqgs));
    memset(publblob, 0, sizeof(publblob));
    memset(publblobreenc, 0, sizeof(publblobreenc));
    memset(privblob, 0, sizeof(privblob));
    memset(privblobreenc, 0, sizeof(privblobreenc));

    rc = build_ep11_attrs(tokdata, publ_tmpl, &dsa_pPublicKeyTemplate,
                          &dsa_ulPublicKeyAttributeCount,
                          CKK_DSA, CKO_PUBLIC_KEY, -1, pMechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_ep11_attrs failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = build_ep11_attrs(tokdata, priv_tmpl, &dsa_pPrivateKeyTemplate,
                          &dsa_ulPrivateKeyAttributeCount,
                          CKK_DSA, CKO_PRIVATE_KEY, -1, pMechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_ep11_attrs failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = check_key_attributes(tokdata, CKK_DSA, CKO_PUBLIC_KEY,
                              dsa_pPublicKeyTemplate,
                              dsa_ulPublicKeyAttributeCount,
                              &new_publ_attrs, &new_publ_attrs_len, -1);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s DSA check public key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = check_key_attributes(tokdata, CKK_DSA, CKO_PRIVATE_KEY,
                              dsa_pPrivateKeyTemplate,
                              dsa_ulPrivateKeyAttributeCount,
                              &new_priv_attrs, &new_priv_attrs_len, -1);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s DSA check private key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    /*
     * card does not want CKA_PRIME/CKA_BASE/CKA_SUBPRIME in template but in
     * dsa_pqgs
     */
    rc = template_attribute_get_non_empty(publ_tmpl, CKA_PRIME,
                                          &prime_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s DSA No CKA_PRIME attribute found\n", __func__);
        goto dsa_generate_keypair_end;
    }

    rc = template_attribute_get_non_empty(publ_tmpl, CKA_SUBPRIME,
                                          &sub_prime_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s DSA No CKA_SUBPRIME attribute found\n", __func__);
        goto dsa_generate_keypair_end;
    }

    rc = template_attribute_get_non_empty(publ_tmpl, CKA_BASE,
                                          &base_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s DSA No CKA_BASE attribute found\n", __func__);
        goto dsa_generate_keypair_end;
    }

    /* if CKA_SUBPRIME,CKA_BASE are smaller than CKA_PRIME
     * then they are extented by leading zeros till they have
     * the size of CKA_PRIME
     */
    dsa_pqgs.pqg = malloc(prime_attr->ulValueLen * 3);
    if (!dsa_pqgs.pqg) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        rc = CKR_HOST_MEMORY;
        goto dsa_generate_keypair_end;
    }

    memset(dsa_pqgs.pqg, 0, prime_attr->ulValueLen * 3);
    memcpy(dsa_pqgs.pqg, prime_attr->pValue, prime_attr->ulValueLen);
    memcpy(dsa_pqgs.pqg + prime_attr->ulValueLen +
                         (prime_attr->ulValueLen - sub_prime_attr->ulValueLen),
           sub_prime_attr->pValue, sub_prime_attr->ulValueLen);
    memcpy(dsa_pqgs.pqg + 2 * prime_attr->ulValueLen +
                         (prime_attr->ulValueLen - base_attr->ulValueLen),
           base_attr->pValue, base_attr->ulValueLen);
    dsa_pqgs.pqg_bytes = prime_attr->ulValueLen * 3;

#ifdef DEBUG
    TRACE_DEBUG("%s P:\n", __func__);
    TRACE_DEBUG_DUMP("    ", &dsa_pqgs.pqg[0], prime_attr->ulValueLen);
    TRACE_DEBUG("%s Q:\n", __func__);
    TRACE_DEBUG_DUMP("    ", &dsa_pqgs.pqg[prime_attr->ulValueLen],
                     prime_attr->ulValueLen);
    TRACE_DEBUG("%s G:\n", __func__);
    TRACE_DEBUG_DUMP("    ", &dsa_pqgs.pqg[2 * prime_attr->ulValueLen],
                     prime_attr->ulValueLen);
#endif

    rc = add_to_attribute_array(&new_publ_attrs, &new_publ_attrs_len,
                                CKA_IBM_STRUCT_PARAMS, dsa_pqgs.pqg,
                                dsa_pqgs.pqg_bytes);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s add_to_attribute_array failed with rc=0x%lx\n",
                    __func__, rc);
        goto dsa_generate_keypair_end;
    }

    /* copy CKA_PRIME/CKA_BASE/CKA_SUBPRIME to private template */
    rc = build_attribute(CKA_PRIME, prime_attr->pValue,
                         prime_attr->ulValueLen, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(attr);
        goto dsa_generate_keypair_end;
    }

    rc = build_attribute(CKA_SUBPRIME, sub_prime_attr->pValue,
                         sub_prime_attr->ulValueLen, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(attr);
        goto dsa_generate_keypair_end;
    }

    rc = build_attribute(CKA_BASE, base_attr->pValue,
                         base_attr->ulValueLen, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(attr);
        goto dsa_generate_keypair_end;
    }

    trace_attributes(__func__, "DSA public key attributes:",
                     new_publ_attrs, new_publ_attrs_len);
    trace_attributes(__func__, "DSA private key attributes:",
                     new_priv_attrs, new_priv_attrs_len);

    ep11_get_pin_blob(tokdata, ep11_session,
                      ep11_is_session_object(new_priv_attrs,
                                             new_priv_attrs_len),
                      ep11_is_private_object(new_priv_attrs,
                                             new_priv_attrs_len),
                      &priv_ep11_pin_blob, &priv_ep11_pin_blob_len);
    ep11_get_pin_blob(tokdata, ep11_session,
                      ep11_is_session_object(new_publ_attrs,
                                             new_publ_attrs_len),
                      ep11_is_private_object(new_publ_attrs,
                                             new_publ_attrs_len),
                      &publ_ep11_pin_blob, &publ_ep11_pin_blob_len);

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_CREATE_KEY2_START()
        rc = dll_m_GenerateKeyPair(pMechanism,
                                   new_publ_attrs, new_publ_attrs_len,
                                   new_priv_attrs, new_priv_attrs_len,
                                   priv_ep11_pin_blob, priv_ep11_pin_blob_len, privblob,
                                   &privblobsize, publblob, &publblobsize,
                                   target_info->target);
    RETRY_REENC_CREATE_KEY2_END(tokdata, sess, target_info,
                                privblob, privblobreenc, privblobsize,
                                publblob, publblobreenc, publblobsize, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s m_GenerateKeyPair failed with rc=0x%lx\n", __func__,
                    rc);
        goto dsa_generate_keypair_end;
    }

    TRACE_INFO("%s rc=0x%lx plen=%zd publblobsize=0x%zx privblobsize=0x%zx\n",
               __func__, rc, prime_attr->ulValueLen, publblobsize, privblobsize);

    if (check_expected_mkvp(tokdata, privblob, privblobsize, NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto dsa_generate_keypair_end;
    }

    if (priv_ep11_pin_blob != publ_ep11_pin_blob) {
        /* Re-create the MACed SPKI with the desired EP11 session */
        spki_len = publblobsize;
        publblobsize = sizeof(publblob);
        rc = make_maced_spki(tokdata, sess, NULL,
                             new_publ_attrs, new_publ_attrs_len,
                             publblob, spki_len,
                             publblob, publblobreenc, &publblobsize, -1);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s failed to re-make a MACed-SPKI rc=0x%lx\n",
                        __func__, rc);
            goto dsa_generate_keypair_end;
        }
    }

    if (check_expected_mkvp(tokdata, publblob, publblobsize, NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto dsa_generate_keypair_end;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, publblob, publblobsize, &opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = template_update_attribute(publ_tmpl, opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(opaque_attr);
        goto dsa_generate_keypair_end;
    }

    if (ep11_data->mk_change_active) {
        rc = build_attribute(CKA_IBM_OPAQUE_REENC, publblobreenc, publblobsize,
                             &opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__,
                        rc);
            goto dsa_generate_keypair_end;
        }

        rc = template_update_attribute(publ_tmpl, opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(opaque_attr);
            goto dsa_generate_keypair_end;
        }
    }

    rc = build_attribute(CKA_IBM_OPAQUE, privblob, privblobsize, &opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = template_update_attribute(priv_tmpl, opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(opaque_attr);
        goto dsa_generate_keypair_end;
    }

    if (ep11_data->mk_change_active) {
        rc = build_attribute(CKA_IBM_OPAQUE_REENC, privblobreenc, privblobsize,
                             &opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__,
                        rc);
            goto dsa_generate_keypair_end;
        }

        rc = template_update_attribute(priv_tmpl, opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(opaque_attr);
            goto dsa_generate_keypair_end;
        }
    }

    /* set CKA_VALUE of the public key, first get key from SPKI */
    rc = ber_decode_SPKI(publblob, &oid, &oid_len, &parm, &parm_len,
                         &key, &bit_str_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s reading DSA SPKI failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    /* key must be an integer */
    rc = ber_decode_INTEGER(key, &data, &data_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s reading DSA public key failed with rc=0x%lx\n",
                    __func__, rc);
        goto dsa_generate_keypair_end;
    }
#ifdef DEBUG
    TRACE_DEBUG("%s dsa_generate_keypair public key:\n", __func__);
    TRACE_DEBUG_DUMP("    ", data, data_len);
#endif

    rc = build_attribute(CKA_VALUE, data, data_len, &value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = template_update_attribute(publ_tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(value_attr);
        goto dsa_generate_keypair_end;
    }

dsa_generate_keypair_end:
    if (dsa_pqgs.pqg != NULL)
        free(dsa_pqgs.pqg);
    if (dsa_pPublicKeyTemplate)
        free_attribute_array(dsa_pPublicKeyTemplate,
                             dsa_ulPublicKeyAttributeCount);
    if (dsa_pPrivateKeyTemplate)
        free_attribute_array(dsa_pPrivateKeyTemplate,
                             dsa_ulPrivateKeyAttributeCount);
    if (new_publ_attrs)
        free_attribute_array(new_publ_attrs, new_publ_attrs_len);
    if (new_priv_attrs)
        free_attribute_array(new_priv_attrs, new_priv_attrs_len);
    return rc;
}

static CK_RV rsa_ec_generate_keypair(STDLL_TokData_t *tokdata,
                                     SESSION *sess,
                                     CK_MECHANISM_PTR pMechanism,
                                     TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_ATTRIBUTE *n_attr = NULL;
    CK_BYTE privkey_blob[MAX_BLOBSIZE];
    CK_BYTE privkey_blobreenc[MAX_BLOBSIZE];
    size_t privkey_blob_len = sizeof(privkey_blob);
    unsigned char spki[MAX_BLOBSIZE];
    unsigned char spkireenc[MAX_BLOBSIZE];
    size_t spki_len = sizeof(spki);
    CK_ULONG bit_str_len;
    CK_BYTE *key;
    CK_BYTE *data, *oid, *parm;
    CK_ULONG data_len, oid_len, parm_len;
    CK_ULONG field_len;
    CK_ULONG ktype;
    unsigned char *priv_ep11_pin_blob = NULL;
    CK_ULONG priv_ep11_pin_blob_len = 0;
    unsigned char *publ_ep11_pin_blob = NULL;
    CK_ULONG publ_ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;
    CK_ATTRIBUTE *new_publ_attrs = NULL, *new_priv_attrs = NULL;
    CK_ULONG new_publ_attrs_len = 0, new_priv_attrs_len = 0;
    CK_ATTRIBUTE *new_publ_attrs2 = NULL, *new_priv_attrs2 = NULL;
    CK_ULONG new_publ_attrs2_len = 0, new_priv_attrs2_len = 0;
    const struct _ec *curve = NULL;
    CK_ULONG raw_spki_len;

    if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
        ktype = CKK_EC;
    } else if ((pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) ||
               (pMechanism->mechanism == CKM_RSA_X9_31_KEY_PAIR_GEN)) {
        ktype = CKK_RSA;
    } else {
        TRACE_ERROR("%s Neither RSA nor EC mech type provided for "
                    "RSA/EC_key_pair_gen\n", __func__);
        return CKR_MECHANISM_INVALID;
    }

    if (ktype == CKK_EC) {
        if (!ep11tok_ec_curve_supported2(tokdata, publ_tmpl, &curve)) {
            TRACE_ERROR("Curve not supported.\n");
            return CKR_CURVE_NOT_SUPPORTED;
        }
    }

    rc = build_ep11_attrs(tokdata, publ_tmpl,
                          &new_publ_attrs, &new_publ_attrs_len,
                          ktype, CKO_PUBLIC_KEY,
                          curve != NULL ? curve->curve_type : -1, pMechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_ep11_attrs failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = build_ep11_attrs(tokdata, priv_tmpl,
                          &new_priv_attrs, &new_priv_attrs_len,
                          ktype, CKO_PRIVATE_KEY,
                          curve != NULL ? curve->curve_type : -1, pMechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_ep11_attrs failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = check_key_attributes(tokdata, ktype, CKO_PUBLIC_KEY,
                              new_publ_attrs, new_publ_attrs_len,
                              &new_publ_attrs2, &new_publ_attrs2_len,
                              curve != NULL ? curve->curve_type : -1);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s RSA/EC check public key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        return rc;
    }

    rc = check_key_attributes(tokdata, ktype, CKO_PRIVATE_KEY,
                              new_priv_attrs, new_priv_attrs_len,
                              &new_priv_attrs2, &new_priv_attrs2_len,
                              curve != NULL ? curve->curve_type : -1);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s RSA/EC check private key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto error;
    }

    trace_attributes(__func__, "RSA/EC public key attributes:",
                     new_publ_attrs2, new_publ_attrs2_len);
    trace_attributes(__func__, "RSA/EC private key attributes:",
                     new_priv_attrs2, new_priv_attrs2_len);

    ep11_get_pin_blob(tokdata, ep11_session,
                      ep11_is_session_object(new_priv_attrs2,
                                             new_priv_attrs2_len),
                      ep11_is_private_object(new_priv_attrs2,
                                             new_priv_attrs2_len),
                      &priv_ep11_pin_blob, &priv_ep11_pin_blob_len);
    ep11_get_pin_blob(tokdata, ep11_session,
                      ep11_is_session_object(new_publ_attrs,
                                             new_publ_attrs_len),
                      ep11_is_private_object(new_publ_attrs,
                                             new_publ_attrs_len),
                      &publ_ep11_pin_blob, &publ_ep11_pin_blob_len);

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_CREATE_KEY2_START()
        rc = dll_m_GenerateKeyPair(pMechanism,
                                   new_publ_attrs2, new_publ_attrs2_len,
                                   new_priv_attrs2, new_priv_attrs2_len,
                                   priv_ep11_pin_blob, priv_ep11_pin_blob_len,
                                   privkey_blob, &privkey_blob_len, spki,
                                   &spki_len, target_info->target);
    RETRY_REENC_CREATE_KEY2_END(tokdata, sess, target_info, privkey_blob,
                                privkey_blobreenc, privkey_blob_len,
                                spki, spkireenc, spki_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s m_GenerateKeyPair rc=0x%lx spki_len=0x%zx "
                    "privkey_blob_len=0x%zx mech='%s'\n",
                    __func__, rc, spki_len, privkey_blob_len,
                    ep11_get_ckm(tokdata, pMechanism->mechanism));
        goto error;
    }
    TRACE_INFO("%s m_GenerateKeyPair rc=0x%lx spki_len=0x%zx "
               "privkey_blob_len=0x%zx mech='%s'\n",
               __func__, rc, spki_len, privkey_blob_len,
              ep11_get_ckm(tokdata, pMechanism->mechanism));

    if (check_expected_mkvp(tokdata, privkey_blob, privkey_blob_len,
                            NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto error;
    }

    if (spki_len > MAX_BLOBSIZE || privkey_blob_len > MAX_BLOBSIZE) {
        TRACE_ERROR("%s blobsize error\n", __func__);
        rc = CKR_KEY_INDIGESTIBLE;
        goto error;
    }

    if (priv_ep11_pin_blob != publ_ep11_pin_blob) {
        /* Re-create the MACed SPKI with the desired EP11 session */
        raw_spki_len = spki_len;
        spki_len = sizeof(spki);
        rc = make_maced_spki(tokdata, sess, NULL,
                             new_publ_attrs, new_publ_attrs_len,
                             spki, raw_spki_len,
                             spki, spkireenc, &spki_len,
                             curve != NULL ? curve->curve_type : -1);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s failed to re-make a MACed-SPKI rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
    }

    if (check_expected_mkvp(tokdata, spki, spki_len, NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto error;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, spki, spki_len, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }
    rc = template_update_attribute(publ_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(attr);
        goto error;
    }

    if (ep11_data->mk_change_active) {
        rc = build_attribute(CKA_IBM_OPAQUE_REENC, spkireenc, spki_len, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__,
                        rc);
            goto error;
        }
        rc = template_update_attribute(publ_tmpl, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(attr);
            goto error;
        }
    }

    rc = build_attribute(CKA_IBM_OPAQUE, privkey_blob, privkey_blob_len, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(attr);
        goto error;
    }

    if (ep11_data->mk_change_active) {
        rc = build_attribute(CKA_IBM_OPAQUE_REENC, privkey_blobreenc,
                             privkey_blob_len, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
            goto error;
        }
        rc = template_update_attribute(priv_tmpl, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(attr);
            goto error;
        }
    }

    if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
        /* scan the SPKI for CKA_EC_POINT */

#ifdef DEBUG
        TRACE_DEBUG("%s ec_generate_keypair spki:\n", __func__);
        TRACE_DEBUG_DUMP("    ", spki, spki_len);
#endif
        rc = ber_decode_SPKI(spki, &oid, &oid_len, &parm, &parm_len,
                             &key, &bit_str_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s read key from SPKI failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        /* 'key' is already EC point,
         * SEC 1: Elliptic Curve Cryptography:
         * The elliptic curve public key (a value of type ECPoint
         * that is an OCTET STRING) is mapped to a subjectPublicKey
         * (a value encoded as type BIT STRING) as follows: The most
         * significant bit of the value of the OCTET STRING becomes
         * the most significant bit of the value of the BIT STRING
         * and so on with consecutive bits until the least significant
         * bit of the OCTET STRING becomes the least significant bit
         * of the BIT STRING.
         */
        TRACE_INFO("%s ecpoint length 0x%lx\n", __func__, bit_str_len);
        data_len = bit_str_len;
        data = key;

#ifdef DEBUG
        TRACE_DEBUG("%s ec_generate_keypair ecpoint:\n", __func__);
        TRACE_DEBUG_DUMP("    ", data, data_len);
#endif

        /* build and add CKA_EC_POINT as BER encoded OCTET STRING */
        rc = ber_encode_OCTET_STRING(FALSE, &data, &data_len,
                                     key, bit_str_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
            goto error;
        }

        rc = build_attribute(CKA_EC_POINT, data, data_len, &attr);
        free(data);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        rc = template_update_attribute(publ_tmpl, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(attr);
            goto error;
        }

        /* copy CKA_EC_PARAMS/CKA_ECDSA_PARAMS to private template  */
        rc = template_attribute_get_non_empty(publ_tmpl, CKA_EC_PARAMS, &attr);
        if (rc == CKR_OK) {
            rc = build_attribute(attr->type, attr->pValue,
                                 attr->ulValueLen, &n_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                            __func__, rc);
                goto error;
            }

            rc = template_update_attribute(priv_tmpl, n_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s template_update_attribute failed with "
                            "rc=0x%lx\n", __func__, rc);
                free(n_attr);
                goto error;
            }
        }

        rc = template_attribute_get_non_empty(publ_tmpl, CKA_ECDSA_PARAMS,
                                              &attr);
        if (rc == CKR_OK) {
            rc = build_attribute(attr->type, attr->pValue,
                                 attr->ulValueLen, &n_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                            __func__, rc);
                goto error;
            }

            rc = template_update_attribute(priv_tmpl, n_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s template_update_attribute failed with "
                            "rc=0x%lx\n", __func__, rc);
                free(n_attr);
                goto error;
            }
        }
    } else {
        /* scan the SPKI for modulus and public exponent and
         * set the public key attributes, a user would use the
         * already built SPKI (in CKA_IBM_OPAQUE of the public key).
         */
        CK_BYTE *modulus, *publ_exp;

        rc = ber_decode_SPKI(spki, &oid, &oid_len, &parm, &parm_len,
                             &key, &bit_str_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s read key from SPKI failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        /* key must be a sequence holding two integers,
         * modulus and public exponent
         */
        rc = ber_decode_SEQUENCE(key, &data, &data_len, &field_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s read sequence failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        modulus = key + field_len - data_len;
        rc = ber_decode_INTEGER(modulus, &data, &data_len, &field_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s read modulus failed with rc=0x%lx\n", __func__, rc);
            goto error;
        }
#ifdef DEBUG
        TRACE_DEBUG("%s rsa_generate_keypair modulus:\n", __func__);
        TRACE_DEBUG_DUMP("    ", data, data_len);
#endif

        /* build and add CKA_MODULUS */
        rc = build_attribute(CKA_MODULUS, data, data_len, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        rc = template_update_attribute(publ_tmpl, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(attr);
            goto error;
        }

        /* read public exponent */
        publ_exp = modulus + field_len;
        rc = ber_decode_INTEGER(publ_exp, &data, &data_len, &field_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s read public exponent failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
#ifdef DEBUG
        TRACE_DEBUG("%s rsa_generate_keypair public exponent:\n", __func__);
        TRACE_DEBUG_DUMP("    ", data, data_len);
#endif

        /* build and add CKA_PUBLIC_EXPONENT */
        rc = build_attribute(CKA_PUBLIC_EXPONENT, data, data_len, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        rc = template_update_attribute(publ_tmpl, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(attr);
            goto error;
        }
    }

error:
    if (new_publ_attrs)
        free_attribute_array(new_publ_attrs, new_publ_attrs_len);
    if (new_priv_attrs)
        free_attribute_array(new_priv_attrs, new_priv_attrs_len);
    if (new_publ_attrs2)
        free_attribute_array(new_publ_attrs2, new_publ_attrs2_len);
    if (new_priv_attrs2)
        free_attribute_array(new_priv_attrs2, new_priv_attrs2_len);
    return rc;
}

static CK_RV ibm_pqc_generate_keypair(STDLL_TokData_t *tokdata,
                                      SESSION *sess,
                                      CK_MECHANISM_PTR pMechanism,
                                      TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE privkey_blob[MAX_BLOBSIZE];
    CK_BYTE privkey_blobreenc[MAX_BLOBSIZE];
    size_t privkey_blob_len = sizeof(privkey_blob);
    unsigned char spki[MAX_BLOBSIZE];
    unsigned char spkireenc[MAX_BLOBSIZE];
    size_t spki_len = sizeof(spki);
    CK_ULONG ktype;
    unsigned char *priv_ep11_pin_blob = NULL;
    CK_ULONG priv_ep11_pin_blob_len = 0;
    unsigned char *publ_ep11_pin_blob = NULL;
    CK_ULONG publ_ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;
    CK_ATTRIBUTE *new_publ_attrs = NULL, *new_priv_attrs = NULL;
    CK_ULONG new_publ_attrs_len = 0, new_priv_attrs_len = 0;
    CK_ATTRIBUTE *new_publ_attrs2 = NULL, *new_priv_attrs2 = NULL;
    CK_ULONG new_publ_attrs2_len = 0, new_priv_attrs2_len = 0;
    const struct pqc_oid *pqc_oid;
    const char *key_type_str;
    CK_ULONG raw_spki_len;

    switch (pMechanism->mechanism) {
    case CKM_IBM_DILITHIUM:
        key_type_str = "Dilithium";
        ktype = CKK_IBM_PQC_DILITHIUM;
        break;
    case CKM_IBM_KYBER:
        key_type_str = "Kyber";
        ktype = CKK_IBM_PQC_KYBER;
        break;
    default:
        TRACE_ERROR("Invalid mechanism provided for %s\n ", __func__);
        return CKR_MECHANISM_INVALID;
    }

    rc = build_ep11_attrs(tokdata, publ_tmpl,
                          &new_publ_attrs, &new_publ_attrs_len,
                          ktype, CKO_PUBLIC_KEY, -1, pMechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_ep11_attrs failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = build_ep11_attrs(tokdata, priv_tmpl,
                          &new_priv_attrs, &new_priv_attrs_len,
                          ktype, CKO_PRIVATE_KEY, -1, pMechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_ep11_attrs failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    pqc_oid = ibm_pqc_get_keyform_mode(publ_tmpl, pMechanism->mechanism);
    if (pqc_oid == NULL)
        pqc_oid = ibm_pqc_get_keyform_mode(priv_tmpl, pMechanism->mechanism);
    if (pqc_oid == NULL) {
        switch (pMechanism->mechanism) {
        case CKM_IBM_DILITHIUM:
            pqc_oid = find_pqc_by_keyform(dilithium_oids,
                                          CK_IBM_DILITHIUM_KEYFORM_ROUND2_65);
            break;
        case CKM_IBM_KYBER:
            pqc_oid = find_pqc_by_keyform(kyber_oids,
                                          CK_IBM_KYBER_KEYFORM_ROUND2_1024);
            break;
        default:
            /* pqc_oid stays NULL */
            break;
        }
    }
    if (pqc_oid == NULL) {
        TRACE_ERROR("%s Failed to determine %s OID\n", __func__, key_type_str);
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    TRACE_INFO("%s Generate %s key with keyform %lu\n", __func__, key_type_str,
               pqc_oid->keyform);

    rc = add_to_attribute_array(&new_publ_attrs, &new_publ_attrs_len,
                                CKA_IBM_PQC_PARAMS,
                                (CK_BYTE *)pqc_oid->oid,
                                pqc_oid->oid_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s add_to_attribute_array failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    rc = add_to_attribute_array(&new_priv_attrs, &new_priv_attrs_len,
                                CKA_IBM_PQC_PARAMS,
                                (CK_BYTE *)pqc_oid->oid,
                                pqc_oid->oid_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s add_to_attribute_array failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    rc = check_key_attributes(tokdata, ktype, CKO_PUBLIC_KEY,
                              new_publ_attrs, new_publ_attrs_len,
                              &new_publ_attrs2, &new_publ_attrs2_len, -1);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s %s check public key attributes failed with "
                    "rc=0x%lx\n", __func__, key_type_str, rc);
        goto error;
    }

    rc = check_key_attributes(tokdata, ktype, CKO_PRIVATE_KEY,
                              new_priv_attrs, new_priv_attrs_len,
                              &new_priv_attrs2, &new_priv_attrs2_len, -1);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s %s check private key attributes failed with "
                    "rc=0x%lx\n", __func__, key_type_str, rc);
        goto error;
    }

    trace_attributes(__func__, "PQC public key attributes:",
                     new_publ_attrs2, new_publ_attrs2_len);
    trace_attributes(__func__, "PQC private key attributes:",
                     new_priv_attrs2, new_priv_attrs2_len);

    ep11_get_pin_blob(tokdata, ep11_session,
                      ep11_is_session_object(new_priv_attrs2,
                                             new_priv_attrs2_len),
                      ep11_is_private_object(new_priv_attrs2,
                                             new_priv_attrs2_len),
                       &priv_ep11_pin_blob, &priv_ep11_pin_blob_len);
    ep11_get_pin_blob(tokdata, ep11_session,
                      ep11_is_session_object(new_publ_attrs,
                                             new_publ_attrs_len),
                      ep11_is_private_object(new_publ_attrs,
                                             new_publ_attrs_len),
                      &publ_ep11_pin_blob, &publ_ep11_pin_blob_len);

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_CREATE_KEY2_START()
        if (ep11_pqc_strength_supported(target_info, pMechanism->mechanism,
                                        pqc_oid))
            rc = dll_m_GenerateKeyPair(pMechanism,
                                       new_publ_attrs2, new_publ_attrs2_len,
                                       new_priv_attrs2, new_priv_attrs2_len,
                                       priv_ep11_pin_blob, priv_ep11_pin_blob_len,
                                       privkey_blob, &privkey_blob_len, spki,
                                       &spki_len, target_info->target);
        else
            rc = CKR_KEY_SIZE_RANGE;
    RETRY_REENC_CREATE_KEY2_END(tokdata, sess, target_info, privkey_blob,
                                privkey_blobreenc, privkey_blob_len,
                                spki, spkireenc, spki_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, sess)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s m_GenerateKeyPair rc=0x%lx spki_len=0x%zx "
                    "privkey_blob_len=0x%zx mech='%s'\n",
                    __func__, rc, spki_len, privkey_blob_len,
                    ep11_get_ckm(tokdata, pMechanism->mechanism));
        goto error;
    }
    TRACE_INFO("%s m_GenerateKeyPair rc=0x%lx spki_len=0x%zx "
               "privkey_blob_len=0x%zx mech='%s'\n",
               __func__, rc, spki_len, privkey_blob_len,
              ep11_get_ckm(tokdata, pMechanism->mechanism));

    if (check_expected_mkvp(tokdata, privkey_blob, privkey_blob_len,
                            NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto error;
    }

    if (spki_len > MAX_BLOBSIZE || privkey_blob_len > MAX_BLOBSIZE) {
        TRACE_ERROR("%s blobsize error\n", __func__);
        rc = CKR_KEY_INDIGESTIBLE;
        goto error;
    }

    if (priv_ep11_pin_blob != publ_ep11_pin_blob) {
        /* Re-create the MACed SPKI with the desired EP11 session */
        raw_spki_len = spki_len;
        spki_len = sizeof(spki);
        rc = make_maced_spki(tokdata, sess, NULL,
                             new_publ_attrs, new_publ_attrs_len,
                             spki, raw_spki_len,
                             spki, spkireenc, &spki_len, -1);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s failed to re-make a MACed-SPKI rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
    }

    if (check_expected_mkvp(tokdata, spki, spki_len, NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto error;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, spki, spki_len, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }
    rc = template_update_attribute(publ_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(attr);
        goto error;
    }

    if (ep11_data->mk_change_active) {
        rc = build_attribute(CKA_IBM_OPAQUE_REENC, spkireenc, spki_len, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__,
                        rc);
            goto error;
        }
        rc = template_update_attribute(publ_tmpl, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(attr);
            goto error;
        }
    }

    rc = build_attribute(CKA_IBM_OPAQUE, privkey_blob, privkey_blob_len, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        free(attr);
        goto error;
    }

    if (ep11_data->mk_change_active) {
        rc = build_attribute(CKA_IBM_OPAQUE_REENC, privkey_blobreenc,
                             privkey_blob_len, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__,
                        rc);
            goto error;
        }
        rc = template_update_attribute(priv_tmpl, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            free(attr);
            goto error;
        }
    }

    /* Decode SPKI */
    rc = ibm_pqc_priv_unwrap_get_data(publ_tmpl, ktype,
                                      spki, spki_len, TRUE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ibm_pqc_priv_unwrap_get_data with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    rc = ibm_pqc_priv_unwrap_get_data(priv_tmpl, ktype,
                                      spki, spki_len, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ibm_pqc_priv_unwrap_get_data with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

error:
    if (new_publ_attrs)
        free_attribute_array(new_publ_attrs, new_publ_attrs_len);
    if (new_priv_attrs)
        free_attribute_array(new_priv_attrs, new_priv_attrs_len);
    if (new_publ_attrs2)
        free_attribute_array(new_publ_attrs2, new_publ_attrs2_len);
    if (new_priv_attrs2)
        free_attribute_array(new_priv_attrs2, new_priv_attrs2_len);
    return rc;
}

/* generic function to generate RSA,DH,EC and DSA key pairs */
CK_RV ep11tok_generate_key_pair(STDLL_TokData_t * tokdata, SESSION * sess,
                                CK_MECHANISM_PTR pMechanism,
                                CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                CK_ULONG ulPublicKeyAttributeCount,
                                CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                CK_ULONG ulPrivateKeyAttributeCount,
                                CK_OBJECT_HANDLE_PTR phPublicKey,
                                CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    CK_RV rc;
    OBJECT *public_key_obj = NULL;
    OBJECT *private_key_obj = NULL;
    CK_ULONG priv_ktype, publ_ktype;
    CK_ULONG class;
    CK_ATTRIBUTE *attr = NULL;
    CK_ATTRIBUTE *n_attr = NULL;
    CK_BYTE *spki = NULL;
    CK_ULONG spki_length = 0;

    /* Get the keytype to use when creating the key object */
    rc = pkcs_get_keytype(pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                          pMechanism, &priv_ktype, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_keytype failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = pkcs_get_keytype(pPublicKeyTemplate, ulPublicKeyAttributeCount,
                          pMechanism, &publ_ktype, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_keytype failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = check_ab_pair(pPublicKeyTemplate, ulPublicKeyAttributeCount,
                       pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
    if (rc != CKR_OK)
        goto error;

#ifndef NO_PKEY
    /* Ensure the firmware master key verification pattern is available */
    rc = ep11tok_pkey_get_firmware_mk_vp(tokdata, sess);
    if (rc != CKR_OK && rc != CKR_FUNCTION_NOT_SUPPORTED)
        goto error;
#endif /* NO_PKEY */

    /* Now build the skeleton key. */
    rc = object_mgr_create_skel(tokdata, sess, pPublicKeyTemplate,
                                ulPublicKeyAttributeCount, MODE_KEYGEN,
                                CKO_PUBLIC_KEY, publ_ktype, &public_key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s Object mgr create skeleton failed\n", __func__);
        goto error;
    }

    rc = object_mgr_create_skel(tokdata, sess, pPrivateKeyTemplate,
                                ulPrivateKeyAttributeCount, MODE_KEYGEN,
                                CKO_PRIVATE_KEY, priv_ktype, &private_key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s Object mgr create skeleton failed\n", __func__);
        goto error;
    }

    switch (pMechanism->mechanism) {
    case CKM_DH_PKCS_KEY_PAIR_GEN:
        rc = dh_generate_keypair(tokdata, sess, pMechanism,
                                 public_key_obj->template,
                                 private_key_obj->template);
        break;
    case CKM_EC_KEY_PAIR_GEN:  /* takes same parameters as RSA */
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
    case CKM_RSA_X9_31_KEY_PAIR_GEN:
        rc = rsa_ec_generate_keypair(tokdata, sess, pMechanism,
                                     public_key_obj->template,
                                     private_key_obj->template);
        break;
    case CKM_DSA_KEY_PAIR_GEN:
        rc = dsa_generate_keypair(tokdata, sess, pMechanism,
                                  public_key_obj->template,
                                  private_key_obj->template);
        break;
    case CKM_IBM_DILITHIUM:
    case CKM_IBM_KYBER:
        rc = ibm_pqc_generate_keypair(tokdata, sess, pMechanism,
                                      public_key_obj->template,
                                      private_key_obj->template);
        break;
    default:
        TRACE_ERROR("%s invalid mech %s\n", __func__,
                    ep11_get_ckm(tokdata, pMechanism->mechanism));
        rc = CKR_MECHANISM_INVALID;
        goto error;
    }

    if (rc != CKR_OK) {
        TRACE_ERROR("%s rc=0x%lx hpubkey=0x%lx hprivkey=0x%lx"
                    " pub_name='%s' priv_name='%s' pub_obj=%p priv_obj=%p\n",
                    __func__, rc, *phPublicKey, *phPrivateKey,
                    public_key_obj->name, private_key_obj->name,
                    (void *)public_key_obj, (void *)private_key_obj);
        goto error;
    } else {
        TRACE_INFO("%s rc=0x%lx hpubkey=0x%lx hprivkey=0x%lx"
                   " pub_name='%s' priv_name='%s' pub_obj=%p priv_obj=%p\n",
                   __func__, rc, *phPublicKey, *phPrivateKey,
                   public_key_obj->name, private_key_obj->name,
                   (void *)public_key_obj, (void *)private_key_obj);
    }

    rc = update_ep11_attrs_from_blob(tokdata, sess, private_key_obj, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s update_ep11_attrs_from_blob failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    rc = update_ep11_attrs_from_blob(tokdata, sess, public_key_obj, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s update_ep11_attrs_from_blob failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    /* Copy CKA_MODULUS and CKA_PUBLIC_EXPONENT attributes from
     * public key object to private key object to fulfill PKCS#11
     * private key template requirements
     */

    if (template_attribute_find(public_key_obj->template, CKA_MODULUS, &attr)) {
        rc = build_attribute(attr->type, attr->pValue, attr->ulValueLen,
                             &n_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        rc = template_update_attribute(private_key_obj->template, n_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto error;
        }
        n_attr = NULL;
    }

    if (template_attribute_find(public_key_obj->template,
                                CKA_PUBLIC_EXPONENT, &attr)) {
        rc = build_attribute(attr->type, attr->pValue, attr->ulValueLen,
                             &n_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        rc = template_update_attribute(private_key_obj->template, n_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto error;
        }
        n_attr = NULL;
    }

    /* add CKA_KEY_GEN_MECHANISM */
    rc = build_attribute(CKA_KEY_GEN_MECHANISM,
                         (CK_BYTE *)&pMechanism->mechanism,
                         sizeof(CK_MECHANISM_TYPE), &n_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                                __func__, rc);
         goto error;
    }

    rc = template_update_attribute(public_key_obj->template, n_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto error;
    }
    n_attr = NULL;

    rc = build_attribute(CKA_KEY_GEN_MECHANISM,
                         (CK_BYTE *)&pMechanism->mechanism,
                         sizeof(CK_MECHANISM_TYPE), &n_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                                __func__, rc);
         goto error;
    }

    rc = template_update_attribute(private_key_obj->template, n_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto error;
    }
    n_attr = NULL;

    /* Extract the SPKI and add CKA_PUBLIC_KEY_INFO to both keys */
    rc = publ_key_get_spki(public_key_obj->template, publ_ktype, FALSE,
                           &spki, &spki_length);
    if (rc != CKR_OK) {
        TRACE_DEVEL("publ_key_get_spki failed\n");
        goto error;
    }
    rc = build_attribute(CKA_PUBLIC_KEY_INFO, spki, spki_length, &n_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(public_key_obj->template, n_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto error;
    }
    n_attr = NULL;
    rc = build_attribute(CKA_PUBLIC_KEY_INFO, spki, spki_length, &n_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(private_key_obj->template, n_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto error;
    }
    n_attr = NULL;
    free(spki);
    spki = NULL;

    /* Set CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE */
    rc = key_mgr_apply_always_sensitive_never_extractable_attrs(tokdata,
                                                            private_key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s key_mgr_apply_always_sensitive_never_extractable_attrs "
                    "failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    /* Keys should be fully constructed,
     * assign object handles and store keys.
     */
    rc = object_mgr_create_final(tokdata, sess, public_key_obj, phPublicKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s Object mgr create final failed\n", __func__);
        goto error;
    }

    /* Enforce policy */
    rc = object_mgr_create_final(tokdata, sess, private_key_obj, phPrivateKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s Object mgr create final failed\n", __func__);
        object_mgr_destroy_object(tokdata, sess, *phPublicKey);
        public_key_obj = NULL;
        goto error;
    }

    INC_COUNTER(tokdata, sess, pMechanism, private_key_obj,
                POLICY_STRENGTH_IDX_0);

    return rc;

error:
    if (public_key_obj)
        object_free(public_key_obj);
    if (private_key_obj)
        object_free(private_key_obj);
    if (spki != NULL)
        free(spki);
    if (n_attr != NULL)
        free(n_attr);

    *phPublicKey = 0;
    *phPrivateKey = 0;

    return rc;
}


/* Returns a blob for a key object.
 * The blob is created if none was build yet.
 * The passed key_obj must hold the READ lock!
 */
static CK_RV obj_opaque_2_blob(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                               CK_BYTE **blob, size_t *blobsize)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    UNUSED(tokdata);

    /* blob already exists */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc == CKR_OK) {
        *blob = attr->pValue;
        *blobsize = (size_t) attr->ulValueLen;
        TRACE_INFO("%s blob found blobsize=0x%zx\n", __func__, *blobsize);
        return CKR_OK;
    } else {
        /* should not happen, imported key types not supported
         * should cause a failing token_specific_object_add
         */
        TRACE_ERROR("%s no blob\n", __func__);
        return rc;
    }
}

/* Returns a re-enciphered blob for a key object.
 * The passed key_obj must hold the READ lock!
 */
static CK_RV obj_opaque_2_reenc_blob(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                                     CK_BYTE **blob, size_t *blobsize)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    UNUSED(tokdata);

    /* blob already exists */
    rc = template_attribute_get_non_empty(key_obj->template,
                                          CKA_IBM_OPAQUE_REENC,
                                          &attr);
    if (rc == CKR_OK) {
        *blob = attr->pValue;
        *blobsize = (size_t) attr->ulValueLen;
        TRACE_INFO("%s reenc blob found blobsize=0x%zx\n", __func__, *blobsize);
        return CKR_OK;
    } else {
        TRACE_INFO("%s no reenc blob\n", __func__);
        return rc;
    }
}

/* Returns a blob for a key handle.
 * The blob is created if none was build yet.
 * The caller must put the returned kobj when no longer needed.
 * The caller must unlock the returned kobj when no longer needed
 */
static CK_RV h_opaque_2_blob(STDLL_TokData_t *tokdata, CK_OBJECT_HANDLE handle,
                             CK_BYTE **blob, size_t *blobsize, OBJECT **kobj,
                             OBJ_LOCK_TYPE lock_type)
{
    OBJECT *key_obj;
    CK_RV rc;

    /* find the key obj by the key handle */
    rc = object_mgr_find_in_map1(tokdata, handle, &key_obj, lock_type);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s key 0x%lx not mapped\n", __func__, handle);
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            rc = CKR_KEY_HANDLE_INVALID;
        return rc;
    }

    rc = obj_opaque_2_blob(tokdata, key_obj, blob, blobsize);

    if (rc == CKR_OK) {
        *kobj = key_obj;
    } else {
        object_put(tokdata, key_obj, lock_type != NO_LOCK);
        key_obj = NULL;
    }

    return rc;
}

/**
 * Initializes the sign/verify context for the two IBM-specific Edwards
 * curves. Common mechanisms using Edwards curves are introduced with
 * PKCS#11 3.0 and support for these will be added in common code at a later
 * time. Let's keep support for IBM-specific ED curves local to the EP11 token,
 * because they are only supported here.
 */
CK_RV ep11tok_sign_verify_init_ibm_ed(STDLL_TokData_t *tokdata,
                                      SESSION *sess, SIGN_VERIFY_CONTEXT *ctx,
                                      CK_MECHANISM *mech, CK_OBJECT_HANDLE key,
                                      CK_BBOOL sign, CK_BBOOL checkauth)
{
    OBJECT *key_obj = NULL;
    CK_KEY_TYPE keytype;
    CK_OBJECT_CLASS class;
    CK_BBOOL flag;
    CK_RV rc;

    if (!sess || !ctx) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    if (ctx->active != FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        return CKR_OPERATION_ACTIVE;
    }

    /* Check key usage restrictions */
    rc = object_mgr_find_in_map1(tokdata, key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    ctx->auth_required = FALSE;
    if (checkauth) {
        rc = key_object_is_always_authenticate(key_obj->template,
                                               &ctx->auth_required);
        if (rc != CKR_OK) {
            TRACE_ERROR("key_object_is_always_authenticate failed\n");
            goto done;
        }
    }

    if (sign) {
        rc = template_attribute_get_bool(key_obj->template, CKA_SIGN, &flag);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_SIGN for the key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }
    } else {
        rc = template_attribute_get_bool(key_obj->template, CKA_VERIFY, &flag);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VERIFY for the key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }
    }

    if (flag != TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_FUNCTION_NOT_PERMITTED));
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    if (!key_object_is_mechanism_allowed(key_obj->template, mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    if (mech->ulParameterLen != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                      &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
        goto done;
    }

    if (keytype != CKK_EC) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto done;
    }

    /* Check key class: must be either a private or public key */
    rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                      &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        goto done;
    }

    if (sign) {
        if (class != CKO_PRIVATE_KEY) {
            TRACE_ERROR("This operation requires a private key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }
    } else {
        if (class != CKO_PUBLIC_KEY) {
            TRACE_ERROR("This operation requires a public key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }
    }

    ctx->context_len = 0;
    ctx->context = NULL;
    ctx->key = key;
    ctx->mech.mechanism = mech->mechanism;
    ctx->mech.pParameter = NULL;
    ctx->mech.ulParameterLen = 0;
    ctx->multi_init = FALSE;
    ctx->multi = FALSE;
    ctx->active = TRUE;
    ctx->recover = FALSE;
    ctx->pkey_active = FALSE;

    rc = CKR_OK;

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ep11tok_hmac_mech_check_keytype(CK_MECHANISM_TYPE mech, OBJECT *key_obj)
{
    CK_KEY_TYPE keytype, exp_keytype, alt_keytype;
    CK_RV rc;

    rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                      &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find attribute CKA_KEY_TYPE for the key.\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    rc = pkcsget_keytype_for_mech(mech, &exp_keytype, &alt_keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("pkcsget_keytype_for_mech failed.\n");
        return rc;
    }

    if (keytype != exp_keytype && keytype != alt_keytype) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    return CKR_OK;
}

CK_RV ep11tok_check_single_mech_key(STDLL_TokData_t *tokdata, SESSION * session,
                                    CK_MECHANISM *mech, CK_OBJECT_HANDLE key,
                                    CK_ULONG operation, CK_BBOOL *auth_required)
{
    OBJECT *key_obj = NULL;
    size_t blob_len = 0;
    CK_BYTE *blob;
    CK_ATTRIBUTE_TYPE type;
    CK_BBOOL flag;
    int policy_op;
    const char *str_op;
    CK_RV rc;

    switch (operation) {
    case OP_ENCRYPT_INIT:
        policy_op = POLICY_CHECK_ENCRYPT;
        type = CKA_ENCRYPT;
        str_op = "encrypt";
        break;
    case OP_DECRYPT_INIT:
        policy_op = POLICY_CHECK_DECRYPT;
        type = CKA_DECRYPT;
        str_op = "decrypt";
        break;
    case OP_SIGN_INIT:
        policy_op = POLICY_CHECK_SIGNATURE;
        type = CKA_SIGN;
        str_op = "sign";
        break;
    case OP_VERIFY_INIT:
        policy_op = POLICY_CHECK_VERIFY;
        type = CKA_VERIFY;
        str_op = "verify";
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_ARGUMENTS_BAD;
    }

    rc = h_opaque_2_blob(tokdata, key, &blob, &blob_len, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = template_attribute_get_bool(key_obj->template, type, &flag);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find attribute 0x%lx for the key (op: %s).\n",
                    type, str_op);
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto error;
    }

    if (flag != TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_FUNCTION_NOT_PERMITTED));
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto error;
    }

    if (!key_object_is_mechanism_allowed(key_obj->template, mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto error;
    }

    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &key_obj->strength, policy_op,
                                          session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY_VIOLATION on %s initialization\n", str_op);
        goto error;
    }

    if (auth_required != NULL) {
        rc = key_object_is_always_authenticate(key_obj->template,
                                               auth_required);
        if (rc != CKR_OK) {
            TRACE_ERROR("key_object_is_always_authenticate failed\n");
            goto error;
        }
    }

    switch (mech->mechanism) {
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA3_224_HMAC:
    case CKM_SHA3_256_HMAC:
    case CKM_SHA3_384_HMAC:
    case CKM_SHA3_512_HMAC:
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        rc = ep11tok_hmac_mech_check_keytype(mech->mechanism, key_obj);
        if (rc != CKR_OK)
            goto error;
        break;
    }

    INC_COUNTER(tokdata, session, mech, key_obj, POLICY_STRENGTH_IDX_0);

error:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

struct ECDSA_OTHER_MECH_PARAM {
    CK_MECHANISM mech;
    ECSG_Var_t param;
};

static CK_RV ep11tok_ecdsa_other_mech_adjust(CK_MECHANISM *mech,
                                      struct ECDSA_OTHER_MECH_PARAM *mech_ep11)
{
    CK_IBM_ECDSA_OTHER_PARAMS *param;

    if (mech->mechanism != CKM_IBM_ECDSA_OTHER)
        return CKR_MECHANISM_INVALID;

    if (mech->ulParameterLen != sizeof(CK_IBM_ECDSA_OTHER_PARAMS) ||
        mech->pParameter == NULL) {
        TRACE_ERROR("%s Invalid mechanism param for CKM_IBM_ECDSA_OTHER\n",
                    __func__);
        return CKR_MECHANISM_PARAM_INVALID;
    }

    mech_ep11->mech.mechanism = CKM_IBM_ECDSA_OTHER;
    mech_ep11->mech.pParameter = &mech_ep11->param;
    mech_ep11->mech.ulParameterLen = sizeof(mech_ep11->param);

    param = (CK_IBM_ECDSA_OTHER_PARAMS *)mech->pParameter;
    switch (param->submechanism) {
    case CKM_IBM_ECSDSA_RAND:
        mech_ep11->param = ECSG_IBM_ECSDSA_S256;
        break;
    case CKM_IBM_ECSDSA_COMPR_MULTI:
        mech_ep11->param = ECSG_IBM_ECSDSA_COMPR_MULTI;
        break;
    default:
       TRACE_ERROR("%s Invalid sub mechanism for CKM_IBM_ECDSA_OTHER: %lu\n",
                   __func__, param->submechanism);
       return CKR_MECHANISM_PARAM_INVALID;
    }

    return CKR_OK;
}

struct RSA_OAEP_MECH_PARAM {
    CK_MECHANISM mech;
    CK_RSA_PKCS_OAEP_PARAMS param;
};

static CK_RV ep11tok_rsa_oaep_mech_adjust(STDLL_TokData_t *tokdata,
                                          CK_MECHANISM *mech,
                                          struct RSA_OAEP_MECH_PARAM *mech_ep11)
{
    if (mech->mechanism != CKM_RSA_PKCS_OAEP)
        return CKR_MECHANISM_INVALID;

    if (mech->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS) ||
        mech->pParameter == NULL) {
        TRACE_ERROR("%s Invalid mechanism param for CKM_RSA_PKCS_OAEP\n",
                    __func__);
        return CKR_MECHANISM_PARAM_INVALID;
    }

    mech_ep11->mech.mechanism = mech->mechanism;
    mech_ep11->mech.pParameter = &mech_ep11->param;
    mech_ep11->mech.ulParameterLen = sizeof(mech_ep11->param);

    memcpy(&mech_ep11->param, mech->pParameter, sizeof(mech_ep11->param));
    ep11tok_pkcs11_mech_translate(tokdata, mech_ep11->param.hashAlg,
                                  &mech_ep11->param.hashAlg);
    ep11tok_pkcs11_mgf_translate(tokdata, mech_ep11->param.mgf,
                                 &mech_ep11->param.mgf);

    return CKR_OK;
}

CK_BOOL ep11tok_mech_single_only(CK_MECHANISM *mech)
{
    switch (mech->mechanism) {
    case CKM_IBM_ECDSA_OTHER:
    case CKM_IBM_KYBER:
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
    case CKM_RSA_PKCS_PSS:
    case CKM_RSA_X9_31:
    case CKM_ECDSA:
    case CKM_DSA:
    case CKM_IBM_ED25519_SHA512:
    case CKM_IBM_ED448_SHA3:
    case CKM_IBM_DILITHIUM:
        return CK_TRUE;
    default:
        return CK_FALSE;
    }
}

CK_RV ep11tok_sign_init(STDLL_TokData_t * tokdata, SESSION * session,
                        CK_MECHANISM * mech, CK_BBOOL recover_mode,
                        CK_OBJECT_HANDLE key, CK_BBOOL checkauth)
{
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
    size_t ep11_sign_state_l = MAX_SIGN_STATE_BYTES * 2;
    CK_BYTE *ep11_sign_state = calloc(ep11_sign_state_l, 1);
    struct ECDSA_OTHER_MECH_PARAM mech_ep11;
    CK_BYTE *useblob, *usestate;
    size_t useblobsize, usestate_len;
    CK_ULONG strength_index = POLICY_STRENGTH_IDX_0;
    CK_MECHANISM ep11_mech;

    UNUSED(recover_mode);

    if (!ep11_sign_state) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    rc = h_opaque_2_blob(tokdata, key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        free(ep11_sign_state);
        return rc;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &key_obj->strength,
                                          POLICY_CHECK_SIGNATURE,
                                          session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Sign init\n");
        free(ep11_sign_state);
        goto done;
    }

    if (!key_object_is_mechanism_allowed(key_obj->template, mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        free(ep11_sign_state);
        goto done;
    }

#ifndef NO_PKEY
    rc = ep11tok_pkey_check(tokdata, session, key_obj, mech);
    switch (rc) {
    case CKR_OK:
        strength_index = key_obj->strength.strength;
        /*
         * Release obj lock, sign_mgr_init or ep11tok_sign_verify_init_ibm_ed
         * may re-acquire the lock
         */
        object_put(tokdata, key_obj, TRUE);
        key_obj = NULL;

        /* Note that Edwards curves in general are not yet supported in
         * opencryptoki. These two special IBM specific ED mechs are only
         * supported by the ep11token, so let's keep them local here. */
        if (mech->mechanism == CKM_IBM_ED25519_SHA512 ||
            mech->mechanism == CKM_IBM_ED448_SHA3)
            rc = ep11tok_sign_verify_init_ibm_ed(tokdata, session, ctx,
                                                 mech, key, CK_TRUE,
                                                 checkauth);
        else
            /* Policy already checked. */
            rc = sign_mgr_init(tokdata, session, ctx, mech, recover_mode, key,
                               FALSE, checkauth);
        if (rc == CKR_OK)
            ctx->pkey_active = TRUE;
        /* Regardless of the rc goto done here, because ep11tok_pkey_check
         * could have unlocked/relocked the obj so that the blob is no more
         * valid.
         */
        free(ep11_sign_state);
        goto done;
    case CKR_FUNCTION_NOT_SUPPORTED:
        /* ep11 fallback */
        break;
    default:
        free(ep11_sign_state);
        goto done;
    }
#endif /* NO_PKEY */

    switch (mech->mechanism) {
    case CKM_IBM_ECDSA_OTHER:
        rc = ep11tok_ecdsa_other_mech_adjust(mech, &mech_ep11);
        if (rc != CKR_OK) {
            free(ep11_sign_state);
            goto done;
        }
        mech = &mech_ep11.mech;
        break;
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA3_224_HMAC:
    case CKM_SHA3_256_HMAC:
    case CKM_SHA3_384_HMAC:
    case CKM_SHA3_512_HMAC:
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        rc = ep11tok_hmac_mech_check_keytype(mech->mechanism, key_obj);
        if (rc != CKR_OK) {
            free(ep11_sign_state);
            goto done;
        }
        break;
    }

    if (checkauth) {
        rc = key_object_is_always_authenticate(key_obj->template,
                                               &ctx->auth_required);
        if (rc != CKR_OK) {
            TRACE_ERROR("key_object_is_always_authenticate failed\n");
            free(ep11_sign_state);
            goto done;
        }
    }

    ep11_mech = *mech;
    ep11tok_pkcs11_mech_translate(tokdata, mech->mechanism,
                                  &ep11_mech.mechanism);

    /*
     * state is allocated large enough to hold 2 times the max state blob.
     * Initially use the first half only. The second half is for the
     * re-enciphered state blob (if mk change is active).
     */
    ep11_sign_state_l /= 2;

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_STATE_START(tokdata, target_info, key_obj, keyblob,
                                 keyblobsize, useblob, useblobsize,
                                 ep11_sign_state,
                                 ep11_sign_state + ep11_sign_state_l,
                                 ep11_sign_state_l,
                                 usestate, usestate_len, rc)
        if (ep11_pqc_obj_strength_supported(target_info, ep11_mech.mechanism,
                                            key_obj))
            rc = dll_m_SignInit(usestate, &usestate_len,
                                &ep11_mech, useblob, useblobsize,
                                target_info->target);
        else
            rc = CKR_KEY_SIZE_RANGE;
        if (rc == CKR_OK && retry == 1) {
            /*
             * Initially, the real state_len is unknown, and is set to
             * allocated state size / 2. When the state was created on
             * an APQN with new WK set already, move the state to the
             * final place, which is state + usestate_len, where
             * usestate_len now is the real state size.
             */
            memmove(ep11_sign_state + usestate_len,
                    ep11_sign_state + ep11_sign_state_l, usestate_len);
        }
        ep11_sign_state_l = usestate_len;
    RETRY_REENC_BLOB_STATE_END(tokdata, session, target_info,
                               keyblob, keyblobsize,
                               useblob, useblobsize, ep11_sign_state,
                               ep11_sign_state + ep11_sign_state_l,
                               ep11_sign_state_l, usestate, usestate_len,
                               TRUE, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx blobsize=0x%zx key=0x%lx mech=0x%lx\n",
                    __func__, rc, keyblobsize, key, ep11_mech.mechanism);
        free(ep11_sign_state);
    } else {
        /* SIGN_VERIFY_CONTEX holds all needed for continuing,
         * also by another adapter (stateless requests)
         */
        ctx->key = key;
        ctx->active = TRUE;
        ctx->context = ep11_sign_state;
        ctx->context_len = ep11_sign_state_l * 2; /* current and re-enciphered state */
        ctx->pkey_active = FALSE;
        if (mech != &ctx->mech) { /* deferred init dup'ed mech already */
            ctx->mech.mechanism = mech->mechanism;
            if (mech->ulParameterLen > 0 && mech->pParameter != NULL) {
                ctx->mech.pParameter = (CK_BYTE *) malloc(mech->ulParameterLen);
                if (ctx->mech.pParameter == NULL) {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    rc = CKR_HOST_MEMORY;
                    sign_mgr_cleanup(tokdata, session, ctx);
                    goto done;
                }
                memcpy(ctx->mech.pParameter, mech->pParameter,
                      mech->ulParameterLen);
                ctx->mech.ulParameterLen = mech->ulParameterLen;
            }
        }

        TRACE_INFO("%s rc=0x%lx blobsize=0x%zx key=0x%lx mech=0x%lx\n",
                   __func__, rc, keyblobsize, key, ep11_mech.mechanism);
    }

done:
    if (rc == CKR_OK)
        INC_COUNTER(tokdata, session, mech, key_obj, strength_index);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV ep11tok_sign(STDLL_TokData_t * tokdata, SESSION * session,
                   CK_BBOOL length_only, CK_BYTE * in_data,
                   CK_ULONG in_data_len, CK_BYTE * signature,
                   CK_ULONG * sig_len)
{
#ifdef NO_PKEY
    UNUSED(length_only);
#endif
    CK_RV rc;
    SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *state;
    size_t state_len;

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                          READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob, rc=0x%lx\n", __func__, rc);
        return rc;
    }

#ifndef NO_PKEY
    if (ctx->pkey_active) {
        /* Note that Edwards curves in general are not yet supported in
         * opencryptoki. These two special IBM specific ED mechs are only
         * supported by the ep11token, so let's keep them local here. */
        if (ctx->mech.mechanism == CKM_IBM_ED25519_SHA512 ||
            ctx->mech.mechanism == CKM_IBM_ED448_SHA3) {
            rc = pkey_ibm_ed_sign(tokdata, session, key_obj, in_data,
                                  in_data_len, signature, sig_len,
                                  ep11tok_pkey_convert_key);
        } else {
            /* Release obj lock, sign_mgr_sign may re-acquire the lock */
            object_put(tokdata, key_obj, TRUE);
            key_obj = NULL;

            rc = sign_mgr_sign(tokdata, session, length_only, ctx, in_data,
                               in_data_len, signature, sig_len);
        }
        goto done; /* no ep11 fallback possible */
    }
#endif /* NO_PKEY */

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_UPDATE_BLOB_START(tokdata, target_info,
                            ctx->context, ctx->context_len / 2,
                            ctx->context + (ctx->context_len / 2),
                            ctx->context_len / 2, state, state_len)
        rc = dll_m_Sign(state, state_len,
                        in_data, in_data_len,
                        signature, sig_len, target_info->target);
    RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                          ctx->context, ctx->context_len / 2,
                          ctx->context + (ctx->context_len / 2),
                          ctx->context_len / 2, state, state_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

#ifndef NO_PKEY
done:
#endif

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV ep11tok_sign_update(STDLL_TokData_t * tokdata, SESSION * session,
                          CK_BYTE * in_data, CK_ULONG in_data_len)
{
    CK_RV rc;
    SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *state;
    size_t state_len;

    if (!in_data || !in_data_len)
        return CKR_OK;

    if (ctx->pkey_active) {
        rc = sign_mgr_sign_update(tokdata, session, ctx, in_data, in_data_len);
        goto done; /* no ep11 fallback possible */
    }

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                          READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob, rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_UPDATE_BLOB_START(tokdata, target_info,
                            ctx->context, ctx->context_len / 2,
                            ctx->context + (ctx->context_len / 2),
                            ctx->context_len / 2, state, state_len)
        rc = dll_m_SignUpdate(state, state_len, in_data,
                              in_data_len, target_info->target);
    RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                          ctx->context, ctx->context_len / 2,
                          ctx->context + (ctx->context_len / 2),
                          ctx->context_len / 2, state, state_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

done:

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV ep11tok_sign_final(STDLL_TokData_t * tokdata, SESSION * session,
                         CK_BBOOL length_only, CK_BYTE * signature,
                         CK_ULONG * sig_len)
{
    CK_RV rc;
    SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *state;
    size_t state_len;

    if (ctx->pkey_active) {
        rc = sign_mgr_sign_final(tokdata, session, length_only, ctx, signature, sig_len);
        goto done; /* no ep11 fallback possible */
    }

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                          READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob, rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_UPDATE_BLOB_START(tokdata, target_info,
                            ctx->context, ctx->context_len / 2,
                            ctx->context + (ctx->context_len / 2),
                            ctx->context_len / 2, state, state_len)
        rc = dll_m_SignFinal(state, state_len, signature, sig_len,
                             target_info->target);
    RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                          ctx->context, ctx->context_len / 2,
                          ctx->context + (ctx->context_len / 2),
                          ctx->context_len / 2, state, state_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

done:

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ep11tok_sign_single(STDLL_TokData_t *tokdata, SESSION *session,
                          CK_MECHANISM *mech, CK_BBOOL length_only,
                          CK_OBJECT_HANDLE key, CK_BYTE *in_data,
                          CK_ULONG in_data_len, CK_BYTE *signature,
                          CK_ULONG *sig_len)
{
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    struct ECDSA_OTHER_MECH_PARAM mech_ep11;
    CK_BYTE *useblob;
    size_t useblobsize;
    CK_MECHANISM ep11_mech;

    UNUSED(length_only);

    rc = h_opaque_2_blob(tokdata, key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &key_obj->strength,
                                          POLICY_CHECK_SIGNATURE,
                                          session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Sign single\n");
        goto done;
    }

    if (!key_object_is_mechanism_allowed(key_obj->template, mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    switch (mech->mechanism) {
    case CKM_IBM_ECDSA_OTHER:
        rc = ep11tok_ecdsa_other_mech_adjust(mech, &mech_ep11);
        if (rc != CKR_OK)
            goto done;
        mech = &mech_ep11.mech;
        break;
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA3_224_HMAC:
    case CKM_SHA3_256_HMAC:
    case CKM_SHA3_384_HMAC:
    case CKM_SHA3_512_HMAC:
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        rc = ep11tok_hmac_mech_check_keytype(mech->mechanism, key_obj);
        if (rc != CKR_OK)
            goto done;
        break;
    }

    ep11_mech = *mech;
    ep11tok_pkcs11_mech_translate(tokdata, mech->mechanism,
                                  &ep11_mech.mechanism);

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, key_obj, keyblob, keyblobsize,
                           useblob, useblobsize, rc)
        if (ep11_pqc_obj_strength_supported(target_info, ep11_mech.mechanism,
                                            key_obj))
            rc = dll_m_SignSingle(useblob, useblobsize, &ep11_mech,
                                  in_data, in_data_len,
                                  signature, sig_len, target_info->target);
        else
            rc = CKR_KEY_SIZE_RANGE;
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblobsize, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV ep11tok_verify_init(STDLL_TokData_t * tokdata, SESSION * session,
                          CK_MECHANISM * mech, CK_BBOOL recover_mode,
                          CK_OBJECT_HANDLE key)
{
    CK_RV rc;
    CK_BYTE *spki;
    size_t spki_len = 0;
    OBJECT *key_obj = NULL;
    SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
    size_t ep11_sign_state_l = MAX_SIGN_STATE_BYTES * 2;
    CK_BYTE *ep11_sign_state = calloc(ep11_sign_state_l, 1);
    struct ECDSA_OTHER_MECH_PARAM mech_ep11;
    CK_BYTE *useblob, *usestate;
    size_t useblob_len, usestate_len;
    CK_ULONG strength_index = POLICY_STRENGTH_IDX_0;
    CK_MECHANISM ep11_mech;

    if (!ep11_sign_state) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    rc = h_opaque_2_blob(tokdata, key, &spki, &spki_len, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        free(ep11_sign_state);
        return rc;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &key_obj->strength,
                                          POLICY_CHECK_VERIFY,
                                          session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Verify init\n");
        free(ep11_sign_state);
        goto done;
    }

    if (!key_object_is_mechanism_allowed(key_obj->template, mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        free(ep11_sign_state);
        goto done;
    }

    /*
     * Enforce key usage restrictions. EP11 does not allow to restrict
     * public keys with CKA_VERIFY=FALSE. Thus we need to enforce the
     * restriction here.
     */
    rc = check_key_restriction(key_obj,
                               recover_mode ? CKA_VERIFY_RECOVER : CKA_VERIFY);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s check_key_restriction rc=0x%lx\n", __func__, rc);
        free(ep11_sign_state);
        goto done;
    }

#ifndef NO_PKEY
    rc = ep11tok_pkey_check(tokdata, session, key_obj, mech);
    switch (rc) {
    case CKR_OK:
        strength_index = key_obj->strength.strength;
        /*
         * Release obj lock, verify_mgr_init or ep11tok_sign_verify_init_ibm_ed
         * may re-acquire the lock
         */
        object_put(tokdata, key_obj, TRUE);
        key_obj = NULL;

        /* Note that Edwards curves in general are not yet supported in
         * opencryptoki. These two special IBM specific ED mechs are only
         * supported by the ep11token, so let's keep them local here. */
        if (mech->mechanism == CKM_IBM_ED25519_SHA512 ||
            mech->mechanism == CKM_IBM_ED448_SHA3)
            rc = ep11tok_sign_verify_init_ibm_ed(tokdata, session,
                                                 ctx, mech, key, CK_FALSE,
                                                 CK_FALSE);
        else
            /* Policy already checked */
            rc = verify_mgr_init(tokdata, session, ctx, mech, CK_FALSE, key,
                                 FALSE);
        if (rc == CKR_OK)
            ctx->pkey_active = TRUE;
        /* Regardless of the rc goto done here, because ep11tok_pkey_check
         * could have unlocked/relocked the obj so that the blob is no more
         * valid.
         */
        free(ep11_sign_state);
        goto done;
    case CKR_FUNCTION_NOT_SUPPORTED:
        /* ep11 fallback */
        break;
    default:
        free(ep11_sign_state);
        goto done;
    }
#endif /* NO_PKEY */

    switch (mech->mechanism) {
    case CKM_IBM_ECDSA_OTHER:
        rc = ep11tok_ecdsa_other_mech_adjust(mech, &mech_ep11);
        if (rc != CKR_OK) {
            free(ep11_sign_state);
            goto done;
        }
        mech = &mech_ep11.mech;
        break;
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA3_224_HMAC:
    case CKM_SHA3_256_HMAC:
    case CKM_SHA3_384_HMAC:
    case CKM_SHA3_512_HMAC:
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        rc = ep11tok_hmac_mech_check_keytype(mech->mechanism, key_obj);
        if (rc != CKR_OK) {
            free(ep11_sign_state);
            goto done;
        }
        break;
    }

    ep11_mech = *mech;
    ep11tok_pkcs11_mech_translate(tokdata, mech->mechanism,
                                  &ep11_mech.mechanism);

    /*
     * state is allocated large enough to hold 2 times the max state blob.
     * Initially use the first half only. The second half is for the
     * re-enciphered state blob (if mk change is active).
     */
    ep11_sign_state_l /= 2;

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_STATE_START(tokdata, target_info, key_obj, spki, spki_len,
                                 useblob, useblob_len,
                                 ep11_sign_state,
                                 ep11_sign_state + ep11_sign_state_l,
                                 ep11_sign_state_l,
                                 usestate, usestate_len, rc)
        if (ep11_pqc_obj_strength_supported(target_info, ep11_mech.mechanism,
                                            key_obj))
            rc = dll_m_VerifyInit(usestate, &usestate_len, &ep11_mech,
                                  useblob, useblob_len, target_info->target);
        else
            rc = CKR_KEY_SIZE_RANGE;
        if (rc == CKR_OK && retry == 1) {
            /*
             * Initially, the real state_len is unknown, and is set to
             * allocated state size / 2. When the state was created on
             * an APQN with new WK set already, move the state to the
             * final place, which is state + usestate_len, where
             * usestate_len now is the real state size.
             */
            memmove(ep11_sign_state + usestate_len,
                    ep11_sign_state + ep11_sign_state_l, usestate_len);
        }
        ep11_sign_state_l = usestate_len;
    RETRY_REENC_BLOB_STATE_END(tokdata, session, target_info, spki, spki_len,
                               useblob, useblob_len, ep11_sign_state,
                               ep11_sign_state + ep11_sign_state_l,
                               ep11_sign_state_l, usestate, usestate_len,
                               TRUE, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx spki_len=0x%zx key=0x%lx "
                    "ep11_sign_state_l=0x%zx mech=0x%lx\n", __func__,
                    rc, spki_len, key, ep11_sign_state_l, ep11_mech.mechanism);
        free(ep11_sign_state);
    } else {
        ctx->key = key;
        ctx->active = TRUE;
        ctx->context = ep11_sign_state;
        ctx->context_len = ep11_sign_state_l * 2; /* current and re-enciphered state */
        ctx->pkey_active = FALSE;
        if (mech != &ctx->mech) { /* deferred init dup'ed mech already */
            ctx->mech.mechanism = mech->mechanism;
            if (mech->ulParameterLen > 0 && mech->pParameter != NULL) {
                ctx->mech.pParameter = (CK_BYTE *) malloc(mech->ulParameterLen);
                if (ctx->mech.pParameter == NULL) {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    rc = CKR_HOST_MEMORY;
                    verify_mgr_cleanup(tokdata, session, ctx);
                    goto done;
                }
                memcpy(ctx->mech.pParameter, mech->pParameter,
                      mech->ulParameterLen);
                ctx->mech.ulParameterLen = mech->ulParameterLen;
            }
        }

        TRACE_INFO("%s rc=0x%lx spki_len=0x%zx key=0x%lx "
                   "ep11_sign_state_l=0x%zx mech=0x%lx\n", __func__,
                   rc, spki_len, key, ep11_sign_state_l, ep11_mech.mechanism);
    }

done:
    if (rc == CKR_OK)
        INC_COUNTER(tokdata, session, mech, key_obj, strength_index);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV ep11tok_verify(STDLL_TokData_t * tokdata, SESSION * session,
                     CK_BYTE * in_data, CK_ULONG in_data_len,
                     CK_BYTE * signature, CK_ULONG sig_len)
{
    CK_RV rc;
    SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *state;
    size_t state_len;

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob, rc=0x%lx\n", __func__, rc);
        return rc;
    }

#ifndef NO_PKEY
    if (ctx->pkey_active) {
        /* Note that Edwards curves in general are not yet supported in
         * opencryptoki. These two special IBM specific ED mechs are only
         * supported by the ep11token, so let's keep them local here. */
        if (ctx->mech.mechanism == CKM_IBM_ED25519_SHA512 ||
            ctx->mech.mechanism == CKM_IBM_ED448_SHA3) {
            rc = pkey_ibm_ed_verify(key_obj, in_data, in_data_len,
                                    signature, sig_len);
        } else {
            /* Release obj lock, verify_mgr_verify may re-acquire the lock */
            object_put(tokdata, key_obj, TRUE);
            key_obj = NULL;

            rc = verify_mgr_verify(tokdata, session, ctx, in_data,
                                   in_data_len, signature, sig_len);
        }
        goto done; /* no ep11 fallback possible */
    }
#endif /* NO_PKEY */

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_UPDATE_BLOB_START(tokdata, target_info,
                            ctx->context, ctx->context_len / 2,
                            ctx->context + (ctx->context_len / 2),
                            ctx->context_len / 2, state, state_len)
        rc = dll_m_Verify(state, state_len,
                          in_data, in_data_len,
                          signature, sig_len, target_info->target);
    RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                          ctx->context, ctx->context_len / 2,
                          ctx->context + (ctx->context_len / 2),
                          ctx->context_len / 2, state, state_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

#ifndef NO_PKEY
done:
#endif

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV ep11tok_verify_update(STDLL_TokData_t * tokdata, SESSION * session,
                            CK_BYTE * in_data, CK_ULONG in_data_len)
{
    CK_RV rc;
    SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *state;
    size_t state_len;

    if (!in_data || !in_data_len)
        return CKR_OK;

    if (ctx->pkey_active) {
        rc = verify_mgr_verify_update(tokdata, session, ctx, in_data, in_data_len);
        goto done; /* no ep11 fallback possible */
    }

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob, rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_UPDATE_BLOB_START(tokdata, target_info,
                            ctx->context, ctx->context_len / 2,
                            ctx->context + (ctx->context_len / 2),
                            ctx->context_len / 2, state, state_len)
        rc = dll_m_VerifyUpdate(state, state_len, in_data,
                                in_data_len, target_info->target);
    RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                          ctx->context, ctx->context_len / 2,
                          ctx->context + (ctx->context_len / 2),
                          ctx->context_len / 2, state, state_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

done:

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV ep11tok_verify_final(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_BYTE * signature, CK_ULONG sig_len)
{
    CK_RV rc;
    SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *state;
    size_t state_len;

    if (ctx->pkey_active) {
        rc = verify_mgr_verify_final(tokdata, session, ctx, signature, sig_len);
        goto done; /* no ep11 fallback possible */
    }

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob, rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_UPDATE_BLOB_START(tokdata, target_info,
                            ctx->context, ctx->context_len / 2,
                            ctx->context + (ctx->context_len / 2),
                            ctx->context_len / 2, state, state_len)
        rc = dll_m_VerifyFinal(state, state_len, signature,
                               sig_len, target_info->target);
    RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                          ctx->context, ctx->context_len / 2,
                          ctx->context + (ctx->context_len / 2),
                          ctx->context_len / 2, state, state_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

done:

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ep11tok_verify_single(STDLL_TokData_t *tokdata, SESSION *session,
                            CK_MECHANISM *mech, CK_OBJECT_HANDLE key,
                            CK_BYTE *in_data, CK_ULONG in_data_len,
                            CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_RV rc;
    CK_BYTE *spki;
    size_t spki_len = 0;
    OBJECT *key_obj = NULL;
    struct ECDSA_OTHER_MECH_PARAM mech_ep11;
    CK_BYTE *useblob;
    size_t useblob_len;
    CK_MECHANISM ep11_mech;

    rc = h_opaque_2_blob(tokdata, key, &spki, &spki_len, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &key_obj->strength,
                                          POLICY_CHECK_VERIFY,
                                          session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Verify single\n");
        goto done;
    }

    if (!key_object_is_mechanism_allowed(key_obj->template, mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }
    /*
     * Enforce key usage restrictions. EP11 does not allow to restrict
     * public keys with CKA_VERIFY=FALSE. Thus we need to enforce the
     * restriction here.
     */
    rc = check_key_restriction(key_obj, CKA_VERIFY);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s check_key_restriction rc=0x%lx\n", __func__, rc);
        goto done;
    }

    switch (mech->mechanism) {
    case CKM_IBM_ECDSA_OTHER:
        rc = ep11tok_ecdsa_other_mech_adjust(mech, &mech_ep11);
        if (rc != CKR_OK)
            goto done;
        mech = &mech_ep11.mech;
        break;
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA3_224_HMAC:
    case CKM_SHA3_256_HMAC:
    case CKM_SHA3_384_HMAC:
    case CKM_SHA3_512_HMAC:
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        rc = ep11tok_hmac_mech_check_keytype(mech->mechanism, key_obj);
        if (rc != CKR_OK)
            goto done;
        break;
    }

    ep11_mech = *mech;
    ep11tok_pkcs11_mech_translate(tokdata, mech->mechanism,
                                  &ep11_mech.mechanism);

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, key_obj, spki, spki_len,
                           useblob, useblob_len, rc)
        if (ep11_pqc_obj_strength_supported(target_info, ep11_mech.mechanism,
                                            key_obj))
            rc = dll_m_VerifySingle(useblob, useblob_len, &ep11_mech,
                                    in_data, in_data_len,
                                    signature, sig_len, target_info->target);
        else
            rc = CKR_KEY_SIZE_RANGE;
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblob_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ep11tok_decrypt_final(STDLL_TokData_t * tokdata, SESSION * session,
                            CK_BYTE_PTR output_part,
                            CK_ULONG_PTR p_output_part_len)
{
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *ctx = &session->decr_ctx;
    CK_BBOOL length_only = (output_part == NULL ? CK_TRUE : CK_FALSE);
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *state;
    size_t state_len;

    if (ctx->pkey_active) {
        rc = decr_mgr_decrypt_final(tokdata, session, length_only,
                                    ctx, output_part, p_output_part_len);
        goto done; /* no ep11 fallback possible */
    }

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob, rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_UPDATE_BLOB_START(tokdata, target_info,
                            ctx->context, ctx->context_len / 2,
                            ctx->context + (ctx->context_len / 2),
                            ctx->context_len / 2, state, state_len)
        rc = dll_m_DecryptFinal(state, state_len,
                                output_part, p_output_part_len,
                                target_info->target);
    RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                          ctx->context, ctx->context_len / 2,
                          ctx->context + (ctx->context_len / 2),
                          ctx->context_len / 2, state, state_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    rc = constant_time_select(constant_time_eq(rc, CKR_OK),
                              ep11_error_to_pkcs11_error(rc, session),
                              rc);
    if (!is_rsa_mechanism(ctx->mech.mechanism)) {
        if (rc != CKR_OK) {
            TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
        } else {
            TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
        }
    }

done:

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV ep11tok_decrypt(STDLL_TokData_t * tokdata, SESSION * session,
                      CK_BYTE_PTR input_data, CK_ULONG input_data_len,
                      CK_BYTE_PTR output_data, CK_ULONG_PTR p_output_data_len)
{
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *ctx = &session->decr_ctx;
    CK_BBOOL length_only = (output_data == NULL ? CK_TRUE : CK_FALSE);
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *state;
    size_t state_len;

    if (ctx->pkey_active) {
        rc = decr_mgr_decrypt(tokdata, session, length_only, ctx,
                              input_data, input_data_len, output_data,
                              p_output_data_len);
        goto done; /* no ep11 fallback possible */
    }

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob, rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_UPDATE_BLOB_START(tokdata, target_info,
                            ctx->context, ctx->context_len / 2,
                            ctx->context + (ctx->context_len / 2),
                            ctx->context_len / 2, state, state_len)
        rc = dll_m_Decrypt(state, state_len, input_data,
                           input_data_len, output_data, p_output_data_len,
                           target_info->target);
    RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                          ctx->context, ctx->context_len / 2,
                          ctx->context + (ctx->context_len / 2),
                          ctx->context_len / 2, state, state_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    rc = constant_time_select(constant_time_eq(rc, CKR_OK),
                              ep11_error_to_pkcs11_error(rc, session),
                              rc);
    if (!is_rsa_mechanism(ctx->mech.mechanism)) {
        if (rc != CKR_OK) {
            TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
        } else {
            TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
        }
    }

done:

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV ep11tok_decrypt_update(STDLL_TokData_t * tokdata, SESSION * session,
                             CK_BYTE_PTR input_part, CK_ULONG input_part_len,
                             CK_BYTE_PTR output_part,
                             CK_ULONG_PTR p_output_part_len)
{
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *ctx = &session->decr_ctx;
    CK_BBOOL length_only = (output_part == NULL ? CK_TRUE : CK_FALSE);
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *state;
    size_t state_len;

    if (!input_part || !input_part_len) {
        *p_output_part_len = 0;
        return CKR_OK;          /* nothing to update, keep context */
    }

    if (ctx->pkey_active) {
        rc = decr_mgr_decrypt_update(tokdata, session, length_only,
                                     ctx, input_part, input_part_len,
                                     output_part, p_output_part_len);
        goto done; /* no ep11 fallback possible */
    }

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob, rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_UPDATE_BLOB_START(tokdata, target_info,
                            ctx->context, ctx->context_len / 2,
                            ctx->context + (ctx->context_len / 2),
                            ctx->context_len / 2, state, state_len)
        rc = dll_m_DecryptUpdate(state, state_len,
                                 input_part, input_part_len, output_part,
                                 p_output_part_len, target_info->target);
    RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                          ctx->context, ctx->context_len / 2,
                          ctx->context + (ctx->context_len / 2),
                          ctx->context_len / 2, state, state_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    rc = constant_time_select(constant_time_eq(rc, CKR_OK),
                              ep11_error_to_pkcs11_error(rc, session),
                              rc);
    if (!is_rsa_mechanism(ctx->mech.mechanism)) {
        if (rc != CKR_OK) {
            TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
        } else {
            TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
        }
    }

done:

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ep11tok_decrypt_single(STDLL_TokData_t *tokdata, SESSION *session,
                             CK_MECHANISM *mech, CK_BBOOL length_only,
                             CK_OBJECT_HANDLE key, CK_BYTE_PTR input_data,
                             CK_ULONG input_data_len, CK_BYTE_PTR output_data,
                             CK_ULONG_PTR p_output_data_len)
{
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *useblob;
    size_t useblobsize;
    struct RSA_OAEP_MECH_PARAM rsa_oaep_mech_ep11;

    UNUSED(length_only);

    rc = h_opaque_2_blob(tokdata, key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    if (!key_object_is_mechanism_allowed(key_obj->template, mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &key_obj->strength,
                                          POLICY_CHECK_DECRYPT,
                                          session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY_VIOLATION on decrypt single\n");
        goto done;
    }

    if (mech->mechanism == CKM_RSA_PKCS_OAEP) {
        rc = ep11tok_rsa_oaep_mech_adjust(tokdata, mech, &rsa_oaep_mech_ep11);
        if (rc != CKR_OK)
            goto done;
        mech = &rsa_oaep_mech_ep11.mech;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, key_obj, keyblob, keyblobsize,
                           useblob, useblobsize, rc)
        if (ep11_pqc_obj_strength_supported(target_info, mech->mechanism,
                                            key_obj))
            rc = dll_m_DecryptSingle(useblob, useblobsize, mech, input_data,
                                     input_data_len, output_data,
                                     p_output_data_len,
                                     target_info->target);
        else
            rc = CKR_KEY_SIZE_RANGE;
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblobsize, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    rc = constant_time_select(constant_time_eq(rc, CKR_OK),
                              ep11_error_to_pkcs11_error(rc, session),
                              rc);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ep11tok_encrypt_final(STDLL_TokData_t * tokdata, SESSION * session,
                            CK_BYTE_PTR output_part,
                            CK_ULONG_PTR p_output_part_len)
{
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *ctx = &session->encr_ctx;
    CK_BBOOL length_only = (output_part == NULL ? CK_TRUE : CK_FALSE);
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *state;
    size_t state_len;

    if (ctx->pkey_active) {
        rc = encr_mgr_encrypt_final(tokdata, session, length_only,
                                    ctx, output_part, p_output_part_len);
        goto done; /* no ep11 fallback possible */
    }

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob, rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_UPDATE_BLOB_START(tokdata, target_info,
                            ctx->context, ctx->context_len / 2,
                            ctx->context + (ctx->context_len / 2),
                            ctx->context_len / 2, state, state_len)
        rc = dll_m_EncryptFinal(state, state_len,
                                output_part, p_output_part_len,
                                target_info->target);
    RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                          ctx->context, ctx->context_len / 2,
                          ctx->context + (ctx->context_len / 2),
                          ctx->context_len / 2, state, state_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

done:

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV ep11tok_encrypt(STDLL_TokData_t * tokdata, SESSION * session,
                      CK_BYTE_PTR input_data, CK_ULONG input_data_len,
                      CK_BYTE_PTR output_data, CK_ULONG_PTR p_output_data_len)
{
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *ctx = &session->encr_ctx;
    CK_BBOOL length_only = (output_data == NULL ? CK_TRUE : CK_FALSE);
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *state;
    size_t state_len;

    if (ctx->pkey_active) {
        rc = encr_mgr_encrypt(tokdata, session, length_only, ctx,
                              input_data, input_data_len, output_data,
                              p_output_data_len);
        goto done; /* no ep11 fallback possible */
    }

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob, rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_UPDATE_BLOB_START(tokdata, target_info,
                            ctx->context, ctx->context_len / 2,
                            ctx->context + (ctx->context_len / 2),
                            ctx->context_len / 2, state, state_len)
        rc = dll_m_Encrypt(state, state_len, input_data,
                           input_data_len, output_data, p_output_data_len,
                           target_info->target);
    RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                          ctx->context, ctx->context_len / 2,
                          ctx->context + (ctx->context_len / 2),
                          ctx->context_len / 2, state, state_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

done:

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV ep11tok_encrypt_update(STDLL_TokData_t * tokdata, SESSION * session,
                             CK_BYTE_PTR input_part, CK_ULONG input_part_len,
                             CK_BYTE_PTR output_part,
                             CK_ULONG_PTR p_output_part_len)
{
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *ctx = &session->encr_ctx;
    CK_BBOOL length_only = (output_part == NULL ? CK_TRUE : CK_FALSE);
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *state;
    size_t state_len;

    if (!input_part || !input_part_len) {
        *p_output_part_len = 0;
        return CKR_OK;          /* nothing to update, keep context */
    }

    if (ctx->pkey_active) {
        rc = encr_mgr_encrypt_update(tokdata, session, length_only, ctx,
                                     input_part, input_part_len, output_part,
                                     p_output_part_len);
        goto done; /* no ep11 fallback possible */
    }

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob, rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_UPDATE_BLOB_START(tokdata, target_info,
                            ctx->context, ctx->context_len / 2,
                            ctx->context + (ctx->context_len / 2),
                            ctx->context_len / 2, state, state_len)
        rc = dll_m_EncryptUpdate(state, state_len,
                                 input_part, input_part_len, output_part,
                                 p_output_part_len, target_info->target);
    RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                          ctx->context, ctx->context_len / 2,
                          ctx->context + (ctx->context_len / 2),
                          ctx->context_len / 2, state, state_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

done:

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ep11tok_encrypt_single(STDLL_TokData_t *tokdata, SESSION *session,
                             CK_MECHANISM *mech, CK_BBOOL length_only,
                             CK_OBJECT_HANDLE key, CK_BYTE_PTR input_data,
                             CK_ULONG input_data_len, CK_BYTE_PTR output_data,
                             CK_ULONG_PTR p_output_data_len)
{
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    CK_BYTE *useblob;
    size_t useblobsize;
    struct RSA_OAEP_MECH_PARAM rsa_oaep_mech_ep11;

    UNUSED(length_only);

    rc = h_opaque_2_blob(tokdata, key, &keyblob, &keyblobsize, &key_obj,
                         READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    if (!key_object_is_mechanism_allowed(key_obj->template, mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &key_obj->strength,
                                          POLICY_CHECK_ENCRYPT,
                                          session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY_VIOLATION on encrypt single\n");
        goto done;
    }

    /*
     * Enforce key usage restrictions. EP11 does not allow to restrict
     * public keys with CKA_ENCRYPT=FALSE. Thus we need to enforce the
     * restriction here.
     */
    rc = check_key_restriction(key_obj, CKA_ENCRYPT);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s check_key_restriction rc=0x%lx\n", __func__, rc);
        goto done;
    }

    if (mech->mechanism == CKM_RSA_PKCS_OAEP) {
        rc = ep11tok_rsa_oaep_mech_adjust(tokdata, mech, &rsa_oaep_mech_ep11);
        if (rc != CKR_OK)
            goto done;
        mech = &rsa_oaep_mech_ep11.mech;
    }

    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, key_obj, keyblob, keyblobsize,
                           useblob, useblobsize, rc)
        if (ep11_pqc_obj_strength_supported(target_info, mech->mechanism,
                                            key_obj))
            rc = dll_m_EncryptSingle(useblob, useblobsize, mech, input_data,
                                     input_data_len, output_data,
                                     p_output_data_len,
                                     target_info->target);
        else
            rc = CKR_KEY_SIZE_RANGE;
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblobsize, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

static CK_RV ep11_ende_crypt_init(STDLL_TokData_t * tokdata, SESSION * session,
                                  CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key,
                                  int op, CK_BBOOL checkauth)
{
    CK_RV rc = CKR_OK;
    CK_BYTE *blob;
    size_t blob_len = 0;
    OBJECT *key_obj = NULL;
    size_t ep11_state_l = MAX_CRYPT_STATE_BYTES * 2;
    CK_BYTE *ep11_state;
    CK_BYTE *useblob, *usestate;
    size_t useblob_len, usestate_len;
    CK_ULONG strength_index = POLICY_STRENGTH_IDX_0;
    struct RSA_OAEP_MECH_PARAM rsa_oaep_mech_ep11;

    ep11_state = calloc(ep11_state_l, 1); /* freed by encr/decr_mgr.c */
    if (!ep11_state) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    rc = h_opaque_2_blob(tokdata, key, &blob, &blob_len, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        goto error;
    }

    if (!key_object_is_mechanism_allowed(key_obj->template, mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto error;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &key_obj->strength,
                                          op == DECRYPT ? POLICY_CHECK_DECRYPT :
                                            POLICY_CHECK_ENCRYPT,
                                          session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY_VIOLATION on encrypt/decrypt initialization\n");
        goto error;
    }

#ifndef NO_PKEY
    rc = ep11tok_pkey_check(tokdata, session, key_obj, mech);
    switch (rc) {
    case CKR_OK:
        strength_index = key_obj->strength.strength;
        /* Release obj lock, encr/decr_mgr_init may re-acquire the lock */
        object_put(tokdata, key_obj, TRUE);
        key_obj = NULL;

        if (op == DECRYPT) {
            /* Policy and always-auth already checked */
            rc = decr_mgr_init(tokdata, session, &session->decr_ctx,
                               OP_DECRYPT_INIT, mech, key, FALSE, checkauth);
        } else {
            /* Policy already checked */
            rc = encr_mgr_init(tokdata, session, &session->encr_ctx,
                               OP_ENCRYPT_INIT, mech, key, FALSE);
        }
        if (rc == CKR_OK) {
            if (op == DECRYPT)
                (&session->decr_ctx)->pkey_active = TRUE;
            else
                (&session->encr_ctx)->pkey_active = TRUE;
        }
        /* Regardless of the rc goto done here, because ep11tok_pkey_check
         * could have unlocked/relocked the obj so that the blob is no more
         * valid.
         */
        free(ep11_state);
        goto done;
    case CKR_FUNCTION_NOT_SUPPORTED:
        /* if mechanism is AES XTS, return error else fallback to ep11 path */
        if (mech->mechanism == CKM_AES_XTS) {
            TRACE_ERROR("EP11 AES XTS mech is supported only for protected keys\n");
            rc = CKR_KEY_UNEXTRACTABLE;
            free(ep11_state);
            goto done;
        }
        break;
    default:
        /* internal error or lock problem */
        free(ep11_state);
        goto done;
    }
#endif /* NO_PKEY */

    if (mech->mechanism == CKM_RSA_PKCS_OAEP) {
        rc = ep11tok_rsa_oaep_mech_adjust(tokdata, mech, &rsa_oaep_mech_ep11);
        if (rc != CKR_OK)
            goto error;
        mech = &rsa_oaep_mech_ep11.mech;
    }

    /*
     * ep11_state is allocated large enough to hold 2 times the max state blob.
     * Initially use the first half only. The second half is for the
     * re-enciphered state blob (if mk change is active).
     */
    ep11_state_l /= 2;

    if (op == DECRYPT) {
        ENCR_DECR_CONTEXT *ctx = &session->decr_ctx;

        if (checkauth) {
            rc = key_object_is_always_authenticate(key_obj->template,
                                                   &ctx->auth_required);
            if (rc != CKR_OK) {
                TRACE_ERROR("key_object_is_always_authenticate failed\n");
                goto error;
            }
        }

        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_BLOB_STATE_START(tokdata, target_info, key_obj, blob,
                                     blob_len, useblob, useblob_len,
                                     ep11_state, ep11_state + ep11_state_l,
                                     ep11_state_l, usestate, usestate_len, rc)
            rc = dll_m_DecryptInit(usestate, &usestate_len, mech, useblob,
                                   useblob_len, target_info->target);
            if (rc == CKR_OK && retry == 1) {
                /*
                 * Initially, the real state_len is unknown, and is set to
                 * allocated state size / 2. When the state was created on
                 * an APQN with new WK set already, move the state to the
                 * final place, which is state + usestate_len, where
                 * usestate_len now is the real state size.
                 */
                memmove(ep11_state + usestate_len,
                        ep11_state + ep11_state_l, usestate_len);
            }
            ep11_state_l = usestate_len;
        RETRY_REENC_BLOB_STATE_END(tokdata, session, target_info,
                                   blob, blob_len, useblob, useblob_len,
                                   ep11_state, ep11_state + ep11_state_l,
                                   ep11_state_l, usestate, usestate_len,
                                   TRUE, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
        ctx->key = key;
        ctx->active = TRUE;
        ctx->context = ep11_state;
        ctx->context_len = ep11_state_l * 2; /* current and re-enciphered state */
        ctx->pkey_active = FALSE;
        if (mech != &ctx->mech) { /* deferred init dup'ed mech already */
            ctx->mech.mechanism = mech->mechanism;
            if (mech->ulParameterLen > 0 && mech->pParameter != NULL) {
                ctx->mech.pParameter = (CK_BYTE *) malloc(mech->ulParameterLen);
                if (ctx->mech.pParameter == NULL) {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    rc = CKR_HOST_MEMORY;
                    decr_mgr_cleanup(tokdata, session, ctx);
                    goto done;
                }
                memcpy(ctx->mech.pParameter, mech->pParameter,
                      mech->ulParameterLen);
                ctx->mech.ulParameterLen = mech->ulParameterLen;
            }
        }
        if (rc != CKR_OK) {
            decr_mgr_cleanup(tokdata, session, ctx);
            rc = ep11_error_to_pkcs11_error(rc, session);
            TRACE_ERROR("%s m_DecryptInit rc=0x%lx blob_len=0x%zx "
                        "mech=0x%lx\n", __func__, rc, blob_len,
                        mech->mechanism);
        } else {
            TRACE_INFO("%s m_DecryptInit rc=0x%lx blob_len=0x%zx "
                       "mech=0x%lx\n", __func__, rc, blob_len, mech->mechanism);
        }
    } else {
        ENCR_DECR_CONTEXT *ctx = &session->encr_ctx;

        /*
         * Enforce key usage restrictions. EP11 does not allow to restrict
         * public keys with CKA_ENCRYPT=FALSE. Thus we need to enforce the
         * restriction here.
         */
        rc = check_key_restriction(key_obj, CKA_ENCRYPT);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s check_key_restriction rc=0x%lx\n", __func__, rc);
            goto error;
        }

        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_REENC_BLOB_STATE_START(tokdata, target_info, key_obj, blob,
                                     blob_len, useblob, useblob_len,
                                     ep11_state, ep11_state + ep11_state_l,
                                     ep11_state_l, usestate, usestate_len, rc)
            rc = dll_m_EncryptInit(usestate, &usestate_len, mech, useblob,
                                   useblob_len, target_info->target);
            if (rc == CKR_OK && retry == 1) {
                /*
                 * Initially, the real state_len is unknown, and is set to
                 * allocated state size / 2. When the state was created on
                 * an APQN with new WK set already, move the state to the
                 * final place, which is state + usestate_len, where
                 * usestate_len now is the real state size.
                 */
                memmove(ep11_state + usestate_len,
                        ep11_state + ep11_state_l, usestate_len);
            }
            ep11_state_l = usestate_len;
        RETRY_REENC_BLOB_STATE_END(tokdata, session, target_info,
                                   blob, blob_len, useblob, useblob_len,
                                   ep11_state, ep11_state + ep11_state_l,
                                   ep11_state_l, usestate, usestate_len,
                                   TRUE, rc)
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)
        ctx->key = key;
        ctx->active = TRUE;
        ctx->context = ep11_state;
        ctx->context_len = ep11_state_l * 2; /* current and re-enciphered state */
        ctx->pkey_active = FALSE;
        if (mech != &ctx->mech) { /* deferred init dup'ed mech already */
            ctx->mech.mechanism = mech->mechanism;
            if (mech->ulParameterLen > 0 && mech->pParameter != NULL) {
                ctx->mech.pParameter = (CK_BYTE *) malloc(mech->ulParameterLen);
                if (ctx->mech.pParameter == NULL) {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    rc = CKR_HOST_MEMORY;
                    encr_mgr_cleanup(tokdata, session, ctx);
                    goto done;
                }
                memcpy(ctx->mech.pParameter, mech->pParameter,
                      mech->ulParameterLen);
                ctx->mech.ulParameterLen = mech->ulParameterLen;
            }
        }
        if (rc != CKR_OK) {
            encr_mgr_cleanup(tokdata, session, ctx);
            rc = ep11_error_to_pkcs11_error(rc, session);
            TRACE_ERROR("%s m_EncryptInit rc=0x%lx blob_len=0x%zx "
                        "mech=0x%lx\n", __func__, rc, blob_len,
                        mech->mechanism);
        } else {
            TRACE_INFO("%s m_EncryptInit rc=0x%lx blob_len=0x%zx "
                       "mech=0x%lx\n", __func__, rc, blob_len, mech->mechanism);
        }
    }

done:
    if (rc == CKR_OK)
        INC_COUNTER(tokdata, session, mech, key_obj, strength_index);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;

error:
    if (ep11_state != NULL)
        free(ep11_state);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;
    return rc;
}


CK_RV ep11tok_encrypt_init(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key)
{
    CK_RV rc;

    TRACE_INFO("%s key=0x%lx\n", __func__, key);

    rc = ep11_ende_crypt_init(tokdata, session, mech, key, ENCRYPT, FALSE);

    if (rc != CKR_OK) {
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_decrypt_init(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key,
                           CK_BBOOL checkauth)
{
    CK_RV rc;

    TRACE_INFO("%s key=0x%lx mech=0x%lx\n", __func__, key, mech->mechanism);

    rc = ep11_ende_crypt_init(tokdata, session, mech, key, DECRYPT, checkauth);

    if (rc != CKR_OK) {
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_wrap_key(STDLL_TokData_t * tokdata, SESSION * session,
                       CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE wrapping_key,
                       CK_OBJECT_HANDLE key, CK_BYTE_PTR wrapped_key,
                       CK_ULONG_PTR p_wrapped_key_len)
{
    CK_RV rc;
    CK_BYTE *wrapping_blob, *use_wrapping_blob = NULL;
    size_t wrapping_blob_len, use_wrapping_blob_len = 0;
    CK_OBJECT_CLASS class;
    CK_BYTE *wrap_target_blob, *use_wrap_target_blob;
    size_t wrap_target_blob_len, use_wrap_target_blob_len;
    int size_query = 0;
    OBJECT *key_obj = NULL, *wrap_key_obj = NULL, *sobj = NULL;
    CK_BYTE *sign_blob = NULL, *use_sign_blob = NULL;
    size_t sign_blob_len = ~0, use_sign_blob_len = 0;
    CK_KEY_TYPE ktype;

    /* ep11 weakness:
     * it does not set *p_wrapped_key_len if wrapped_key == NULL
     * (that is with a size query)
     */
    if (wrapped_key == NULL) {
        size_query = 1;
        *p_wrapped_key_len = MAX_BLOBSIZE;
        wrapped_key = malloc(MAX_BLOBSIZE);
        if (!wrapped_key) {
            TRACE_ERROR("%s Memory allocation failed\n", __func__);
            return CKR_HOST_MEMORY;
        }
    }

    /* the key that encrypts */
    rc = h_opaque_2_blob(tokdata, wrapping_key, &wrapping_blob,
                         &wrapping_blob_len, &wrap_key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob(wrapping_key) failed with rc=0x%lx\n",
                    __func__, rc);
        if (size_query)
            free(wrapped_key);
        return rc;
    }

    rc = template_attribute_get_ulong(wrap_key_obj->template, CKA_KEY_TYPE, &ktype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Invalid key type attribute\n");
        goto done;
    }

    if (mech->mechanism == CKM_AES_XTS || ktype == CKK_AES_XTS) {
        TRACE_ERROR("%s Key wrap with AES-XTS is not supported\n", __func__);
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto done;
    }

    if (!key_object_is_mechanism_allowed(wrap_key_obj->template,
                                         mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    /* the key to be wrapped */
    rc = h_opaque_2_blob(tokdata, key, &wrap_target_blob,
                         &wrap_target_blob_len, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob(key) failed with rc=0x%lx\n", __func__,
                    rc);
        goto done;
    }
    rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE, &ktype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Invalid key type attribute\n");
        goto done;
    }

    if (ktype == CKK_AES_XTS) {
        TRACE_ERROR("%s Wrapping an AES-XTS key is not supported\n", __func__);
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto done;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &wrap_key_obj->strength,
                                          POLICY_CHECK_WRAP, session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: key wrap\n");
        goto done;
    }
    rc = tokdata->policy->is_key_allowed(tokdata->policy, &key_obj->strength,
                                         session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: key wrap\n");
        goto done;
    }
    if (!key_object_wrap_template_matches(wrap_key_obj->template,
                                          key_obj->template)) {
        TRACE_ERROR("Wrap template does not match.\n");
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    rc = check_ab_wrap(tokdata, &sign_blob, &sign_blob_len, &sobj,
                       key_obj, wrap_key_obj, mech, session);
    if (rc != CKR_OK) {
        TRACE_ERROR("AB wrapping check failed (rc=0x%lx).\n", rc);
        goto done;
    }

    /* check if wrap mechanism is allowed for the key to be wrapped.
     * AES_ECB and AES_CBC is only allowed to wrap secret keys.
     */
    rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        goto done;
    }

    if (class != CKO_SECRET_KEY &&
        ((mech->mechanism == CKM_AES_ECB) ||
         (mech->mechanism == CKM_AES_CBC))) {
        TRACE_ERROR("%s Wrap mechanism does not match to target key type\n",
                    __func__);
        rc = CKR_KEY_NOT_WRAPPABLE;
        goto done;
    }

    /* debug */
    TRACE_INFO("%s start wrapKey: mech=0x%lx wr_key=0x%lx\n",
               __func__, mech->mechanism, wrapping_key);

    /* The key to be wrapped is extracted from its blob by the card.
     * A standard BER encoding is built and encrypted by the wrapping key
     * (wrapping blob). The wrapped key can be processed by any PKCS11
     * implementation.
     */
    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB3_START(tokdata, target_info,
                            key_obj, wrap_target_blob, wrap_target_blob_len,
                            use_wrap_target_blob, use_wrap_target_blob_len,
                            wrap_key_obj, wrapping_blob, wrapping_blob_len,
                            use_wrapping_blob, use_wrapping_blob_len,
                            sobj, sign_blob, sign_blob_len, use_sign_blob,
                            use_sign_blob_len, rc)
        rc = dll_m_WrapKey(use_wrap_target_blob, use_wrap_target_blob_len,
                           use_wrapping_blob, use_wrapping_blob_len,
                           use_sign_blob, use_sign_blob_len, mech,
                           wrapped_key, p_wrapped_key_len, target_info->target);
    RETRY_REENC_BLOB3_END(tokdata, target_info,
                          use_wrap_target_blob, use_wrap_target_blob_len,
                          use_wrapping_blob, use_wrapping_blob_len,
                          use_sign_blob, use_sign_blob_len, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        TRACE_ERROR("%s m_WrapKey failed with rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx wr_key=%p wr_key_len=0x%lx\n",
                   __func__, rc, (void *)wrapped_key, *p_wrapped_key_len);
    }

done:
    if (rc == CKR_OK && !size_query)
        INC_COUNTER(tokdata, session, mech, wrap_key_obj,
                    POLICY_STRENGTH_IDX_0);

    if (size_query)
        free(wrapped_key);

    object_put(tokdata, wrap_key_obj, TRUE);
    wrap_key_obj = NULL;
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;
    object_put(tokdata, sobj, TRUE);
    sobj = NULL;

    return rc;
}


CK_RV ep11tok_unwrap_key(STDLL_TokData_t * tokdata, SESSION * session,
                         CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR attrs,
                         CK_ULONG attrs_len, CK_BYTE_PTR wrapped_key,
                         CK_ULONG wrapped_key_len,
                         CK_OBJECT_HANDLE wrapping_key,
                         CK_OBJECT_HANDLE_PTR p_key)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE *wrapping_blob, *use_wrapping_blob, *temp;
    size_t wrapping_blob_len, use_wrapping_blob_len;
    CK_BYTE csum[MAX_BLOBSIZE];
    CK_ULONG cslen = sizeof(csum), temp_len;
    OBJECT *key_obj = NULL;
    CK_BYTE keyblob[MAX_BLOBSIZE];
    CK_BYTE keyblobreenc[MAX_BLOBSIZE];
    size_t keyblobsize = sizeof(keyblob);
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG i;
    CK_ULONG ktype;
    CK_ULONG class;
    CK_ULONG len;
    CK_ATTRIBUTE_PTR new_attrs = NULL, tmp_attrs = NULL;
    CK_ULONG new_attrs_len = 0, tmp_attrs_len = 0;
    OBJECT *kobj = NULL;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) session->private_data;
    CK_ATTRIBUTE *new_attrs2 = NULL;
    CK_ULONG new_attrs2_len = 0;
    CK_BBOOL isab;
    CK_BYTE *verifyblob = NULL, *use_verifyblob = NULL;
    size_t verifyblobsize = ~0, use_verifyblobsize = 0;
    OBJECT *vobj = NULL;
    CK_KEY_TYPE keytype;

    /* get wrapping key blob */
    rc = h_opaque_2_blob(tokdata, wrapping_key, &wrapping_blob,
                         &wrapping_blob_len, &kobj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob(wrapping_key) failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    rc = template_attribute_get_ulong(kobj->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Invalid key type attribute\n");
        goto done;
    }

    if (mech->mechanism == CKM_AES_XTS || keytype == CKK_AES_XTS) {
        TRACE_ERROR("%s Key unwrap with AES-XTS is not supported\n", __func__);
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto done;
    }

    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &kobj->strength,
                                          POLICY_CHECK_UNWRAP, session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: key unwrap\n");
        goto done;
    }

    TRACE_DEVEL("%s start unwrapKey:  mech=0x%lx attrs_len=0x%lx "
                "wr_key=0x%lx\n", __func__, mech->mechanism, attrs_len,
                wrapping_key);
    for (i = 0; i < attrs_len; i++) {
        TRACE_DEVEL(" attribute attrs.type=0x%lx\n", attrs[i].type);
    }

    if (!key_object_is_mechanism_allowed(kobj->template, mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto error;
    }

    memset(keyblob, 0, sizeof(keyblob));
    memset(keyblobreenc, 0, sizeof(keyblobreenc));

    /*get key type of unwrapped key */
    CK_ATTRIBUTE_PTR cla_attr =
        get_attribute_by_type(attrs, attrs_len, CKA_CLASS);
    CK_ATTRIBUTE_PTR keytype_attr =
        get_attribute_by_type(attrs, attrs_len, CKA_KEY_TYPE);
    if (!cla_attr || !keytype_attr) {
        TRACE_ERROR("%s CKA_CLASS or CKA_KEY_CLASS attributes not found\n",
                    __func__);
        rc = CKR_TEMPLATE_INCONSISTENT;
        goto error;
    }
    rc = check_ab_unwrap(tokdata, &verifyblob, &verifyblobsize, &vobj, kobj,
                         attrs, attrs_len, mech, &isab, session);
    if (rc != CKR_OK) {
        TRACE_ERROR("check_ab_unwrap failed with rc=0x%08lx\n", rc);
        goto error;
    }
    if (isab) {
        rc = check_ab_kek_type(kobj->template, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
        if (rc != CKR_OK)
            goto error;
        /* AB unwrapping is taking care of all the boolean usage flags.
         * No need to check attributes, just need to duplicate the array. */
        rc = dup_attribute_array(attrs,attrs_len,
                                 &new_attrs, &new_attrs_len);
        if (rc != CKR_OK)
            goto error;
    } else {
        switch (*(CK_OBJECT_CLASS *) cla_attr->pValue) {
        case CKO_SECRET_KEY:
            rc = check_key_attributes(tokdata,
                                     *(CK_KEY_TYPE *) keytype_attr->pValue,
                                     CKO_SECRET_KEY, attrs,
                                     attrs_len, &new_attrs, &new_attrs_len, -1);
            break;
        case CKO_PUBLIC_KEY:
            rc = check_key_attributes(tokdata,
                                     *(CK_KEY_TYPE *) keytype_attr->pValue,
                                     CKO_PUBLIC_KEY, attrs, attrs_len,
                                     &new_attrs, &new_attrs_len, -1);
            break;
        case CKO_PRIVATE_KEY:
            rc = check_key_attributes(tokdata,
                                     *(CK_KEY_TYPE *) keytype_attr->pValue,
                                     CKO_PRIVATE_KEY, attrs, attrs_len,
                                     &new_attrs, &new_attrs_len, -1);
            break;
        default:
            TRACE_ERROR("%s Missing CKA_CLASS type of wrapped key\n", __func__);
            rc = CKR_TEMPLATE_INCOMPLETE;
            goto error;
        }
        if (rc != CKR_OK) {
            TRACE_ERROR("%s check key attributes failed: rc=0x%lx\n", __func__, rc);
            goto error;
        }
    }

    /* check if unwrap mechanism is allowed for the key to be unwrapped.
     * AES_ECB and AES_CBC only allowed to unwrap secret keys.
     */
    if ((*(CK_OBJECT_CLASS *) cla_attr->pValue != CKO_SECRET_KEY) &&
        ((mech->mechanism == CKM_AES_ECB) ||
         (mech->mechanism == CKM_AES_CBC))) {
        rc = CKR_ARGUMENTS_BAD;
        goto error;
    }

    tmp_attrs = new_attrs;
    tmp_attrs_len = new_attrs_len;
    new_attrs = NULL;
    new_attrs_len = 0;
    rc = key_object_apply_template_attr(kobj->template, CKA_UNWRAP_TEMPLATE,
                                        tmp_attrs, tmp_attrs_len,
                                        &new_attrs, &new_attrs_len);
    free_attribute_array(tmp_attrs, tmp_attrs_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("key_object_apply_template_attr failed.\n");
        goto done;
    }

    /* Get the keytype to use when creating the key object */
    rc = pkcs_get_keytype(new_attrs, new_attrs_len, mech, &ktype, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_subclass failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    if (ktype == CKK_AES_XTS) {
        TRACE_ERROR("%s Unwrapping an AES-XTS key is not supported\n", __func__);
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto done;
    }

#ifndef NO_PKEY
    /* Ensure the firmware master key verification pattern is available */
    rc = ep11tok_pkey_get_firmware_mk_vp(tokdata, session);
    if (rc != CKR_OK && rc != CKR_FUNCTION_NOT_SUPPORTED)
        goto error;
#endif /* NO_PKEY */

    /* Start creating the key object */
    rc = object_mgr_create_skel(tokdata, session, new_attrs, new_attrs_len,
                                MODE_UNWRAP, class, ktype, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s object_mgr_create_skel failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    rc = build_ep11_attrs(tokdata, key_obj->template,
                          &new_attrs2, &new_attrs2_len,
                          ktype, *(CK_OBJECT_CLASS *) cla_attr->pValue, -1,
                          mech);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_ep11_attrs failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    trace_attributes(__func__, "Unwrap:", new_attrs2, new_attrs2_len);

    ep11_get_pin_blob(tokdata, ep11_session,
                      ep11_is_session_object(attrs, attrs_len),
                      ep11_is_private_object(attrs, attrs_len),
                      &ep11_pin_blob, &ep11_pin_blob_len);

    /* we need a blob for the new key created by unwrapping,
     * the wrapped key comes in BER
     */
    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB2_START(tokdata, target_info,
                            kobj, wrapping_blob, wrapping_blob_len,
                            use_wrapping_blob, use_wrapping_blob_len,
                            vobj, verifyblob, verifyblobsize,
                            use_verifyblob, use_verifyblobsize, rc)
    RETRY_REENC_CREATE_KEY_START()
        rc = dll_m_UnwrapKey(wrapped_key, wrapped_key_len, use_wrapping_blob,
                             use_wrapping_blob_len, use_verifyblob,
                             use_verifyblobsize, ep11_pin_blob,
                             ep11_pin_blob_len, mech,
                             new_attrs2, new_attrs2_len,
                             keyblob, &keyblobsize, csum, &cslen,
                             target_info->target);
    RETRY_REENC_CREATE_KEY_END(tokdata, session, target_info,
                               keyblob, keyblobreenc, keyblobsize, rc)
    RETRY_REENC_BLOB2_END(tokdata, target_info, use_wrapping_blob,
                          use_wrapping_blob_len, use_verifyblob,
                          use_verifyblobsize, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s m_UnwrapKey rc=0x%lx blobsize=0x%zx mech=0x%lx\n",
                    __func__, rc, keyblobsize, mech->mechanism);
        goto error;
    }
    TRACE_INFO("%s m_UnwrapKey rc=0x%lx blobsize=0x%zx mech=0x%lx\n",
               __func__, rc, keyblobsize, mech->mechanism);

    if (check_expected_mkvp(tokdata, keyblob, keyblobsize, NULL) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto error;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, keyblob, keyblobsize, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = template_update_attribute(key_obj->template, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }
    attr = NULL;

    if (ep11_data->mk_change_active) {
        rc = build_attribute(CKA_IBM_OPAQUE_REENC, keyblobreenc, keyblobsize,
                             &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__,
                        rc);
            goto error;
        }

        rc = template_update_attribute(key_obj->template, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        attr = NULL;
    }

    if (isab) {
        rc = ab_unwrap_update_template(tokdata, session,
                                       keyblob, keyblobsize, key_obj,
                                       *(CK_KEY_TYPE *) keytype_attr->pValue);
        if (rc != CKR_OK) {
            TRACE_ERROR("ab_unwrap_update_template failed with rc=0x%08lx\n", rc);
            goto error;
        }
    }

    rc = update_ep11_attrs_from_blob(tokdata, session, key_obj, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s update_ep11_attrs_from_blob failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    switch (*(CK_OBJECT_CLASS *) cla_attr->pValue) {
    case CKO_SECRET_KEY:
        /* card provides bit length in csum last 4 bytes big endian */
        if (cslen < EP11_CSUMSIZE + 4) {
            rc = CKR_FUNCTION_FAILED;
            TRACE_ERROR("%s Invalid csum length cslen=%lu\n", __func__, cslen);
            goto error;
        }

        len = csum[cslen - 1] + 256 * csum[cslen - 2] +
              256 * 256 * csum[cslen - 3] +  256 * 256 * 256 * csum[cslen - 4];
        len = len / 8;              /* comes in bits */
        TRACE_INFO("%s m_UnwrapKey length %lu 0x%lx\n", __func__, len, len);

        switch (*(CK_KEY_TYPE *) keytype_attr->pValue) {
        case CKK_AES:
        case CKK_GENERIC_SECRET:
        case CKK_SHA_1_HMAC:
        case CKK_SHA224_HMAC:
        case CKK_SHA256_HMAC:
        case CKK_SHA384_HMAC:
        case CKK_SHA512_HMAC:
        case CKK_SHA3_224_HMAC:
        case CKK_SHA3_256_HMAC:
        case CKK_SHA3_384_HMAC:
        case CKK_SHA3_512_HMAC:
        case CKK_SHA512_224_HMAC:
        case CKK_SHA512_256_HMAC:
            rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE *)&len,
                                 sizeof(CK_ULONG), &attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                            __func__, rc);
                goto error;
            }

            rc = template_update_attribute(key_obj->template, attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s template_update_attribute failed with "
                            "rc=0x%lx\n", __func__, rc);
                goto error;
            }
            attr = NULL;
            break;
        }

        /* First 3 bytes of csum is the check value */
        rc = build_attribute(CKA_CHECK_VALUE, csum, EP11_CSUMSIZE, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        rc = template_update_attribute(key_obj->template, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto error;
        }
        attr = NULL;
        break;

    case CKO_PRIVATE_KEY:
        /*
         * In case of unwrapping a private key (CKA_CLASS == CKO_PRIVATE_KEY),
         * the public key attributes needs to be added to the new template.
         */
        switch (*(CK_KEY_TYPE *) keytype_attr->pValue) {
        case CKK_EC:
            rc = ecdsa_priv_unwrap_get_data(key_obj->template, csum, cslen,
                                            FALSE);
            break;
        case CKK_RSA:
            rc = rsa_priv_unwrap_get_data(key_obj->template, csum, cslen,
                                          FALSE);
            break;
        case CKK_DSA:
            rc = dsa_priv_unwrap_get_data(key_obj->template, csum, cslen,
                                          FALSE);
            break;
        case CKK_DH:
            rc = dh_priv_unwrap_get_data(key_obj->template, csum, cslen,
                                         FALSE);
            break;
        case CKK_IBM_PQC_DILITHIUM:
            rc = ibm_dilithium_priv_unwrap_get_data(key_obj->template,
                                                    csum, cslen, FALSE);
            break;
        case CKK_IBM_PQC_KYBER:
            rc = ibm_kyber_priv_unwrap_get_data(key_obj->template,
                                                csum, cslen, FALSE);
            break;
        }

        if (rc != 0) {
            TRACE_ERROR("%s xxx_priv_unwrap_get_data rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        /* csum is a MACed SPKI, get length of SPKI part only */
        rc = ber_decode_SEQUENCE(csum, &temp, &temp_len, &cslen);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s ber_decode_SEQUENCE failed rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        rc = build_attribute(CKA_PUBLIC_KEY_INFO, csum, cslen, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        rc = template_update_attribute(key_obj->template, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto error;
        }
        attr = NULL;
        break;
    }

    /* key should be fully constructed.
     * Assign an object handle and store key.
     * Enforce policy.
     */
    rc = object_mgr_create_final(tokdata, session, key_obj, p_key);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s object_mgr_create_final with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    INC_COUNTER(tokdata, session, mech, kobj, POLICY_STRENGTH_IDX_0);

    goto done;

error:
    if (key_obj)
        object_free(key_obj);
    if (attr != NULL)
        free(attr);
    *p_key = 0;
done:
    if (new_attrs)
        free_attribute_array(new_attrs, new_attrs_len);
    if (new_attrs2)
        free_attribute_array(new_attrs2, new_attrs2_len);

    object_put(tokdata, kobj, TRUE);
    object_put(tokdata, vobj, TRUE);
    kobj = NULL;

    return rc;
}

static const CK_MECHANISM_TYPE ep11_supported_mech_list[] = {
    CKM_AES_CBC,
    CKM_AES_CBC_PAD,
    CKM_AES_CMAC,
    CKM_AES_ECB,
    CKM_AES_XTS,
    CKM_AES_KEY_GEN,
    CKM_AES_XTS_KEY_GEN,
    CKM_DES2_KEY_GEN,
    CKM_DES3_CBC,
    CKM_DES3_CBC_PAD,
    CKM_DES3_CMAC,
    CKM_DES3_ECB,
    CKM_DES3_KEY_GEN,
    CKM_DH_PKCS_DERIVE,
    CKM_DH_PKCS_KEY_PAIR_GEN,
    CKM_DSA,
    CKM_DSA_KEY_PAIR_GEN,
    CKM_DSA_SHA1,
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDH1_DERIVE,
    CKM_ECDSA,
    CKM_ECDSA_SHA1,
    CKM_ECDSA_SHA224,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKM_IBM_CMAC,
    CKM_IBM_DILITHIUM,
    CKM_IBM_EC_X25519,
    CKM_IBM_EC_X448,
    CKM_IBM_ED25519_SHA512,
    CKM_IBM_ED448_SHA3,
    CKM_IBM_KYBER,
    CKM_IBM_SHA3_224,
    CKM_IBM_SHA3_224_HMAC,
    CKM_IBM_SHA3_256,
    CKM_IBM_SHA3_256_HMAC,
    CKM_IBM_SHA3_384,
    CKM_IBM_SHA3_384_HMAC,
    CKM_IBM_SHA3_512,
    CKM_IBM_SHA3_512_HMAC,
    CKM_IBM_CPACF_WRAP,
    CKM_PBE_SHA1_DES3_EDE_CBC,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS_OAEP,
    CKM_RSA_PKCS_PSS,
    CKM_RSA_X9_31,
    CKM_RSA_X9_31_KEY_PAIR_GEN,
    CKM_SHA1_KEY_DERIVATION,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA1_RSA_X9_31,
    CKM_SHA224,
    CKM_SHA224_HMAC,
    CKM_SHA224_KEY_DERIVATION,
    CKM_SHA224_RSA_PKCS,
    CKM_SHA224_RSA_PKCS_PSS,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_KEY_DERIVATION,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384,
    CKM_SHA384_HMAC,
    CKM_SHA384_KEY_DERIVATION,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512,
    CKM_SHA512_224,
    CKM_SHA512_224_HMAC,
    CKM_SHA512_224_KEY_DERIVATION,
    CKM_SHA512_256,
    CKM_SHA512_256_HMAC,
    CKM_SHA512_256_KEY_DERIVATION,
    CKM_SHA512_HMAC,
    CKM_SHA512_KEY_DERIVATION,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA512_RSA_PKCS_PSS,
    CKM_SHA_1,
    CKM_SHA_1_HMAC,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_IBM_ATTRIBUTEBOUND_WRAP,
    CKM_IBM_ECDSA_OTHER,
    CKM_IBM_BTC_DERIVE,
};

static const CK_ULONG supported_mech_list_len =
    (sizeof(ep11_supported_mech_list) / sizeof(CK_MECHANISM_TYPE));

struct mech_translate {
    CK_MECHANISM_TYPE pkcs11_mech;
    CK_MECHANISM_TYPE ep11_mech;
};

/* Translate PKCS#11 v3.0 SHA3 mechs to IBM-specific SHA3 mechs */
static const struct mech_translate pkcs11_mechanism_translation[] = {
    { CKM_SHA3_224,           CKM_IBM_SHA3_224 },
    { CKM_SHA3_224_HMAC,      CKM_IBM_SHA3_224_HMAC },
    { CKM_SHA3_256,           CKM_IBM_SHA3_256 },
    { CKM_SHA3_256_HMAC,      CKM_IBM_SHA3_256_HMAC },
    { CKM_SHA3_384,           CKM_IBM_SHA3_384 },
    { CKM_SHA3_384_HMAC,      CKM_IBM_SHA3_384_HMAC },
    { CKM_SHA3_512,           CKM_IBM_SHA3_512 },
    { CKM_SHA3_512_HMAC,      CKM_IBM_SHA3_512_HMAC },
    { CKM_SHA_1_KEY_GEN,      CKM_GENERIC_SECRET_KEY_GEN },
    { CKM_SHA224_KEY_GEN,     CKM_GENERIC_SECRET_KEY_GEN },
    { CKM_SHA256_KEY_GEN,     CKM_GENERIC_SECRET_KEY_GEN },
    { CKM_SHA384_KEY_GEN,     CKM_GENERIC_SECRET_KEY_GEN },
    { CKM_SHA512_KEY_GEN,     CKM_GENERIC_SECRET_KEY_GEN },
    { CKM_SHA512_224_KEY_GEN, CKM_GENERIC_SECRET_KEY_GEN },
    { CKM_SHA512_256_KEY_GEN, CKM_GENERIC_SECRET_KEY_GEN },
    { CKM_SHA3_224_KEY_GEN,   CKM_GENERIC_SECRET_KEY_GEN },
    { CKM_SHA3_256_KEY_GEN,   CKM_GENERIC_SECRET_KEY_GEN },
    { CKM_SHA3_384_KEY_GEN,   CKM_GENERIC_SECRET_KEY_GEN },
    { CKM_SHA3_512_KEY_GEN,   CKM_GENERIC_SECRET_KEY_GEN },
};

static const CK_ULONG pkcs11_mechanism_translation_len =
    (sizeof(pkcs11_mechanism_translation) / sizeof(struct mech_translate));

struct mgf_translate {
    CK_RSA_PKCS_MGF_TYPE pkcs11_mgf;
    CK_RSA_PKCS_MGF_TYPE ep11_mgf;
};

/* Translate PKCS#11 v3.0 SHA3 MGFs to IBM-specific SHA3 MGFs */
static const struct mgf_translate pkcs11_mgf_translation[] = {
    { CKG_MGF1_SHA3_224, CKG_IBM_MGF1_SHA3_224 },
    { CKG_MGF1_SHA3_256, CKG_IBM_MGF1_SHA3_256 },
    { CKG_MGF1_SHA3_384, CKG_IBM_MGF1_SHA3_384 },
    { CKG_MGF1_SHA3_512, CKG_IBM_MGF1_SHA3_512 },
};

static const CK_ULONG pkcs11_mgf_translation_len =
    (sizeof(pkcs11_mgf_translation) / sizeof(struct mgf_translate));

struct keytype_translate {
    CK_KEY_TYPE pkcs11_keytype;
    CK_KEY_TYPE ep11_keytype;
};

/* Translate PKCS#11 SHA-HMAC key types to generic secrets */
static const struct keytype_translate pkcs11_keytype_translation[] = {
    { CKK_SHA_1_HMAC, CKK_GENERIC_SECRET },
    { CKK_SHA224_HMAC, CKK_GENERIC_SECRET },
    { CKK_SHA256_HMAC, CKK_GENERIC_SECRET },
    { CKK_SHA384_HMAC, CKK_GENERIC_SECRET },
    { CKK_SHA512_HMAC, CKK_GENERIC_SECRET },
    { CKK_SHA512_224_HMAC, CKK_GENERIC_SECRET },
    { CKK_SHA512_256_HMAC, CKK_GENERIC_SECRET },
    { CKK_SHA3_224_HMAC, CKK_GENERIC_SECRET },
    { CKK_SHA3_256_HMAC, CKK_GENERIC_SECRET },
    { CKK_SHA3_384_HMAC, CKK_GENERIC_SECRET },
    { CKK_SHA3_512_HMAC, CKK_GENERIC_SECRET },
};

static const CK_ULONG pkcs11_keytype_translation_len =
    (sizeof(pkcs11_keytype_translation) / sizeof(struct keytype_translate));

static CK_RV ep11tok_pkcs11_mech_translate(STDLL_TokData_t *tokdata,
                                           CK_MECHANISM_TYPE type,
                                           CK_MECHANISM_TYPE* ep11_type)
{
    CK_ULONG i;

    for (i = 0; i < pkcs11_mechanism_translation_len; i++) {
        if (type == pkcs11_mechanism_translation[i].pkcs11_mech) {
            TRACE_DEVEL("%s Mech '%s' is backed by '%s'\n", __func__,
                        ep11_get_ckm(tokdata,
                                pkcs11_mechanism_translation[i].pkcs11_mech),
                        ep11_get_ckm(tokdata,
                                pkcs11_mechanism_translation[i].ep11_mech));
            *ep11_type = pkcs11_mechanism_translation[i].ep11_mech;
            return CKR_OK;
        }
    }

    return CKR_MECHANISM_INVALID;
}

static CK_RV ep11tok_pkcs11_mgf_translate(STDLL_TokData_t *tokdata,
                                          CK_RSA_PKCS_MGF_TYPE mgf,
                                          CK_RSA_PKCS_MGF_TYPE* ep11_mgf)
{
    CK_ULONG i;

    UNUSED(tokdata);

    for (i = 0; i < pkcs11_mgf_translation_len; i++) {
        if (mgf == pkcs11_mgf_translation[i].pkcs11_mgf) {
            TRACE_DEVEL("%s MGF 0x%lx is backed by 0x%lx\n", __func__,
                        pkcs11_mgf_translation[i].pkcs11_mgf,
                        pkcs11_mgf_translation[i].ep11_mgf);
            *ep11_mgf = pkcs11_mgf_translation[i].ep11_mgf;
            return CKR_OK;
        }
    }

    return CKR_MECHANISM_INVALID;
}

static CK_RV ep11tok_pkcs11_keytype_translate(STDLL_TokData_t *tokdata,
                                              CK_KEY_TYPE keytype,
                                              CK_KEY_TYPE* ep11_keytype)
{
    CK_ULONG i;

    UNUSED(tokdata);

    for (i = 0; i < pkcs11_keytype_translation_len; i++) {
        if (keytype == pkcs11_keytype_translation[i].pkcs11_keytype) {
            TRACE_DEVEL("%s Keytype 0x%lx is backed by 0x%lx\n", __func__,
                        pkcs11_keytype_translation[i].pkcs11_keytype,
                        pkcs11_keytype_translation[i].ep11_keytype);
            *ep11_keytype = pkcs11_keytype_translation[i].ep11_keytype;
            return CKR_OK;
        }
    }

    return CKR_KEY_TYPE_INCONSISTENT;
}

/* Note: Do not move this function inside
   ep11tok_is_mechanism_supported since that would introduce an
   endless loop.  Also do not use it in ep11tok_get_mechanism_info for
   the same reason. */
static CK_RV ep11tok_check_policy_for_mech(STDLL_TokData_t *tokdata,
                                           CK_MECHANISM_TYPE mech,
                                           CK_MECHANISM_INFO_PTR pinfo)
{
    CK_RV rc;

    if (tokdata->policy->active == CK_FALSE)
        return CKR_OK;
    rc = ep11tok_get_mechanism_info(tokdata, mech, pinfo);
    if (rc != CKR_OK)
        return rc;
    return tokdata->policy->update_mech_info(tokdata->policy, mech, pinfo);
}

static CK_RV ep11tok_mechanism_list_add_translated(
                                        STDLL_TokData_t * tokdata,
                                        CK_MECHANISM_TYPE_PTR pMechanismList,
                                        CK_ULONG_PTR pulCount, CK_ULONG size)
{
    CK_ULONG i;

    for (i = 0; i < pkcs11_mechanism_translation_len; i++) {
        if (ep11tok_is_mechanism_supported(tokdata,
                      pkcs11_mechanism_translation[i].pkcs11_mech) != CKR_OK)
            continue;

        if (pMechanismList != NULL && *pulCount < size)
            pMechanismList[*pulCount] =
                        pkcs11_mechanism_translation[i].pkcs11_mech;
        *pulCount += 1;
    }

    return CKR_OK;
}

struct sha_combined {
    CK_MECHANISM_TYPE combined_mech;
    CK_MECHANISM_TYPE hash_mech;
    CK_MECHANISM_TYPE base_mech;
};

/*
 * Note: For RSA-PSS, EP11 requires that the data-hash function is the same
 * as the 'mgf' and 'hashalg' fields in the mechanism parameter.
 * So CKM_SHA3_nnn_RSA_PKCS_PSS would need to use CKM_[IBM_]SHA3_nnn and
 * CKG_[IBM_]MGF1_SHA3_nnn. However, EP11 currently does not support the SHA3
 * algorithms for the RSA-PSS mechanism parameter (only for RSA-OAEP).
 * Thus CKM_SHA3_nnn_RSA_PKCS_PSS can not be supported with SHA3 hashing,
 * even though the data hashing would be performed by libica.
 */
static const struct sha_combined sha3_combined_libica_only_mechs[] = {
    { CKM_SHA3_224_RSA_PKCS, CKM_IBM_SHA3_224, CKM_RSA_PKCS },
    { CKM_SHA3_256_RSA_PKCS, CKM_IBM_SHA3_256, CKM_RSA_PKCS },
    { CKM_SHA3_384_RSA_PKCS, CKM_IBM_SHA3_384, CKM_RSA_PKCS },
    { CKM_SHA3_512_RSA_PKCS, CKM_IBM_SHA3_512, CKM_RSA_PKCS },
    { CKM_ECDSA_SHA3_224, CKM_IBM_SHA3_224, CKM_ECDSA },
    { CKM_ECDSA_SHA3_256, CKM_IBM_SHA3_256, CKM_ECDSA },
    { CKM_ECDSA_SHA3_384, CKM_IBM_SHA3_384, CKM_ECDSA },
    { CKM_ECDSA_SHA3_512, CKM_IBM_SHA3_512, CKM_ECDSA },
};

static const CK_ULONG sha3_combined_libica_only_mechs_len =
    (sizeof(sha3_combined_libica_only_mechs) / sizeof(struct sha_combined));

static const struct sha_combined *ep11tok_find_sha3_combined_libica_only_mech(
                                                   STDLL_TokData_t *tokdata,
                                                   CK_MECHANISM_TYPE type)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_ULONG i;

    for (i = 0; i < sha3_combined_libica_only_mechs_len; i++) {
        if (type == sha3_combined_libica_only_mechs[i].combined_mech) {
            /* Only supported if hash mech is available via libica */
            if (!ep11tok_libica_digest_available(tokdata, ep11_data,
                              sha3_combined_libica_only_mechs[i].hash_mech))
                continue;

            TRACE_DEVEL("%s Mech '%s' is a combined libica-only mech backed by "
                        "'%s' and '%s'\n",
                        __func__, ep11_get_ckm(tokdata, type),
                        ep11_get_ckm(tokdata,
                                sha3_combined_libica_only_mechs[i].hash_mech),
                        ep11_get_ckm(tokdata,
                                sha3_combined_libica_only_mechs[i].base_mech));

            return &sha3_combined_libica_only_mechs[i];
        }
    }

    return NULL;
}

static CK_RV ep11tok_mechanism_list_add_sha3_combined(
                                        STDLL_TokData_t *tokdata,
                                        CK_MECHANISM_TYPE_PTR pMechanismList,
                                        CK_ULONG_PTR pulCount, CK_ULONG size)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_ULONG i;

    for (i = 0; i < sha3_combined_libica_only_mechs_len; i++) {
        if (ep11tok_is_mechanism_supported(tokdata,
                sha3_combined_libica_only_mechs[i].hash_mech) != CKR_OK ||
            ep11tok_is_mechanism_supported(tokdata,
                sha3_combined_libica_only_mechs[i].base_mech) != CKR_OK)
            continue;

        /* Only add if hash mech is available via libica */
        if (!ep11tok_libica_digest_available(tokdata, ep11_data,
                                sha3_combined_libica_only_mechs[i].hash_mech))
            continue;

        if (pMechanismList != NULL && *pulCount < size)
            pMechanismList[*pulCount] =
                    sha3_combined_libica_only_mechs[i].combined_mech;
        *pulCount += 1;
    }

    return CKR_OK;
}

/* filtering out some mechanisms we do not want to provide
 * makes it complicated
 */
CK_RV ep11tok_get_mechanism_list(STDLL_TokData_t * tokdata,
                                 CK_MECHANISM_TYPE_PTR pMechanismList,
                                 CK_ULONG_PTR pulCount)
{
    CK_RV rc = 0;
    CK_ULONG counter = 0, size = 0;
    CK_MECHANISM_TYPE_PTR mlist = NULL;
    CK_MECHANISM_TYPE_PTR tmp;
    CK_ULONG i;
    ep11_target_info_t* target_info;
    CK_MECHANISM_INFO info;

    target_info = get_target_info(tokdata);
    if (target_info == NULL)
        return CKR_FUNCTION_FAILED;

    /* size query */
    if (pMechanismList == NULL) {
        RETRY_SINGLE_APQN_START(tokdata, rc)
            rc = dll_m_GetMechanismList(0, pMechanismList, pulCount,
                                        target_info->target);
        RETRY_SINGLE_APQN_END(rc, tokdata, target_info)
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s bad rc=0x%lx from m_GetMechanismList() #1\n",
                        __func__, rc);
            goto out;
        }

        /* adjust the size according to the ban list,
         * for this we need to know what the card provides
         */
        counter = *pulCount;

        /*
         * For mixed card levels, the size query call and the call to obtain the
         * list may run on different cards. When the size query call runs on a
         * card with less mechanisms than the second call, return code
         * CKR_BUFFER_TOO_SMALL may be encountered, when the card where the
         * second call runs supports more mechanisms than the one where the
         * size query was run. Repeat the call to obtain the list with the
         * larger list.
         */
        do {
            tmp = (CK_MECHANISM_TYPE *) realloc(mlist,
                                    sizeof(CK_MECHANISM_TYPE) * counter);
            if (!tmp) {
                TRACE_ERROR("%s Memory allocation failed\n", __func__);
                rc = CKR_HOST_MEMORY;
                goto out;
            }
            mlist = tmp;
            RETRY_SINGLE_APQN_START(tokdata, rc)
                rc = dll_m_GetMechanismList(0, mlist, &counter,
                                            target_info->target);
            RETRY_SINGLE_APQN_END(rc, tokdata, target_info)
            if (rc != CKR_OK) {
                rc = ep11_error_to_pkcs11_error(rc, NULL);
                TRACE_ERROR("%s bad rc=0x%lx from m_GetMechanismList() #2\n",
                            __func__, rc);
                if (rc != CKR_BUFFER_TOO_SMALL)
                    goto out;
            }
            /* counter was updated in case of CKR_BUFFER_TOO_SMALL */
            *pulCount = counter;
        } while (rc == CKR_BUFFER_TOO_SMALL);

        for (i = 0; i < counter; i++) {
            if (mlist[i] == CKM_IBM_CPACF_WRAP) {
                /* Internal mechanisms should not be exposed. */
                *pulCount = *pulCount - 1;
            } else if (ep11tok_is_mechanism_supported(tokdata, mlist[i]) != CKR_OK) {
                /* banned mech found,
                 * decrement reported list size
                 */
                *pulCount = *pulCount - 1;
            } else if (ep11tok_check_policy_for_mech(tokdata, mlist[i], &info) !=
                    CKR_OK) {
                TRACE_DEVEL("Policy blocks mechanism 0x%lx!\n", mlist[i]);
                *pulCount -= 1;
            }
        }

        if (ep11tok_is_mechanism_supported(tokdata, CKM_AES_XTS) == CKR_OK &&
            ep11tok_is_mechanism_supported(tokdata, CKM_AES_XTS_KEY_GEN) == CKR_OK) {
            *pulCount += 2;
        }
        rc = ep11tok_mechanism_list_add_translated(tokdata, pMechanismList,
                                                   pulCount, 0);
        if (rc != CKR_OK)
            goto out;
        rc = ep11tok_mechanism_list_add_sha3_combined(tokdata, pMechanismList,
                                                      pulCount, 0);
    } else {
        /* 2. call, content request */
        size = *pulCount;

        /* find out size ep11 will report, cannot use the size
         * that comes as parameter, this is a 'reduced size',
         * ep11 would complain about insufficient list size
         */
        RETRY_SINGLE_APQN_START(tokdata, rc)
            rc = dll_m_GetMechanismList(0, mlist, &counter,
                                        target_info->target);
        RETRY_SINGLE_APQN_END(rc, tokdata, target_info)
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s bad rc=0x%lx from m_GetMechanismList() #3\n",
                        __func__, rc);
            goto out;
        }

        /*
         * For mixed card levels, the size query call and the call to obtain the
         * list may run on different cards. When the size query call runs on a
         * card with less mechanisms than the second call, return code
         * CKR_BUFFER_TOO_SMALL may be encountered, when the card where the
         * second call runs supports more mechanisms than the one where the
         * size query was run. Repeat the call to obtain the list with the
         * larger list.
         */
        do {
            tmp = (CK_MECHANISM_TYPE *) realloc(mlist,
                                    sizeof(CK_MECHANISM_TYPE) * counter);
            if (!tmp) {
                TRACE_ERROR("%s Memory allocation failed\n", __func__);
                rc = CKR_HOST_MEMORY;
                goto out;
            }
            mlist = tmp;
            /* all the card has */
            RETRY_SINGLE_APQN_START(tokdata, rc)
                rc = dll_m_GetMechanismList(0, mlist, &counter,
                                            target_info->target);
            RETRY_SINGLE_APQN_END(rc, tokdata, target_info)
            if (rc != CKR_OK) {
                rc = ep11_error_to_pkcs11_error(rc, NULL);
                TRACE_ERROR("%s bad rc=0x%lx from m_GetMechanismList() #4\n",
                            __func__, rc);
                if (rc != CKR_BUFFER_TOO_SMALL)
                    goto out;
            }
        } while (rc == CKR_BUFFER_TOO_SMALL);

        for (i = 0; i < counter; i++)
            TRACE_INFO("%s raw mech list entry '%s'\n",
                       __func__, ep11_get_ckm(tokdata, mlist[i]));

        /* copy only mechanisms not banned */
        *pulCount = 0;
        for (i = 0; i < counter; i++) {
            if (mlist[i] == CKM_IBM_CPACF_WRAP)
                /* Internal mechanisms should not be exposed. */
                continue;
            if (ep11tok_check_policy_for_mech(tokdata, mlist[i], &info) !=
                CKR_OK) {
                TRACE_DEVEL("Policy blocks mechanism 0x%lx!\n", mlist[i]);
                continue;
            }
            if (ep11tok_is_mechanism_supported(tokdata, mlist[i]) == CKR_OK) {
                if (*pulCount < size)
                    pMechanismList[*pulCount] = mlist[i];
                *pulCount = *pulCount + 1;
            }
        }

        if (ep11tok_is_mechanism_supported(tokdata, CKM_AES_XTS) == CKR_OK &&
            ep11tok_is_mechanism_supported(tokdata, CKM_AES_XTS_KEY_GEN) == CKR_OK) {
            if (*pulCount < size)
                pMechanismList[*pulCount] = CKM_AES_XTS_KEY_GEN;
            *pulCount = *pulCount + 1;
            if (*pulCount < size)
                pMechanismList[*pulCount] = CKM_AES_XTS;
            *pulCount = *pulCount + 1;
        }
        rc = ep11tok_mechanism_list_add_translated(tokdata, pMechanismList,
                                                   pulCount, size);
        if (*pulCount > size)
            rc = CKR_BUFFER_TOO_SMALL;
        if (rc != CKR_OK)
            goto out;
        rc = ep11tok_mechanism_list_add_sha3_combined(tokdata, pMechanismList,
                                                      pulCount, size);
        if (*pulCount > size)
            rc = CKR_BUFFER_TOO_SMALL;
    }

out:
    if (mlist)
        free(mlist);
    put_target_info(tokdata, target_info);
    return rc;
}


CK_RV ep11tok_is_mechanism_supported(STDLL_TokData_t *tokdata,
                                     CK_MECHANISM_TYPE type)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_VERSION ver1_3 = { .major = 1, .minor = 3 };
    CK_VERSION ver3 = { .major = 3, .minor = 0 };
    CK_VERSION ver3_1 = { .major = 3, .minor = 0x10 };
    CK_VERSION ver4 = { .major = 4, .minor = 0 };
    CK_BBOOL found = FALSE;
    CK_ULONG i;
    int status;
    CK_RV rc = CKR_OK;
    ep11_target_info_t* target_info;
    CK_MECHANISM_TYPE orig_mech = type;
    const struct sha_combined *comb_mech;

    comb_mech = ep11tok_find_sha3_combined_libica_only_mech(tokdata, type);
    if (comb_mech != NULL &&
        ep11tok_is_mechanism_supported(tokdata,
                                       comb_mech->hash_mech) == CKR_OK)
        type = comb_mech->base_mech;

    ep11tok_pkcs11_mech_translate(tokdata, type, &type);

    for (i = 0; i < supported_mech_list_len; i++) {
        if (type == ep11_supported_mech_list[i]) {
            found = TRUE;
            break;
        }
    }

    if (!found) {
        TRACE_INFO("%s Mech '%s' not suppported\n", __func__,
                   ep11_get_ckm(tokdata, type));
        return CKR_MECHANISM_INVALID;
    }

    target_info = get_target_info(tokdata);
    if (target_info == NULL)
        return CKR_FUNCTION_FAILED;

    if (check_cps_for_mechanism(tokdata, ep11_data->cp_config,
                                type, target_info->control_points,
                                target_info->control_points_len,
                                target_info->max_control_point_index) != CKR_OK) {
        TRACE_INFO("%s Mech '%s' banned due to control point\n",
                   __func__, ep11_get_ckm(tokdata, orig_mech));
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    switch(type) {
    case CKM_SHA_1_HMAC:
    case CKM_SHA_1_HMAC_GENERAL:
    case CKM_SHA224_HMAC:
    case CKM_SHA224_HMAC_GENERAL:
    case CKM_SHA256_HMAC:
    case CKM_SHA256_HMAC_GENERAL:
    case CKM_SHA384_HMAC:
    case CKM_SHA384_HMAC_GENERAL:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_HMAC_GENERAL:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_224_HMAC_GENERAL:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA512_256_HMAC_GENERAL:
        /*
         * Older levels of the EP11 firmware report ulMinKeySize in bytes,
         * but ulMaxKeySize in bits for HMAC mechanisms. Newer levels of the
         * EP11 firmware report both ulMinKeySize and ulMaxKeySize in bytes.
         * HMAC mechanisms are only supported when all configured EP11
         * crypto adapters either have the fix, or all don't have the fix.
         */
        status = check_required_versions(tokdata, hmac_req_versions,
                                         NUM_HMAC_REQ);
        if (status == -1) {
            TRACE_INFO("%s Mech '%s' banned due to old card or mixed firmware versions\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        break;

    case CKM_RSA_PKCS_OAEP:
        /* CKM_RSA_PKCS_OAEP is not supported with EP11 host library <= 1.3 */
        if (compare_ck_version(&ep11_data->ep11_lib_version, &ver1_3) <= 0) {
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }

        status = check_required_versions(tokdata, oaep_req_versions,
                                         NUM_OAEP_REQ);
        if (status != 1) {
            TRACE_INFO("%s Mech '%s' banned due to old card or mixed firmware versions\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        break;

    case CKM_IBM_SHA3_224:
    case CKM_IBM_SHA3_256:
    case CKM_IBM_SHA3_384:
    case CKM_IBM_SHA3_512:
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        status = check_required_versions(tokdata, ibm_sha3_req_versions,
                                         NUM_IBM_SHA3_REQ);
        if (status != 1) {
            TRACE_INFO("%s Mech '%s' banned due to old card or mixed firmware versions\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        break;

    case CKM_DES3_CMAC:
    case CKM_DES3_CMAC_GENERAL:
    case CKM_AES_CMAC:
    case CKM_AES_CMAC_GENERAL:
        status = check_required_versions(tokdata, cmac_req_versions,
                                         NUM_CMAC_REQ);
        if (status != 1) {
            TRACE_INFO("%s Mech '%s' banned due to old card or mixed firmware versions\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        break;

    case CKM_IBM_EC_X25519:
    case CKM_IBM_ED25519_SHA512:
    case CKM_IBM_EC_X448:
    case CKM_IBM_ED448_SHA3:
        if (compare_ck_version(&ep11_data->ep11_lib_version, &ver3) < 0) {
            TRACE_INFO("%s Mech '%s' banned due to host library version\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }

        status = check_required_versions(tokdata, edwards_req_versions,
                                         NUM_EDWARDS_REQ);
        if (status != 1) {
            TRACE_INFO("%s Mech '%s' banned due to old card or mixed firmware versions\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        break;

    case CKM_IBM_DILITHIUM:
        if (compare_ck_version(&ep11_data->ep11_lib_version, &ver3) <= 0) {
            TRACE_INFO("%s Mech '%s' banned due to host library version\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        status = check_required_versions(tokdata, ibm_dilithium_req_versions,
                                         NUM_DILITHIUM_REQ);
        if (status != 1) {
            TRACE_INFO("%s Mech '%s' banned due to old card or mixed firmware versions\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        break;

    case CKM_IBM_KYBER:
        if (compare_ck_version(&ep11_data->ep11_lib_version, &ver4) < 0) {
            TRACE_INFO("%s Mech '%s' banned due to host library version\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        status = check_required_versions(tokdata, ibm_kyber_req_versions,
                                         NUM_KYBER_REQ);
        if (status != 1) {
            TRACE_INFO("%s Mech '%s' banned due to old card or mixed firmware versions\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        break;

#ifndef NO_PKEY
    case CKM_IBM_CPACF_WRAP:
        if (compare_ck_version(&ep11_data->ep11_lib_version, &ver3) <= 0) {
            TRACE_INFO("%s Mech '%s' banned due to host library version\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));

            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        status = check_required_versions(tokdata, ibm_cpacf_wrap_req_versions,
                                         NUM_CPACF_WRAP_REQ);
        if (status != 1) {
            TRACE_INFO("%s Mech '%s' banned due to old card or mixed firmware versions\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        break;
#endif /* NO_PKEY */

    case CKM_IBM_BTC_DERIVE:
        if (compare_ck_version(&ep11_data->ep11_lib_version, &ver3_1) < 0) {
            TRACE_INFO("%s Mech '%s' banned due to host library version\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        status = check_required_versions(tokdata, ibm_btc_req_versions,
                                         NUM_BTC_REQ);
        if (status != 1) {
            TRACE_INFO("%s Mech '%s' banned due to old card or mixed firmware versions\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        break;

    case CKM_IBM_ECDSA_OTHER:
        if (compare_ck_version(&ep11_data->ep11_lib_version, &ver3_1) < 0) {
            TRACE_INFO("%s Mech '%s' banned due to host library version\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        status = check_required_versions(tokdata, ibm_ecdsa_other_req_versions,
                                         NUM_ECDSA_OTHER_REQ);
        if (status != 1) {
            TRACE_INFO("%s Mech '%s' banned due to old card or mixed firmware versions\n",
                       __func__, ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        break;

    case CKM_AES_XTS:
    case CKM_AES_XTS_KEY_GEN:
        if ((ep11_data->pkey_wrap_support_checked && !ep11_data->pkey_wrap_supported) ||
            ep11tok_pkey_option_disabled(tokdata) || ep11_data->msa_level < 4 ||
            ep11tok_is_mechanism_supported(tokdata, CKM_IBM_CPACF_WRAP) != CKR_OK ||
            ep11tok_is_mechanism_supported(tokdata, CKM_AES_KEY_GEN) != CKR_OK) {
            TRACE_INFO("%s Mech '%s' not suppported\n", __func__,
                       ep11_get_ckm(tokdata, orig_mech));
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }
        break;
    }

out:
    put_target_info(tokdata, target_info);
    return rc;
}

CK_RV ep11tok_is_mechanism_supported_ex(STDLL_TokData_t *tokdata,
                                        CK_MECHANISM_PTR mech)
{
    CK_RSA_PKCS_OAEP_PARAMS *params;
    int status;
    CK_RV rc;

    rc = ep11tok_is_mechanism_supported(tokdata, mech->mechanism);
    if (rc != CKR_OK)
        return rc;

    switch (mech->mechanism) {
    case  CKM_RSA_PKCS_OAEP:
        if (mech->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS) ||
            mech->pParameter == NULL)
            return CKR_MECHANISM_PARAM_INVALID;

        params = (CK_RSA_PKCS_OAEP_PARAMS *)mech->pParameter;

        status = check_required_versions(tokdata, oaep_sha2_req_versions,
                                         NUM_OAEP_SHA2_REQ);
        if (status == 1)
            return CKR_OK;

        /*
         * Not all APQNs have the required firmware level, restrict to SHA1
         * for hashing algorithm and MGF.
         */
        if (params->hashAlg == CKM_SHA_1 && params->mgf == CKG_MGF1_SHA1)
            return CKR_OK;

        TRACE_INFO("%s RSA-OAEP supports SHA1 only due to mixed firmware "
                   "  versions\n", __func__);
        return CKR_MECHANISM_PARAM_INVALID;
    }
    return CKR_OK;
}

CK_RV ep11tok_get_mechanism_info(STDLL_TokData_t * tokdata,
                                 CK_MECHANISM_TYPE type,
                                 CK_MECHANISM_INFO_PTR pInfo)
{
    CK_RV rc;
    int status;
    ep11_target_info_t* target_info;
    const struct sha_combined *comb_mech;

    rc = ep11tok_is_mechanism_supported(tokdata, type);
    if (rc != CKR_OK) {
        TRACE_DEBUG("%s rc=0x%lx unsupported '%s'\n", __func__, rc,
                    ep11_get_ckm(tokdata, type));
        return rc;
    }

    ep11tok_pkcs11_mech_translate(tokdata, type, &type);

    /* Get base-mech for combined libica-only mechanism */
    comb_mech = ep11tok_find_sha3_combined_libica_only_mech(tokdata, type);
    if(comb_mech != NULL)
        type = comb_mech->base_mech;

    target_info = get_target_info(tokdata);
    if (target_info == NULL)
        return CKR_FUNCTION_FAILED;

    switch (type) {
        case CKM_AES_XTS:
            pInfo->ulMinKeySize = 32;
            pInfo->ulMaxKeySize = 64;
            pInfo->flags = (CK_FLAGS)(CKF_ENCRYPT|CKF_DECRYPT);
            break;
        case CKM_AES_XTS_KEY_GEN:
            pInfo->ulMinKeySize = 32;
            pInfo->ulMaxKeySize = 64;
            pInfo->flags = (CK_FLAGS)(CKF_HW|CKF_GENERATE);
            break;
        default:
            RETRY_SINGLE_APQN_START(tokdata, rc)
                rc = dll_m_GetMechanismInfo(0, type, pInfo, 
                                            target_info->target);
            RETRY_SINGLE_APQN_END(rc, tokdata, target_info)
            break;
        }

    put_target_info(tokdata, target_info);

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s m_GetMechanismInfo(0x%lx) failed with rc=0x%lx\n",
                    __func__, type, rc);
        return rc;
    }

    /* The card operates always in a FISP mode that requires stronger
     * key sizes, but, in theory, can also operate with weaker key sizes.
     * Customers are not interested in theory but in what mechanism
     * they can use (mechanisms that are not rejected by the card).
     */
#ifdef DEFENSIVE_MECHLIST
    switch (type) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
    case CKM_RSA_X9_31_KEY_PAIR_GEN:
    case CKM_RSA_PKCS_PSS:
    case CKM_RSA_PKCS_OAEP:
    case CKM_SHA1_RSA_X9_31:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_SHA3_256_RSA_PKCS:
    case CKM_SHA3_224_RSA_PKCS:
    case CKM_SHA3_384_RSA_PKCS:
    case CKM_SHA3_512_RSA_PKCS:
    case CKM_RSA_X_509:
    case CKM_RSA_X9_31:
        /* EP11 card always in a FIPS mode rejecting
         * lower key sizes
         */
        pInfo->ulMinKeySize = 1024;
        break;

    case CKM_SHA_1_HMAC:
    case CKM_SHA_1_HMAC_GENERAL:
    case CKM_SHA224_HMAC:
    case CKM_SHA224_HMAC_GENERAL:
    case CKM_SHA256_HMAC:
    case CKM_SHA256_HMAC_GENERAL:
    case CKM_SHA384_HMAC:
    case CKM_SHA384_HMAC_GENERAL:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_HMAC_GENERAL:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_224_HMAC_GENERAL:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA512_256_HMAC_GENERAL:
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        /*
         * Older levels of the EP11 firmware report ulMinKeySize in bytes,
         * but ulMaxKeySize in bits for HMAC mechanisms. Adjust ulMinKeySize
         * so that both are in bits, as required by the PKCS#11 standard.
         * Newer levels of the EP11 firmware report both ulMinKeySize and
         * ulMaxKeySize in bytes. Adjust both, so that both are in bits, as
         * required by the PKCS#11 standard.
         */
        status = check_required_versions(tokdata, hmac_req_versions,
                                         NUM_HMAC_REQ);
        if (status == -1)
            return CKR_MECHANISM_INVALID;

        pInfo->ulMinKeySize *= 8;
        if (status == 1)
            pInfo->ulMaxKeySize *= 8;
        break;

    case CKM_DES3_ECB:
    case CKM_DES3_CBC:
    case CKM_DES3_CBC_PAD:
        /* EP11 card always in a FIPS mode rejecting
         * lower key sizes < 80 bits.
         */
        if (pInfo->ulMinKeySize == 8)
            pInfo->ulMinKeySize = 16;
        break;

    case CKM_SHA1_KEY_DERIVATION:
        pInfo->ulMinKeySize = 8;
        pInfo->ulMaxKeySize = SHA1_HASH_SIZE * 8;
        break;
    case CKM_SHA224_KEY_DERIVATION:
        pInfo->ulMinKeySize = 8;
        pInfo->ulMaxKeySize = SHA224_HASH_SIZE * 8;
        break;
    case CKM_SHA256_KEY_DERIVATION:
        pInfo->ulMinKeySize = 8;
        pInfo->ulMaxKeySize = SHA256_HASH_SIZE * 8;
        break;
    case CKM_SHA384_KEY_DERIVATION:
        pInfo->ulMinKeySize = 8;
        pInfo->ulMaxKeySize = SHA384_HASH_SIZE * 8;
        break;
    case CKM_SHA512_KEY_DERIVATION:
        pInfo->ulMinKeySize = 8;
        pInfo->ulMaxKeySize = SHA512_HASH_SIZE * 8;
        break;
    case CKM_SHA512_224_KEY_DERIVATION:
        pInfo->ulMinKeySize = 8;
        pInfo->ulMaxKeySize = SHA224_HASH_SIZE * 8;
        break;
    case CKM_SHA512_256_KEY_DERIVATION:
        pInfo->ulMinKeySize = 8;
        pInfo->ulMaxKeySize = SHA256_HASH_SIZE * 8;
        break;

    default:
        ; /* do not touch */
    }
#endif                          /* DEFENSIVE_MECHLIST */

    /*
     * EP11 only supports uncompressed EC public keys, but the EP11 token
     * also supports compressed EC public keys, by uncompressing them before
     * passing them to EP11. Thus, for all mechanisms that have the
     * CKF_EC_UNCOMPRESS flag set, also set CKF_EC_COMPRESS.
     */
    if (pInfo->flags & CKF_EC_UNCOMPRESS)
        pInfo->flags |= CKF_EC_COMPRESS;

    return tokdata->policy->update_mech_info(tokdata->policy, type, pInfo);
}

static CK_RV ep11_config_add_apqn(ep11_private_data_t *ep11_data,
                                  struct ConfigNumPairNode *pair,
                                  const char *fname)
{
    if (pair->value1 > 255) {
        OCK_SYSLOG(LOG_ERR, "%s: Error: Expected valid adapter"
                   " number, found '%lu' in config file '%s' at line %d\n",
                   __func__, pair->value1, fname, pair->base.line);
        TRACE_ERROR(" Error: Expected valid adapter number, found '%lu' in "
                    "config file '%s' at line %d\n", pair->value1, fname,
                    pair->base.line);
        return CKR_ARGUMENTS_BAD;
    }

    if (pair->value2 > 255) {
        OCK_SYSLOG(LOG_ERR, "%s: Error: Expected valid domain"
                   " number, found '%lu' in config file '%s' at line %d\n",
                   __func__, pair->value2, fname, pair->base.line);
        TRACE_ERROR(" Error: Expected valid domain number, found '%lu' in "
                    "config file '%s' at line %d\n", pair->value2, fname,
                    pair->base.line);
        return CKR_ARGUMENTS_BAD;
    }

    if (ep11_data->target_list.length >= MAX_APQN) {
        OCK_SYSLOG(LOG_ERR,"%s: Error: Too many APQNs in config "
                   "file '%s' (max %d)\n", __func__, fname, (int) MAX_APQN);
        TRACE_ERROR("Too many APQNs in config file '%s' (max %d)\n",
                    fname, (int) MAX_APQN);
        return CKR_BUFFER_TOO_SMALL;
    }

    ep11_data->target_list.apqns[ep11_data->target_list.length * 2] =
                                                                pair->value1;
    ep11_data->target_list.apqns[ep11_data->target_list.length * 2 + 1] =
                                                                pair->value2;
    ep11_data->target_list.length++;

    return CKR_OK;
}

void ep11_config_parse_error(int line, int col, const char *msg)
{
    OCK_SYSLOG(LOG_ERR, "Error parsing EP11 config file: line %d column %d: %s\n",
               line, col, msg);
    TRACE_ERROR("Error parsing EP11 config file: line %d column %d: %s\n",
                line, col, msg);
}

void ep11_config_error_token(const char *fname, const char *key,
                             int line, const char *expected)
{
    if (expected != NULL) {
        OCK_SYSLOG(LOG_ERR, "Error parsing config file '%s': unexpected token "
                   "'%s' at line %d, expected %s\n", fname,
                   key != NULL ? key : "(none)", line, expected);
        TRACE_ERROR("Error parsing config file '%s': unexpected token "
                "   '%s' at line %d, expected %s\n", fname,
                    key != NULL ? key : "(none)", line, expected);

    } else {
        OCK_SYSLOG(LOG_ERR, "Error parsing config file '%s': "
                   "unexpected token '%s' at line %d\n", fname,
                   key != NULL ? key : "(none)", line);
        TRACE_ERROR("Error parsing config file '%s': unexpected token "
                    "'%s' at line %d\n", fname, key != NULL ? key : "(none)", line);
    }
}

static void ep11_config_error_eof(const char *fname, const char *expected)
{
    if (expected != NULL) {
        OCK_SYSLOG(LOG_ERR, "Error: Unexpected end of file found in config "
                   "file '%s', expected %s\n", fname, expected);
        TRACE_ERROR("Error: Unexpected end of file found in config file '%s', "
                    "expected %s\\n", fname, expected);

    } else {
        OCK_SYSLOG(LOG_ERR, "Error: Unexpected end of file found in config "
                   "file '%s'\n", fname);
        TRACE_ERROR("Error: Unexpected end of file found in config file '%s'\n",
                    fname);
    }
}

CK_RV ep11_config_next(struct ConfigBaseNode **c, unsigned typemask,
                       const char *fname, const char *expected)
{
    *c = (*c)->next;

    if (*c == NULL) {
        ep11_config_error_eof(fname, expected);
        return CKR_FUNCTION_FAILED;
    }

    if (!confignode_hastype(*c, typemask)) {
        ep11_config_error_token(fname, (*c)->key, (*c)->line, expected);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV ep11_config_set_cpfilter(ep11_private_data_t *ep11_data,
                                      const char *fname, const char *strval)
{
    if (strlen(strval) >
        sizeof(ep11_data->cp_filter_config_filename) - 1) {
        TRACE_ERROR("%s CP-Filter config file name is too long: '%s'\n",
                    __func__, strval);
        OCK_SYSLOG(LOG_ERR,
                   "%s: Error: CP-Filter config file name '%s' is "
                   "too long in config file '%s'\n", __func__, strval, fname);
        return CKR_FUNCTION_FAILED;
    }

    strncpy(ep11_data->cp_filter_config_filename, strval,
            sizeof(ep11_data->cp_filter_config_filename) - 1);
    ep11_data->cp_filter_config_filename[
        sizeof(ep11_data->cp_filter_config_filename) - 1] = '\0';

    return CKR_OK;
}

static CK_RV ep11_config_set_pkey_mode(ep11_private_data_t *ep11_data,
                                       const char *fname, const char *strval)
{
    if (strcmp(strval, "DISABLED") == 0)
        ep11_data->pkey_mode = PKEY_MODE_DISABLED;
#ifndef NO_PKEY
    else if (strcmp(strval, "DEFAULT") == 0)
        ep11_data->pkey_mode = PKEY_MODE_DEFAULT;
    else if (strcmp(strval, "ENABLE4NONEXTR") == 0)
        ep11_data->pkey_mode = PKEY_MODE_ENABLE4NONEXTR;
    else if (strcmp(strval, "ENABLE4EXTR") == 0)
        ep11_data->pkey_mode = PKEY_MODE_ENABLE4EXTR;
    else if (strcmp(strval, "ENABLE4ALL") == 0)
        ep11_data->pkey_mode = PKEY_MODE_ENABLE4ALL;
#endif /* NO_PKEY */
    else {
        TRACE_ERROR("%s unsupported PKEY mode : '%s'\n", __func__, strval);
        OCK_SYSLOG(LOG_ERR,"%s: Error: unsupported PKEY mode '%s' "
                   "in config file '%s'\n", __func__, strval, fname);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV ep11_config_set_libica(ep11_private_data_t *ep11_data,
                                    const char *fname, const char *strval)
{
    if (strcmp(strval, "OFF") == 0) {
        ep11_data->digest_libica = 0;
    } else if (strcmp(strval, "DEFAULT") == 0) {
        ep11_data->digest_libica = 1;
        strcpy(ep11_data->digest_libica_path, "");
    } else {
        if (strlen(strval) >
                        sizeof(ep11_data->digest_libica_path)-1) {
            TRACE_ERROR("%s libica path is too long: '%s'\n", __func__, strval);
            OCK_SYSLOG(LOG_ERR,"%s: Error: libica path '%s' is too long"
                       " in config file '%s'\n", __func__, strval, fname);
            return CKR_FUNCTION_FAILED;
        }
        ep11_data->digest_libica = 1;
        strncpy(ep11_data->digest_libica_path, strval,
                sizeof(ep11_data->digest_libica_path)-1);
        ep11_data->digest_libica_path[
                  sizeof(ep11_data->digest_libica_path)-1] = '\0';
    }

    return CKR_OK;
}

static CK_RV ep11_config_set_wkvp(ep11_private_data_t *ep11_data,
                                  const char *fname, const char *strval)
{
    unsigned int i, val;

    if (strncasecmp(strval, "0x", 2) == 0)
        strval += 2;

    if (strlen(strval) < sizeof(ep11_data->expected_wkvp) * 2) {
        TRACE_ERROR("%s expected WKVP is too short: '%s', expected %lu hex "
                    "characters in config file '%s'\n", __func__, strval,
                    sizeof(ep11_data->expected_wkvp) * 2, fname);
        OCK_SYSLOG(LOG_ERR,"%s: Error: expected WKVP is too short: '%s', "
                   "expected %lu hex characters in config file '%s'\n",
                   __func__, strval, sizeof(ep11_data->expected_wkvp) * 2,
                   fname);
        return CKR_FUNCTION_FAILED;
    }

    if (strlen(strval) > sizeof(ep11_data->expected_wkvp) * 2) {
        TRACE_INFO("%s only the first %lu characters of the expected WKVP in "
                   "config file '%s' are used: %s\n", __func__,
                    sizeof(ep11_data->expected_wkvp) * 2, fname, strval);
        OCK_SYSLOG(LOG_INFO,"%s: Info: only the first %lu characters of the "
                   "expected WKVP in config file '%s' are used: %s\n", __func__,
                    sizeof(ep11_data->expected_wkvp) * 2, fname, strval);
    }

    for (i = 0; i < sizeof(ep11_data->expected_wkvp); i++) {
        if (sscanf(strval + (i * 2), "%02x", &val) != 1) {
            TRACE_ERROR("%s failed to parse expected WKVP: '%s' at character "
                        "%u in config file '%s'\n", __func__, strval, (i * 2),
                        fname);
            OCK_SYSLOG(LOG_ERR,"%s: Error: failed to parse expected WKVP: '%s' "
                       "at character %u in config file '%s'\n", __func__,
                       strval, (i * 2), fname);
            return CKR_FUNCTION_FAILED;
        }
        ep11_data->expected_wkvp[i] = val;
    }
    ep11_data->expected_wkvp_set = 1;

    TRACE_DEBUG_DUMP("Expected WKVP:  ", ep11_data->expected_wkvp,
                     sizeof(ep11_data->expected_wkvp));

    return CKR_OK;
}

static CK_RV read_adapter_config_file(STDLL_TokData_t * tokdata,
                                      const char *conf_name)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    FILE *ap_fp = NULL;         /* file pointer adapter config file */
    int i, k;
    int whitemode = 0;
    int anymode = 0;
    /* Since the ep11 token config contains the path to libica that
     * will later be dlopen()ed, we cannot use a token config
     * directory from an untrusted environment.
     */
    char *conf_dir = secure_getenv("OCK_EP11_TOKEN_DIR");
    char fname[PATH_MAX];
    CK_RV rc = CKR_OK;
    char *cfg_dir;
    char cfgname[2*PATH_MAX + 1];
    struct ConfigBaseNode *c, *e, *config = NULL;
    struct ConfigBareConstNode *bare;
    struct ConfigNumPairListNode *list;
    struct ConfigBareStringConstNode *barestr;
    const char *strval;

    if (tokdata->initialized)
        return CKR_OK;

    memset(fname, 0, PATH_MAX);

    /* via environment variable it is possible to overwrite the
     * directory where the ep11 token config file is searched.
     */
    if (conf_dir) {
        if (conf_name && strlen(conf_name) > 0) {
            /* extract filename part from conf_name */
            for (i = strlen(conf_name) - 1; i >= 0 && conf_name[i] != '/'; i--);

            snprintf(fname, sizeof(fname), "%s/%s", conf_dir,
                     conf_name + i + 1);
            fname[sizeof(fname) - 1] = '\0';
            ap_fp = fopen(fname, "r");

            if (!ap_fp)
                TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
                            __func__, fname, errno);
        }
        if (!ap_fp) {
            snprintf(fname, sizeof(fname), "%s/%s", conf_dir,
                     EP11_DEFAULT_CFG_FILE);
            fname[sizeof(fname) - 1] = '\0';
            ap_fp = fopen(fname, "r");
            if (!ap_fp)
                TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
                            __func__, fname, errno);
        }
    } else {
        if (conf_name && strlen(conf_name) > 0) {
            snprintf(fname, sizeof(fname), "%s/%s", OCK_CONFDIR, conf_name);
            fname[sizeof(fname) - 1] = '\0';
            ap_fp = fopen(fname, "r");
            if (!ap_fp)
                TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
                            __func__, fname, errno);
        } else {
            snprintf(fname, sizeof(fname), "%s/%s", OCK_CONFDIR,
                     EP11_DEFAULT_CFG_FILE);
            fname[sizeof(fname) - 1] = '\0';
            ap_fp = fopen(fname, "r");
            if (!ap_fp)
                TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
                            __func__, fname, errno);
        }
    }

    /* now we should really have an open ep11 token config file */
    if (!ap_fp) {
        TRACE_ERROR("%s no valid EP 11 config file found\n", __func__);
        OCK_SYSLOG(LOG_ERR, "%s: Error: EP 11 config file '%s' not found\n",
                   __func__, fname);
        return CKR_FUNCTION_FAILED;
    }

    TRACE_INFO("%s EP 11 token config file is '%s'\n", __func__, fname);

    rc = parse_configlib_file(ap_fp, &config, ep11_config_parse_error, 0);
    fclose(ap_fp);
    if (rc != 0) {
        TRACE_ERROR("Error parsing config file '%s'\n", fname);
        return CKR_FUNCTION_FAILED;
    }

    strncpy(ep11_data->token_config_filename, fname,
            sizeof(ep11_data->token_config_filename));
    ep11_data->token_config_filename[
                    sizeof(ep11_data->token_config_filename) - 1] = '\0';

    ep11_data->target_list.length = 0;
#ifndef NO_PKEY
    ep11_data->pkey_mode = PKEY_MODE_DEFAULT;
#else
    ep11_data->pkey_mode = PKEY_MODE_DISABLED;
#endif

    /* Default to use default libica library for digests */
    ep11_data->digest_libica = 1;
    strcpy(ep11_data->digest_libica_path, "");

    /* Analyse the parsed config elements
     * please note, we still accept the LOGLEVEL entry
     * for compatibility reasons but just ignore it.
     */
    confignode_foreach(c, config, i) {
        TRACE_DEBUG("Config node: '%s' type: %u line: %u\n",
                    c->key, c->type, c->line);

        if (confignode_hastype(c, CT_FILEVERSION)) {
            TRACE_DEBUG("Config file version: '%s'\n",
                        confignode_to_fileversion(c)->base.key);
            continue;
        }

        if (confignode_hastype(c, CT_STRINGVAL) ||
            confignode_hastype(c, CT_BAREVAL)) {
            /* New style (key = value) tokens */
            strval = confignode_getstr(c);

            if (strcmp(c->key, "CPFILTER") == 0) {
                rc = ep11_config_set_cpfilter(ep11_data, fname, strval);
                if (rc != CKR_OK)
                    break;
                continue;
            }

            if (strcmp(c->key, "PKEY_MODE") == 0) {
                rc = ep11_config_set_pkey_mode(ep11_data, fname, strval);
                if (rc != CKR_OK)
                    break;
                continue;
            }

            if (strcmp(c->key, "DIGEST_LIBICA") == 0) {
                rc = ep11_config_set_libica(ep11_data, fname, strval);
                if (rc != CKR_OK)
                    break;
                continue;
            }

            if (strcmp(c->key, "EXPECTED_WKVP") == 0) {
                rc = ep11_config_set_wkvp(ep11_data, fname, strval);
                if (rc != CKR_OK)
                    break;
                continue;
            }
        }

        if (confignode_hastype(c, CT_NUMPAIRLIST)) {
            list = confignode_to_numpairlist(c);

            if ((strcmp(list->base.key, "APQN_WHITELIST") != 0 &&
                 strcmp(list->base.key, "APQN_ALLOWLIST") != 0) ||
                strcmp(list->end, "END") != 0) {
                ep11_config_error_token(fname, list->base.key, list->base.line,
                                        "APQN_ALLOWLIST ... END");
                rc = CKR_FUNCTION_FAILED;
                break;
            }

            whitemode = 1;
            confignode_foreach(e, list->value, k) {
                if (!confignode_hastype(e, CT_NUMPAIR)) {
                    ep11_config_error_token(fname, e->key, e->line,
                                            "pair of NUMBERs");
                    rc = CKR_FUNCTION_FAILED;
                    break;
                }

                rc = ep11_config_add_apqn(ep11_data, confignode_to_numpair(e),
                                          fname);
                if (rc != CKR_OK)
                    break;
            }
            if (rc != CKR_OK)
                break;
            continue;
        }

        if (!confignode_hastype(c, CT_BARECONST)) {
            ep11_config_error_token(fname, c->key, c->line, NULL);
            rc = CKR_FUNCTION_FAILED;
            break;
        }

        bare = confignode_to_bareconst(c);

        if (strcmp(bare->base.key, "APQN_ANY") == 0) {
            anymode = 1;
            continue;
        }

        if (strcmp(bare->base.key, "FORCE_SENSITIVE") == 0) {
            ep11_data->cka_sensitive_default_true = 1;
            continue;
        }

        if (strcmp(bare->base.key, "CPFILTER") == 0) {
            rc = ep11_config_next(&c, CT_BARECONST | CT_BARESTRINGCONST, fname,
                                 "CP-Filter config file name");
            if (rc != CKR_OK)
                break;

            if (confignode_hastype(c, CT_BARECONST))
                strval = confignode_to_bareconst(c)->base.key;
            else
                strval = confignode_to_barestringconst(c)->base.key;

            rc = ep11_config_set_cpfilter(ep11_data, fname,strval);
            if (rc != CKR_OK)
                break;
            continue;
        }

        if (strcmp(bare->base.key, "STRICT_MODE") == 0) {
            ep11_data->strict_mode = 1;
            continue;
        }

        if (strcmp(bare->base.key, "VHSM_MODE") == 0) {
            ep11_data->vhsm_mode = 1;
            continue;
        }

        if (strcmp(bare->base.key, "FIPS_SESSION_MODE") == 0) {
            ep11_data->fips_session_mode = 1;
            continue;
        }

        if (strcmp(bare->base.key, "OPTIMIZE_SINGLE_PART_OPERATIONS") == 0) {
            ep11_data->optimize_single_ops = 1;
            continue;
        }

        if (strcmp(bare->base.key, "PKEY_MODE") == 0) {
            rc = ep11_config_next(&c, CT_BARECONST, fname, "PKEY mode");
            if (rc != CKR_OK)
                break;

            rc = ep11_config_set_pkey_mode(ep11_data, fname,
                                       confignode_to_bareconst(c)->base.key);
            if (rc != CKR_OK)
                break;
            continue;
        }

        if (strcmp(bare->base.key, "DIGEST_LIBICA") == 0) {
            rc = ep11_config_next(&c, CT_BARECONST | CT_BARESTRINGCONST, fname,
                                  "libica path, 'DEFAULT', or 'OFF'");
            if (rc != CKR_OK)
                break;

            if (confignode_hastype(c, CT_BARECONST))
                strval = confignode_to_bareconst(c)->base.key;
            else
                strval = confignode_to_barestringconst(c)->base.key;

            rc = ep11_config_set_libica(ep11_data, fname,strval);
            if (rc != CKR_OK)
                break;
            continue;
        }

        if (strcmp(bare->base.key, "USE_PRANDOM") == 0) {
            token_specific.t_rng = NULL;
            continue;
        }

        if (strcmp(bare->base.key, "EXPECTED_WKVP") == 0) {
            rc = ep11_config_next(&c, CT_BARESTRINGCONST, fname,
                                  "WKID as quoted hex string");
            if (rc != CKR_OK)
                break;
            barestr = confignode_to_barestringconst(c);

            rc = ep11_config_set_wkvp(ep11_data, fname, barestr->base.key);
            if (rc != CKR_OK)
                break;
            continue;
        }

        ep11_config_error_token(fname, c->key, c->line, NULL);
        rc = CKR_FUNCTION_FAILED;
        break;
    }

    confignode_deepfree(config);

    if (rc != CKR_OK)
        return rc;

    /* do some checks: */
    if (ep11_data->fips_session_mode &&
        (ep11_data->strict_mode || ep11_data->vhsm_mode)) {
        TRACE_ERROR("%s FIPS_SESSION_MODE can not be enabled together with "
                    "STRICT_MODE or VHSM_MODE\n", __func__);
        OCK_SYSLOG(LOG_ERR, "%s: FIPS_SESSION_MODE can not be enabled together "
                   "with STRICT_MODE or VHSM_MODE in config file '%s'\n",
                   __func__, fname);
        return CKR_FUNCTION_FAILED;
    }

    if (!(whitemode || anymode)) {
        TRACE_ERROR("%s At least one APQN mode needs to be present in "
                    "config file: APQN_ALLOWLIST or APQN_ANY\n", __func__);
        OCK_SYSLOG(LOG_ERR,
                   "%s: Error: At least one APQN mode needs to be present "
                   " in config file '%s': APQN_ALLOWLIST or APQN_ANY\n",
                   __func__, fname);
        return CKR_FUNCTION_FAILED;
    } else if (whitemode && anymode) {
        TRACE_ERROR("%s Only one APQN mode can be present in config file:"
                    " APQN_ALLOWLIST or APQN_ANY\n", __func__);
        OCK_SYSLOG(LOG_ERR,
                   "%s: Error: Only one APQN mode can be present in"
                   " config file '%s': APQN_ALLOWLIST or APQN_ANY\n",
                   __func__, fname);
        return CKR_FUNCTION_FAILED;
    } else if (whitemode) {
        /* at least one APQN needs to be defined */
        if (ep11_data->target_list.length < 1) {
            TRACE_ERROR("%s At least one APQN needs to be defined in the "
                        "config file\n", __func__);
            OCK_SYSLOG(LOG_ERR,
                       "%s: Error: At least one APQN needs to be defined in"
                       " config file '%s'\n", __func__, fname);
            return CKR_FUNCTION_FAILED;
        }
    }

    /* log the whitelist of APQNs */
    if (whitemode) {
        TRACE_INFO("%s whitelist with %d APQNs defined:\n",
                   __func__, ep11_data->target_list.length);
        for (i = 0; i < ep11_data->target_list.length; i++) {
            TRACE_INFO(" APQN entry %d: adapter=%d domain=%d\n", i,
                       ep11_data->target_list.apqns[2 * i],
                       ep11_data->target_list.apqns[2 * i + 1]);
        }
    }

    /* read CP-filter config file */
    cfg_dir = dirname(fname);
    if (strlen(ep11_data->cp_filter_config_filename) == 0) {
        snprintf(ep11_data->cp_filter_config_filename,
                 sizeof(ep11_data->cp_filter_config_filename) - 1,
                 "%s/%s", cfg_dir, EP11_DEFAULT_CPFILTER_FILE);
        ep11_data->cp_filter_config_filename[
            sizeof(ep11_data->cp_filter_config_filename) - 1] = '\0';
    }

    if (strchr(ep11_data->cp_filter_config_filename, '/') == NULL) {
        cfgname[0] = '\0';

        if (strlen(cfg_dir) + 1 + strlen(ep11_data->cp_filter_config_filename)
                                                    <= sizeof(cfgname) - 1) {
            strcpy(cfgname, cfg_dir);
            cfgname[strlen(cfg_dir)] = '/';
            strcpy(cfgname + strlen(cfg_dir) + 1,
                   ep11_data->cp_filter_config_filename);
        }
        if (strlen(cfgname) < sizeof(ep11_data->cp_filter_config_filename))
            strcpy(ep11_data->cp_filter_config_filename, cfgname);
        ep11_data->cp_filter_config_filename[
            sizeof(ep11_data->cp_filter_config_filename) - 1] = '\0';
    }

    rc = read_cp_filter_config_file(tokdata,
                                    ep11_data->cp_filter_config_filename,
                                    &ep11_data->cp_config);
    return rc;
}

static CK_RV read_cp_filter_config_file(STDLL_TokData_t *tokdata,
                                        const char *conf_name,
                                        cp_config_t ** cp_config)
{
    CK_RV rc = CKR_OK;
    FILE *fp = NULL;
    char line[1024];
    char *tok;
    unsigned long int val;
    char *endp;
    cp_config_t *cp;
    cp_config_t *last_cp = NULL;
    cp_mech_config_t *mech;
    cp_mech_config_t *last_mech;

    TRACE_INFO("%s EP 11 CP-filter config file is '%s'\n", __func__, conf_name);

    fp = fopen(conf_name, "r");
    if (fp == NULL) {
        TRACE_ERROR("%s no valid EP 11 CP-filter config file found\n",
                    __func__);
        OCK_SYSLOG(LOG_WARNING,
                   "%s: Warning: EP 11 CP-filter config file '%s'"
                   " does not exist, no filtering will be used\n", __func__,
                   conf_name);
        /* this is not an error condition. When no CP-filter file is available,
         * then the mechanisms are not filtered. */
        return CKR_OK;
    }

    while (fgets((char *) line, sizeof(line), fp)) {
        tok = strtok(line, ": \t\n");

        if (tok == NULL)
            continue;
        if (*tok == '#')
            continue;

        val = strtoul(tok, &endp, 0);
        if (*endp != '\0') {
            val = ep11_get_cp_by_name(tok);
            if (val == UNKNOWN_CP) {
                TRACE_ERROR("%s Syntax error in EP 11 CP-filter config file "
                            "found. \n", __func__);
                OCK_SYSLOG(LOG_ERR,
                           "%s: Error: Expected valid control point name or "
                           "number, found '%s' in CP-filter config file '%s'\n",
                           __func__, tok, conf_name);
                rc = CKR_FUNCTION_FAILED;
                goto out_fclose;
            }
        }

        cp = (cp_config_t *) malloc(sizeof(cp_config_t));
        if (cp == NULL) {
            TRACE_ERROR("%s Out of memory.\n", __func__);
            rc = CKR_HOST_MEMORY;
            goto out_fclose;
        }
        cp->cp = val;
        cp->mech = NULL;
        cp->next = NULL;

        last_mech = NULL;
        while ((tok = strtok(NULL, ", \t\n")) != NULL) {
            if (*tok == '#')
                break;

            val = strtoul(tok, &endp, 0);
            if (*endp != '\0') {
                val = ep11_get_mechanisms_by_name(tokdata, tok);
                if (val == UNKNOWN_MECHANISM) {
                    TRACE_ERROR("%s Syntax error in EP 11 CP-filter config file"
                                " found. \n", __func__);
                    OCK_SYSLOG(LOG_ERR,
                               "%s: Error: Expected valid mechanism name or "
                               "number, found '%s' in CP-filter config file "
                               "'%s'\n", __func__, tok, conf_name);
                    rc = CKR_FUNCTION_FAILED;
                    free_cp_config(cp);
                    goto out_fclose;
                }
            }

            mech = (cp_mech_config_t *) malloc(sizeof(cp_mech_config_t));
            if (mech == NULL) {
                TRACE_ERROR("%s Out of memory.\n", __func__);
                OCK_SYSLOG(LOG_ERR, "%s: Error: Out of memory while parsing the"
                           " CP-filter config file '%s'\n",
                           __func__, conf_name);
                rc = CKR_HOST_MEMORY;
                free_cp_config(cp);
                goto out_fclose;
            }
            mech->mech = val;
            mech->next = NULL;

            if (last_mech == NULL)
                cp->mech = mech;
            else
                last_mech->next = mech;
            last_mech = mech;
        }

        if (cp->mech == NULL) {
            /* empty CP, skip this one */
            free(cp);
            continue;
        }

        if (last_cp == NULL)
            *cp_config = cp;
        else
            last_cp->next = cp;
        last_cp = cp;
    }

#ifdef DEBUG
    /* print CP filter config */
    TRACE_INFO("%s CP-Filter defined:\n", __func__);
    cp = *cp_config;
    while (cp != NULL) {
        TRACE_INFO("  CP %lu (%s):\n", cp->cp, ep11_get_cp(cp->cp));
        mech = cp->mech;
        while (mech != NULL) {
            TRACE_INFO("    Mechanism 0x%08lx (%s)\n", mech->mech,
                       ep11_get_ckm(tokdata, mech->mech));
            mech = mech->next;
        }
        cp = cp->next;
    }
#endif

out_fclose:
    fclose(fp);
    return rc;
}

static void free_cp_config(cp_config_t * cp)
{
    cp_config_t *next_cp = cp;
    cp_mech_config_t *mech;
    cp_mech_config_t *next_mech;

    TRACE_INFO("%s running\n", __func__);

    while (cp != NULL) {
        mech = cp->mech;
        while (mech != NULL) {
            next_mech = mech->next;
            free(mech);
            mech = next_mech;
        }

        next_cp = cp->next;
        free(cp);
        cp = next_cp;
    }
}

static const_info_t ep11_cps[] = {
    CONSTINFO(XCP_CPB_ADD_CPBS),
    CONSTINFO(XCP_CPB_DELETE_CPBS),
    CONSTINFO(XCP_CPB_SIGN_ASYMM),
    CONSTINFO(XCP_CPB_SIGN_SYMM),
    CONSTINFO(XCP_CPB_SIGVERIFY_SYMM),
    CONSTINFO(XCP_CPB_ENCRYPT_SYMM),
    CONSTINFO(XCP_CPB_DECRYPT_ASYMM),
    CONSTINFO(XCP_CPB_DECRYPT_SYMM),
    CONSTINFO(XCP_CPB_WRAP_ASYMM),
    CONSTINFO(XCP_CPB_WRAP_SYMM),
    CONSTINFO(XCP_CPB_UNWRAP_ASYMM),
    CONSTINFO(XCP_CPB_UNWRAP_SYMM),
    CONSTINFO(XCP_CPB_KEYGEN_ASYMM),
    CONSTINFO(XCP_CPB_KEYGEN_SYMM),
    CONSTINFO(XCP_CPB_RETAINKEYS),
    CONSTINFO(XCP_CPB_SKIP_KEYTESTS),
    CONSTINFO(XCP_CPB_NON_ATTRBOUND),
    CONSTINFO(XCP_CPB_MODIFY_OBJECTS),
    CONSTINFO(XCP_CPB_RNG_SEED),
    CONSTINFO(XCP_CPB_ALG_RAW_RSA),
    CONSTINFO(XCP_CPB_ALG_NFIPS2009),
    CONSTINFO(XCP_CPB_ALG_NBSI2009),
    CONSTINFO(XCP_CPB_KEYSZ_HMAC_ANY),
    CONSTINFO(XCP_CPB_KEYSZ_BELOW80BIT),
    CONSTINFO(XCP_CPB_KEYSZ_80BIT),
    CONSTINFO(XCP_CPB_KEYSZ_112BIT),
    CONSTINFO(XCP_CPB_KEYSZ_128BIT),
    CONSTINFO(XCP_CPB_KEYSZ_192BIT),
    CONSTINFO(XCP_CPB_KEYSZ_256BIT),
    CONSTINFO(XCP_CPB_KEYSZ_RSA65536),
    CONSTINFO(XCP_CPB_ALG_RSA),
    CONSTINFO(XCP_CPB_ALG_DSA),
    CONSTINFO(XCP_CPB_ALG_EC),
    CONSTINFO(XCP_CPB_ALG_EC_BPOOLCRV),
    CONSTINFO(XCP_CPB_ALG_EC_NISTCRV),
    CONSTINFO(XCP_CPB_ALG_NFIPS2011),
    CONSTINFO(XCP_CPB_ALG_NBSI2011),
    CONSTINFO(XCP_CPB_USER_SET_TRUSTED),
    CONSTINFO(XCP_CPB_ALG_SKIP_CROSSCHK),
    CONSTINFO(XCP_CPB_WRAP_CRYPT_KEYS),
    CONSTINFO(XCP_CPB_SIGN_CRYPT_KEYS),
    CONSTINFO(XCP_CPB_WRAP_SIGN_KEYS),
    CONSTINFO(XCP_CPB_USER_SET_ATTRBOUND),
    CONSTINFO(XCP_CPB_ALLOW_PASSPHRASE),
    CONSTINFO(XCP_CPB_WRAP_STRONGER_KEY),
    CONSTINFO(XCP_CPB_WRAP_WITH_RAW_SPKI),
    CONSTINFO(XCP_CPB_ALG_DH),
    CONSTINFO(XCP_CPB_DERIVE),
    CONSTINFO(XCP_CPB_ALLOW_NONSESSION),
    CONSTINFO(XCP_CPB_ALG_EC_25519),
    CONSTINFO(XCP_CPB_ALG_EC_SECGCRV),
    CONSTINFO(XCP_CPB_ALG_NBSI2017),
    CONSTINFO(XCP_CPB_CPACF_PK),
    CONSTINFO(XCP_CPB_ALG_PQC_DILITHIUM),
    CONSTINFO(XCP_CPB_ALG_PQC),
    CONSTINFO(XCP_CPB_BTC),
    CONSTINFO(XCP_CPB_ECDSA_OTHER),
    CONSTINFO(XCP_CPB_ALG_NFIPS2021),
    CONSTINFO(XCP_CPB_ALG_NFIPS2024),
    CONSTINFO(XCP_CPB_COMPAT_LEGACY_SHA3),
    CONSTINFO(XCP_CPB_DSA_PARAMETER_GEN),
    CONSTINFO(XCP_CPB_DERIVE_NON_AB_KEYS),
    CONSTINFO(XCP_CPB_ALLOW_LOGIN_PRE_F2021),
    CONSTINFO(XCP_CPB_ALG_RSA_OAEP),
    CONSTINFO(XCP_CPB_ALLOW_COMBINED_EXTRACT),
    CONSTINFO(XCP_CPB_ALG_EC_PAIRING_FRIENDLY),
};

#ifdef DEBUG
static const char *ep11_get_cp(unsigned int cp)
{
    unsigned int i;

    for (i = 0; i < (sizeof(ep11_cps) / sizeof(ep11_cps[0])); i++) {
        if (ep11_cps[i].code == cp)
            return ep11_cps[i].name;
    }

    TRACE_WARNING("%s unknown control point %u\n", __func__, cp);
    return "UNKNOWN";
}
#endif

static CK_ULONG ep11_get_cp_by_name(const char *name)
{
    unsigned int i;

    for (i = 0; i < (sizeof(ep11_cps) / sizeof(ep11_cps[0])); i++) {
        if (strcmp(ep11_cps[i].name, name) == 0)
            return ep11_cps[i].code;
    }

    TRACE_WARNING("%s unknown control point name '%s'\n", __func__, name);
    return UNKNOWN_CP;
}

static CK_RV check_cps_for_mechanism(STDLL_TokData_t *tokdata,
                                     cp_config_t * cp_config,
                                     CK_MECHANISM_TYPE mech,
                                     unsigned char *cp, size_t cp_len,
                                     size_t max_cp_index)
{
    UNUSED(tokdata);
    cp_config_t *cp_cfg = cp_config;
    cp_mech_config_t *mech_cfg;

    TRACE_DEBUG("%s Check mechanism 0x%08lx ('%s')\n", __func__, mech,
                ep11_get_ckm(tokdata, mech));

    while (cp_cfg != NULL) {
        if (CP_BYTE_NO(cp_cfg->cp) < cp_len &&
            cp_cfg->cp <= max_cp_index &&
            (cp[CP_BYTE_NO(cp_cfg->cp)] & CP_BIT_MASK(cp_cfg->cp)) == 0) {
            /* CP is off, check if the current mechanism is
             * associated with it */
            mech_cfg = cp_cfg->mech;
            while (mech_cfg != NULL) {
                if (mech_cfg->mech == mech) {
                    TRACE_DEBUG("%s mechanism 0x%08lx ('%s') not enabled\n",
                                __func__, mech, ep11_get_ckm(tokdata, mech));
                    return CKR_MECHANISM_INVALID;
                }
                mech_cfg = mech_cfg->next;
            }
        }
        cp_cfg = cp_cfg->next;
    }

    return CKR_OK;
}

static CK_RV file_fgets(const char *fname, char *buf, size_t buflen)
{
    FILE *fp;
    char *end;
    CK_RV rc = CKR_OK;

    buf[0] = '\0';

    fp = fopen(fname, "r");
    if (fp == NULL) {
        TRACE_ERROR("Failed to open file '%s'\n", fname);
        return CKR_FUNCTION_FAILED;
    }
    if (fgets(buf, buflen, fp) == NULL) {
        TRACE_ERROR("Failed to read from file '%s'\n", fname);
        rc = CKR_FUNCTION_FAILED;
        goto out_fclose;
    }

    end = memchr(buf, '\n', buflen);
    if (end)
        *end = 0;
    else
        buf[buflen - 1] = 0;

    if (strlen(buf) == 0) {
        rc = CKR_FUNCTION_FAILED;
        goto out_fclose;
    }

out_fclose:
    fclose(fp);
    return rc;
}

CK_BBOOL is_apqn_online(uint_32 card, uint_32 domain)
{
    char fname[290];
    char buf[250];
    CK_RV rc;

#ifdef EP11_HSMSIM
    return CK_TRUE;
#endif

    sprintf(fname, "%s/card%02x/%02x.%04x/online", SYSFS_DEVICES_AP,
            card, card, domain);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc != CKR_OK)
        return CK_FALSE;
    if (strcmp(buf, "1") != 0)
        return CK_FALSE;

    sprintf(fname, "%s/card%02x/%02x.%04x/config", SYSFS_DEVICES_AP,
            card, card, domain);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc == CKR_OK && strcmp(buf, "1") != 0)
        return CK_FALSE;

    sprintf(fname, "%s/card%02x/%02x.%04x/chkstop", SYSFS_DEVICES_AP,
            card, card, domain);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc == CKR_OK && strcmp(buf, "0") != 0)
        return CK_FALSE;

    return CK_TRUE;
}

static CK_RV is_card_ep11_and_online(const char *name)
{
    char fname[290];
    char buf[250];
    CK_RV rc;
    unsigned long val;

#ifdef EP11_HSMSIM
    return CKR_OK;
#endif

    sprintf(fname, "%s%s/online", SYSFS_DEVICES_AP, name);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc != CKR_OK)
        return rc;
    if (strcmp(buf, "1") != 0)
        return CKR_FUNCTION_FAILED;

    sprintf(fname, "%s%s/config", SYSFS_DEVICES_AP, name);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc == CKR_OK && strcmp(buf, "1") != 0)
        return CKR_FUNCTION_FAILED;

    sprintf(fname, "%s%s/chkstop", SYSFS_DEVICES_AP, name);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc == CKR_OK && strcmp(buf, "0") != 0)
        return CKR_FUNCTION_FAILED;

    sprintf(fname, "%s%s/ap_functions", SYSFS_DEVICES_AP, name);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc != CKR_OK)
        return rc;
    if (sscanf(buf, "%lx", &val) != 1)
        val = 0x00000000;
    if ((val & MASK_EP11) == 0)
        return CKR_FUNCTION_FAILED;

    return CKR_OK;
}

static CK_RV scan_for_card_domains(const char *name, adapter_handler_t handler,
                                   void *handler_data)
{
    char fname[290];
    regex_t reg_buf;
    regmatch_t pmatch[1];
    DIR *d;
    struct dirent *de;
    char *tok;
    uint_32 adapter, domain;

#ifdef EP11_HSMSIM
    return handler(0, 0, handler_data);
#endif

    if (regcomp(&reg_buf, REGEX_SUB_CARD_PATTERN, REG_EXTENDED) != 0) {
        TRACE_ERROR("Failed to compile regular expression '%s'\n",
                    REGEX_SUB_CARD_PATTERN);
        return CKR_FUNCTION_FAILED;
    }

    sprintf(fname, "%s%s/", SYSFS_DEVICES_AP, name);
    d = opendir(fname);
    if (d == NULL) {
        TRACE_ERROR("Directory %s is not available\n", fname);
        regfree(&reg_buf);
        // ignore this error, card may have been removed in the meantime
        return CKR_OK;
    }

    while ((de = readdir(d)) != NULL) {
        if (regexec(&reg_buf, de->d_name, (size_t) 1, pmatch, 0) == 0) {
            tok = strtok(de->d_name, ".");
            if (tok == NULL)
                continue;
            if (sscanf(tok, "%x", &adapter) != 1)
                continue;

            tok = strtok(NULL, ",");
            if (tok == NULL)
                continue;
            if (sscanf(tok, "%x", &domain) != 1)
                continue;

            if (handler(adapter, domain, handler_data) != CKR_OK)
                break;
        }
    }

    closedir(d);
    regfree(&reg_buf);
    return CKR_OK;
}

/*
 * Iterate over all cards in the sysfs directorys /sys/device/ap/cardxxx
 * and check if the card is online. Calls the handler function for all
 * online EP11 cards.
 */
static CK_RV scan_for_ep11_cards(adapter_handler_t handler, void *handler_data)
{
    DIR *d;
    struct dirent *de;
    regex_t reg_buf;
    regmatch_t pmatch[1];

    if (handler == NULL)
        return CKR_ARGUMENTS_BAD;

#ifdef EP11_HSMSIM
    return handler(0, 0, handler_data);
#endif

    if (regcomp(&reg_buf, REGEX_CARD_PATTERN, REG_EXTENDED) != 0) {
        TRACE_ERROR("Failed to compile regular expression '%s'\n",
                    REGEX_CARD_PATTERN);
        return CKR_FUNCTION_FAILED;
    }

    d = opendir(SYSFS_DEVICES_AP);
    if (d == NULL) {
        TRACE_ERROR("Directory %s is not available\n", SYSFS_DEVICES_AP);
        regfree(&reg_buf);
        return CKR_FUNCTION_FAILED;
    }

    while ((de = readdir(d)) != NULL) {
        if (regexec(&reg_buf, de->d_name, (size_t) 1, pmatch, 0) == 0) {
            if (is_card_ep11_and_online(de->d_name) != CKR_OK)
                continue;

            if (scan_for_card_domains(de->d_name, handler, handler_data) !=
                CKR_OK)
                break;
        }
    }

    closedir(d);
    regfree(&reg_buf);
    return CKR_OK;
}

CK_RV handle_all_ep11_cards(ep11_target_t * ep11_targets,
                            adapter_handler_t handler, void *handler_data)
{
    int i;
    CK_RV rc;

    if (ep11_targets->length > 0) {
        /* APQN_WHITELIST or APQN_ALLOWLIST is specified */
        for (i = 0; i < ep11_targets->length; i++) {
            rc = handler(ep11_targets->apqns[2 * i],
                         ep11_targets->apqns[2 * i + 1], handler_data);
            if (rc != CKR_OK)
                return rc;
        }
    } else {
        /* APQN_ANY used, scan sysfs for available cards */
        return scan_for_ep11_cards(handler, handler_data);
    }

    return CKR_OK;
}

static CK_RV get_control_points_for_adapter(uint_32 adapter, uint_32 domain,
                                            unsigned char *cp, size_t * cp_len,
                                            size_t *max_cp_index)
{
    unsigned char rsp[200];
    unsigned char cmd[100];
    struct XCPadmresp rb;
    size_t rlen, clen;
    CK_RV rc = 0;
    long len;
    target_t target;
    CK_IBM_XCP_INFO xcp_info;
    CK_ULONG xcp_info_len = sizeof(xcp_info);

    rc = get_ep11_target_for_apqn(adapter, domain, &target, 0);
    if (rc != CKR_OK)
        return rc;

    memset(cmd, 0, sizeof(cmd));
    len = dll_xcpa_queryblock(cmd, sizeof(cmd), XCP_ADMQ_DOM_CTRLPOINTS,
                             (uint64_t) adapter << 32 | domain, NULL, 0);
    if (len < 0) {
        TRACE_ERROR("%s xcpa_queryblock failed: rc=%ld\n", __func__, len);
        rc = CKR_DEVICE_ERROR;
        goto out;
    }
    clen = len;

    memset(rsp, 0, sizeof(rsp));
    rlen = sizeof(rsp);
    rc = dll_m_admin(rsp, &rlen, NULL, NULL, cmd, clen, NULL, 0, target);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s m_admin rc=%ld\n", __func__, rc);
        goto out;
    }

    memset(&rb, 0, sizeof(rb));
    len = dll_xcpa_internal_rv(rsp, rlen, &rb, &rc);
    if (len < 0 || rc != 0) {
        TRACE_ERROR("%s xcpa_internal_rv failed: rc=%ld len=%ld\n",
                    __func__, rc, len);
        rc = CKR_DEVICE_ERROR;
        goto out;
    }

    if (*cp_len < rb.pllen) {
        TRACE_ERROR("%s Cp_len is too small. cp_len=%lu required=%lu\n",
                    __func__, *cp_len, rb.pllen);
        *cp_len = rb.pllen;
        rc = CKR_ARGUMENTS_BAD;
        goto out;
    }

    memcpy(cp, rb.payload, rb.pllen);
    *cp_len = rb.pllen;

    rc = dll_m_get_xcp_info(&xcp_info, &xcp_info_len, CK_IBM_XCPQ_MODULE, 0,
                            target);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to query xcp info from adapter %02X.%04X\n",
                    __func__, adapter, domain);
        rc = CKR_DEVICE_ERROR;
        goto out;
    }

    *max_cp_index = xcp_info.controlPoints;

out:
    free_ep11_target_for_apqn(target);
    return rc;
}

typedef struct cp_handler_data {
    STDLL_TokData_t *tokdata;
    unsigned char combined_cp[XCP_CP_BYTES];
    unsigned char first_cp[XCP_CP_BYTES];
    uint32_t first_adapter;
    uint32_t first_domain;
    int first;
    size_t max_cp_index;
    CK_BBOOL error;
    CK_BBOOL allow_combined_extract;
} cp_handler_data_t;

static CK_RV control_point_handler(uint_32 adapter, uint_32 domain,
                                   void *handler_data)
{
    CK_RV rc;
    cp_handler_data_t *data = (cp_handler_data_t *) handler_data;
    ep11_private_data_t *ep11_data = data->tokdata->private_data;
    unsigned char cp[XCP_CP_BYTES];
    size_t cp_len = sizeof(cp);
    size_t max_cp_index;
    CK_ULONG i;

    TRACE_INFO("Getting control points for adapter %02X.%04X\n", adapter,
               domain);

    memset(cp, 0, sizeof(cp));
    rc = get_control_points_for_adapter(adapter, domain, cp, &cp_len,
                                        &max_cp_index);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to get CPS from adapter %02X.%04X\n",
                    __func__, adapter, domain);
        // card may no longer be online, so ignore this error situation
        return CKR_OK;
    }
#ifdef DEBUG
    TRACE_DEBUG("Control points from adapter %02X.%04X\n", adapter, domain);
    TRACE_DEBUG_DUMP("    ", cp, cp_len);
    TRACE_DEBUG("Max control point index: %lu\n", max_cp_index);
#endif

    if (data->first) {
        data->first_adapter = adapter;
        data->first_domain = domain;
        /* Apply CP bits 0 to max_cp_index only */
        for (i = 0; i <= max_cp_index; i++) {
            data->combined_cp[CP_BYTE_NO(i)] &=
                                    (cp[CP_BYTE_NO(i)] | ~CP_BIT_MASK(i));
        }
        memcpy(data->first_cp, data->combined_cp, sizeof(data->first_cp));
        data->max_cp_index = max_cp_index;
        data->first = 0;
    } else {
        // check if subsequent adapters have the same CPs
        if (memcmp(cp, data->first_cp, sizeof(cp)) != 0) {
            TRACE_WARNING("%s Adapter %02X.%04X has different control points "
                          "than adapter %02X.%04X, using minimum.\n",
                          __func__, adapter, domain, data->first_adapter,
                          data->first_domain);
            OCK_SYSLOG(LOG_WARNING,
                       "Warning: Adapter %02X.%04X has different control points"
                       " than adapter %02X.%04X, using minimum\n",
                       adapter, domain, data->first_adapter,
                       data->first_domain);
        }

        for (i = 0; i <= max_cp_index; i++) {
            /* Apply CP bits 0 to max_cp_index only */
            data->combined_cp[CP_BYTE_NO(i)] &=
                                    (cp[CP_BYTE_NO(i)] | ~CP_BIT_MASK(i));
        }

        if (max_cp_index != data->max_cp_index) {
            TRACE_WARNING("%s Adapter %02X.%04X has a different number of "
                          "control points than adapter %02X.%04X, using "
                          "maximum.\n", __func__, adapter, domain,
                          data->first_adapter, data->first_domain);
            OCK_SYSLOG(LOG_WARNING,
                       "Warning: Adapter %02X.%04X has a different number of "
                       "control points than adapter %02X.%04X, using maximum\n",
                       adapter, domain, data->first_adapter,
                       data->first_domain);

            data->max_cp_index = MAX(max_cp_index, data->max_cp_index);
        }
    }

    /* Combined extract is only supported if all APQNs support it */
    if (max_cp_index < XCP_CPB_ALLOW_COMBINED_EXTRACT ||
        (cp[CP_BYTE_NO(XCP_CPB_ALLOW_COMBINED_EXTRACT)] &
         CP_BIT_MASK(XCP_CPB_ALLOW_COMBINED_EXTRACT)) == 0) {
        data->allow_combined_extract = CK_FALSE;

        if (ep11_data->pkey_mode == PKEY_MODE_ENABLE4EXTR ||
            ep11_data->pkey_mode == PKEY_MODE_ENABLE4ALL) {
            TRACE_ERROR("Control point setting for adapter %02X.%04X does not "
                        "allow combined extract, but PKEY_MODE ENABLE4EXTR or "
                        "ENABLE4ALL specified in ep11 token config file.\n",
                        adapter, domain);
            OCK_SYSLOG(LOG_ERR,
                        "Control point setting for adapter %02X.%04X does not "
                        "allow combined extract, but PKEY_MODE ENABLE4EXTR or "
                        "ENABLE4ALL specified in ep11 token config file.\n",
                        adapter, domain);
            data->error = TRUE;
        }
    }

    /* Check FIPS-session related CPs for non-FIPS-session mode */
    if (!ep11_data->fips_session_mode) {
        if (max_cp_index >= XCP_CPB_ALLOW_NONSESSION &&
            (cp[CP_BYTE_NO(XCP_CPB_ALLOW_NONSESSION)] &
                                CP_BIT_MASK(XCP_CPB_ALLOW_NONSESSION)) == 0) {
            TRACE_WARNING("%s Adapter %02X.%04X has control point "
                          "XCP_CPB_ALLOW_NONSESSION off, but FIPS-session mode "
                          "is not enabled\n", __func__, adapter, domain);
            OCK_SYSLOG(LOG_ERR,
                       "Adapter %02X.%04X has control point "
                       "XCP_CPB_ALLOW_NONSESSION off, but FIPS-session mode "
                       "is not enabled\n", adapter, domain);
            data->error = TRUE;
        }

        if (max_cp_index >= XCP_CPB_ALLOW_LOGIN_PRE_F2021 &&
            (cp[CP_BYTE_NO(XCP_CPB_ALLOW_LOGIN_PRE_F2021)] &
                            CP_BIT_MASK(XCP_CPB_ALLOW_LOGIN_PRE_F2021)) == 0) {
            TRACE_WARNING("%s Adapter %02X.%04X has control point "
                          "XCP_CPB_ALLOW_LOGIN_PRE_F2021 off, but FIPS-session "
                          "mode is not enabled\n", __func__, adapter, domain);
            OCK_SYSLOG(LOG_ERR,
                       "Adapter %02X.%04X has control point "
                       "XCP_CPB_ALLOW_LOGIN_PRE_F2021 off, but FIPS-session "
                       "mode is not enabled\n", adapter, domain);
            data->error = TRUE;
        }
    }

    return CKR_OK;
}

#ifdef DEBUG
static void print_control_points(unsigned char *cp, size_t cp_len,
                                 size_t max_cp_index)
{
    unsigned int i;

    for (i = 0; i <= max_cp_index && CP_BYTE_NO(i) < cp_len; i++) {
        if ((cp[CP_BYTE_NO(i)] & CP_BIT_MASK(i)) == 0)
            TRACE_INFO("CP %u (%s) is off\n", i, ep11_get_cp(i));
        else
            TRACE_INFO("CP %u (%s) is on\n", i, ep11_get_cp(i));
    }
}
#endif

static CK_RV get_control_points(STDLL_TokData_t * tokdata,
                                unsigned char *cp, size_t * cp_len,
                                size_t *max_cp_index)
{
    CK_RV rc;
    cp_handler_data_t data;
    ep11_private_data_t *ep11_data = tokdata->private_data;

    memset(&data, 0, sizeof(data));
    data.tokdata = tokdata;

    /*
     * Turn all CPs ON by default, so that newer control points that are unknown
     * to older cards default to ON. CPs being OFF disable functionality.
     */
    memset(data.combined_cp, 0xff, sizeof(data.combined_cp));
    data.allow_combined_extract = CK_TRUE;
    data.first = 1;
    rc = handle_all_ep11_cards(&ep11_data->target_list, control_point_handler,
                               &data);
    if (rc != CKR_OK)
        return rc;

    *cp_len = MIN(*cp_len, sizeof(data.combined_cp));
    memcpy(cp, data.combined_cp, *cp_len);
    *max_cp_index = data.max_cp_index;

#ifdef DEBUG
    TRACE_DEBUG("Combined control points from all cards (%lu CPs):\n",
                data.max_cp_index);
    TRACE_DEBUG_DUMP("    ", cp, *cp_len);
    TRACE_DEBUG("Max control point index: %lu\n", data.max_cp_index);
    print_control_points(cp, *cp_len, data.max_cp_index);
#endif

    if (data.allow_combined_extract == CK_FALSE)
        __sync_or_and_fetch(&ep11_data->pkey_combined_extract_supported, 0);
    else
        __sync_or_and_fetch(&ep11_data->pkey_combined_extract_supported, 1);

    return data.error ? CKR_DEVICE_ERROR : CKR_OK;
}

CK_BBOOL ep11tok_optimize_single_ops(STDLL_TokData_t *tokdata)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

    return ep11_data->optimize_single_ops ? CK_TRUE : CK_FALSE;
}

/* return -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2 */
static int compare_ck_version(const CK_VERSION *v1, const CK_VERSION *v2)
{

    if (v1->major < v2->major)
        return -1;
    if (v1->major > v2->major)
        return 1;
    if (v1->minor < v2->minor)
        return -1;
    if (v1->minor > v2->minor)
        return 1;
    return 0;
}

static CK_RV get_card_type(uint_32 adapter, CK_ULONG *type)
{
    char fname[PATH_MAX];
    char buf[250];
    CK_RV rc;
    CK_ULONG hwtype, rawtype;

#ifdef EP11_HSMSIM
#ifdef EP11_HSMSIM_CARD_TYPE
    *type = EP11_HSMSIM_CARD_TYPE;
#else
    *type = 7;
#endif
    return CKR_OK;
#endif

    sprintf(fname, "%scard%02x/type", SYSFS_DEVICES_AP, adapter);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc != CKR_OK)
        return rc;
    if (sscanf(buf, "CEX%luP", type) != 1)
        return CKR_FUNCTION_FAILED;

    sprintf(fname, "%scard%02x/hwtype", SYSFS_DEVICES_AP, adapter);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc != CKR_OK)
        return rc;
    if (sscanf(buf, "%lu", &hwtype) != 1)
        return CKR_FUNCTION_FAILED;

    sprintf(fname, "%scard%02x/raw_hwtype", SYSFS_DEVICES_AP, adapter);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc != CKR_OK)
        return rc;
    if (sscanf(buf, "%lu", &rawtype) != 1)
        return CKR_FUNCTION_FAILED;

    if (rawtype > hwtype) {
        TRACE_DEVEL("%s adapter: %u hwtype: %lu raw_hwtype: %lu\n",
                    __func__, adapter, hwtype, rawtype);
        /* Tolerated new card level: report calculated type */
        *type += (rawtype - hwtype);
    }

    return CKR_OK;
}

static CK_RV check_apqn_for_fips_session_mode(uint_32 adapter, uint_32 domain,
                                              target_t target)
{
    CK_BYTE func_bit_mask[16] = { 0 };
    CK_ULONG func_bit_mask_len = sizeof(func_bit_mask);
    uint32_t *res = NULL;
    CK_ULONG reslen = 0;
    CK_ULONG i;
    uint32_t caps = 0;
    CK_BBOOL alg_found = FALSE,  ktype_found = FALSE;
    CK_RV rc;

    /* Check if module supports Login/LogoutExtended */
    rc = dll_m_get_xcp_info(&func_bit_mask, &func_bit_mask_len,
                            CK_IBM_XCPQ_MODULE, CK_IBM_XCPMSQ_FNLIST,
                            target);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to query function list from adapter %02X.%04X\n",
                    __func__, adapter, domain);
       /* card may no longer be online, so ignore this error situation */
        return CKR_OK;
    }

    TRACE_DEBUG("Function bitmask of %02X.%04X:\n", adapter, domain);
    TRACE_DEBUG_DUMP("", func_bit_mask, func_bit_mask_len);

    if (func_bit_mask_len <= (__FNID_LoginExtended / 8) ||
        (func_bit_mask[__FNID_LoginExtended / 8] &
                    (0x80 >> (__FNID_LoginExtended % 8))) == 0 ||
        (func_bit_mask[__FNID_LogoutExtended / 8] &
                    (0x80 >> (__FNID_LogoutExtended % 8))) == 0) {
        TRACE_ERROR("%s Adapter %02X.%04X does not support LoginExtended "
                    "or LogoutExtended but this is required by "
                    "FIPS-session mode\n", __func__, adapter, domain);
        OCK_SYSLOG(LOG_ERR,
                   "Adapter %02X.%04X does not support LoginExtended "
                   "or LogoutExtended but this is required by "
                   "FIPS-session mode\n", adapter, domain);
       return CKR_DEVICE_ERROR;
    }

    /* Check extended capabilities for Login Algorithm and importer key type */
    reslen = sizeof(caps);
    rc = dll_m_get_xcp_info(&caps, &reslen, CK_IBM_XCPQ_EXT_CAPS, 0, target);
    if (rc != CKR_OK || reslen != sizeof(caps)) {
        TRACE_ERROR("%s Failed to query extended capabilities from adapter %02X.%04X\n",
                    __func__, adapter, domain);
        return CKR_DEVICE_ERROR;
    }

    reslen = caps * sizeof(uint32_t) * 2;
    res = calloc(1, reslen);
    if (res == NULL) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    rc = dll_m_get_xcp_info(res, &reslen, CK_IBM_XCPQ_EXT_CAPLIST, 0, target);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to query extended capabilities from adapter %02X.%04X\n",
                    __func__, adapter, domain);
        rc = CKR_DEVICE_ERROR;
        goto out;
    }

    for (i = 0; i < reslen / 4; i += 2) {
        switch (res[i]) {
        case CK_IBM_XCPXQ_LOGIN_ALG:
            if (res[i + 1] & (0x80000000 >> XCP_LOGIN_ALG_F2021))
                alg_found = TRUE;
            break;
        case CK_IBM_XCPXQ_LOGIN_KEYTYPES:
            if (res[i + 1] & (0x80000000 >> XCP_LOGIN_IMPR_EC_P521))
                ktype_found = TRUE;
            break;
        }
    }

    if (!alg_found) {
        TRACE_ERROR("%s Adapter %02X.%04X does not support the FIPS "
                    "login algorithm but this is required by "
                    "FIPS-session mode\n", __func__, adapter, domain);
        OCK_SYSLOG(LOG_ERR,
                   "Adapter %02X.%04X does not support the FIPS "
                   "login algorithm but this is required by "
                   "FIPS-session mode\n", adapter, domain);
        rc = CKR_DEVICE_ERROR;
    }

    if (!ktype_found) {
        TRACE_ERROR("%s Adapter %02X.%04X does not support the P521 "
                    "login importer key type but this is required by "
                    "FIPS-session mode\n", __func__, adapter, domain);
        OCK_SYSLOG(LOG_ERR,
                   "Adapter %02X.%04X does not support the P521 "
                   "login importer key type but this is required by "
                   "FIPS-session mode\n", adapter, domain);
        rc = CKR_DEVICE_ERROR;
    }

out:
    free(res);

    return rc;
}

typedef struct query_version
{
    STDLL_TokData_t *tokdata;
    ep11_target_info_t *target_info;
    CK_CHAR serialNumber[16];
    CK_BBOOL first;
    CK_BBOOL error;
    CK_BYTE pqc_strength[PQC_BYTES];
} query_version_t;

static CK_RV version_query_handler(uint_32 adapter, uint_32 domain,
                                   void *handler_data)
{
    query_version_t *qv = (query_version_t *)handler_data;
    ep11_private_data_t *ep11_data = qv->tokdata->private_data;
    CK_IBM_XCP_INFO xcp_info;
    CK_ULONG xcp_info_len = sizeof(xcp_info);
    CK_BYTE pqc_strength[PQC_BYTES] = { 0 };
    CK_ULONG pqc_strength_len = sizeof(pqc_strength);
    CK_RV rc;
    target_t target;
    CK_ULONG card_type, i;
    ep11_card_version_t *card_version;

    rc = get_ep11_target_for_apqn(adapter, domain, &target, 0);
    if (rc != CKR_OK)
        return rc;

    rc = dll_m_get_xcp_info(&xcp_info, &xcp_info_len, CK_IBM_XCPQ_MODULE, 0,
                            target);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to query module version from adapter %02X.%04X\n",
                           __func__, adapter, domain);
       /* card may no longer be online, so ignore this error situation */
        rc = CKR_OK;
        goto out;
    }

    rc = get_card_type(adapter, &card_type);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to get card type for adapter %02X.%04X\n",
                   __func__, adapter, domain);
        /* card may no longer be online, so ignore this error situation */
        rc = CKR_OK;
        goto out;
    }

    /* Try to find existing version info for this card type */
    card_version = qv->target_info->card_versions;
    while (card_version != NULL) {
        if (card_version->card_type == card_type)
           break;
        card_version = card_version->next;
    }

    if (card_version == NULL) {
        /*
         * No version info for this card type found, create new entry and add
         * it to the list
         */
        card_version = calloc(1, sizeof(ep11_card_version_t));
        if (card_version == NULL) {
            TRACE_ERROR("%s Memory allocation failed\n", __func__);
            qv->error = TRUE;
            rc = CKR_HOST_MEMORY;
            goto out;
        }

        card_version->card_type = card_type;
#ifdef EP11_HSMSIM
#ifdef EP11_HSMSIM_FW_API
        card_version->firmware_API_version = EP11_HSMSIM_FW_API;
#else
        card_version->firmware_API_version = xcp_info.firmwareApi;
#endif
#else
        card_version->firmware_API_version = xcp_info.firmwareApi;
#endif
#ifdef EP11_HSMSIM
#ifdef EP11_HSMSIM_FW_VER_MAJOR
        card_version->firmware_version.major = EP11_HSMSIM_FW_VER_MAJOR;
#ifdef EP11_HSMSIM_FW_VER_MINOR
        card_version->firmware_version.minor = EP11_HSMSIM_FW_VER_MINOR;
#else
        card_version->firmware_version.minor = 0;
#endif
#else
        card_version->firmware_version = xcp_info.firmwareVersion;
#endif
#else
        card_version->firmware_version = xcp_info.firmwareVersion;
#endif

        card_version->next = qv->target_info->card_versions;
        qv->target_info->card_versions = card_version;
    } else {
        /*
         * Version info for this card type is already available, so check this
         * card against the existing info
         */
        if (card_version->firmware_API_version != xcp_info.firmwareApi) {
            TRACE_ERROR("%s Adapter %02X.%04X has a different API version "
                        "than the previous CEX%luP adapters: %lu\n", __func__,
                        adapter, domain, card_version->card_type,
                        xcp_info.firmwareApi);
            OCK_SYSLOG(LOG_ERR,
                       "Warning: Adapter %02X.%04X has a different API version "
                       "than the previous CEX%luP adapters: %lu\n",
                       adapter, domain, card_version->card_type,
                       xcp_info.firmwareApi);
            qv->error = TRUE;
            rc = CKR_OK;
        }

        if (compare_ck_version(&card_version->firmware_version,
                               &xcp_info.firmwareVersion) != 0) {
            TRACE_ERROR("%s Adapter %02X.%04X has a different firmware version "
                        "than the previous CEX%luP adapters: %d.%d\n", __func__,
                        adapter, domain, card_version->card_type,
                        xcp_info.firmwareVersion.major,
                        xcp_info.firmwareVersion.minor);
            OCK_SYSLOG(LOG_ERR,
                       "Warning: Adapter %02X.%04X has a different firmware "
                       "version than the previous CEX%luP adapters: %d.%d\n",
                       adapter, domain, card_version->card_type,
                       xcp_info.firmwareVersion.major,
                       xcp_info.firmwareVersion.minor);
            qv->error = TRUE;
            rc = CKR_OK;
        }
    }

    if (qv->first)
        memcpy(qv->serialNumber, xcp_info.serialNumber,
               sizeof(qv->serialNumber));

    /* Query for PQC strength support. If the PQC strength query is not
       available only Dilithium 6-5 round 2 is available. */
    rc = dll_m_get_xcp_info(&pqc_strength, &pqc_strength_len,
                            CK_IBM_XCPQ_PQC_STRENGTHS, 0, target);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s Failed to query PQC-strength from adapter %02X.%04X\n",
                    __func__, adapter, domain);
        /* Only R2_65 is available */
        pqc_strength[PQC_BYTE_NO(XCP_PQC_S_DILITHIUM_R2_65)] |=
                                    PQC_BIT_MASK(XCP_PQC_S_DILITHIUM_R2_65);
        rc = CKR_OK;
    }

    TRACE_DEBUG("PQC-strength of %02X.%04X:\n", adapter, domain);
    TRACE_DEBUG_DUMP("", pqc_strength, sizeof(qv->pqc_strength));

    if (qv->first) {
        memcpy(qv->pqc_strength, pqc_strength, sizeof(qv->pqc_strength));
    } else {
        for (i = 0; i < sizeof(qv->pqc_strength); i++)
            qv->pqc_strength[i] &= pqc_strength[i];
    }

    qv->first = FALSE;

    if (ep11_data->fips_session_mode) {
        rc = check_apqn_for_fips_session_mode(adapter, domain, target);
        if (rc != CKR_OK) {
            qv->error = TRUE;
            rc = CKR_OK;
        }
    }

out:
    free_ep11_target_for_apqn(target);
    return rc;
}

static CK_RV ep11tok_get_ep11_library_version(CK_VERSION *lib_version)
{
    unsigned int host_version;
    CK_ULONG version_len = sizeof(host_version);
    CK_RV rc;

    if (dll_m_get_xcp_info == NULL) {
        TRACE_ERROR("%s Function dll_m_get_xcp_info is not available\n",
                    __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = dll_m_get_xcp_info(&host_version, &version_len,
                            CK_IBM_XCPHQ_VERSION, 0, 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s dll_m_get_xcp_info (HOST) failed: rc=0x%lx\n", __func__,
                    rc);
        return rc;
    }
    TRACE_DEVEL("%s host_version=0x08%x\n", __func__, host_version);
    lib_version->major = (host_version & 0x00FF0000) >> 16;
    /* Minor is 4 bits release number and 4 bits modification level */
    lib_version->minor = (host_version & 0x00000F00) >> 4 |
                                            (host_version & 0x0000000F);
    if ((host_version & 0x0000F000) != 0) {
        lib_version->minor |= 0xF0;
        TRACE_DEVEL("%s relelase > 15, treating as 15\n", __func__);
    }
    if ((host_version & 0x000000F0) != 0) {
        lib_version->minor |= 0x0F;
        TRACE_DEVEL("%s modification level > 15, treating as 15\n", __func__);
    }
    /*
     * EP11 host library < v2.0 returns an invalid version (i.e. 0x100). This
     * can safely be treated as version 1.0
     */
    if (lib_version->major == 0) {
        lib_version->major = 1;
        lib_version->minor = 0;
    }

    return CKR_OK;
}

static CK_RV ep11tok_get_ep11_version(STDLL_TokData_t *tokdata,
                                      ep11_target_info_t *target_info)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_card_version_t *card_version;
    query_version_t qv;
    CK_ULONG i;
    CK_RV rc;

    memset(&qv, 0, sizeof(qv));
    qv.tokdata = tokdata;
    qv.target_info = target_info;
    qv.first = TRUE;

    rc = handle_all_ep11_cards(&ep11_data->target_list, version_query_handler,
                               &qv);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s handle_all_ep11_cards failed: rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }
    if (qv.first) {
        TRACE_ERROR("%s No EP11 adapters are online or configured\n", __func__);
        return CKR_DEVICE_ERROR;
    }
    if (qv.error) {
        TRACE_ERROR("%s Failed to query version of EP11 adapters\n", __func__);
        return CKR_DEVICE_ERROR;
    }

    memcpy(target_info->serialNumber, qv.serialNumber,
           sizeof(target_info->serialNumber));

    TRACE_INFO("%s Serial number: %.16s\n", __func__, target_info->serialNumber);

    /* EP11 host lib version <= 2 only support API version 2 */
    if (ep11_data->ep11_lib_version.major <= 2)
        target_info->used_firmware_API_version = 2;
    else
        target_info->used_firmware_API_version = 0;

    card_version = target_info->card_versions;
    while (card_version != NULL) {
        TRACE_INFO("%s Card type: CEX%luP\n", __func__,
                   card_version->card_type);
        TRACE_INFO("%s   Firmware API: %lu\n", __func__,
                card_version->firmware_API_version);
        TRACE_INFO("%s   Firmware Version: %d.%d\n", __func__,
                card_version->firmware_version.major,
                card_version->firmware_version.minor);

        if (target_info->used_firmware_API_version == 0)
            target_info->used_firmware_API_version =
                                card_version->firmware_API_version;
        else
            target_info->used_firmware_API_version =
                                MIN(target_info->used_firmware_API_version,
                                    card_version->firmware_API_version);

        card_version = card_version->next;
    }

    TRACE_INFO("%s Used Firmware API: %lu\n", __func__,
               target_info->used_firmware_API_version);

    memcpy(target_info->pqc_strength, qv.pqc_strength, sizeof(qv.pqc_strength));

    TRACE_INFO("Combined PQC-strength:\n");
    for (i = 1; i <= XCP_PQC_MAX; i++) {
        TRACE_INFO("  Strength %lu: %d\n", i,
                   (qv.pqc_strength[PQC_BYTE_NO(i)] & PQC_BIT_MASK(i)) != 0);
    }

    return CKR_OK;
}

static void free_card_versions(ep11_card_version_t *card_version)
{
    ep11_card_version_t *next_card_version;

    TRACE_INFO("%s running\n", __func__);

    while (card_version != NULL) {
        next_card_version = card_version->next;
        free(card_version);
        card_version = next_card_version;
    }
}

typedef struct query_wkvp
{
    ep11_private_data_t *ep11_data;
    ep11_target_info_t *target_info;
    CK_BBOOL error;
} query_wkvp_t;

const unsigned char ep11_zero_mkvp[XCP_WKID_BYTES] = { 0 };

static CK_RV wkvp_query_handler(uint_32 adapter, uint_32 domain,
                                void *handler_data)
{
    query_wkvp_t *qw = (query_wkvp_t *)handler_data;
    CK_IBM_DOMAIN_INFO domain_info;
    CK_ULONG domain_info_len = sizeof(domain_info);
    CK_RV rc;
    target_t target;

    /*
     * If an MK change operation is active, the current APQN must be part
     * of the operation, even if it is offline (this only applies to an
     * APQN_ALLOWLIST configuration, for a APQN_ANY configuration, we will only
     * be called for currently online APQNs anyway).
     */
    if (qw->ep11_data->mk_change_active &&
        !hsm_mk_change_apqns_find(qw->ep11_data->mk_change_apqns,
                                  qw->ep11_data->num_mk_change_apqns,
                                  adapter, domain)) {
        TRACE_ERROR("APQN %02X.%04X is used by the EP11 token, but it is "
                    "not part of the active MK change operation '%s'\n",
                    adapter, domain, qw->ep11_data->mk_change_op);
        OCK_SYSLOG(LOG_ERR, "APQN %02X.%04X is used by the EP11 token, but "
                   "it is not part of the active MK change operation '%s'\n",
                   adapter, domain, qw->ep11_data->mk_change_op);
        qw->error = TRUE;
        return CKR_OK;
    }

    rc = get_ep11_target_for_apqn(adapter, domain, &target, 0);
    if (rc != CKR_OK)
        return rc;

    rc = dll_m_get_xcp_info(&domain_info, &domain_info_len, CK_IBM_XCPQ_DOMAIN,
                            0, target);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to query domain info from APQN %02X.%04X\n",
                           __func__, adapter, domain);
       /* card may no longer be online, so ignore this error situation */
        rc = CKR_OK;
        goto out;
    }

    if ((domain_info.flags & CK_IBM_DOM_CURR_WK) == 0) {
        TRACE_ERROR("%s No EP11 wrapping key is set on APQN %02X.%04X\n",
                    __func__, adapter, domain);
        OCK_SYSLOG(LOG_ERR, "%s No EP11 wrapping key is set on APQN %02X.%04X\n",
                   __func__, adapter, domain);
        qw->error = TRUE;
        rc = CKR_OK;
        goto out;
    }

    TRACE_DEBUG("%s WKVP of APQN %02X.%04X:\n", __func__, adapter, domain);
    TRACE_DEBUG_DUMP("full WKVP: ", domain_info.wk, sizeof(domain_info.wk));

    if ((domain_info.flags & CK_IBM_DOM_COMMITTED_NWK) != 0) {
        TRACE_DEBUG_DUMP("New WKVP: ", domain_info.nextwk,
                         sizeof(domain_info.nextwk));

        /* New WK must be the expected new WK if a MK change op is ongoing */
        if (qw->ep11_data->mk_change_active &&
            memcmp(domain_info.nextwk, qw->ep11_data->new_wkvp,
                   XCP_WKID_BYTES) != 0) {
            TRACE_ERROR("New EP11 wrapping key on APQN %02X.%04X does not "
                        "match the expected wrapping key of the active MK "
                        "change operation '%s'\n",
                        adapter, domain, qw->ep11_data->mk_change_op);
            OCK_SYSLOG(LOG_ERR, "New EP11 wrapping key on APQN %02X.%04X does "
                       "not match the expected wrapping key of the active "
                       "HSM MK change operation '%s'\n",
                       adapter, domain, qw->ep11_data->mk_change_op);
            qw->error = TRUE;
            rc = CKR_OK;
            goto out;
        }
    } else {
        /*
         * No new WK loaded: current WK must be the expected new WK if a MK
         * change op is ongoing
         */
        if (qw->ep11_data->mk_change_active &&
            memcmp(domain_info.wk, qw->ep11_data->new_wkvp,
                   XCP_WKID_BYTES) != 0) {
             TRACE_ERROR("Current EP11 wrapping key on APQN %02X.%04X does not "
                         "match the expected new wrapping key of the active MK "
                         "change operation '%s'\n",
                         adapter, domain, qw->ep11_data->mk_change_op);
             OCK_SYSLOG(LOG_ERR, "Current EP11 wrapping key on APQN %02X.%04X "
                        "does not match the expected new wrapping key of the "
                        "active HSM MK change operation '%s'\n",
                        adapter, domain, qw->ep11_data->mk_change_op);
             /*
              * Report error only if not within the pkcshsm_mk_change tool
              * process. Otherwise the MK change operation could not be canceled
              * when the new WK register has already been cleared by HSM admin.
              */
             if (strcmp(program_invocation_short_name,
                        "pkcshsm_mk_change") != 0) {
                 qw->error = TRUE;
                 rc = CKR_OK;
                 goto out;
             }
         }
    }

    /*
     * If an MK change operation is pending, the current WK may already
     * be the new WK of the operation.
     */
    if (qw->ep11_data->mk_change_active &&
        memcmp(domain_info.wk, qw->ep11_data->new_wkvp,
               XCP_WKID_BYTES) == 0) {
        TRACE_DEBUG("%s APQN %02X.%04X already has the new WK\n",
                    __func__, adapter, domain);
        rc = CKR_OK;
        goto out;
    }

    if (qw->ep11_data->expected_wkvp_set == FALSE &&
        memcmp(qw->ep11_data->expected_wkvp, ep11_zero_mkvp,
               XCP_WKID_BYTES) == 0) {
        /* zero expected MKVP, copy current one */
        memcpy(qw->ep11_data->expected_wkvp, domain_info.wk, XCP_WKID_BYTES);
    } else {
        if (memcmp(domain_info.wk, qw->ep11_data->expected_wkvp,
                   XCP_WKID_BYTES) != 0) {
            TRACE_ERROR("EP11 wrapping key on APQN %02X.%04X does not "
                        "match the %s wrapping key\n", adapter, domain,
                        qw->ep11_data->expected_wkvp_set ?
                                                "expected" : "other APQN's");
            OCK_SYSLOG(LOG_ERR, "EP11 wrapping key on APQN %02X.%04X does not "
                       "match the %s wrapping key\n", adapter, domain,
                        qw->ep11_data->expected_wkvp_set ?
                                                "expected" : "other APQN's");
            qw->error = TRUE;
            rc = CKR_OK;
            goto out;
        }
    }

out:
    free_ep11_target_for_apqn(target);
    return rc;
}

static CK_RV ep11tok_check_wkvps(STDLL_TokData_t *tokdata,
                                 ep11_target_info_t *target_info)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    query_wkvp_t qw;
    CK_RV rc;

    memset(&qw, 0, sizeof(qw));
    qw.ep11_data = ep11_data;
    qw.target_info = target_info;

    rc = handle_all_ep11_cards(&ep11_data->target_list, wkvp_query_handler,
                               &qw);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s handle_all_ep11_cards failed: rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    if (qw.error) {
        TRACE_ERROR("%s Errors occurred during WKVP query\n", __func__);
        return CKR_DEVICE_ERROR;
    }

    if (ep11_data->expected_wkvp_set == FALSE) {
        /*
         * If a MK change operation is active, and all APQNs have the new WK
         * already, use the new WK as the queried one.
         */
        if (ep11_data->mk_change_active &&
            memcmp(ep11_data->expected_wkvp, ep11_zero_mkvp,
                   XCP_WKID_BYTES) == 0) {
            TRACE_DEBUG("%s All APQNs already have the new WK\n",__func__);
            memcpy(ep11_data->expected_wkvp, ep11_data->new_wkvp,
                   XCP_WKID_BYTES);
        }

        TRACE_DEBUG_DUMP("WKVP (queried): ", ep11_data->expected_wkvp,
                         XCP_WKID_BYTES);
    } else {
        TRACE_DEBUG_DUMP("WKVP (config): ", ep11_data->expected_wkvp,
                         XCP_WKID_BYTES);
    }

    return CKR_OK;
}

CK_RV token_specific_get_token_info(STDLL_TokData_t *tokdata,
                                    CK_TOKEN_INFO_PTR pInfo)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_target_info_t* target_info;

    target_info = get_target_info(tokdata);
    if (target_info == NULL)
        return CKR_FUNCTION_FAILED;

    /*
     * report the EP11 firmware version as hardware version, and
     * the EP11 host library version as firmware version
     */
    if (target_info->card_versions != NULL)
        pInfo->hardwareVersion = target_info->card_versions->firmware_version;
    pInfo->firmwareVersion = ep11_data->ep11_lib_version;
    pInfo->firmwareVersion.minor >>= 4; /* report release, skip mod-level */
    memcpy(pInfo->serialNumber, target_info->serialNumber,
           sizeof(pInfo->serialNumber));

    put_target_info(tokdata, target_info);

    return CKR_OK;
}

/**
 * Returns 1 if all APQNs that are present are at least at the required
 * versions. If non of the APQNs are at the required versions, 0 is returned.
 * If the APQN versions are inconsistent, -1 is returned.
 * Card types > the highest card type contained in the requirements array are
 * assumed to fulfill the minimum version requirements.
 */
static int check_required_versions(STDLL_TokData_t *tokdata,
                                   const version_req_t req[],
                                   CK_ULONG num_req)
{
    CK_ULONG i, max_card_type = 0, min_card_type = 0xFFFFFFFF;
    CK_BBOOL req_not_fullfilled = CK_FALSE;
    CK_BBOOL req_fullfilled = CK_FALSE;
    ep11_card_version_t *card_version;
    ep11_target_info_t* target_info;
    int status;

    target_info = get_target_info(tokdata);
    if (target_info == NULL)
        return CKR_FUNCTION_FAILED;

    for (i = 0; i < num_req; i++) {
        status = check_card_version(tokdata, req[i].card_type,
                                           req[i].min_lib_version,
                                           req[i].min_firmware_version,
                                           req[i].min_firmware_API_version);
        if (status == 0)
            req_not_fullfilled = CK_TRUE;
        if (status == 1)
            req_fullfilled = CK_TRUE;
        max_card_type = MAX(max_card_type, req[i].card_type);
        min_card_type = MIN(min_card_type, req[i].card_type);
    }

    /* Are card types < min_card_type present? */
    card_version = target_info->card_versions;
    while (card_version != NULL) {
         if (card_version->card_type < min_card_type)
             req_not_fullfilled = CK_TRUE;
         card_version = card_version->next;
     }

    /* Are card types > max_card_type present? */
    card_version = target_info->card_versions;
    while (card_version != NULL) {
        if (card_version->card_type > max_card_type) {
            /*
              * Card types > the highest card type contained in the requirements
              * array are assumed to fulfill the minimum version requirements.
              * So all others must also meet the version requirements or be
              * not present.
              */
            status = 1;
             if (req_not_fullfilled == CK_TRUE)
                 status = -1;
             goto out;
        }
        card_version = card_version->next;
    }

     /* No newer cards then max_card_type are present */
    if (req_not_fullfilled == CK_TRUE) {
        /*
         * At least one don't meet the requirements, so all other must not
         * fulfill the requirements, too, or are not present.
         */
        status = 0;
        if (req_fullfilled == CK_TRUE)
            status = -1;
        goto out;
    } else {
        /* All of the cards that are present fulfill the requirements */
        status = 1;
        goto out;
    }

out:
    put_target_info(tokdata, target_info);
    return status;
}

/**
 * returns 1 if all APQNs of the specified card type are at least at the
 * specified versions, 0 otherwise. If no APQN of that card type is online,
 * then -1 is returned.
 * Those parameters that are NULL are not checked.
 */
static int check_card_version(STDLL_TokData_t *tokdata, CK_ULONG card_type,
                              const CK_VERSION *ep11_lib_version,
                              const CK_VERSION *firmware_version,
                              const CK_ULONG *firmware_API_version)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_card_version_t *card_version;
    ep11_target_info_t* target_info;
    int status = 1;

    TRACE_DEBUG("%s checking versions for CEX%luP cards.\n", __func__, card_type);

    if (ep11_lib_version != NULL) {
        if (compare_ck_version(&ep11_data->ep11_lib_version,
                               ep11_lib_version) < 0) {
            TRACE_DEBUG("%s ep11_lib_version is less than required\n", __func__);
            return 0;
        }
    }

    target_info = get_target_info(tokdata);
    if (target_info == NULL)
        return -1;

    card_version = target_info->card_versions;
    while (card_version != NULL) {
        if (card_version->card_type == card_type)
            break;
        card_version = card_version->next;
    }

    if (card_version == NULL) {
        status = -1;
        goto out;
    }

    if (firmware_version != NULL) {
        if (compare_ck_version(&card_version->firmware_version,
                               firmware_version) < 0) {
            TRACE_DEBUG("%s firmware_version is less than required\n", __func__);
            status = 0;
            goto out;
        }
    }

    if (firmware_API_version != NULL) {
        if (card_version->firmware_API_version < *firmware_API_version) {
            TRACE_DEBUG("%s firmware_API_version is less than required\n",
                       __func__);
            status = 0;
            goto out;
        }
    }

 out:
    put_target_info(tokdata, target_info);
    return status;
}

static CK_RV ep11tok_setup_target(STDLL_TokData_t *tokdata,
                                  ep11_target_info_t *target_info)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    struct XCP_Module module;
    CK_RV rc = CKR_OK;
    short i;

    if (dll_m_add_module == NULL) {
        TRACE_WARNING("%s Function dll_m_add_module is not available, falling "
                      "back to old target handling\n", __func__);

        if (target_info->used_firmware_API_version > 2) {
            TRACE_ERROR("%s selecting an API version is not possible with old "
                        "target handling\n", __func__);
            return CKR_FUNCTION_FAILED;
        }

        target_info->target = (target_t)&ep11_data->target_list;
        return CKR_OK;
    }

    if (target_info->used_firmware_API_version > 2 &&
        ep11_data->ep11_lib_version.major < 3) {
        TRACE_ERROR("%s selecting an API version is not possible with an EP11"
                    " host library version < 3.0\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    target_info->target = XCP_TGT_INIT;
    memset(&module, 0, sizeof(module));
    module.version = ep11_data->ep11_lib_version.major >= 3 ? XCP_MOD_VERSION_2
                                                            : XCP_MOD_VERSION_1;
    module.flags = XCP_MFL_VIRTUAL | XCP_MFL_MODULE;
    module.api = target_info->used_firmware_API_version;

    TRACE_DEVEL("%s XCP_MOD_VERSION: %u\n", __func__, module.version);

    if (ep11_data->target_list.length == 0) {
        /* APQN_ANY: Create an empty module group */
        rc = dll_m_add_module(&module, &target_info->target);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s dll_m_add_module (ANY) failed: rc=%ld\n",
                        __func__, rc);
            return CKR_FUNCTION_FAILED;
        }
        return CKR_OK;
    }

    for (i = 0; i < ep11_data->target_list.length; i++) {
        module.module_nr = ep11_data->target_list.apqns[2 * i];
        memset(module.domainmask, 0, sizeof(module.domainmask));
        XCPTGTMASK_SET_DOM(module.domainmask,
                           ep11_data->target_list.apqns[2 * i + 1]);

        rc = dll_m_add_module(&module, &target_info->target);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s dll_m_add_module (%02x.%04x) failed: rc=%ld\n",
                    __func__, ep11_data->target_list.apqns[2 * i],
                    ep11_data->target_list.apqns[2 * i + 1], rc);
            dll_m_rm_module(NULL, target_info->target);
            return CKR_FUNCTION_FAILED;
        }
    }

    return CKR_OK;
}

CK_RV get_ep11_target_for_apqn(uint_32 adapter, uint_32 domain,
                               target_t *target, uint64_t flags)
{
    ep11_target_t *target_list;
    struct XCP_Module module;
    CK_VERSION lib_version;
    CK_RV rc;

    *target = XCP_TGT_INIT;

    rc = ep11tok_get_ep11_library_version(&lib_version);
    if (rc != CKR_OK)
        return rc;

    if (dll_m_add_module != NULL) {
        memset(&module, 0, sizeof(module));
        module.version = lib_version.major >= 3 ? XCP_MOD_VERSION_2
                                                : XCP_MOD_VERSION_1;
        module.flags = XCP_MFL_MODULE | flags;
        module.module_nr = adapter;
        XCPTGTMASK_SET_DOM(module.domainmask, domain);
        rc = dll_m_add_module(&module, target);
        if (rc != 0) {
            TRACE_ERROR("%s dll_m_add_module (%02x.%04x) failed: rc=%ld\n",
                                __func__, adapter, domain, rc);
            return CKR_FUNCTION_FAILED;
        }
    } else {
        /* Fall back to old target handling */
        target_list = (ep11_target_t *)calloc(1, sizeof(ep11_target_t));
        if (target_list == NULL)
            return CKR_HOST_MEMORY;
        target_list->length = 1;
        target_list->apqns[0] = adapter;
        target_list->apqns[1] = domain;
        *target = (target_t)target_list;
    }

    return CKR_OK;
}

void free_ep11_target_for_apqn(target_t target)
{
    CK_RV rc;

    if (dll_m_rm_module != NULL) {
        rc = dll_m_rm_module(NULL, target);
        if (rc != 0) {
            TRACE_DEBUG("%s dll_m_rm_module failed: rc=%ld\n", __func__, rc);
        }
    } else {
        /* With the old target handling, target is a pointer to ep11_target_t */
        free((ep11_target_t *)target);
    }
}

struct single_target_data {
    ep11_private_data_t *ep11_data;
    int found;
    int new_wk_found;
    uint_32 adapter;
    uint_32 domain;
};

static CK_RV setup_single_target_handler(uint_32 adapter, uint_32 domain,
                                         void *handler_data)
{
    struct single_target_data *std = (struct single_target_data *)handler_data;
    CK_IBM_DOMAIN_INFO domain_info;
    CK_ULONG domain_info_len = sizeof(domain_info);
    CK_RV rc;
    target_t target;
    int target_allocated = 0;

    if (!std->new_wk_found) {
        /* Check if this APQN has the new WK loaded */
        rc = get_ep11_target_for_apqn(adapter, domain, &target, 0);
        if (rc != CKR_OK)
            return rc;

        target_allocated = 1;

        rc = dll_m_get_xcp_info(&domain_info, &domain_info_len,
                                CK_IBM_XCPQ_DOMAIN, 0, target);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s Failed to query domain info from APQN %02X.%04X\n",
                        __func__, adapter, domain);
            /* card may no longer be online, so ignore this error situation */
            goto out;
        }

        if ((domain_info.flags & CK_IBM_DOM_CURR_WK) == 0) {
            TRACE_ERROR("%s No EP11 wrapping key is set on APQN %02X.%04X\n",
                        __func__, adapter, domain);
            goto out;
        }

        if (memcmp(domain_info.wk, std->ep11_data->new_wkvp,
                   XCP_WKID_BYTES) == 0) {
            std->adapter = adapter;
            std->domain = domain;
            std->new_wk_found = 1;
            std->found = 1;

            TRACE_DEVEL("%s Select APQN %02X.%04X with new WK set\n",
                        __func__, adapter, domain);
        }
    }

    if (!std->found && !std->new_wk_found) {
        std->adapter = adapter;
        std->domain = domain;
        std->found = 1;

        TRACE_DEVEL("%s Select APQN %02X.%04X\n", __func__, adapter, domain);
    }

out:
    if (target_allocated)
        free_ep11_target_for_apqn(target);

    return CKR_OK;
}

static CK_RV ep11tok_setup_single_target(STDLL_TokData_t *tokdata,
                                         ep11_target_info_t *target_info,
                                         CK_BBOOL wait_for_new_wk)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    struct single_target_data std;
    CK_RV rc;
    int retries = 0;

retry:
    memset(&std, 0, sizeof(std));
    std.ep11_data = ep11_data;

    /* Search for an online APQN that preferably has the new WK set already */
    rc = handle_all_ep11_cards(&ep11_data->target_list,
                               setup_single_target_handler, &std);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s handle_all_ep11_cards failed: rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    if (!std.found) {
        TRACE_ERROR("%s no online APQN found\n",__func__);
        return CKR_DEVICE_ERROR;;
    }

    if (wait_for_new_wk && !std.new_wk_found) {
        TRACE_DEVEL("%s no APQN with new MK set found, retry in 1 second\n",
                    __func__);

        retries++;
        if (retries > 3600) /* Retry for max 1 hour */
            return CKR_DEVICE_ERROR;

        sleep(1);
        goto retry;
    }

    rc = get_ep11_target_for_apqn(std.adapter, std.domain,
                                  &target_info->target, 0);
    if (rc != CKR_OK)
        return rc;

    target_info->single_apqn = 1;
    target_info->adapter = std.adapter;
    target_info->domain = std.domain;
    target_info->single_apqn_has_new_wk = std.new_wk_found;

    OCK_SYSLOG(LOG_INFO, "Slot %lu: A concurrent HSM master key change "
               "operation (%s) is active, EP11 token uses a single APQN: "
               "%02X.%04X\n", tokdata->slot_id, ep11_data->mk_change_op,
               std.adapter, std.domain);

    return CKR_OK;
}

/**
 * This function is called when the attributes of a key object are changed, or
 * if the object is copied by means of C_CopyObject. In case attributes
 * CKA_TOKEN and/or CKA_PRIVATE are changed (only allowed during C_CopyObject),
 * special checking is required in regards of session bound keys.
 * In case strict session mode, VHSM mode or FIPS session mode is active,
 * the changed attributes may cause the key object to be expected to be bound
 * to a different EP11 session as it currently is. Check if the key object
 * is bound to the expected session, and fail if not.
 */
CK_RV ep11tok_set_attrs_check_session(STDLL_TokData_t *tokdata,
                                      SESSION *session, OBJECT* obj,
                                      TEMPLATE *new_tmpl)
{
    ep11_session_t *ep11_session = (ep11_session_t *)session->private_data;
    unsigned char *cur_ep11_pin_blob = NULL;
    CK_ULONG cur_ep11_pin_blob_len = 0;
    unsigned char *new_ep11_pin_blob = NULL;
    CK_ULONG new_ep11_pin_blob_len = 0;
    CK_BBOOL cur_token, cur_private, new_token, new_private;
    CK_RV rc;

    cur_token = !object_is_session_object(obj);
    cur_private = object_is_private(obj);

    new_token = cur_token;
    rc = template_attribute_get_bool(new_tmpl, CKA_TOKEN, &new_token);
    if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE)
        return rc;

    new_private = cur_private;
    rc = template_attribute_get_bool(new_tmpl, CKA_PRIVATE, &new_private);
    if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE)
        return rc;

    if (cur_token == new_token && cur_private == new_private)
        return CKR_OK;

    /* CKA_TOKEN and/or CKA_PRIVATE is changed, check the session */
    ep11_get_pin_blob(tokdata, ep11_session, !cur_token, cur_private,
                      &cur_ep11_pin_blob, &cur_ep11_pin_blob_len);
    ep11_get_pin_blob(tokdata, ep11_session, !new_token, new_private,
                      &new_ep11_pin_blob, &new_ep11_pin_blob_len);

    if (new_ep11_pin_blob != cur_ep11_pin_blob) {
        TRACE_ERROR("Attribute change would cause the key to be bound to a "
                    "different session. Change is rejected\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
}

CK_RV token_specific_set_attribute_values(STDLL_TokData_t *tokdata,
                                          SESSION *session,
                                          OBJECT *obj,
                                          TEMPLATE *new_tmpl)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE ktype;
    size_t keyblobsize = 0, reencblobsize = 0;
    CK_BYTE *keyblob, *reencblob = NULL;
    DL_NODE *node;
    CK_ATTRIBUTE *ibm_opaque_attr = NULL, *ibm_opaque_reenc_attr = NULL;
    CK_ATTRIBUTE_PTR attributes = NULL;
    CK_ULONG num_attributes = 0;
    CK_ATTRIBUTE *attr;
    CK_RV rc;

    rc = template_attribute_get_ulong(obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s CKA_CLASS is missing\n", __func__);
        return rc;
    }

    switch (class) {
    case CKO_SECRET_KEY:
    case CKO_PRIVATE_KEY:
    case CKO_PUBLIC_KEY:
        break;
    default:
        /* Not a key, nothing to do */
        return CKR_OK;
    }

    rc = template_attribute_get_ulong(obj->template, CKA_KEY_TYPE, &ktype);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s CKA_KEY_TYPE is missing\n", __func__);
        return rc;
    }

    rc = obj_opaque_2_blob(tokdata, obj, &keyblob, &keyblobsize);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no key-blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    if (ep11_data->mk_change_active) {
        rc = obj_opaque_2_reenc_blob(tokdata, obj, &reencblob, &reencblobsize);
        if (rc == CKR_TEMPLATE_INCOMPLETE) {
            TRACE_DEVEL("%s no reenc key-blob, use old key-blob\n", __func__);
            reencblob = keyblob;
            reencblobsize = keyblobsize;
            rc = CKR_OK;
        }
        if (rc != CKR_OK) {
            TRACE_ERROR("%s failed to get reenc key-blob rc=0x%lx\n", __func__,
                        rc);
            return rc;
        }
    }

    rc = ep11tok_set_attrs_check_session(tokdata, session, obj, new_tmpl);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ep11tok_set_attrs_check_session rc=0x%lx\n", __func__, rc);
        return rc;
    }

#ifndef NO_PKEY
    /* Ensure the firmware master key verification pattern is available */
    rc = ep11tok_pkey_get_firmware_mk_vp(tokdata, session);
    if (rc != CKR_OK && rc != CKR_FUNCTION_NOT_SUPPORTED)
        return rc;
#endif /* NO_PKEY */

    node = new_tmpl->attribute_list;
    while (node) {
        attr = (CK_ATTRIBUTE *)node->data;

        /* EP11 can set certain boolean attributes only */
        switch (attr->type) {
        case CKA_VERIFY:
        case CKA_VERIFY_RECOVER:
        case CKA_ENCRYPT:
            /* Can not restrict public key for verify and encrypt */
            if (class == CKO_PUBLIC_KEY)
                break;
            /* Fallthrough */
        case CKA_EXTRACTABLE:
        case CKA_MODIFIABLE:
        case CKA_SIGN:
        case CKA_SIGN_RECOVER:
        case CKA_DECRYPT:
        case CKA_DERIVE:
        case CKA_UNWRAP:
        case CKA_WRAP:
        case CKA_WRAP_WITH_TRUSTED:
        case CKA_TRUSTED:
        case CKA_IBM_RESTRICTABLE:
        case CKA_IBM_USE_AS_DATA:
            rc = add_to_attribute_array(&attributes, &num_attributes,
                                        attr->type, attr->pValue,
                                        attr->ulValueLen);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s add_to_attribute_array failed rc=0x%lx\n",
                            __func__, rc);
                goto out;
            }
            break;
#ifndef NO_PKEY
        case CKA_IBM_PROTKEY_EXTRACTABLE:
            if (ep11_data->pkey_wrap_supported) {
                rc = add_to_attribute_array(&attributes, &num_attributes,
                                            attr->type, attr->pValue,
                                            attr->ulValueLen);
                if (rc != CKR_OK) {
                    TRACE_ERROR("%s add_to_attribute_array failed rc=0x%lx\n",
                                __func__, rc);
                    goto out;
                }
            }
            break;
#endif /* NO_PKEY */
        default:
            /* Either non-boolean, or read-only */
            break;
        }

        node = node->next;
    }

    if (attributes != NULL && num_attributes > 0) {
        rc = build_attribute(CKA_IBM_OPAQUE, keyblob, keyblobsize,
                             &ibm_opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed rc=0x%lx\n", __func__, rc);
            goto out;
        }

        if (reencblob != NULL) {
            rc = build_attribute(CKA_IBM_OPAQUE_REENC, reencblob, reencblobsize,
                                 &ibm_opaque_reenc_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s build_attribute failed rc=0x%lx\n", __func__,
                            rc);
                goto out;
            }
        }

        RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
        RETRY_UPDATE_BLOB_START(tokdata, target_info,
                                ibm_opaque_attr->pValue,
                                ktype != CKK_AES_XTS ?
                                    ibm_opaque_attr->ulValueLen :
                                    ibm_opaque_attr->ulValueLen / 2,
                                ibm_opaque_reenc_attr != NULL ?
                                    ibm_opaque_reenc_attr->pValue : NULL,
                                ibm_opaque_reenc_attr != NULL ?
                                    (ktype != CKK_AES_XTS ?
                                        ibm_opaque_reenc_attr->ulValueLen :
                                        ibm_opaque_reenc_attr->ulValueLen / 2) :
                                    0,
                                keyblob, keyblobsize);
            rc = dll_m_SetAttributeValue(keyblob, keyblobsize,
                                         attributes, num_attributes,
                                         target_info->target);
        RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                              ibm_opaque_attr->pValue,
                              ktype != CKK_AES_XTS ?
                                  ibm_opaque_attr->ulValueLen :
                                  ibm_opaque_attr->ulValueLen / 2,
                              ibm_opaque_reenc_attr != NULL ?
                                  ibm_opaque_reenc_attr->pValue : NULL,
                              ibm_opaque_reenc_attr != NULL ?
                                  (ktype != CKK_AES_XTS ?
                                      ibm_opaque_reenc_attr->ulValueLen :
                                      ibm_opaque_reenc_attr->ulValueLen / 2) :
                                  0,
                              keyblob, keyblobsize, rc);
        RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s m_SetAttributeValue failed rc=0x%lx\n",
                        __func__, rc);
            goto out;
        }

        if (ktype == CKK_AES_XTS) {
            RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
            RETRY_UPDATE_BLOB_START(tokdata, target_info,
                                    (CK_BYTE *)ibm_opaque_attr->pValue +
                                         (ibm_opaque_attr->ulValueLen / 2),
                                    ibm_opaque_attr->ulValueLen / 2,
                                    ibm_opaque_reenc_attr != NULL ?
                                      (CK_BYTE *)ibm_opaque_reenc_attr->pValue +
                                      (ibm_opaque_reenc_attr->ulValueLen / 2) :
                                      NULL,
                                    ibm_opaque_reenc_attr != NULL ?
                                        ibm_opaque_reenc_attr->ulValueLen / 2 :
                                        0,
                                    keyblob, keyblobsize);
                rc = dll_m_SetAttributeValue(keyblob, keyblobsize,
                                             attributes, num_attributes,
                                             target_info->target);
            RETRY_UPDATE_BLOB_END(tokdata, session, target_info,
                                  (CK_BYTE *)ibm_opaque_attr->pValue +
                                       (ibm_opaque_attr->ulValueLen / 2),
                                  ibm_opaque_attr->ulValueLen / 2,
                                  ibm_opaque_reenc_attr != NULL ?
                                    (CK_BYTE *)ibm_opaque_reenc_attr->pValue +
                                    (ibm_opaque_reenc_attr->ulValueLen / 2) :
                                    NULL,
                                  ibm_opaque_reenc_attr != NULL ?
                                      ibm_opaque_reenc_attr->ulValueLen / 2 :
                                      0,
                                  keyblob, keyblobsize, rc);
            RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

            if (rc != CKR_OK) {
                rc = ep11_error_to_pkcs11_error(rc, NULL);
                TRACE_ERROR("%s m_SetAttributeValue failed rc=0x%lx\n",
                            __func__, rc);
                goto out;
            }
        }

        rc = template_update_attribute(new_tmpl, ibm_opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed rc=0x%lx\n",
                        __func__, rc);
            goto out;
        }
        ibm_opaque_attr = NULL;

        if (ibm_opaque_reenc_attr != NULL) {
            rc = template_update_attribute(new_tmpl, ibm_opaque_reenc_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s template_update_attribute failed rc=0x%lx\n",
                            __func__, rc);
                goto out;
            }
            ibm_opaque_reenc_attr = NULL;
        }
    }

out:
    if (attributes)
        free_attribute_array(attributes, num_attributes);

    if (ibm_opaque_attr != NULL)
        free(ibm_opaque_attr);
    if (ibm_opaque_reenc_attr != NULL)
        free(ibm_opaque_reenc_attr);

    return rc;
}

/*
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
static CK_RV ep11tok_handle_apqn_event(STDLL_TokData_t *tokdata,
                                       unsigned int event_type,
                                       event_udev_apqn_data_t *apqn_data)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_BBOOL found = FALSE;
    CK_RV rc = CKR_OK;
    char name[20];
    int i;

    /* Is it one of the configured APQNs ?*/
    if (ep11_data->target_list.length > 0) {
        /* APQN_WHITELIST or APQN_ALLOWLIST is specified */
        for (i = 0; i < ep11_data->target_list.length; i++) {
            if (ep11_data->target_list.apqns[2 * i] == apqn_data->card &&
                ep11_data->target_list.apqns[2 * i + 1] == apqn_data->domain) {
                found = TRUE;
                break;
            }
        }
    } else {
        /* APQN_ANY is specified */
        found = TRUE;
        if (event_type == EVENT_TYPE_APQN_ADD) {
            snprintf(name, sizeof(name), "card%02x", apqn_data->card);
            if (is_card_ep11_and_online(name) != CKR_OK)
                found = FALSE; /* Not an EP11 APQN */
        }
    }
    if (!found)
        return CKR_OK;

    TRACE_DEVEL("%s Refreshing target infos due to event for APQN %02x.%04x\n",
                __func__, apqn_data->card, apqn_data->domain);

    rc = refresh_target_info(tokdata, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s Failed to get the target infos (refresh_target_info "
                    "rc=0x%lx)\n", __func__, rc);

        if (__sync_fetch_and_or(&ep11_data->inconsistent, 1) == 0) {
            TRACE_ERROR("EP11 APQN setup is inconsistent, all crypto operations "
                        "will fail from now on\n");
            OCK_SYSLOG(LOG_ERR, "EP11 APQN setup is inconsistent, all crypto "
                       "operations will fail from now on\n");
        }
        return rc;
    }

    if (__sync_fetch_and_and(&ep11_data->inconsistent, 0) != 0) {
        TRACE_INFO("EP11 APQN setup is now consistent again\n");
        OCK_SYSLOG(LOG_INFO, "EP11 APQN setup is now consistent again\n");
    }

    /* Re-check after APQN set change if CPACF_WRAP mech is supported */
    if (ep11tok_is_mechanism_supported(tokdata, CKM_IBM_CPACF_WRAP) != CKR_OK) {
        TRACE_INFO("CKM_IBM_CPACF_WRAP not supported on this system.\n");
        if (pthread_mutex_lock(&ep11_data->pkey_mutex)) {
            TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
            return CKR_CANT_LOCK;
        }
        /* Disable pkey */
        __sync_and_and_fetch(&ep11_data->pkey_wrap_supported, 0);
        __sync_and_and_fetch(&ep11_data->pkey_wrap_support_checked, 1);
        if (pthread_mutex_unlock(&ep11_data->pkey_mutex)) {
            TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
        }
    } else if (ep11_data->pkey_wrap_supported == 0 &&
               !ep11tok_pkey_option_disabled(tokdata)) {
        if (pthread_mutex_lock(&ep11_data->pkey_mutex)) {
            TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
            return CKR_CANT_LOCK;
        }
        /* Will be re-checked at next usage attempt */
        __sync_and_and_fetch(&ep11_data->pkey_wrap_support_checked, 0);
        if (pthread_mutex_unlock(&ep11_data->pkey_mutex)) {
            TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
        }
    }

    return CKR_OK;
}

/*
 * Called by the event thread, on receipt of an event.
 *
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
CK_RV token_specific_handle_event(STDLL_TokData_t *tokdata,
                                  unsigned int event_type,
                                  unsigned int event_flags,
                                  const char *payload,
                                  unsigned int payload_len)
{
    UNUSED(event_flags);

    switch (event_type) {
    case EVENT_TYPE_APQN_ADD:
    case EVENT_TYPE_APQN_REMOVE:
        if (payload_len != sizeof(event_udev_apqn_data_t))
            return CKR_FUNCTION_FAILED;
        return ep11tok_handle_apqn_event(tokdata, event_type,
                                         (event_udev_apqn_data_t *)payload);

    case EVENT_TYPE_MK_CHANGE_INITIATE_QUERY:
    case EVENT_TYPE_MK_CHANGE_REENCIPHER:
    case EVENT_TYPE_MK_CHANGE_FINALIZE_QUERY:
    case EVENT_TYPE_MK_CHANGE_FINALIZE:
    case EVENT_TYPE_MK_CHANGE_CANCEL_QUERY:
    case EVENT_TYPE_MK_CHANGE_CANCEL:
        return ep11tok_handle_mk_change_event(tokdata, event_type, event_flags,
                                              payload, payload_len);

    default:
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    return CKR_OK;
}

/*
 * Refreshes the target info using the currently configured and available
 * APQNs. Registers the newly allocated target info as the current one in a
 * thread save way and gives back the previous one so that it is release when
 * no longer used (i.e. by a concurrently running thread).
 */
CK_RV refresh_target_info(STDLL_TokData_t *tokdata, CK_BBOOL wait_for_new_wk)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    volatile ep11_target_info_t *prev_info;
    ep11_target_info_t *target_info;
    CK_RV rc;

    target_info = calloc(1, sizeof(ep11_target_info_t));
    if (target_info == NULL) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    target_info->ref_count = 1;

    /* Get and check the WKVPs freshly with the current set of APQNs */
    rc = ep11tok_check_wkvps(tokdata, target_info);
    if (rc != CKR_OK)
        goto error;

    /* Get the version info freshly with the current set of APQNs */
    rc = ep11tok_get_ep11_version(tokdata, target_info);
    if (rc != CKR_OK)
        goto error;

    /* Get the control points freshly with the current set of APQNs */
    target_info->control_points_len = sizeof(target_info->control_points);
    rc = get_control_points(tokdata, target_info->control_points,
                            &target_info->control_points_len,
                            &target_info->max_control_point_index);
    if (rc != CKR_OK)
        goto error;

    if (ep11_data->mk_change_active) {
        /* MK change active: Setup a single APQN target */
        rc = ep11tok_setup_single_target(tokdata, target_info, wait_for_new_wk);
        if (rc != CKR_OK)
            goto error;
    } else {
        /* Setup the group target freshly with the current set of APQNs */
        rc = ep11tok_setup_target(tokdata, target_info);
        if (rc != CKR_OK)
            goto error;
    }

    /* Set the new one as the current one (locked against concurrent get's) */
    if (pthread_rwlock_wrlock(&ep11_data->target_rwlock) != 0) {
        TRACE_DEVEL("Target Write-Lock failed.\n");
        rc = CKR_CANT_LOCK;
        goto error;
    }

    prev_info = ep11_data->target_info;
    ep11_data->target_info = target_info;

    if (pthread_rwlock_unlock(&ep11_data->target_rwlock) != 0) {
        TRACE_DEVEL("Target Unlock failed.\n");
        return CKR_CANT_LOCK;
    }

    /* Release the previous one */
    if (prev_info != NULL)
        put_target_info(tokdata, (ep11_target_info_t *)prev_info);

    return CKR_OK;

error:
    free_card_versions(target_info->card_versions);
    free((void *)target_info);
    return rc;
}

/*
 * Get the current EP11 target info.
 * Do NOT use the ep11_data->target_info directly, always get a copy using
 * this function. This will increment the reference count of the target info,
 * and return the current target info in a thread save way.
 * When no longer needed, put it back using put_target_info().
 */
ep11_target_info_t *get_target_info(STDLL_TokData_t *tokdata)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    volatile ep11_target_info_t *target_info;
#ifdef DEBUG
    unsigned long ref_count;
#endif

    /*
     * Lock until we have obtained the current target info and have
     * increased the reference counter
     */
    if (pthread_rwlock_rdlock(&ep11_data->target_rwlock) != 0) {
        TRACE_DEVEL("Target Read-Lock failed.\n");
        return NULL;
    }

    target_info = *((void * volatile *)&ep11_data->target_info);
    if (target_info == NULL) {
        TRACE_ERROR("%s: target_info is NULL\n", __func__);
        if (pthread_rwlock_unlock(&ep11_data->target_rwlock) != 0)
            TRACE_DEVEL("Target Unlock failed.\n");
        return NULL;
    }

#ifdef DEBUG
    ref_count = __sync_add_and_fetch(&target_info->ref_count, 1);

    TRACE_DEBUG("%s: target_info: %p ref_count: %lu\n", __func__,
                (void *)target_info, ref_count);
#else
    __sync_add_and_fetch(&target_info->ref_count, 1);
#endif

    if (pthread_rwlock_unlock(&ep11_data->target_rwlock) != 0) {
        TRACE_DEVEL("Target Unlock failed.\n");
        return NULL;
    }

    return (ep11_target_info_t *)target_info;
}

/*
 * Give back an EP11 target info. This will decrement the reference count,
 * and will free it if the reference count reaches zero.
 */
void put_target_info(STDLL_TokData_t *tokdata, ep11_target_info_t *target_info)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    unsigned long ref_count;

    if (target_info == NULL)
        return;

    if (target_info->ref_count > 0) {
        ref_count = __sync_sub_and_fetch(&target_info->ref_count, 1);

        TRACE_DEBUG("%s: target_info: %p ref_count: %lu\n", __func__,
                    (void *)target_info, ref_count);
    } else {
        TRACE_WARNING("%s: target_info: %p ref_count already 0.\n", __func__,
                      (void *)target_info);
        ref_count = 0;
    }

    if (ref_count == 0 && target_info != ep11_data->target_info) {
        TRACE_DEBUG("%s: target_info: %p is freed\n", __func__,
                    (void *)target_info);

        if (dll_m_rm_module != NULL)
            dll_m_rm_module(NULL, target_info->target);
        free_card_versions(target_info->card_versions);
        free(target_info);
    }
}

/*
 * Must be called either with WRITE_LOCK on the object that owns the template
 * specified as @tmpl, or before the object is made publicly available via
 * object_mgr_create_final.
 */
static CK_RV update_ep11_attrs_from_blob(STDLL_TokData_t *tokdata,
                                         SESSION *session, OBJECT *key_obj,
                                         CK_BBOOL aes_xts)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_BBOOL restr = CK_FALSE; /*, never_mod = CK_FALSE; */
    CK_BBOOL attrb = CK_FALSE, useasdata = CK_FALSE;
    CK_BBOOL pkeyextr = CK_FALSE, pkeyneverextr = CK_FALSE;
    CK_ULONG stdcomp1 = 0;
    CK_ATTRIBUTE *attr, *blob_attr = NULL;
    CK_RV rc = CKR_OK;
    CK_ULONG i;
    CK_BYTE *useblob, *blob;
    CK_OBJECT_CLASS class;
    size_t usebloblen;

    CK_ATTRIBUTE ibm_attrs[] = {
        { CKA_IBM_RESTRICTABLE, &restr, sizeof(restr) },
     /* Skip CKA_IBM_NEVER_MODIFIABLE for now, it causes CKR_ARGUMENTS_BAD
        { CKA_IBM_NEVER_MODIFIABLE, &never_mod, sizeof(never_mod) }, */
        { CKA_IBM_USE_AS_DATA, &useasdata, sizeof(useasdata) },
        { CKA_IBM_ATTRBOUND, &attrb, sizeof(attrb) },
        { CKA_IBM_STD_COMPLIANCE1, &stdcomp1, sizeof(stdcomp1) },
        /* PROTKEY attributes must be the last 2 */
        { CKA_IBM_PROTKEY_EXTRACTABLE, &pkeyextr, sizeof(pkeyextr) },
        { CKA_IBM_PROTKEY_NEVER_EXTRACTABLE, &pkeyneverextr,
          sizeof(pkeyneverextr) },
    };
    CK_ULONG num_ibm_attrs = sizeof(ibm_attrs) / sizeof(CK_ATTRIBUTE);

    if (template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                     &class) != CKR_OK) {
        TRACE_ERROR("This key has no CKA_CLASS: should not occur!\n");
        return CKR_FUNCTION_FAILED;
    }

    if (!ep11_data->pkey_wrap_supported || class == CKO_PUBLIC_KEY)
        num_ibm_attrs -= 2;

    if (template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                         &blob_attr) != CKR_OK) {
        TRACE_ERROR("This key has no CKA_IBM_OPAQUE: should not occur!\n");
        return CKR_FUNCTION_FAILED;
    }

    blob = blob_attr->pValue;
    RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)
    RETRY_REENC_BLOB_START(tokdata, target_info, key_obj,
                           blob, blob_attr->ulValueLen,
                           useblob, usebloblen, rc)
        rc = dll_m_GetAttributeValue(useblob,
                                     aes_xts ? usebloblen / 2 : usebloblen,
                                     ibm_attrs, num_ibm_attrs,
                                     target_info->target);
    RETRY_REENC_BLOB_END(tokdata, target_info, useblob, usebloblen, rc)
    RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s m_GetAttributeValue failed rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    /* Set/Update all available attributes in the object's template */
    for (i = 0; i < num_ibm_attrs; i++) {
        if (ibm_attrs[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
            TRACE_DEVEL("%s Attribute 0x%lx not available\n", __func__,
                        ibm_attrs[i].type);
            continue;
        }

        rc = build_attribute(ibm_attrs[i].type, ibm_attrs[i].pValue,
                             ibm_attrs[i].ulValueLen, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
            return rc;
        }

        rc = template_update_attribute(key_obj->template, attr);
        if (rc != CKR_OK) {
            free(attr);
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            return rc;
        }
    }

    return CKR_OK;
}

CK_RV token_specific_check_obj_access(STDLL_TokData_t *tokdata,
                                      OBJECT *obj, CK_BBOOL create)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_OBJECT_CLASS class;
    CK_RV rc;

    UNUSED(create);

    if (ep11_data->fips_session_mode == 0)
        return CKR_OK;

   rc = template_attribute_get_ulong(obj->template, CKA_CLASS, &class);
   if (rc != CKR_OK) {
       TRACE_ERROR("Class attribute not found\n");
       return rc;
   }

   switch (class) {
   case CKO_SECRET_KEY:
   case CKO_PUBLIC_KEY:
   case CKO_PRIVATE_KEY:
       break;
   default:
       return CKR_OK;
   }

   if (!session_mgr_user_session_exists(tokdata))
       return CKR_USER_NOT_LOGGED_IN;

   return CKR_OK;
}
