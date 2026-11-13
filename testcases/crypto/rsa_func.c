/*
 * COPYRIGHT (c) International Business Machines Corp. 2011-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

 /*
  * openCryptoki testcase for RSA
  *
  * August 18, 2011
  *
  * Fionnuala Gunter <fin@linux.vnet.ibm.com>
  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include <openssl/bn.h>

#include "pkcs11types.h"
#include "common.c"
#include "regress.h"
#include "mechtable.h"
#include "mech_to_str.h"

#include "rsa.h"

enum rsa_key_format {
    RSA_KEY_FORMAT_FULL = 0,
    RSA_KEY_FORMAT_ME,
    RSA_KEY_FORMAT_CRT,
};

static const char *rsa_key_format_str(enum rsa_key_format format)
{
    switch (format) {
    case RSA_KEY_FORMAT_ME:
        return " (ME-format)";
    case RSA_KEY_FORMAT_CRT:
        return " (CRT-only)";
    case RSA_KEY_FORMAT_FULL:
    default:
        return "";
    }
}

/**
 * Note: do_EncryptDecryptRSA fails if we don't manually
 * remove padding from decrypted values. This might be a bug.
 **/


/* This function should test:
 * RSA Key Generation, CKM_RSA_PKCS_KEY_PAIR_GEN
 * RSA Encryption, mechanism chosen by caller
 * RSA Decryption, mechanism chosen by caller
 *
 * 1. Generate RSA Key Pair
 * 2. Generate plaintext
 * 3. Encrypt plaintext
 * 4. Decrypt encrypted data
 * 5. Compare plaintext with decrypted data
 *
 */
CK_RV do_EncryptDecryptRSA(struct GENERATED_TEST_SUITE_INFO *tsuite)
{
    unsigned int i, j;
    CK_BYTE original[BIG_REQUEST];
    CK_ULONG original_len;
    CK_BYTE crypt[BIG_REQUEST];
    CK_ULONG crypt_len;
    CK_BYTE decrypt[BIG_REQUEST];
    CK_ULONG decrypt_len;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key, priv_key;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;
    CK_RSA_PKCS_OAEP_PARAMS oaep_params;

    char *s;

    // begin testsuite
    testsuite_begin("%s Encrypt Decrypt.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported_flags(slot_id, tsuite->mech.mechanism,
                              CKF_ENCRYPT | CKF_DECRYPT)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id, tsuite->keygen_mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->keygen_mech.mechanism),
                       (unsigned int) tsuite->keygen_mech.mechanism);
        goto testcase_cleanup;
    }
    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
                          tsuite->tv[i].publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }
        // begin testcase
        testcase_begin("%s Encrypt and Decrypt with test vector %u."
                       "\npubl_exp='%s', modbits=%lu, publ_exp_len=%lu, "
                       "inputlen=%lu.", tsuite->name, i, s,
                       tsuite->tv[i].modbits,
                       tsuite->tv[i].publ_exp_len, tsuite->tv[i].inputlen);

        rc = CKR_OK;            // set rc

        if (tsuite->tv[i].modbits > 4096 && !rsa8k) {
            testcase_skip("Tests with  modbits='%lu' are not enabled",
                          tsuite->tv[i].modbits);
            free(s);
            continue;
        }
        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].modbits);
            free(s);
            continue;
        }

        if (is_ep11_token(slot_id)) {
            if (!is_valid_ep11_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("EP11 Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }
        // cca special cases:
        // cca token can only use a few public exponents
        // so skip test if invalid public exponent is used
        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].publ_exp,
                                     tsuite->tv[i].publ_exp_len)) {
                testcase_skip("CCA Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }

            if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP &&
                 tsuite->tv[i].oaep_params.hashAlg != CKM_SHA_1 &&
                 tsuite->tv[i].oaep_params.hashAlg != CKM_SHA224 &&
                 tsuite->tv[i].oaep_params.hashAlg != CKM_SHA256 &&
                 tsuite->tv[i].oaep_params.hashAlg != CKM_SHA384 &&
                 tsuite->tv[i].oaep_params.hashAlg != CKM_SHA512) {
                 testcase_skip("CCA Token cannot use RSA OAEP with a hash "
                              "algorithm other than SHA1 and SHA2: %s",
                              mech_to_str(tsuite->tv[i].oaep_params.hashAlg));
                 free(s);
                 continue;
             }

            if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP &&
                 tsuite->tv[i].oaep_params.source == CKZ_DATA_SPECIFIED &&
                 tsuite->tv[i].oaep_params.ulSourceDataLen > 0) {
                 testcase_skip("CCA Token cannot use RSA OAEP with non empty "
                               "source data");
                 free(s);
                 continue;
             }
        }

        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("Soft Token cannot be used with publ_exp.='%s'",
                              s);
                free(s);
                continue;
            }
        }
        // tpm special cases:
        // tpm token can only use public exponent 0x010001 (65537)
        // so skip test if invalid public exponent is used
        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].modbits))) {
                testcase_skip("TPM Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }

        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len) ||
                (tsuite->tv[i].modbits < 1024)) {
                testcase_skip("ICSF Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP) {
            if (!mech_supported(slot_id, tsuite->tv[i].oaep_params.hashAlg)) {
                testcase_skip("Slot %u doesn't support OAEP hash alg %s (0x%x)",
                              (unsigned int)slot_id,
                              mech_to_str(tsuite->tv[i].oaep_params.hashAlg),
                              (unsigned int)tsuite->tv[i].oaep_params.hashAlg);
                free(s);
                continue;
            }
        }

        free(s);

        // clear buffers
        memset(original, 0, BIG_REQUEST);
        memset(crypt, 0, BIG_REQUEST);
        memset(decrypt, 0, BIG_REQUEST);

        // get test vector parameters
        original_len = tsuite->tv[i].inputlen;

        // generate key pair
        rc = generate_RSA_PKCS_KeyPair_cached(session,
                                              tsuite->keygen_mech.mechanism,
                                              tsuite->tv[i].modbits,
                                              tsuite->tv[i].publ_exp,
                                              tsuite->tv[i].publ_exp_len,
                                              &publ_key, &priv_key);

        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key generation is not allowed by policy");
                continue;
            }
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key size is not in supported range");
                continue;
            }

            testcase_error("generate_RSA_PKCS_KeyPair_cached(), "
                           "rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // generate plaintext
        for (j = 0; j < original_len; j++) {
            original[j] = (j + 1) % 255;
        }

        // set cipher buffer length
        crypt_len = BIG_REQUEST;
        decrypt_len = BIG_REQUEST;

        // get mech
        mech = tsuite->mech;
        if (mech.mechanism == CKM_RSA_PKCS_OAEP) {
            oaep_params = tsuite->tv[i].oaep_params;
            mech.pParameter = &oaep_params;
            mech.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
        }
        // initialize (public key) encryption
        rc = funcs->C_EncryptInit(session, &mech, publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_ep11_token(slot_id) &&
                (oaep_params.hashAlg != CKM_SHA_1 ||
                 oaep_params.mgf != CKG_MGF1_SHA1)) {
                testcase_skip("EP11 Token does not support RSA OAEP with hash "
                              "and/or MGF other than SHA-1");
                continue;
            }

            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_cca_token(slot_id) &&
                ((oaep_params.hashAlg != CKM_SHA_1 &&
                  oaep_params.hashAlg != CKM_SHA256) ||
                 (oaep_params.mgf != CKG_MGF1_SHA1 &&
                  oaep_params.mgf != CKG_MGF1_SHA256))) {
                testcase_skip("CCA Token does only support RSA OAEP with hash "
                              "and/or MGF other than SHA-1/SHA256 with "
                              "CCA 8.1 or later");
                continue;
            }

            testcase_error("C_EncryptInit, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // do (public key) encryption
        rc = funcs->C_Encrypt(session,
                              original, original_len, crypt, &crypt_len);
        if (rc != CKR_OK) {
            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_cca_token(slot_id) &&
                ((oaep_params.hashAlg != CKM_SHA_1 &&
                  oaep_params.hashAlg != CKM_SHA256) ||
                 (oaep_params.mgf != CKG_MGF1_SHA1 &&
                  oaep_params.mgf != CKG_MGF1_SHA256))) {
                testcase_skip("CCA Token does only support RSA OAEP with hash "
                              "and/or MGF other than SHA-1/SHA256 with "
                              "CCA 8.1 or later");
                continue;
            }

            testcase_error("C_Encrypt, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // initialize (private key) decryption
        rc = funcs->C_DecryptInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // do (private key) decryption
        rc = funcs->C_Decrypt(session, crypt, crypt_len, decrypt, &decrypt_len);
        if (rc != CKR_OK) {
            testcase_error("C_Decrypt, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // FIXME: there shouldn't be any padding here
        // remove padding if mech is CKM_RSA_X_509
        if (mech.mechanism == CKM_RSA_X_509) {
            memmove(decrypt,
                    decrypt + decrypt_len - original_len, original_len);
            decrypt_len = original_len;
        }
        // check results
        testcase_new_assertion();

        if (decrypt_len != original_len) {
            testcase_fail("decrypted length does not match"
                          "original data length.\n expected length = %lu,"
                          "but found length=%lu.\n", original_len, decrypt_len);
        } else if (memcmp(decrypt, original, original_len)) {
            testcase_fail("decrypted data does not match " "original data.");
        } else {
            testcase_pass("C_Encrypt and C_Decrypt.");
        }

    }

    goto testcase_cleanup;

testcase_cleanup:
    free_rsa_key_cache(session);
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions, rc=%s", p11_get_ckr(loc_rc));
    }

    return rc;
}

/**
 * Note: do_EncryptDecryptImportRSA fails if we don't manually
 * remove padding from decrypted values. This might be a bug.
 **/


/* This function should test:
 * RSA Key Import
 * RSA Encryption, mechanism chosen by caller
 * RSA Decryption, mechanism chosen by caller
 *
 * 1. Import RSA Key Pair
 * 2. Generate plaintext
 * 3. Encrypt plaintext
 * 4. Decrypt encrypted data
 * 5. Compare plaintext with decrypted data
 *
 */
CK_RV do_EncryptDecryptImportRSA(struct PUBLISHED_TEST_SUITE_INFO *tsuite,
                                 enum rsa_key_format format)
{
    unsigned int i, j;
    CK_BYTE original[BIG_REQUEST];
    CK_ULONG original_len;
    CK_BYTE crypt[BIG_REQUEST];
    CK_ULONG crypt_len;
    CK_BYTE decrypt[BIG_REQUEST];
    CK_ULONG decrypt_len;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    char *s;

    // begin testsuite
    testsuite_begin("%s Encrypt Decrypt Import%s.", tsuite->name,
                    rsa_key_format_str(format));
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    if (is_icsf_token(slot_id) && format != RSA_KEY_FORMAT_FULL) {
        testsuite_skip(tsuite->tvcount,
                       "ICSF Token does not support RSA private keys in "
                       "ME-only or CRT-only format");
        goto testcase_cleanup;
    }

    if (is_cca_token(slot_id) && tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP) {
        if (((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->hashAlg !=
                                                                CKM_SHA_1 &&
            ((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->hashAlg !=
                                                                CKM_SHA224 &&
            ((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->hashAlg !=
                                                                CKM_SHA256 &&
            ((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->hashAlg !=
                                                                CKM_SHA384 &&
            ((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->hashAlg !=
                                                                CKM_SHA512) {
             testcase_skip("CCA Token cannot use RSA OAEP with a hash "
                          "algorithm other than SHA1 and SHA2: %s",
                          mech_to_str(((CK_RSA_PKCS_OAEP_PARAMS *)
                                          tsuite->mech.pParameter)->hashAlg));
             goto testcase_cleanup;
         }

        if (((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->source ==
                                                        CKZ_DATA_SPECIFIED &&
            ((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->ulSourceDataLen
                                                        > 0) {
             testcase_skip("CCA Token cannot use RSA OAEP with non empty "
                           "source data");
             goto testcase_cleanup;
         }
    }

    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].pub_exp,
                          tsuite->tv[i].pubexp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }
        // begin testcase
        testcase_begin("%s Encrypt and Decrypt Import with test vector %u%s."
                       "\npubl_exp='%s', modbits=%lu, publ_exp_len=%lu.",
                       tsuite->name, i, rsa_key_format_str(format), s,
                       tsuite->tv[i].mod_len * 8,
                       tsuite->tv[i].pubexp_len);

        rc = CKR_OK;            // set rc

        if (tsuite->tv[i].mod_len * 8 > 4096 && !rsa8k) {
            testcase_skip("Tests with  modbits='%lu' are not enabled",
                          tsuite->tv[i].mod_len * 8);
            free(s);
            continue;
        }
        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].mod_len * 8)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].mod_len * 8);
            free(s);
            continue;
        }

        if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP &&
            ((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->hashAlg ==
                                                                   CKM_SHA512 &&
            tsuite->tv[i].mod_len * 8 <= 1024) {
            testcase_skip("OAEP with SHA512 cannot be used with modbits='%lu'",
                          tsuite->tv[i].mod_len * 8);
            free(s);
            continue;
        }

        if (is_ep11_token(slot_id) || is_icsf_token(slot_id)) {
            if (!is_valid_ep11_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len)) {
                testcase_skip("EP11/ICSF Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
            // modulus length must be multiple of 128 byte
            // skip test if modulus length has unsuported size
            if ((tsuite->tv[i].mod_len % 128) != 0) {
                testcase_skip("EP11/ICSF Token cannot be used with this test vector.");
                free(s);
                continue;
            }
        }

        // special case for ica
        // prime1, prime2, exp1, exp2, coef
        // must be size mod_len/2 or smaller
        // skip test if prime1, or prime2, or exp1,
        // or exp2 or coef are too long
        if (is_ica_token(slot_id)) {
            // check sizes
            if ((tsuite->tv[i].prime1_len >
                 (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].prime2_len >
                 (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].exp1_len >
                 (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].exp2_len >
                 (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].coef_len > (tsuite->tv[i].mod_len / 2))) {
                testcase_skip("ICA Token cannot be used with this test vector.");
                free(s);
                continue;
            }

        }

        // cca special cases:
        // cca token can only use a few public exponents
        // so skip test if invalid public exponent is used
        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].pub_exp,
                                     tsuite->tv[i].pubexp_len)) {
                testcase_skip("CCA Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }

        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len)) {
                testcase_skip("Soft Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }

        // tpm special cases:
        // tpm token can only use public exponent 0x010001 (65537)
        // so skip test if invalid public exponent is used
        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].mod_len * 8))) {
                testcase_skip("TPM Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }

        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len) ||
                (tsuite->tv[i].mod_len * 8 < 1024)) {
                testcase_skip("ICSF Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        free(s);

        if (format == RSA_KEY_FORMAT_CRT && tsuite->tv[i].prime1_len == 0) {
            testcase_skip("Test vector does not have CRT components");
            continue;
        }

        // clear buffers
        memset(original, 0, BIG_REQUEST);
        memset(crypt, 0, BIG_REQUEST);
        memset(decrypt, 0, BIG_REQUEST);

        original_len = 10;

        // create (private) key handle
        rc = create_RSAPrivateKey(session,
                                  tsuite->tv[i].mod,
                                  tsuite->tv[i].pub_exp,
                                  format == RSA_KEY_FORMAT_CRT ? NULL : tsuite->tv[i].priv_exp,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].prime1,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].prime2,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].exp1,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].exp2,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].coef,
                                  tsuite->tv[i].mod_len,
                                  tsuite->tv[i].pubexp_len,
                                  format == RSA_KEY_FORMAT_CRT ? 0 : tsuite->tv[i].privexp_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].prime1_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].prime2_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].exp1_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].exp2_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].coef_len,
                                  &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key import is not allowed by policy");
                continue;
            }
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key size is not in supported range");
                continue;
            }
            if (rc == CKR_MECHANISM_INVALID ||
                rc == CKR_TEMPLATE_INCOMPLETE ||
                rc == CKR_TEMPLATE_INCONSISTENT ||
                rc == CKR_FUNCTION_NOT_SUPPORTED) {
                testcase_skip("RSA key format not supported by token");
                continue;
            }

            testcase_error("create_RSAPrivateKey(), rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // create (public) key handle
        rc = create_RSAPublicKey(session,
                                 tsuite->tv[i].mod,
                                 tsuite->tv[i].pub_exp,
                                 tsuite->tv[i].mod_len,
                                 tsuite->tv[i].pubexp_len, &publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key import is not allowed by policy");
                funcs->C_DestroyObject(session, priv_key);
                continue;
            }
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key size is not in supported range");
                continue;
            }

            testcase_error("create_RSAPublicKey(), rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // generate plaintext
        for (j = 0; j < original_len; j++) {
            original[j] = (j + 1) % 255;
        }

        // set cipher buffer length
        crypt_len = BIG_REQUEST;
        decrypt_len = BIG_REQUEST;

        // get mech
        mech = tsuite->mech;
        // initialize (public key) encryption
        rc = funcs->C_EncryptInit(session, &mech, publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_ep11_token(slot_id) &&
                (((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->hashAlg !=
                                                             CKM_SHA_1 ||
                 ((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->mgf !=
                                                             CKG_MGF1_SHA1)) {
                testcase_skip("EP11 Token does not support RSA OAEP with hash "
                              "and/or MGF other than SHA-1");
                goto tv_cleanup;
            }

            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_cca_token(slot_id) &&
                ((((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->hashAlg !=
                                                                CKM_SHA_1 &&
                  ((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->hashAlg !=
                                                                 CKM_SHA256) ||
                 (((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->mgf !=
                                                             CKG_MGF1_SHA1 &&
                  ((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->mgf !=
                                                             CKG_MGF1_SHA256))) {
                testcase_skip("CCA Token does only support RSA OAEP with hash "
                              "and/or MGF other than SHA-1/SHA256 with "
                              "CCA 8.1 or later");
                goto tv_cleanup;
            }

            testcase_error("C_EncryptInit, rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
        }
        // do (public key) encryption
        rc = funcs->C_Encrypt(session,
                              original, original_len, crypt, &crypt_len);
        if (rc != CKR_OK) {
            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_cca_token(slot_id) &&
                ((((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->hashAlg !=
                                                                CKM_SHA_1 &&
                  ((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->hashAlg !=
                                                                 CKM_SHA256) ||
                 (((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->mgf !=
                                                             CKG_MGF1_SHA1 &&
                  ((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->mgf !=
                                                             CKG_MGF1_SHA256))) {
                testcase_skip("CCA Token does only support RSA OAEP with hash "
                              "and/or MGF other than SHA-1/SHA256 with "
                              "CCA 8.1 or later");
                goto tv_cleanup;
            } else if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key size is not in supported range");
                continue;
            }

            testcase_error("C_Encrypt, rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
        }
        // initialize (private key) decryption
        rc = funcs->C_DecryptInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit, rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
        }
        // do (private key) decryption
        rc = funcs->C_Decrypt(session, crypt, crypt_len, decrypt, &decrypt_len);
        if (rc != CKR_OK) {
            testcase_error("C_Decrypt, rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
        }
        // FIXME: there shouldn't be any padding here
        // remove padding if mech is CKM_RSA_X_509
        if (mech.mechanism == CKM_RSA_X_509) {
            memmove(decrypt,
                    decrypt + decrypt_len - original_len, original_len);
            decrypt_len = original_len;
        }
        // check results
        testcase_new_assertion();

        if (decrypt_len != original_len) {
            testcase_fail("decrypted length does not match"
                          "original data length.\n expected length = %lu,"
                          "but found length=%lu.\n", original_len, decrypt_len);
        } else if (memcmp(decrypt, original, original_len)) {
            testcase_fail("decrypted data does not match " "original data.");
        } else {
            testcase_pass("C_Encrypt and C_Decrypt%s.",
                          rsa_key_format_str(format));
        }

        // clean up
tv_cleanup:
        rc = funcs->C_DestroyObject(session, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }

        rc = funcs->C_DestroyObject(session, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }
    }

    goto testcase_cleanup;
error:
    loc_rc = funcs->C_DestroyObject(session, publ_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }

    loc_rc = funcs->C_DestroyObject(session, priv_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }

testcase_cleanup:
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions, rc=%s", p11_get_ckr(loc_rc));
    }

    return rc;
}

/* This function should test:
 * RSA Key Generation, usign CKM_RSA_PKCS_KEY_PAIR_GEN
 * RSA Sign, mechanism chosen by caller
 * RSA Verify, mechanism chosen by caller
 *
 * 1. Generate RSA Key Pair
 * 2. Generate message
 * 3. Sign message
 * 4. Verify signature
 *
 */
CK_RV do_SignVerifyRSA(struct GENERATED_TEST_SUITE_INFO * tsuite,
                       CK_BBOOL recover_mode)
{
    unsigned int i;                      // test vector index
    unsigned int j;                      // message byte index
    CK_BYTE message[MAX_MESSAGE_SIZE];
    CK_ULONG message_len;
    CK_BYTE signature[MAX_SIGNATURE_SIZE];
    CK_ULONG signature_len, siglen_small;
    CK_BYTE out_message[MAX_MESSAGE_SIZE];
    CK_ULONG out_message_len;

    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key, priv_key;

    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc;

    char *s;

    // begin testsuite
    testsuite_begin("%s Sign%s Verify%s.", tsuite->name,
                    recover_mode ? "Recover" : "",
                    recover_mode ? "Recover" : "");
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id, tsuite->keygen_mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->keygen_mech.mechanism),
                       (unsigned int) tsuite->keygen_mech.mechanism);
        goto testcase_cleanup;
    }
    if (recover_mode) {
        if (!mech_supported_flags(slot_id, tsuite->mech.mechanism,
                                  CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER)) {
            testsuite_skip(tsuite->tvcount,
                           "Slot %u doesn't support Sign/VerifyRecover with %s (0x%x)",
                           (unsigned int) slot_id,
                           mech_to_str(tsuite->mech.mechanism),
                           (unsigned int) tsuite->mech.mechanism);
            goto testcase_cleanup;
        }
    }
    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
                          tsuite->tv[i].publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }
        // begin test
        testcase_begin("%s Sign%s and Verify%s with test vector %u, "
                       "\npubl_exp='%s', mod_bits='%lu', keylen='%lu'.",
                       tsuite->name, recover_mode ? "Recover" : "",
                       recover_mode ? "Recover" : "", i, s,
                       tsuite->tv[i].modbits, tsuite->tv[i].keylen);

        if (tsuite->tv[i].modbits > 4096 && !rsa8k) {
            testcase_skip("Tests with  modbits='%lu' are not enabled",
                          tsuite->tv[i].modbits);
            free(s);
            continue;
        }
        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].modbits);
            free(s);
            continue;
        }

        if (is_ep11_token(slot_id)) {
            if (!is_valid_ep11_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("EP11 Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }

        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].publ_exp,
                                     tsuite->tv[i].publ_exp_len)) {
                testcase_skip("CCA Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("Soft Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].modbits))) {
                testcase_skip("TPM Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len) ||
                (tsuite->tv[i].modbits < 1024)) {
                testcase_skip("ICSF Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (tsuite->tv[i].modbits <= 512 &&
            (tsuite->mech.mechanism == CKM_SHA384_RSA_PKCS ||
             tsuite->mech.mechanism == CKM_SHA512_RSA_PKCS ||
             tsuite->mech.mechanism == CKM_SHA3_384_RSA_PKCS ||
             tsuite->mech.mechanism == CKM_SHA3_512_RSA_PKCS)) {
            testcase_skip("Mechanism %s can not be used with a key with mod_bits='%lu'.",
                          mech_to_str(tsuite->mech.mechanism),
                          tsuite->tv[i].modbits);
            free(s);
            continue;
        }

        // free memory
        free(s);

        rc = CKR_OK;            // set rc

        // clear buffers
        memset(message, 0, MAX_MESSAGE_SIZE);
        memset(signature, 0, MAX_SIGNATURE_SIZE);
        memset(out_message, 0, MAX_MESSAGE_SIZE);

        // get test vector parameters
        message_len = tsuite->tv[i].inputlen;

        // generate key pair
        rc = generate_RSA_PKCS_KeyPair_cached(session,
                                              tsuite->keygen_mech.mechanism,
                                              tsuite->tv[i].modbits,
                                              tsuite->tv[i].publ_exp,
                                              tsuite->tv[i].publ_exp_len,
                                              &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key generation is not allowed by policy");
                continue;
            }
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key size is not in supported range");
                continue;
            }

            testcase_error("generate_RSA_PKCS_KeyPair_cached(), "
                           "rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // generate message
        for (j = 0; j < message_len; j++) {
            message[j] = (j + 1) % 255;
        }

        // get  mech
        mech = tsuite->mech;

        // initialize Sign (length only)
        if (recover_mode)
            rc = funcs->C_SignRecoverInit(session, &mech, priv_key);
        else
            rc = funcs->C_SignInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_Sign%sInit(), rc=%s",
                           recover_mode ? "Recover" : "", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        /* a too small buffer must not terminate the operation */
        testcase_new_assertion();
        siglen_small = 1;
        if (recover_mode)
            rc = funcs->C_SignRecover(session, message, message_len,
                                      signature, &siglen_small);
        else
            rc = funcs->C_Sign(session, message, message_len,
                               signature, &siglen_small);
        if (rc != CKR_BUFFER_TOO_SMALL ||
            siglen_small != (tsuite->tv[i].modbits / 8)) {
            testcase_fail("C_Sign%s with too small buffer: expected "
                          "CKR_BUFFER_TOO_SMALL with length %lu, got rc=%s, "
                          "length %lu.", recover_mode ? "Recover" : "",
                          tsuite->tv[i].modbits / 8, p11_get_ckr(rc),
                          siglen_small);
            goto testcase_cleanup;
        }
        testcase_pass("C_Sign%s with too small buffer.",
                      recover_mode ? "Recover" : "");

        // set buffer size
        signature_len = MAX_SIGNATURE_SIZE;

        // do Sign
        if (recover_mode)
            rc = funcs->C_SignRecover(session, message, message_len,
                                     signature, &signature_len);
        else
            rc = funcs->C_Sign(session, message, message_len,
                               signature, &signature_len);
        if (rc != CKR_OK) {
            testcase_error("C_Sign%s(), rc=%s signature len=%lu",
                           recover_mode ? "Recover" : "",
                           p11_get_ckr(rc), signature_len);
            goto testcase_cleanup;
        }
        // initialize Verify
        if (recover_mode)
            rc = funcs->C_VerifyRecoverInit(session, &mech, publ_key);
        else
            rc = funcs->C_VerifyInit(session, &mech, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_Verify%sInit(), rc=%s",
                           recover_mode ? "Recover" : "", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // do Verify
        if (recover_mode) {
            out_message_len = sizeof(out_message);
            rc = funcs->C_VerifyRecover(session, signature, signature_len,
                                        out_message, &out_message_len);
        } else {
            rc = funcs->C_Verify(session, message, message_len,
                                 signature, signature_len);
        }

        // check results
        testcase_new_assertion();
        if (rc == CKR_OK) {
            if (recover_mode) {
                if (mech.mechanism == CKM_RSA_X_509) {
                    // out_message may have been left padded with binary zeros
                    if (memcmp(&message[out_message_len - message_len],
                               out_message, message_len) != 0) {
                        testcase_fail("C_VerifyRecover() message does not match");
                    } else {
                        testcase_pass("C_VerifyRecover.");
                    }
                } else {
                    if (out_message_len != message_len ||
                            memcmp(message, out_message, message_len) != 0) {
                        testcase_fail("C_VerifyRecover() message does not match");
                    } else {
                        testcase_pass("C_VerifyRecover.");
                    }
                }
            } else {
                testcase_pass("C_Verify.");
            }
        } else {
            testcase_fail("C_Verify%s(), rc=%s", recover_mode ? "Recover" : "",
                          p11_get_ckr(rc));
        }

    }

testcase_cleanup:
    free_rsa_key_cache(session);
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloesAllSessions, rc=%s", p11_get_ckr(rc));
    }

    return rc;
}


/* This function should test:
 * RSA Key Generation, usign CKM_RSA_PKCS_KEY_PAIR_GEN
 * RSA-PSS Sign, mechanism chosen by caller
 * RSA-PSS Verify, mechanism chosen by caller
 *
 * 1. Generate RSA Key Pair
 * 2. Generate message
 * 3. Generate hash for the message if required by mechanism.
 * 4. Sign message
 * 5. Verify signature
 *
 */
#define MAX_HASH_SIZE 64
CK_RV do_SignVerify_RSAPSS(struct GENERATED_TEST_SUITE_INFO * tsuite)
{
    unsigned int i;                      // test vector index
    unsigned int j;                      // message byte index
    CK_BYTE message[MAX_MESSAGE_SIZE];
    CK_BYTE signature[MAX_SIGNATURE_SIZE];
    CK_BYTE hash[MAX_HASH_SIZE];
    CK_ULONG message_len, signature_len, siglen_small, h_len;

    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key, priv_key;

    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc;
    CK_RSA_PKCS_PSS_PARAMS pss_params;

    char *s;

    // begin testsuite
    testsuite_begin("%s Sign Verify.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id, tsuite->keygen_mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->keygen_mech.mechanism),
                       (unsigned int) tsuite->keygen_mech.mechanism);
        goto testcase_cleanup;
    }
    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
                          tsuite->tv[i].publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }
        // begin test
        testcase_begin("%s Sign and Verify with test vector %u, "
                       "\npubl_exp='%s', mod_bits='%lu', keylen='%lu'.",
                       tsuite->name, i, s,
                       tsuite->tv[i].modbits, tsuite->tv[i].keylen);

        if (tsuite->tv[i].modbits > 4096 && !rsa8k) {
            testcase_skip("Tests with  modbits='%lu' are not enabled",
                          tsuite->tv[i].modbits);
            free(s);
            continue;
        }
        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].modbits);
            free(s);
            continue;
        }
        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].publ_exp,
                                     tsuite->tv[i].publ_exp_len)) {
                testcase_skip("CCA Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }
        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("Soft Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }
        // free memory
        free(s);

        rc = CKR_OK;            // set rc

        // clear buffers
        memset(message, 0, MAX_MESSAGE_SIZE);
        memset(signature, 0, MAX_SIGNATURE_SIZE);

        // get test vector parameters
        message_len = tsuite->tv[i].inputlen;

        // generate key pair
        rc = generate_RSA_PKCS_KeyPair_cached(session,
                                              tsuite->keygen_mech.mechanism,
                                              tsuite->tv[i].modbits,
                                              tsuite->tv[i].publ_exp,
                                              tsuite->tv[i].publ_exp_len,
                                              &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key generation is not allowed by policy");
                continue;
            }
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key size is not in supported range");
                continue;
            }

            testcase_error("generate_RSA_PKCS_KeyPair_cached(), "
                           "rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // generate message
        for (j = 0; j < message_len; j++) {
            message[j] = (j + 1) % 255;
        }

        if (tsuite->mech.mechanism == CKM_RSA_PKCS_PSS) {
            // create digest of message to pass to C_Sign
            mech.mechanism = tsuite->tv[i].pss_params.hashAlg;
            mech.pParameter = 0;
            mech.ulParameterLen = 0;

            h_len = MAX_HASH_SIZE;

            if (!mech_supported(slot_id, mech.mechanism)) {
                testcase_skip("Slot %u doesn't support %s (0x%x)",
                              (unsigned int)slot_id,
                              mech_to_str(mech.mechanism),
                              (unsigned int)mech.mechanism);
                continue;
            }

            rc = funcs->C_DigestInit(session, &mech);
            if (rc != CKR_OK) {
                testcase_error("C_DigestInit rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }
            rc = funcs->C_Digest(session, message, message_len, hash, &h_len);
            if (rc != CKR_OK) {
                testcase_error("C_Digest rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }
        }
        // set mechanism for signing
        mech = tsuite->mech;
        pss_params = tsuite->tv[i].pss_params;
        mech.pParameter = &pss_params;
        mech.ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);

        // initialize Sign
        rc = funcs->C_SignInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_SignInit(), rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        /* a too small buffer must not terminate the operation */
        testcase_new_assertion();
        siglen_small = 1;
        if (mech.mechanism == CKM_RSA_PKCS_PSS)
            rc = funcs->C_Sign(session, hash, h_len, signature, &siglen_small);
        else
            rc = funcs->C_Sign(session, message, message_len,
                               signature, &siglen_small);
        if (rc != CKR_BUFFER_TOO_SMALL ||
            siglen_small != (tsuite->tv[i].modbits / 8)) {
            testcase_fail("C_Sign with too small buffer: expected "
                          "CKR_BUFFER_TOO_SMALL with length %lu, got rc=%s, "
                          "length %lu.", tsuite->tv[i].modbits / 8,
                          p11_get_ckr(rc), siglen_small);
            goto testcase_cleanup;
        }
        testcase_pass("C_Sign with too small buffer.");

        // set buffer size
        signature_len = MAX_SIGNATURE_SIZE;

        // do Sign
        if (mech.mechanism == CKM_RSA_PKCS_PSS)
            rc = funcs->C_Sign(session, hash, h_len, signature, &signature_len);
        else
            rc = funcs->C_Sign(session, message, message_len,
                               signature, &signature_len);
        if (rc != CKR_OK) {
            testcase_error("C_Sign(), rc=%s signature len=%lu",
                           p11_get_ckr(rc), signature_len);
            goto testcase_cleanup;
        }
        // initialize Verify
        rc = funcs->C_VerifyInit(session, &mech, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_VerifyInit(), rc=%s", p11_get_ckr(rc));
        }
        // do Verify
        if (mech.mechanism == CKM_RSA_PKCS_PSS)
            rc = funcs->C_Verify(session, hash, h_len, signature,
                                 signature_len);
        else
            rc = funcs->C_Verify(session, message, message_len,
                                 signature, signature_len);

        // check results
        testcase_new_assertion();
        if (rc == CKR_OK)
            testcase_pass("C_Verify.");
        else
            testcase_fail("C_Verify(), rc=%s", p11_get_ckr(rc));
    }

testcase_cleanup:
    free_rsa_key_cache(session);
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloesAllSessions, rc=%s", p11_get_ckr(rc));
    }

    return rc;
}


/* This function should test:
 * RSA Key Generation, using CKM_PKCS_KEY_PAIR_GEN
 * RSA Public-Key Wrap
 * RSA Private-Key Unwrap
 *
 */
CK_RV do_WrapUnwrapRSA(struct GENERATED_TEST_SUITE_INFO * tsuite)
{
    unsigned int i = 0, j = 0;
    char *s = NULL;
    CK_OBJECT_HANDLE publ_key, priv_key, secret_key, unwrapped_key;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_ULONG wrapped_keylen, unwrapped_keylen = 0;
    CK_MECHANISM wrap_mech, keygen_mech, mech;
    CK_BYTE clear[32], cipher[32], re_cipher[32];
    CK_ULONG cipher_len = 32, re_cipher_len = 32;
    CK_RSA_PKCS_OAEP_PARAMS oaep_params;
    CK_RSA_AES_KEY_WRAP_PARAMS rsa_aeskw_params;

    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type;
    CK_ATTRIBUTE unwrap_tmpl[] = {
        {CKA_CLASS, &key_class, sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE, &key_type, sizeof(CK_KEY_TYPE)},
        {CKA_VALUE_LEN, &unwrapped_keylen, sizeof(CK_ULONG)}
    };
    CK_ULONG unwrap_tmpl_len;

    // begin test suite
    testsuite_begin("%s Wrap Unwrap.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* create some data */
    for (j = 0; j < 32; j++)
        clear[j] = j;

    // skip all tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    } else if (!wrap_supported(slot_id, tsuite->mech)) {
        // skip all tests if the slot doesn't support wrapping
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support key wrapping",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id, tsuite->keygen_mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->keygen_mech.mechanism),
                       (unsigned int) tsuite->keygen_mech.mechanism);
        goto testcase_cleanup;
    }

    for (i = 0; i < tsuite->tvcount; i++) {
        // skip if the slot doesn't support the keygen mechanism
        if (!mech_supported(slot_id, tsuite->tv[i].keytype.mechanism)) {
            testcase_skip("Slot %u doesn't support %s (0x%x)",
                          (unsigned int) slot_id,
                          mech_to_str(tsuite->tv[i].keytype.mechanism),
                          (unsigned int) tsuite->tv[i].keytype.mechanism);
            continue;
        }

        if (tsuite->tv[i].modbits > 4096 && !rsa8k) {
            testcase_skip("Tests with  modbits='%lu' are not enabled",
                          tsuite->tv[i].modbits);
            continue;
        }
        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].modbits);
            continue;
        }
        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
                          tsuite->tv[i].publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }

        if (is_ep11_token(slot_id)) {
            if (!is_valid_ep11_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("EP11 Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }
        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len) ||
                (tsuite->tv[i].modbits < 1024)) {
                testcase_skip("ICSF Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }
        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) ||
                (!is_valid_tpm_modbits(tsuite->tv[i].modbits))) {
                testcase_skip("TPM Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
           }
        }
        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].publ_exp,
                                     tsuite->tv[i].publ_exp_len)) {
                testcase_skip("CCA Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }

            if (tsuite->tv[i].keytype.mechanism == CKM_GENERIC_SECRET_KEY_GEN) {
                testcase_skip("CCA Token cannot wrap CKK_GENERIC_SECRET keys");
                free(s);
                continue;
            }

            if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP &&
                tsuite->tv[i].oaep_params.hashAlg != CKM_SHA_1 &&
                tsuite->tv[i].oaep_params.hashAlg != CKM_SHA256) {
                testcase_skip("CCA Token cannot use RSA OAEP with a hash "
                             "algorithm other than SHA1 and SHA256: %s",
                             mech_to_str(tsuite->tv[i].oaep_params.hashAlg));
                free(s);
                continue;
            }

            if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP &&
                 tsuite->tv[i].oaep_params.source == CKZ_DATA_SPECIFIED &&
                 tsuite->tv[i].oaep_params.ulSourceDataLen > 0) {
                 testcase_skip("CCA Token cannot use RSA OAEP with non empty "
                               "source data");
                 free(s);
                 continue;
             }

            if (tsuite->mech.mechanism == CKM_RSA_AES_KEY_WRAP &&
                (tsuite->tv[i].keytype.mechanism != CKM_AES_KEY_GEN ||
                 tsuite->tv[i].oaep_params.hashAlg != CKM_SHA_1 ||
                 tsuite->tv[i].oaep_params.mgf != CKG_MGF1_SHA1 ||
                 (tsuite->tv[i].oaep_params.source == CKZ_DATA_SPECIFIED &&
                 tsuite->tv[i].oaep_params.ulSourceDataLen > 0))) {
                 testcase_skip("CCA Token cannot use RSA AES keywrap with "
                               "OAEP params other than SHA-1 and empty source "
                               "data");
                 free(s);
                 continue;
             }
        }
        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("Soft Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP) {
            if (!mech_supported(slot_id, tsuite->tv[i].oaep_params.hashAlg)) {
                testcase_skip("Slot %u doesn't support OAEP hash alg %s (0x%x)",
                              (unsigned int)slot_id,
                              mech_to_str(tsuite->tv[i].oaep_params.hashAlg),
                              (unsigned int)tsuite->tv[i].oaep_params.hashAlg);
                free(s);
                continue;
            }
        }

        // begin test
        testcase_begin("%s Wrap Unwrap with test vector %u, "
                       "\npubl_exp='%s', mod_bits='%lu', keylen='%lu', "
                       "keytype='%s'", tsuite->name, i, s,
                       tsuite->tv[i].modbits, tsuite->tv[i].keylen,
                       p11_get_ckm(&mechtable_funcs,
                                   tsuite->tv[i].keytype.mechanism));

        // free memory
        if (s)
            free(s);

        // get key gen mechanism
        keygen_mech = tsuite->tv[i].keytype;

        if (!mech_supported(slot_id, keygen_mech.mechanism)) {
            testcase_skip("Slot %u doesn't support %s (0x%x)",
                          (unsigned int)slot_id,
                          mech_to_str(keygen_mech.mechanism),
                          (unsigned int)keygen_mech.mechanism);
            continue;
        }
        if (keygen_mech.mechanism == CKM_AES_XTS_KEY_GEN &&
            (is_ep11_token(slot_id) || is_cca_token(slot_id))) {
            testcase_skip("Skip test as CKM_AES_XTS_KEY_GEN is supported " \
                          "only for protected keys in EP11 and CCA token");
            continue;
        }
        // get wrapping mechanism
        wrap_mech = tsuite->mech;
        if (wrap_mech.mechanism == CKM_RSA_PKCS_OAEP) {
            oaep_params = tsuite->tv[i].oaep_params;
            wrap_mech.pParameter = &oaep_params;
            wrap_mech.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
        } else if (wrap_mech.mechanism == CKM_RSA_AES_KEY_WRAP) {
            rsa_aeskw_params.ulAESKeyBits = 256;
            rsa_aeskw_params.pOAEPParams = &tsuite->tv[i].oaep_params;
            wrap_mech.pParameter = &rsa_aeskw_params;
            wrap_mech.ulParameterLen = sizeof(CK_RSA_AES_KEY_WRAP_PARAMS);
        }

        if (!mech_supported(slot_id, wrap_mech.mechanism)) {
            testcase_skip("Slot %u doesn't support %s (0x%x)",
                          (unsigned int)slot_id,
                          mech_to_str(wrap_mech.mechanism),
                          (unsigned int)wrap_mech.mechanism);
            continue;
        }

        // clear out buffers
        memset(cipher, 0, sizeof(cipher));
        memset(re_cipher, 0, sizeof(re_cipher));

        // initialize buffer lengths
        wrapped_keylen = 0;

        // generate RSA key pair
        rc = generate_RSA_PKCS_KeyPair_cached(session,
                                              tsuite->keygen_mech.mechanism,
                                              tsuite->tv[i].modbits,
                                              tsuite->tv[i].publ_exp,
                                              tsuite->tv[i].publ_exp_len,
                                              &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key generation is not allowed by policy");
                continue;
            }
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key size is not in supported range");
                continue;
            }

            testcase_error("C_GenerateKeyPair() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // generate secret key
        rc = generate_SecretKey(session, tsuite->tv[i].keylen,
                                &keygen_mech, &secret_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("Generic secret key generation is not allowed by policy");
                funcs->C_DestroyObject(session, priv_key);
                continue;
            }
            testcase_error("generate_SecretKey(), rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /* Testcase Goals:
         * 1. Encrypt data.
         * 2. Use RSA to wrap the secret key we just used to encrypt.
         * 3. Use RSA to unwrap the secret key.
         * 4. Decrypt with the newly unwrapped key to get original data.
         *
         * The first assertion will be the success of RSA to wrap and
         * unwrap the secret key.
         * The second assertion will be the success of the unwrapped
         * key to decrypt the original text.
         * Note: Generic secret keys are not used for encrypt/decrypt
         *       by default. So they will not be included in second
         *       assertion.
         */
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        if (keygen_mech.mechanism != CKM_GENERIC_SECRET_KEY_GEN) {
            switch (keygen_mech.mechanism) {
            case CKM_AES_KEY_GEN:
                mech.mechanism = CKM_AES_CBC;
                mech.ulParameterLen = AES_IV_SIZE;
                mech.pParameter = &aes_iv;
                key_type = CKK_AES;
                break;
            case CKM_AES_XTS_KEY_GEN:
                mech.mechanism = CKM_AES_XTS;
                mech.ulParameterLen = AES_IV_SIZE;
                mech.pParameter = &aes_iv;
                key_type = CKK_AES_XTS;
                break;
            case CKM_DES3_KEY_GEN:
                mech.mechanism = CKM_DES3_CBC;
                mech.ulParameterLen = DES_IV_SIZE;
                mech.pParameter = &des_iv;
                key_type = CKK_DES3;
                break;
            case CKM_DES_KEY_GEN:
                mech.mechanism = CKM_DES_CBC;
                mech.ulParameterLen = DES_IV_SIZE;
                mech.pParameter = &des_iv;
                key_type = CKK_DES;
                break;
            default:
                testcase_error("unknown mech");
                goto error;
            }

            if (!mech_supported(slot_id, mech.mechanism)) {
                testcase_skip("Slot %u doesn't support %s (0x%x)",
                              (unsigned int) slot_id,
                              mech_to_str(mech.mechanism),
                              (unsigned int)mech.mechanism);
                goto tv_cleanup;
            }

            rc = funcs->C_EncryptInit(session, &mech, secret_key);
            if (rc != CKR_OK) {
                testcase_error("C_EncryptInit secret_key "
                               ": rc = %s", p11_get_ckr(rc));
                goto error;
            }

            rc = funcs->C_Encrypt(session, clear, 32, cipher, &cipher_len);
            if (rc != CKR_OK) {
                testcase_error("C_Encrypt secret_key: rc = %s",
                               p11_get_ckr(rc));
                goto error;
            }
        } else {
            key_type = CKK_GENERIC_SECRET;
        }

        // wrap key (length only)
        rc = funcs->C_WrapKey(session, &wrap_mech, publ_key, secret_key,
                              NULL, &wrapped_keylen);
        if (rc != CKR_OK) {
            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                wrap_mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_ep11_token(slot_id) &&
                (oaep_params.hashAlg != CKM_SHA_1 ||
                 oaep_params.mgf != CKG_MGF1_SHA1)) {
                testcase_skip("EP11 Token does not support RSA OAEP with hash "
                              "and/or MGF other than SHA-1");
                goto tv_cleanup;
            }
            if (rc == CKR_KEY_NOT_WRAPPABLE && is_cca_token(slot_id)) {
                testcase_skip("CCA Token does not support to wrap %s keys "
                              "with %s",
                              wrap_mech.mechanism == CKM_RSA_AES_KEY_WRAP ?
                                                      "DATA" : "CIPHER",
                              mech_to_str(wrap_mech.mechanism));
                goto tv_cleanup;
            }
            if (rc == CKR_WRAPPING_KEY_SIZE_RANGE &&
                wrap_mech.mechanism == CKM_RSA_AES_KEY_WRAP) {
                testcase_skip("%s: Cannot wrap a temporary AES key of size %lu "
                              "with the given RSA key size and OAEP parameters",
                              mech_to_str(wrap_mech.mechanism),
                              rsa_aeskw_params.ulAESKeyBits);
                goto tv_cleanup;
            }

            testcase_error("C_WrapKey(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }

        testcase_new_assertion();       /* assertion #1 */

        // allocate memory for wrapped_key
        wrapped_key = calloc(wrapped_keylen, sizeof(CK_BYTE));
        if (wrapped_key == NULL) {
            testcase_error("Can't allocate memory for %lu bytes.",
                           sizeof(CK_BYTE) * wrapped_keylen);
            rc = CKR_HOST_MEMORY;
            goto error;
        }
        // wrap key
        rc = funcs->C_WrapKey(session, &wrap_mech, publ_key, secret_key,
                              wrapped_key, &wrapped_keylen);
        if (rc != CKR_OK) {
            testcase_fail("C_WrapKey, rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /* variable key length specific case:
         * According to PKCS#11 v2.2 section 12.1.12
         * CKM_RSA_X_509 does not wrap the key type, key length,
         * or any other information about the key; the application
         * must convey these separately, and supply them when
         * unwrapping the key.
         */
        if (((keygen_mech.mechanism == CKM_AES_KEY_GEN) ||
             (keygen_mech.mechanism == CKM_AES_XTS_KEY_GEN) ||
             (keygen_mech.mechanism == CKM_GENERIC_SECRET_KEY_GEN)) &&
            (wrap_mech.mechanism == CKM_RSA_X_509)) {
            unwrapped_keylen = tsuite->tv[i].keylen;
            unwrap_tmpl_len = 3;
        } else {
            unwrap_tmpl_len = 2;
        }

        switch (wrap_mech.mechanism) {
        case CKM_RSA_X_509:
        case CKM_AES_ECB:
        case CKM_AES_CBC:
        case CKM_DES_ECB:
        case CKM_DES_CBC:
        case CKM_DES3_ECB:
        case CKM_DES3_CBC:
            break;
        default:
            unwrap_tmpl_len = 2;
            break;
        }

        // unwrap key
        rc = funcs->C_UnwrapKey(session, &wrap_mech, priv_key,
                                wrapped_key, wrapped_keylen,
                                unwrap_tmpl, unwrap_tmpl_len, &unwrapped_key);
        if (rc != CKR_OK) {
            testcase_fail("C_UnwrapKey, rc=%s", p11_get_ckr(rc));
            goto error;
        } else {
            testcase_pass("wrapped and unwrapped key successful.");
        }

        /* now decrypt the message with the unwrapped key */

        if (keygen_mech.mechanism != CKM_GENERIC_SECRET_KEY_GEN) {
            rc = funcs->C_DecryptInit(session, &mech, unwrapped_key);
            if (rc != CKR_OK) {
                testcase_error("C_DecryptInit unwrapped_key: "
                               " rc = %s", p11_get_ckr(rc));
                goto error;
            }

            rc = funcs->C_Decrypt(session, cipher, cipher_len,
                                  re_cipher, &re_cipher_len);
            if (rc != CKR_OK) {
                testcase_error("C_Decrypt unwrapped_key: "
                               "rc = %s", p11_get_ckr(rc));
                goto error;
            }

            testcase_new_assertion();

            if (memcmp(clear, re_cipher, 32) != 0) {
                testcase_fail("ERROR:data mismatch\n");
                goto error;
            } else {
                testcase_pass("Decrypted data is correct.");
            }
        }
        // clean up
tv_cleanup:
        if (wrapped_key) {
            free(wrapped_key);
            wrapped_key = NULL;
        }

        rc = funcs->C_DestroyObject(session, secret_key);
        if (rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));

    }
    goto testcase_cleanup;

error:
    if (wrapped_key) {
        free(wrapped_key);
        wrapped_key = NULL;
    }

    funcs->C_DestroyObject(session, secret_key);

testcase_cleanup:
    free_rsa_key_cache(session);
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions(), rc=%s.", p11_get_ckr(loc_rc));
    }

    return rc;
}


/* This function should test:
 * C_Sign, mechanism chosen by caller
 *
 * 1. Get message from test vector
 * 2. Get expected signature from test vector
 * 3. Sign message
 * 4. Compare expected signature with actual signature
 *
 */
CK_RV do_SignRSA(struct PUBLISHED_TEST_SUITE_INFO * tsuite,
                 enum rsa_key_format format)
{
    unsigned int i;
    CK_BYTE message[MAX_MESSAGE_SIZE];
    CK_BYTE actual[MAX_SIGNATURE_SIZE];
    CK_BYTE expected[MAX_SIGNATURE_SIZE];
    CK_ULONG message_len, actual_len, expected_len;

    CK_MECHANISM mech;
    CK_OBJECT_HANDLE priv_key;

    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    // begin testsuite
    testsuite_begin("%s Sign%s. ", tsuite->name, rsa_key_format_str(format));
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    if (is_icsf_token(slot_id) && format != RSA_KEY_FORMAT_FULL) {
        testsuite_skip(tsuite->tvcount,
                       "ICSF Token does not support RSA private keys in "
                       "ME-only or CRT-only format");
        goto testcase_cleanup;
    }

    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {
        testcase_begin("%s Sign%s with test vector %u.", tsuite->name,
                       rsa_key_format_str(format), i);

        rc = CKR_OK;            // set return value

        if (tsuite->tv[i].mod_len * 8 > 4096 && !rsa8k) {
            testcase_skip("Tests with  modbits='%lu' are not enabled",
                          tsuite->tv[i].mod_len * 8);
            continue;
        }
        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].mod_len * 8)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].mod_len * 8);
            continue;
        }

        // special case for ica
        // prime1, prime2, exp1, exp2, coef
        // must be size mod_len/2 or smaller
        // skip test if prime1, or prime2, or exp1,
        // or exp2 or coef are too long
        if (is_ica_token(slot_id)) {
            // check sizes
            if ((tsuite->tv[i].prime1_len >
                 (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].prime2_len >
                 (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].exp1_len >
                 (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].exp2_len >
                 (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].coef_len > (tsuite->tv[i].mod_len / 2))) {
                testcase_skip("ICA Token cannot be used with this test vector.");
                continue;
            }
        }

        // special case for EP11 + ICSF
        // modulus length must be multiple of 128 byte
        // skip test if modulus length has unsuported size
        if (is_ep11_token(slot_id) || is_icsf_token(slot_id)) {
            if ((tsuite->tv[i].mod_len % 128) != 0) {
                testcase_skip("EP11/ICSF Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].mod_len))) {
                testcase_skip("TPM Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].pub_exp,
                                     tsuite->tv[i].pubexp_len)) {
                testcase_skip("CCA Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len)) {
                testcase_skip("Soft Token cannot be used with this test vector.");
                continue;
            }
        }

        if (format == RSA_KEY_FORMAT_CRT && tsuite->tv[i].prime1_len == 0) {
            testcase_skip("Test vector does not have CRT components");
            continue;
        }

        // clear buffers
        memset(message, 0, MAX_MESSAGE_SIZE);
        memset(actual, 0, MAX_SIGNATURE_SIZE);
        memset(expected, 0, MAX_SIGNATURE_SIZE);

        actual_len = MAX_SIGNATURE_SIZE;        // set buffer size

        // get message
        message_len = tsuite->tv[i].msg_len;
        memcpy(message, tsuite->tv[i].msg, message_len);

        // get (expected) signature
        expected_len = tsuite->tv[i].sig_len;
        memcpy(expected, tsuite->tv[i].sig, expected_len);

        // create (private) key handle
        rc = create_RSAPrivateKey(session,
                                  tsuite->tv[i].mod,
                                  tsuite->tv[i].pub_exp,
                                  format == RSA_KEY_FORMAT_CRT ? NULL : tsuite->tv[i].priv_exp,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].prime1,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].prime2,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].exp1,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].exp2,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].coef,
                                  tsuite->tv[i].mod_len,
                                  tsuite->tv[i].pubexp_len,
                                  format == RSA_KEY_FORMAT_CRT ? 0 : tsuite->tv[i].privexp_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].prime1_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].prime2_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].exp1_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].exp2_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].coef_len,
                                  &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key import is not allowed by policy");
                continue;
            }
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key size is not in supported range");
                continue;
            }
            if (rc == CKR_MECHANISM_INVALID ||
                rc == CKR_TEMPLATE_INCOMPLETE ||
                rc == CKR_TEMPLATE_INCONSISTENT ||
                rc == CKR_FUNCTION_NOT_SUPPORTED) {
                testcase_skip("RSA key format not supported by token");
                continue;
            }

            testcase_error("create_RSAPrivateKey(), rc=%s", p11_get_ckr(rc));
            goto error;
        }
        // set mechanism
        mech = tsuite->mech;

        // initialize signing
        rc = funcs->C_SignInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_SignInit(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }
        // do signing
        rc = funcs->C_Sign(session, message, message_len, actual, &actual_len);

        if (rc != CKR_OK) {
            testcase_error("C_Sign(), rc=%s.", p11_get_ckr(rc));
            goto skip;
        }
        // check results
        testcase_new_assertion();

        if (actual_len != expected_len) {
            testcase_fail("%s Sign with test vector %u failed. "
                          "Expected len=%lu, found len=%lu.",
                          tsuite->name, i, expected_len, actual_len);
        } else if (memcmp(actual, expected, expected_len)) {
            testcase_fail("%s Sign with test vector %u failed. "
                          "Signature data does not match test vector "
                          "signature.", tsuite->name, i);

        } else {
            testcase_pass("C_Sign%s.", rsa_key_format_str(format));
        }
skip:
        // clean up
        rc = funcs->C_DestroyObject(session, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }
    goto testcase_cleanup;
error:
    loc_rc = funcs->C_DestroyObject(session, priv_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject, rc=%s.", p11_get_ckr(loc_rc));
    }
testcase_cleanup:
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions, rc=%s.", p11_get_ckr(loc_rc));
    }

    return rc;
}

/* This function should test:
 * C_Verify, mechanism chosen by caller
 *
 * 1. Get message from test vector
 * 2. Get signature from test vector
 * 3. Verify signature
 *
 */
CK_RV do_VerifyRSA(struct PUBLISHED_TEST_SUITE_INFO * tsuite)
{
    unsigned int i;
    CK_BYTE actual[MAX_SIGNATURE_SIZE];
    CK_BYTE message[MAX_MESSAGE_SIZE];
    CK_ULONG message_len;
    CK_BYTE signature[MAX_SIGNATURE_SIZE];
    CK_ULONG signature_len;

    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key;

    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    // begin testsuite
    testsuite_begin("%s Verify.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        testcase_begin("%s Verify with test vector %u.", tsuite->name, i);

        rc = CKR_OK;            // set return value

        if (tsuite->tv[i].mod_len * 8 > 4096 && !rsa8k) {
            testcase_skip("Tests with  modbits='%lu' are not enabled",
                          tsuite->tv[i].mod_len * 8);
            continue;
        }
        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].mod_len * 8)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].mod_len * 8);
            continue;
        }

        // special case for EP11 + ICSF
        // modulus length must be multiple of 128 byte
        // skip test if modulus length has unsuported size
        if (is_ep11_token(slot_id) || is_icsf_token(slot_id)) {
            if ((tsuite->tv[i].mod_len % 128) != 0) {
                testcase_skip("EP11/ICSF Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].mod_len))) {
                testcase_skip("TPM Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].pub_exp,
                                     tsuite->tv[i].pubexp_len)) {
                testcase_skip("CCA Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len)) {
                testcase_skip("Soft Token cannot be used with this test vector.");
                continue;
            }
        }

        // clear buffers
        memset(message, 0, MAX_MESSAGE_SIZE);
        memset(signature, 0, MAX_SIGNATURE_SIZE);
        memset(actual, 0, MAX_SIGNATURE_SIZE);

        // get message
        message_len = tsuite->tv[i].msg_len;
        memcpy(message, tsuite->tv[i].msg, message_len);

        // get signature
        signature_len = tsuite->tv[i].sig_len;
        memcpy(signature, tsuite->tv[i].sig, signature_len);

        // create (public) key handle
        rc = create_RSAPublicKey(session,
                                 tsuite->tv[i].mod,
                                 tsuite->tv[i].pub_exp,
                                 tsuite->tv[i].mod_len,
                                 tsuite->tv[i].pubexp_len, &publ_key);

        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key import is not allowed by policy");
                continue;
            }
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key size is not in supported range");
                continue;
            }

            testcase_error("create_RSAPublicKey(), rc=%s", p11_get_ckr(rc));
            goto error;
        }
        // set mechanism
        mech = tsuite->mech;

        // initialize verify
        rc = funcs->C_VerifyInit(session, &mech, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_VerifyInit(), rc=%s", p11_get_ckr(rc));
            goto error;
        }
        // do verify
        rc = funcs->C_Verify(session,
                             message, message_len, signature, signature_len);

        // check result
        testcase_new_assertion();

        if (rc == CKR_OK) {
            testcase_pass("C_Verify.");
        } else if (rc == CKR_KEY_SIZE_RANGE) {
           testcase_skip("RSA key size is not in supported range");
        } else {
            testcase_fail("%s Sign Verify with test vector %u "
                          "failed.", tsuite->name, i);
        }

        // clean up
        rc = funcs->C_DestroyObject(session, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

    }
    goto testcase_cleanup;
error:
    loc_rc = funcs->C_DestroyObject(session, publ_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

CK_RV do_RSAImplicitRejection(struct PUBLISHED_TEST_SUITE_INFO *tsuite)
{
    unsigned int i;
    CK_BYTE decrypt[BIG_REQUEST];
    CK_ULONG decrypt_len;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE priv_key = CK_INVALID_HANDLE;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    char *s;

    // begin testsuite
    testsuite_begin("%s Implicit Rejection.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    if (!is_ica_token(slot_id) && !is_soft_token(slot_id)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support Implicit Rejection",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }
    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].pub_exp,
                          tsuite->tv[i].pubexp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }
        // begin testcase
        testcase_begin("%s Implicit Rejection with test vector %u."
                       "\npubl_exp='%s', modbits=%lu, publ_exp_len=%lu.",
                       tsuite->name, i, s,
                       tsuite->tv[i].mod_len * 8,
                       tsuite->tv[i].pubexp_len);

        rc = CKR_OK;

        if (tsuite->tv[i].mod_len * 8 > 4096 && !rsa8k) {
            testcase_skip("Tests with  modbits='%lu' are not enabled",
                          tsuite->tv[i].mod_len * 8);
            continue;
        }
        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].mod_len * 8)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].mod_len * 8);
            free(s);
            continue;
        }

        free(s);

        // clear buffers
        memset(decrypt, 0, BIG_REQUEST);

        // create (private) key handle
        rc = create_RSAPrivateKey(session,
                                  tsuite->tv[i].mod,
                                  tsuite->tv[i].pub_exp,
                                  tsuite->tv[i].priv_exp,
                                  tsuite->tv[i].prime1,
                                  tsuite->tv[i].prime2,
                                  tsuite->tv[i].exp1,
                                  tsuite->tv[i].exp2,
                                  tsuite->tv[i].coef,
                                  tsuite->tv[i].mod_len,
                                  tsuite->tv[i].pubexp_len,
                                  tsuite->tv[i].privexp_len,
                                  tsuite->tv[i].prime1_len,
                                  tsuite->tv[i].prime2_len,
                                  tsuite->tv[i].exp1_len,
                                  tsuite->tv[i].exp2_len,
                                  tsuite->tv[i].coef_len, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key import is not allowed by policy");
                continue;
            }
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key size is not in supported range");
                continue;
            }

            testcase_error("create_RSAPrivateKey(), rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // set cipher buffer length
        decrypt_len = BIG_REQUEST;

        // get mech
        mech = tsuite->mech;

        // initialize (private key) decryption
        rc = funcs->C_DecryptInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit, rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
        }
        // do (private key) decryption
        rc = funcs->C_Decrypt(session, tsuite->tv[i].msg, tsuite->tv[i].msg_len,
                              decrypt, &decrypt_len);
        if (rc != CKR_OK) {
            testcase_error("C_Decrypt, rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
        }

        // check results
        testcase_new_assertion();

        if (decrypt_len != tsuite->tv[i].sig_len) {
            testcase_fail("decrypted length does not match"
                          "expected data length.\n expected length = %lu, "
                          "but found length=%lu.\n",
                          tsuite->tv[i].sig_len, decrypt_len);
        } else if (memcmp(decrypt, tsuite->tv[i].sig, tsuite->tv[i].sig_len)) {
            testcase_fail("decrypted data does not match expected data.");
        } else {
            testcase_pass("Implicit Rejection.");
        }

        // clean up
tv_cleanup:

        rc = funcs->C_DestroyObject(session, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }
    }

    goto testcase_cleanup;
error:
    loc_rc = funcs->C_DestroyObject(session, priv_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }

testcase_cleanup:
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions, rc=%s", p11_get_ckr(loc_rc));
    }

    return rc;
}


CK_RV do_EncapsDecapsRSA(struct GENERATED_TEST_SUITE_INFO * tsuite)
{
    unsigned int i = 0;
    char *s = NULL;
    CK_OBJECT_HANDLE publ_key, priv_key;
    CK_OBJECT_HANDLE secret_key1 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret_key2 = CK_INVALID_HANDLE;
    CK_BYTE_PTR cipher = NULL;
    CK_ULONG cipher_len;
    CK_MECHANISM encaps_mech, mech;
    CK_RSA_PKCS_OAEP_PARAMS oaep_params;
    CK_BYTE clear[32], encypted[32], re_cipher[32];
    CK_ULONG encrypted_len = 32, re_cipher_len = 32;

    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type;
    CK_ULONG keylen = 0;
    CK_BBOOL ck_false = CK_FALSE;
    CK_ATTRIBUTE encaps_decaps_tmpl[] = {
        {CKA_CLASS, &key_class, sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE, &key_type, sizeof(CK_KEY_TYPE)},
        {CKA_EXTRACTABLE, &ck_false, sizeof(CK_BBOOL)},
        {CKA_VALUE_LEN, &keylen, sizeof(CK_ULONG)}
    };
    CK_ULONG encaps_decaps_tmpl_len;

    // begin test suite
    testsuite_begin("%s Ecapsulate Decapsulate.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    // skip all tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    } else if (!encapsulate_supported(slot_id, tsuite->mech)) {
        // skip all tests if the slot doesn't support wrapping
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support key encapsulation",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id, tsuite->keygen_mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->keygen_mech.mechanism),
                       (unsigned int) tsuite->keygen_mech.mechanism);
        goto testcase_cleanup;
    }

    for (i = 0; i < tsuite->tvcount; i++) {
        // skip if the slot doesn't support the keygen mechanism
        if (!mech_supported(slot_id, tsuite->tv[i].keytype.mechanism)) {
            testcase_skip("Slot %u doesn't support %s (0x%x)",
                          (unsigned int) slot_id,
                          mech_to_str(tsuite->tv[i].keytype.mechanism),
                          (unsigned int) tsuite->tv[i].keytype.mechanism);
            continue;
        }

        if (tsuite->tv[i].modbits > 4096 && !rsa8k) {
            testcase_skip("Tests with  modbits='%lu' are not enabled",
                          tsuite->tv[i].modbits);
            continue;
        }
        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].modbits);
            continue;
        }
        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
                          tsuite->tv[i].publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }

        if (is_ep11_token(slot_id)) {
            if (!is_valid_ep11_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("EP11 Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }
        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len) ||
                (tsuite->tv[i].modbits < 1024)) {
                testcase_skip("ICSF Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }
        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) ||
                (!is_valid_tpm_modbits(tsuite->tv[i].modbits))) {
                testcase_skip("TPM Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
           }
        }
        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].publ_exp,
                                     tsuite->tv[i].publ_exp_len)) {
                testcase_skip("CCA Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }

            if (tsuite->tv[i].keytype.mechanism == CKM_GENERIC_SECRET_KEY_GEN) {
                testcase_skip("CCA Token cannot wrap CKK_GENERIC_SECRET keys");
                free(s);
                continue;
            }

            if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP &&
                tsuite->tv[i].oaep_params.hashAlg != CKM_SHA_1 &&
                tsuite->tv[i].oaep_params.hashAlg != CKM_SHA256) {
                testcase_skip("CCA Token cannot use RSA OAEP with a hash "
                             "algorithm other than SHA1 and SHA256: %s",
                             mech_to_str(tsuite->tv[i].oaep_params.hashAlg));
                free(s);
                continue;
            }

            if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP &&
                 tsuite->tv[i].oaep_params.source == CKZ_DATA_SPECIFIED &&
                 tsuite->tv[i].oaep_params.ulSourceDataLen > 0) {
                 testcase_skip("CCA Token cannot use RSA OAEP with non empty "
                               "source data");
                 free(s);
                 continue;
             }

            if (tsuite->mech.mechanism == CKM_RSA_AES_KEY_WRAP &&
                (tsuite->tv[i].keytype.mechanism != CKM_AES_KEY_GEN ||
                 tsuite->tv[i].oaep_params.hashAlg != CKM_SHA_1 ||
                 tsuite->tv[i].oaep_params.mgf != CKG_MGF1_SHA1 ||
                 (tsuite->tv[i].oaep_params.source == CKZ_DATA_SPECIFIED &&
                 tsuite->tv[i].oaep_params.ulSourceDataLen > 0))) {
                 testcase_skip("CCA Token cannot use RSA AES keywrap with "
                               "OAEP params other than SHA-1 and empty source "
                               "data");
                 free(s);
                 continue;
             }
        }
        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("Soft Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP) {
            if (!mech_supported(slot_id, tsuite->tv[i].oaep_params.hashAlg)) {
                testcase_skip("Slot %u doesn't support OAEP hash alg %s (0x%x)",
                              (unsigned int)slot_id,
                              mech_to_str(tsuite->tv[i].oaep_params.hashAlg),
                              (unsigned int)tsuite->tv[i].oaep_params.hashAlg);
                free(s);
                continue;
            }
        }

        // begin test
        testcase_begin("%s Encapsulate Decapsulate with test vector %u, "
                       "\npubl_exp='%s', mod_bits='%lu', keylen='%lu', "
                       "keytype='%s'", tsuite->name, i, s,
                       tsuite->tv[i].modbits, tsuite->tv[i].keylen,
                       p11_get_ckm(&mechtable_funcs,
                                   tsuite->tv[i].keytype.mechanism));

        // free memory
        if (s)
            free(s);

        encaps_decaps_tmpl_len =
                    sizeof(encaps_decaps_tmpl) / sizeof(CK_ATTRIBUTE);

        // get wrapping mechanism
        encaps_mech = tsuite->mech;
        if (encaps_mech.mechanism == CKM_RSA_PKCS_OAEP) {
            oaep_params = tsuite->tv[i].oaep_params;
            encaps_mech.pParameter = &oaep_params;
            encaps_mech.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
        }

        if (tsuite->tv[i].keytype.mechanism == CKM_AES_XTS_KEY_GEN &&
            (is_ep11_token(slot_id) || is_cca_token(slot_id))) {
            testcase_skip("Skip test as CKM_AES_XTS_KEY_GEN is supported " \
                          "only for protected keys in EP11 and CCA token");
            continue;
        }

        if (!mech_supported(slot_id, encaps_mech.mechanism)) {
            testcase_skip("Slot %u doesn't support %s (0x%x)",
                          (unsigned int)slot_id,
                          mech_to_str(encaps_mech.mechanism),
                          (unsigned int)encaps_mech.mechanism);
            continue;
        }

        // generate RSA key pair
        rc = generate_RSA_PKCS_KeyPair_cached(session,
                                              tsuite->keygen_mech.mechanism,
                                              tsuite->tv[i].modbits,
                                              tsuite->tv[i].publ_exp,
                                              tsuite->tv[i].publ_exp_len,
                                              &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key generation is not allowed by policy");
                continue;
            }
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key size is not in supported range");
                continue;
            }

            testcase_error("C_GenerateKeyPair() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        // get encaps key type and length + key check mech
        switch (tsuite->tv[i].keytype.mechanism) {
        case CKM_AES_KEY_GEN:
            key_type = CKK_AES;
            mech.mechanism = CKM_AES_CBC;
            mech.ulParameterLen = AES_IV_SIZE;
            mech.pParameter = &aes_iv;
            break;
        case CKM_AES_XTS_KEY_GEN:
            key_type = CKK_AES_XTS;
            mech.mechanism = CKM_AES_XTS;
            mech.ulParameterLen = AES_IV_SIZE;
            mech.pParameter = &aes_iv;
            break;
        case CKM_DES3_KEY_GEN:
            key_type = CKK_DES3;
            encaps_decaps_tmpl_len =
                     sizeof(encaps_decaps_tmpl) / sizeof(CK_ATTRIBUTE) - 1;
            mech.mechanism = CKM_DES3_CBC;
            mech.ulParameterLen = DES_IV_SIZE;
            mech.pParameter = &des_iv;
            break;
        case CKM_DES_KEY_GEN:
            key_type = CKK_DES;
            encaps_decaps_tmpl_len =
                     sizeof(encaps_decaps_tmpl) / sizeof(CK_ATTRIBUTE) - 1;
            mech.mechanism = CKM_DES_CBC;
            mech.ulParameterLen = DES_IV_SIZE;
            mech.pParameter = &des_iv;
            break;
        case CKM_GENERIC_SECRET_KEY_GEN:
            key_type = CKK_GENERIC_SECRET;
            break;
        default:
            testcase_error("unknown mech");
            goto error;
        }

        keylen = tsuite->tv[i].keylen;

        // encapsulate key (length only)
        rc = funcs3_2->C_EncapsulateKey(session, &encaps_mech, publ_key,
                                        encaps_decaps_tmpl,
                                        encaps_decaps_tmpl_len,
                                        NULL, &cipher_len, NULL);
        if (rc != CKR_OK) {
            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                encaps_mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_ep11_token(slot_id) &&
                (oaep_params.hashAlg != CKM_SHA_1 ||
                 oaep_params.mgf != CKG_MGF1_SHA1)) {
                testcase_skip("EP11 Token does not support RSA OAEP with hash "
                              "and/or MGF other than SHA-1");
                goto tv_cleanup;
            }
            if (rc == CKR_KEY_NOT_WRAPPABLE && is_cca_token(slot_id)) {
                testcase_skip("CCA Token does not support to encapsulate %s "
                              "keys with %s",
                              encaps_mech.mechanism == CKM_RSA_AES_KEY_WRAP ?
                                                      "DATA" : "CIPHER",
                              mech_to_str(encaps_mech.mechanism));
                goto tv_cleanup;
            }

            testcase_error("C_EncapsulateKey(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }

        testcase_new_assertion();       /* assertion #1 */

        // allocate memory for wrapped_key
        cipher = calloc(cipher_len, sizeof(CK_BYTE));
        if (cipher == NULL) {
            testcase_error("Can't allocate memory for %lu bytes.",
                           sizeof(CK_BYTE) * cipher_len);
            rc = CKR_HOST_MEMORY;
            goto error;
        }
        // encapsulate key
        rc = funcs3_2->C_EncapsulateKey(session, &encaps_mech, publ_key,
                                        encaps_decaps_tmpl,
                                        encaps_decaps_tmpl_len,
                                        cipher, &cipher_len, &secret_key1);
        if (rc != CKR_OK) {
            testcase_fail("C_EncapsulateKey, rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // Decaps does not allow CKA_VALUE_LEN, RSA can recover the key size
        encaps_decaps_tmpl_len =
                 sizeof(encaps_decaps_tmpl) / sizeof(CK_ATTRIBUTE) - 1;

        // decapsulate key
        rc = funcs3_2->C_DecapsulateKey(session, &encaps_mech, priv_key,
                                        encaps_decaps_tmpl,
                                        encaps_decaps_tmpl_len,
                                        cipher, cipher_len, &secret_key2);
        if (rc != CKR_OK) {
            testcase_fail("C_DecapsulateKey, rc=%s", p11_get_ckr(rc));
            goto error;
        } else {
            testcase_pass("encapsulate and decapsulate key successful.");
        }

        if (tsuite->tv[i].keytype.mechanism != CKM_GENERIC_SECRET_KEY_GEN) {
            if (!mech_supported(slot_id, mech.mechanism)) {
                testcase_skip("Slot %u doesn't support %s (0x%x)",
                              (unsigned int) slot_id,
                              mech_to_str(mech.mechanism),
                              (unsigned int)mech.mechanism);
                goto tv_cleanup;
            }

            rc = funcs->C_EncryptInit(session, &mech, secret_key1);
            if (rc != CKR_OK) {
                testcase_error("C_EncryptInit with encapsulated key "
                               ": rc = %s", p11_get_ckr(rc));
                goto error;
            }

            rc = funcs->C_Encrypt(session, clear, sizeof(clear),
                                  encypted, &encrypted_len);
            if (rc != CKR_OK) {
                testcase_error("C_Encrypt secret_key: rc = %s",
                               p11_get_ckr(rc));
                goto error;
            }

            rc = funcs->C_DecryptInit(session, &mech, secret_key2);
            if (rc != CKR_OK) {
                testcase_error("C_DecryptInit with decapsulated key: "
                               " rc = %s", p11_get_ckr(rc));
                goto error;
            }

            rc = funcs->C_Decrypt(session, encypted, encrypted_len,
                                  re_cipher, &re_cipher_len);
            if (rc != CKR_OK) {
                testcase_error("C_Decrypt unwrapped_key: "
                               "rc = %s", p11_get_ckr(rc));
                goto error;
            }

            testcase_new_assertion();

            if (memcmp(clear, re_cipher, 32) != 0) {
                testcase_fail("ERROR:data mismatch\n");
                goto error;
            } else {
                testcase_pass("Decrypted data is correct.");
            }
        }

        // clean up
tv_cleanup:
        if (cipher) {
            free(cipher);
            cipher = NULL;
        }

        if (secret_key1 != CK_INVALID_HANDLE) {
            rc = funcs->C_DestroyObject(session, secret_key1);
            if (rc != CKR_OK)
                testcase_error("C_DestroyObject(), rc=%s.",
                               p11_get_ckr(rc));
            secret_key1 = CK_INVALID_HANDLE;
        }

        if (secret_key2 != CK_INVALID_HANDLE) {
            rc = funcs->C_DestroyObject(session, secret_key2);
            if (rc != CKR_OK)
                testcase_error("C_DestroyObject(), rc=%s.",
                               p11_get_ckr(rc));
            secret_key2 = CK_INVALID_HANDLE;
        }

    }
    goto testcase_cleanup;

error:
    if (cipher) {
        free(cipher);
        cipher = NULL;
    }

    funcs->C_DestroyObject(session, secret_key1);
    funcs->C_DestroyObject(session, secret_key2);

testcase_cleanup:
    free_rsa_key_cache(session);
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions(), rc=%s.", p11_get_ckr(loc_rc));
    }

    return rc;
}

#define PRIVEXP_MAX_LEN     512     /* up to 4096 bit */
#define ARRAY_SIZE(A)       (sizeof(A) / sizeof((A)[0]))

struct privexp_test_vector {
    CK_ULONG modbits;
    CK_ULONG publ_exp_len;
    CK_BYTE publ_exp[3];
};

static const struct privexp_test_vector privexp_tests[] = {
    { 1024, 3, { 0x01, 0x00, 0x01 } },
    { 2048, 3, { 0x01, 0x00, 0x01 } },
    { 1024, 1, { 0x03 } },
    { 2048, 1, { 0x03 } },
    { 1024, 1, { 0x11 } },
    { 2048, 1, { 0x11 } },
    /* 0x030001 = 196609 = 7 * 28087 is not prime */
    { 1024, 3, { 0x03, 0x00, 0x01 } },
    { 2048, 3, { 0x03, 0x00, 0x01 } },
};

/* Returns 1 if both big-endian numbers are equal, ignoring leading zeros */
static int rsa_pubexp_equal(const CK_BYTE *a, CK_ULONG a_len,
                            const CK_BYTE *b, CK_ULONG b_len)
{
    while (a_len > 0 && a[0] == 0) {
        a++;
        a_len--;
    }
    while (b_len > 0 && b[0] == 0) {
        b++;
        b_len--;
    }

    return a_len == b_len && memcmp(a, b, a_len) == 0;
}

/*
 * Returns 1 if d is a valid RSA private exponent for the public exponent e and
 * the primes p and q, i.e. if e * d = 1 mod (p - 1) and e * d = 1 mod (q - 1).
 * This holds for a d calculated modulo phi(n) = (p - 1) * (q - 1) as well as
 * for a d calculated modulo lcm(p - 1, q - 1).
 */
static int rsa_privexp_is_valid(const CK_BYTE *e, CK_ULONG e_len,
                                const CK_BYTE *d, CK_ULONG d_len,
                                const CK_BYTE *p, CK_ULONG p_len,
                                const CK_BYTE *q, CK_ULONG q_len)
{
    BN_CTX *ctx;
    BIGNUM *be, *bd, *bp, *bq, *prod, *m, *rem;
    int valid = 0;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        return 0;

    BN_CTX_start(ctx);
    be = BN_CTX_get(ctx);
    bd = BN_CTX_get(ctx);
    bp = BN_CTX_get(ctx);
    bq = BN_CTX_get(ctx);
    prod = BN_CTX_get(ctx);
    m = BN_CTX_get(ctx);
    rem = BN_CTX_get(ctx);
    if (be == NULL || bd == NULL || bp == NULL || bq == NULL ||
        prod == NULL || m == NULL || rem == NULL)
        goto out;

    if (BN_bin2bn(e, e_len, be) == NULL ||
        BN_bin2bn(d, d_len, bd) == NULL ||
        BN_bin2bn(p, p_len, bp) == NULL ||
        BN_bin2bn(q, q_len, bq) == NULL)
        goto out;

    if (BN_is_zero(bd) || BN_mul(prod, be, bd, ctx) != 1)
        goto out;

    if (BN_sub(m, bp, BN_value_one()) != 1 ||
        BN_mod(rem, prod, m, ctx) != 1 || !BN_is_one(rem))
        goto out;

    if (BN_sub(m, bq, BN_value_one()) != 1 ||
        BN_mod(rem, prod, m, ctx) != 1 || !BN_is_one(rem))
        goto out;

    valid = 1;

out:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return valid;
}

/*
 * Generate RSA key pairs with different public exponents (including a
 * composite one), read back CKA_PRIVATE_EXPONENT, and verify that it is the
 * inverse of the public exponent modulo p - 1 and q - 1.
 *
 * Sign/verify and decrypt use the CRT parameters of the key, so a wrong private
 * exponent is not detected by any other test. The ICA token calculates the
 * private exponent itself, while it is generated by OpenSSL in the soft token.
 * The ICSF token may return it as well. The EP11, CCA tokens do not
 * provide the private exponent.
 */
CK_RV do_RSAPrivateExponent(void)
{
    unsigned int i;
    CK_MECHANISM keygen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE publ_key, priv_key;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;
    CK_BBOOL ck_true = CK_TRUE, ck_false = CK_FALSE;
    CK_ULONG modbits;
    CK_BYTE d[PRIVEXP_MAX_LEN], p[PRIVEXP_MAX_LEN], q[PRIVEXP_MAX_LEN];
    CK_BYTE e[PRIVEXP_MAX_LEN];
    CK_ATTRIBUTE publ_tmpl[3];
    CK_ATTRIBUTE priv_tmpl[3];
    CK_ATTRIBUTE get_tmpl[3];
    CK_ATTRIBUTE get_e_tmpl[1];
    char *s;

    testsuite_begin("RSA Private Exponent.");
    testcase_rw_session();
    testcase_user_login();

    if (is_ep11_token(slot_id) || is_cca_token(slot_id)) {
        testsuite_skip(ARRAY_SIZE(privexp_tests),
                       "Slot %u does not provide the private exponent",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)) {
        testsuite_skip(ARRAY_SIZE(privexp_tests),
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(CKM_RSA_PKCS_KEY_PAIR_GEN),
                       (unsigned int) CKM_RSA_PKCS_KEY_PAIR_GEN);
        goto testcase_cleanup;
    }

    for (i = 0; i < ARRAY_SIZE(privexp_tests); i++) {
        const struct privexp_test_vector *tv = &privexp_tests[i];

        if (p11_ahex_dump(&s, (CK_BYTE *) tv->publ_exp,
                          tv->publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }

        testcase_begin("RSA private exponent with test vector %u."
                       "\npubl_exp='%s', modbits=%lu.", i, s, tv->modbits);
        free(s);

        rc = CKR_OK;

        /*
         * Public exponents not supported by the ICSF token are skipped when
         * the key generation fails with CKR_ATTRIBUTE_VALUE_INVALID.
         */
        if (is_icsf_token(slot_id) && tv->modbits < 1024) {
            testcase_skip("ICSF Token cannot be used with modbits='%lu'",
                          tv->modbits);
            continue;
        }

        if (!keysize_supported(slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN,
                               tv->modbits)) {
            testcase_skip("Token in slot %lu cannot be used with "
                          "modbits='%lu'", SLOT_ID, tv->modbits);
            continue;
        }

        modbits = tv->modbits;

        publ_tmpl[0].type = CKA_MODULUS_BITS;
        publ_tmpl[0].pValue = &modbits;
        publ_tmpl[0].ulValueLen = sizeof(modbits);
        publ_tmpl[1].type = CKA_PUBLIC_EXPONENT;
        publ_tmpl[1].pValue = (CK_BYTE *) tv->publ_exp;
        publ_tmpl[1].ulValueLen = tv->publ_exp_len;
        publ_tmpl[2].type = CKA_VERIFY;
        publ_tmpl[2].pValue = &ck_true;
        publ_tmpl[2].ulValueLen = sizeof(ck_true);

        priv_tmpl[0].type = CKA_SIGN;
        priv_tmpl[0].pValue = &ck_true;
        priv_tmpl[0].ulValueLen = sizeof(ck_true);
        priv_tmpl[1].type = CKA_SENSITIVE;
        priv_tmpl[1].pValue = &ck_false;
        priv_tmpl[1].ulValueLen = sizeof(ck_false);
        priv_tmpl[2].type = CKA_EXTRACTABLE;
        priv_tmpl[2].pValue = &ck_true;
        priv_tmpl[2].ulValueLen = sizeof(ck_true);

        publ_key = CK_INVALID_HANDLE;
        priv_key = CK_INVALID_HANDLE;

        rc = funcs->C_GenerateKeyPair(session, &keygen_mech,
                                      publ_tmpl, 3, priv_tmpl, 3,
                                      &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("RSA key generation is not allowed by policy");
                rc = CKR_OK;
                continue;
            }
            if (rc == CKR_KEY_SIZE_RANGE || rc == CKR_TEMPLATE_INCONSISTENT ||
                rc == CKR_ATTRIBUTE_VALUE_INVALID) {
                testcase_skip("Token cannot generate this key, rc=%s",
                              p11_get_ckr(rc));
                rc = CKR_OK;
                continue;
            }
            testcase_error("C_GenerateKeyPair() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        memset(d, 0, sizeof(d));
        memset(p, 0, sizeof(p));
        memset(q, 0, sizeof(q));
        get_tmpl[0].type = CKA_PRIVATE_EXPONENT;
        get_tmpl[0].pValue = d;
        get_tmpl[0].ulValueLen = sizeof(d);
        get_tmpl[1].type = CKA_PRIME_1;
        get_tmpl[1].pValue = p;
        get_tmpl[1].ulValueLen = sizeof(p);
        get_tmpl[2].type = CKA_PRIME_2;
        get_tmpl[2].pValue = q;
        get_tmpl[2].ulValueLen = sizeof(q);

        memset(e, 0, sizeof(e));
        get_e_tmpl[0].type = CKA_PUBLIC_EXPONENT;
        get_e_tmpl[0].pValue = e;
        get_e_tmpl[0].ulValueLen = sizeof(e);

        rc = funcs->C_GetAttributeValue(session, priv_key, get_tmpl, 3);
        if (rc == CKR_ATTRIBUTE_SENSITIVE || rc == CKR_ATTRIBUTE_TYPE_INVALID) {
            testcase_skip("Token does not provide the private key "
                          "attributes, rc=%s", p11_get_ckr(rc));
            rc = CKR_OK;
        } else if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
        } else if ((rc = funcs->C_GetAttributeValue(session, publ_key,
                                                    get_e_tmpl, 1)) != CKR_OK) {
            testcase_error("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
        } else if (!rsa_pubexp_equal(tv->publ_exp, tv->publ_exp_len,
                                     e, get_e_tmpl[0].ulValueLen)) {
            /* The token did not use the requested public exponent */
            testcase_new_assertion();
            testcase_fail("Token generated the key with a different public "
                          "exponent than requested.");
        } else {
            testcase_new_assertion();
            if (rsa_privexp_is_valid(e, get_e_tmpl[0].ulValueLen,
                                     d, get_tmpl[0].ulValueLen,
                                     p, get_tmpl[1].ulValueLen,
                                     q, get_tmpl[2].ulValueLen))
                testcase_pass("CKA_PRIVATE_EXPONENT is the inverse of "
                              "CKA_PUBLIC_EXPONENT.");
            else
                testcase_fail("CKA_PRIVATE_EXPONENT is not the inverse of "
                              "CKA_PUBLIC_EXPONENT modulo p-1 and q-1.");
        }

        loc_rc = funcs->C_DestroyObject(session, priv_key);
        if (loc_rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
            rc = loc_rc;
        }
        loc_rc = funcs->C_DestroyObject(session, publ_key);
        if (loc_rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
            rc = loc_rc;
        }
        if (rc != CKR_OK)
            goto testcase_cleanup;
    }

testcase_cleanup:
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions, rc=%s", p11_get_ckr(loc_rc));
    }

    return rc;
}

#define WRAPPED_RSA_MAX_LEN     8192

/* This function should test:
 * C_WrapKey of an RSA private key, which is imported in the given key format
 * C_UnwrapKey of the wrapped RSA private key
 *
 * If the private exponent (CRT-only key) or the CRT components (ME-only key)
 * are missing in the imported key, they need to be calculated when the key is
 * wrapped. The calculated values are stored in the key object, so wrapping
 * the key a second time uses the stored values.
 *
 * 1. Import the RSA private key in the given key format
 * 2. Wrap the RSA private key twice with an AES key
 * 3. Compare both wrapped keys, they must be identical
 * 4. Unwrap the first wrapped key
 * 5. Sign the message from the test vector with the unwrapped key and compare
 *    the signature with the signature from the test vector
 * 6. Verify that the private exponent of the unwrapped key is valid
 *    (if the token allows to read it)
 */
CK_RV do_WrapPrivateKeyRSA(struct PUBLISHED_TEST_SUITE_INFO *tsuite,
                           enum rsa_key_format format)
{
    unsigned int i;
    CK_BYTE message[MAX_MESSAGE_SIZE];
    CK_BYTE actual[MAX_SIGNATURE_SIZE];
    CK_BYTE expected[MAX_SIGNATURE_SIZE];
    CK_ULONG message_len, actual_len, expected_len;
    CK_BYTE wrapped1[WRAPPED_RSA_MAX_LEN], wrapped2[WRAPPED_RSA_MAX_LEN];
    CK_ULONG wrapped1_len, wrapped2_len;
    CK_BYTE d[PRIVEXP_MAX_LEN], p[PRIVEXP_MAX_LEN], q[PRIVEXP_MAX_LEN];
    CK_BYTE e[PRIVEXP_MAX_LEN];
    CK_ATTRIBUTE get_tmpl[4];

    CK_MECHANISM mech;
    CK_MECHANISM aes_keygen_mech = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_MECHANISM wrap_mech = { CKM_AES_CBC_PAD, aes_iv, AES_IV_SIZE };
    CK_OBJECT_HANDLE priv_key, wrap_key, unwrapped_key;

    CK_BBOOL ck_true = CK_TRUE, ck_false = CK_FALSE;
    CK_ULONG aes_keylen = 32;
    CK_OBJECT_CLASS wk_class = CKO_SECRET_KEY;
    CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE wrap_tmpl[] = {
        {CKA_CLASS, &wk_class, sizeof(wk_class)},
        {CKA_VALUE_LEN, &aes_keylen, sizeof(aes_keylen)},
        {CKA_TOKEN, &ck_false, sizeof(ck_false)},
        {CKA_WRAP, &ck_true, sizeof(ck_true)},
        {CKA_UNWRAP, &ck_true, sizeof(ck_true)},
    };
    CK_ATTRIBUTE unwrap_tmpl[] = {
        {CKA_CLASS, &priv_class, sizeof(priv_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &ck_false, sizeof(ck_false)},
        {CKA_SIGN, &ck_true, sizeof(ck_true)},
        {CKA_SENSITIVE, &ck_false, sizeof(ck_false)},
        {CKA_EXTRACTABLE, &ck_true, sizeof(ck_true)},
    };

    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    // begin testsuite
    testsuite_begin("%s Wrap Private Key%s. ", tsuite->name,
                    rsa_key_format_str(format));
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support the required mechanisms
    if (!mech_supported(slot_id, tsuite->mech.mechanism) ||
        !mech_supported(slot_id, CKM_AES_KEY_GEN) ||
        !mech_supported(slot_id, CKM_AES_CBC_PAD)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s, %s or %s",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       mech_to_str(CKM_AES_KEY_GEN),
                       mech_to_str(CKM_AES_CBC_PAD));
        goto testcase_cleanup;
    }

    if (is_icsf_token(slot_id) && format != RSA_KEY_FORMAT_FULL) {
        testsuite_skip(tsuite->tvcount,
                       "ICSF Token cannot wrap RSA private keys imported "
                       "without CRT components");
        goto testcase_cleanup;
    }

    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {
        testcase_begin("%s Wrap Private Key%s with test vector %u.",
                       tsuite->name, rsa_key_format_str(format), i);

        rc = CKR_OK;            // set return value
        priv_key = CK_INVALID_HANDLE;
        wrap_key = CK_INVALID_HANDLE;
        unwrapped_key = CK_INVALID_HANDLE;

        if (tsuite->tv[i].mod_len * 8 > 4096 && !rsa8k) {
            testcase_skip("Tests with  modbits='%lu' are not enabled",
                          tsuite->tv[i].mod_len * 8);
            continue;
        }
        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].mod_len * 8)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].mod_len * 8);
            continue;
        }

        // special case for ica
        // prime1, prime2, exp1, exp2, coef
        // must be size mod_len/2 or smaller
        if (is_ica_token(slot_id)) {
            if ((tsuite->tv[i].prime1_len > (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].prime2_len > (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].exp1_len > (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].exp2_len > (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].coef_len > (tsuite->tv[i].mod_len / 2))) {
                testcase_skip("ICA Token cannot be used with this test vector.");
                continue;
            }
        }

        // special case for EP11 + ICSF
        // modulus length must be multiple of 128 byte
        if (is_ep11_token(slot_id) || is_icsf_token(slot_id)) {
            if ((tsuite->tv[i].mod_len % 128) != 0) {
                testcase_skip("EP11/ICSF Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].mod_len))) {
                testcase_skip("TPM Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].pub_exp,
                                     tsuite->tv[i].pubexp_len)) {
                testcase_skip("CCA Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len)) {
                testcase_skip("Soft Token cannot be used with this test vector.");
                continue;
            }
        }

        if (format == RSA_KEY_FORMAT_CRT && tsuite->tv[i].prime1_len == 0) {
            testcase_skip("Test vector does not have CRT components");
            continue;
        }

        // clear buffers
        memset(message, 0, MAX_MESSAGE_SIZE);
        memset(actual, 0, MAX_SIGNATURE_SIZE);
        memset(expected, 0, MAX_SIGNATURE_SIZE);

        actual_len = MAX_SIGNATURE_SIZE;        // set buffer size

        // get message
        message_len = tsuite->tv[i].msg_len;
        memcpy(message, tsuite->tv[i].msg, message_len);

        // get (expected) signature
        expected_len = tsuite->tv[i].sig_len;
        memcpy(expected, tsuite->tv[i].sig, expected_len);

        // create (private) key handle
        rc = create_RSAPrivateKey(session,
                                  tsuite->tv[i].mod,
                                  tsuite->tv[i].pub_exp,
                                  format == RSA_KEY_FORMAT_CRT ? NULL : tsuite->tv[i].priv_exp,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].prime1,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].prime2,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].exp1,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].exp2,
                                  format == RSA_KEY_FORMAT_ME ? NULL : tsuite->tv[i].coef,
                                  tsuite->tv[i].mod_len,
                                  tsuite->tv[i].pubexp_len,
                                  format == RSA_KEY_FORMAT_CRT ? 0 : tsuite->tv[i].privexp_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].prime1_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].prime2_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].exp1_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].exp2_len,
                                  format == RSA_KEY_FORMAT_ME ? 0 : tsuite->tv[i].coef_len,
                                  &priv_key);
        if (rc != CKR_OK) {
            priv_key = CK_INVALID_HANDLE;
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key import is not allowed by policy");
                rc = CKR_OK;
                continue;
            }
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key size is not in supported range");
                rc = CKR_OK;
                continue;
            }
            if (rc == CKR_MECHANISM_INVALID ||
                rc == CKR_TEMPLATE_INCOMPLETE ||
                rc == CKR_TEMPLATE_INCONSISTENT ||
                rc == CKR_FUNCTION_NOT_SUPPORTED) {
                testcase_skip("RSA key format not supported by token");
                rc = CKR_OK;
                continue;
            }

            testcase_error("create_RSAPrivateKey(), rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // generate the wrapping key
        rc = funcs->C_GenerateKey(session, &aes_keygen_mech, wrap_tmpl,
                                  ARRAY_SIZE(wrap_tmpl), &wrap_key);
        if (rc != CKR_OK) {
            wrap_key = CK_INVALID_HANDLE;
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("AES key generation is not allowed by policy");
                rc = CKR_OK;
            } else {
                testcase_error("C_GenerateKey(), rc=%s", p11_get_ckr(rc));
            }
            goto tv_cleanup;
        }

        /*
         * Wrap the key the first time. This calculates the private exponent
         * or the CRT components, if they are missing in the key object, and
         * stores them in the key object.
         */
        wrapped1_len = sizeof(wrapped1);
        rc = funcs->C_WrapKey(session, &wrap_mech, wrap_key, priv_key,
                              wrapped1, &wrapped1_len);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_NOT_WRAPPABLE || rc == CKR_KEY_UNEXTRACTABLE ||
                rc == CKR_KEY_FUNCTION_NOT_PERMITTED ||
                rc == CKR_MECHANISM_INVALID ||
                rc == CKR_FUNCTION_NOT_SUPPORTED) {
                testcase_skip("Token does not support to wrap RSA private "
                              "keys, rc=%s", p11_get_ckr(rc));
                rc = CKR_OK;
            } else if (is_rejected_by_policy(rc, session)) {
                testcase_skip("Wrapping is not allowed by policy");
                rc = CKR_OK;
            } else {
                testcase_error("C_WrapKey(), rc=%s", p11_get_ckr(rc));
            }
            goto tv_cleanup;
        }

        // wrap the key the second time, this uses the values stored in the key
        wrapped2_len = sizeof(wrapped2);
        rc = funcs->C_WrapKey(session, &wrap_mech, wrap_key, priv_key,
                              wrapped2, &wrapped2_len);
        if (rc != CKR_OK) {
            testcase_error("C_WrapKey() (2nd), rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
        }

        // check results
        testcase_new_assertion();

        if (wrapped1_len != wrapped2_len) {
            testcase_fail("%s Wrap Private Key with test vector %u failed. "
                          "Wrapped key length differs: first=%lu, second=%lu.",
                          tsuite->name, i, wrapped1_len, wrapped2_len);
        } else if (memcmp(wrapped1, wrapped2, wrapped1_len) != 0) {
            testcase_fail("%s Wrap Private Key with test vector %u failed. "
                          "Wrapped key differs between first and second wrap.",
                          tsuite->name, i);
        } else {
            testcase_pass("C_WrapKey twice%s.", rsa_key_format_str(format));
        }

        // unwrap the key
        rc = funcs->C_UnwrapKey(session, &wrap_mech, wrap_key,
                                wrapped1, wrapped1_len,
                                unwrap_tmpl, ARRAY_SIZE(unwrap_tmpl),
                                &unwrapped_key);
        if (rc != CKR_OK) {
            unwrapped_key = CK_INVALID_HANDLE;
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("Unwrapping is not allowed by policy");
                rc = CKR_OK;
            } else {
                testcase_fail("C_UnwrapKey(), rc=%s", p11_get_ckr(rc));
            }
            goto tv_cleanup;
        }

        // sign with the unwrapped key
        mech = tsuite->mech;
        rc = funcs->C_SignInit(session, &mech, unwrapped_key);
        if (rc != CKR_OK) {
            testcase_error("C_SignInit(), rc=%s.", p11_get_ckr(rc));
            goto tv_cleanup;
        }
        rc = funcs->C_Sign(session, message, message_len, actual, &actual_len);
        if (rc != CKR_OK) {
            testcase_error("C_Sign(), rc=%s.", p11_get_ckr(rc));
            goto tv_cleanup;
        }

        testcase_new_assertion();

        if (actual_len != expected_len) {
            testcase_fail("%s Sign with unwrapped key with test vector %u "
                          "failed. Expected len=%lu, found len=%lu.",
                          tsuite->name, i, expected_len, actual_len);
        } else if (memcmp(actual, expected, expected_len)) {
            testcase_fail("%s Sign with unwrapped key with test vector %u "
                          "failed. Signature data does not match test vector "
                          "signature.", tsuite->name, i);
        } else {
            testcase_pass("C_UnwrapKey and C_Sign%s.",
                          rsa_key_format_str(format));
        }

        /*
         * Signing uses the CRT components only, so also check the private
         * exponent of the unwrapped key, if the token allows to read it.
         */
        memset(d, 0, sizeof(d));
        memset(p, 0, sizeof(p));
        memset(q, 0, sizeof(q));
        memset(e, 0, sizeof(e));
        get_tmpl[0].type = CKA_PRIVATE_EXPONENT;
        get_tmpl[0].pValue = d;
        get_tmpl[0].ulValueLen = sizeof(d);
        get_tmpl[1].type = CKA_PRIME_1;
        get_tmpl[1].pValue = p;
        get_tmpl[1].ulValueLen = sizeof(p);
        get_tmpl[2].type = CKA_PRIME_2;
        get_tmpl[2].pValue = q;
        get_tmpl[2].ulValueLen = sizeof(q);
        get_tmpl[3].type = CKA_PUBLIC_EXPONENT;
        get_tmpl[3].pValue = e;
        get_tmpl[3].ulValueLen = sizeof(e);

        rc = funcs->C_GetAttributeValue(session, unwrapped_key, get_tmpl, 4);
        if (rc == CKR_OK) {
            testcase_new_assertion();

            if (rsa_privexp_is_valid(e, get_tmpl[3].ulValueLen,
                                     d, get_tmpl[0].ulValueLen,
                                     p, get_tmpl[1].ulValueLen,
                                     q, get_tmpl[2].ulValueLen))
                testcase_pass("CKA_PRIVATE_EXPONENT of unwrapped key is "
                              "valid%s.", rsa_key_format_str(format));
            else
                testcase_fail("CKA_PRIVATE_EXPONENT of unwrapped key is not "
                              "the inverse of CKA_PUBLIC_EXPONENT modulo p-1 "
                              "and q-1 with test vector %u.", i);
        }
        rc = CKR_OK;

tv_cleanup:
        if (unwrapped_key != CK_INVALID_HANDLE) {
            loc_rc = funcs->C_DestroyObject(session, unwrapped_key);
            if (loc_rc != CKR_OK) {
                testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
                rc = loc_rc;
            }
        }
        if (wrap_key != CK_INVALID_HANDLE) {
            loc_rc = funcs->C_DestroyObject(session, wrap_key);
            if (loc_rc != CKR_OK) {
                testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
                rc = loc_rc;
            }
        }
        if (priv_key != CK_INVALID_HANDLE) {
            loc_rc = funcs->C_DestroyObject(session, priv_key);
            if (loc_rc != CKR_OK) {
                testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
                rc = loc_rc;
            }
        }
        if (rc != CKR_OK)
            goto testcase_cleanup;
    }

testcase_cleanup:
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions, rc=%s.", p11_get_ckr(loc_rc));
    }

    return rc;
}

CK_RV rsa_funcs(void)
{
    unsigned int i;
    CK_RV rv = CKR_OK;

    // published (known answer) tests
    for (i = 0; i < NUM_OF_PUBLISHED_TESTSUITES; i++) {
        rv = do_SignRSA(&published_test_suites[i], RSA_KEY_FORMAT_FULL);
        if (rv != CKR_OK && (!no_stop))
            break;

        rv = do_SignRSA(&published_test_suites[i], RSA_KEY_FORMAT_ME);
        if (rv != CKR_OK && (!no_stop))
            break;

        rv = do_SignRSA(&published_test_suites[i], RSA_KEY_FORMAT_CRT);
        if (rv != CKR_OK && (!no_stop))
            break;

        rv = do_VerifyRSA(&published_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    // generated sign verify tests
    for (i = 0; i < NUM_OF_GENERATED_SIGVER_TESTSUITES; i++) {
        rv = do_SignVerifyRSA(&generated_sigver_test_suites[i], FALSE);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    // generated sign verify tests for recover mode
    for (i = 0; i < NUM_OF_GENERATED_SIGVER_TESTSUITES; i++) {
        rv = do_SignVerifyRSA(&generated_sigver_test_suites[i], TRUE);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    for (i = 0; i < NUM_OF_GENERATED_PSS_TESTSUITES; i++) {
        rv = do_SignVerify_RSAPSS(&generated_pss_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    // generated crypto tests
    for (i = 0; i < NUM_OF_GENERATED_CRYPTO_TESTSUITES; i++) {
        rv = do_EncryptDecryptRSA(&generated_crypto_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    for (i = 0; i < NUM_OF_GENERATED_OAEP_TESTSUITES; i++) {
        rv = do_EncryptDecryptRSA(&generated_oaep_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    for (i = 0; i < NUM_OF_GENERATED_OAEP_TESTSUITES; i++) {
        rv = do_WrapUnwrapRSA(&generated_oaep_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    // generated keywrap tests
    for (i = 0; i < NUM_OF_GENERATED_KEYWRAP_TESTSUITES; i++) {
        rv = do_WrapUnwrapRSA(&generated_keywrap_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    // key import tests
    for (i = 0; i < NUM_OF_ENCDEC_IMPORT_TESTSUITES; i++) {
        rv = do_EncryptDecryptImportRSA(&rsa_encdec_import_test_suites[i],
                                        RSA_KEY_FORMAT_FULL);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    for (i = 0; i < NUM_OF_ENCDEC_IMPORT_TESTSUITES; i++) {
        rv = do_EncryptDecryptImportRSA(&rsa_encdec_import_test_suites[i],
                                        RSA_KEY_FORMAT_ME);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    for (i = 0; i < NUM_OF_ENCDEC_IMPORT_TESTSUITES; i++) {
        rv = do_EncryptDecryptImportRSA(&rsa_encdec_import_test_suites[i],
                                        RSA_KEY_FORMAT_CRT);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    // Implicit rejection tests
    for (i = 0; i < NUM_OF_IMPLICIT_REJECTION_TESTSUITES; i++) {
        rv = do_RSAImplicitRejection(&rsa_implicit_rejection_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    // Private exponent test
    rv = do_RSAPrivateExponent();
    if (rv != CKR_OK && (!no_stop))
        return rv;

    // Wrap private key tests, with all RSA key formats
    rv = do_WrapPrivateKeyRSA(&published_test_suites[2], RSA_KEY_FORMAT_FULL);
    if (rv != CKR_OK && (!no_stop))
        return rv;

    rv = do_WrapPrivateKeyRSA(&published_test_suites[2], RSA_KEY_FORMAT_ME);
    if (rv != CKR_OK && (!no_stop))
        return rv;

    rv = do_WrapPrivateKeyRSA(&published_test_suites[2], RSA_KEY_FORMAT_CRT);
    if (rv != CKR_OK && (!no_stop))
        return rv;

    // Encapsulate/Decapsulate tests
    for (i = 0; i < NUM_OF_GENERATED_KEYWRAP_TESTSUITES; i++) {
        rv = do_EncapsDecapsRSA(&generated_keywrap_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    for (i = 0; i < NUM_OF_GENERATED_OAEP_TESTSUITES; i++) {
        rv = do_EncapsDecapsRSA(&generated_oaep_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    return rv;
}

int main(int argc, char **argv)
{
    int rc;
    CK_C_INITIALIZE_ARGS cinit_args;
    CK_RV rv;

    rc = do_ParseArgs(argc, argv);
    if (rc != 1) {
        return rc;
    }

    printf("Using slot #%lu...\n\n", SLOT_ID);
    printf("With option: no_stop: %d\n", no_stop);

    rc = do_GetFunctionList();
    if (!rc) {
        PRINT_ERR("ERROR do_GetFunctionList() Failed, rx = 0x%0x\n", rc);
        return rc;
    }

    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    funcs->C_Initialize(&cinit_args);
    {
        CK_SESSION_HANDLE hsess = 0;
        rc = funcs->C_GetFunctionStatus(hsess);
        if (rc != CKR_FUNCTION_NOT_PARALLEL) {
            return rc;
        }

        rc = funcs->C_CancelFunction(hsess);
        if (rc != CKR_FUNCTION_NOT_PARALLEL) {
            return rc;
        }
    }

    testcase_setup();
    rv = rsa_funcs();
    testcase_print_result();

    free_rsa_key_cache(CK_INVALID_HANDLE);
    funcs->C_Finalize(NULL);

    return testcase_return(rv);
}
