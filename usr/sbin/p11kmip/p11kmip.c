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



static struct kmip_conn_config kmip_config = {
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
	.tls_client_cert = "/tmp/certs/client_certificate_jane_doe.pem",
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

static int passwd_callback(char *pcszBuff,int size,int rwflag, void *pPass);
const char *pcszPassphrase = "";

/***********************************************/
/* KMIP configuration and connection functions */
/***********************************************/

static CK_RV build_kmip_config(void)
{
	FILE *pFile = fopen("/tmp/certs/client_key_jane_doe.pem","rt");
    kmip_config.tls_client_key = PEM_read_PrivateKey(pFile,NULL,passwd_callback,(void*)pcszPassphrase);

	fclose(pFile);

	return CKR_OK;
}

static CK_RV free_kmip_config(void)
{
	EVP_PKEY_free(kmip_config.tls_client_key);

	return CKR_OK;
}

static CK_RV open_kmip_connection(void)
{
	CK_RV rc;
	struct kmip_connection *kmip_conn;

	rc = kmip_connection_new(&kmip_config,&kmip_conn, true);

	return CKR_OK;
}

static CK_RV close_kmip_connection(struct kmip_connection *kmip_conn)
{
	CK_RV rc;

	kmip_connection_free(kmip_conn);

	return CKR_OK;
}

/**
 * Build a KMIP request with the up to 2 operations and payloads
 *
 * @param ph                the plugin handle
 * @param operation1        The 1st operation to perform
 * @param req_pl1           the request payload of the 1st operation
 * @param operation2        The 2nd operation to perform (or 0)
 * @param req_pl2           the request payload of the 2nd operation (or NULL)
 * @param req               On return: the created request.
 * @param batch_err_opt     Batch error option
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _build_kmip_request(enum kmip_operation operation,
			       struct kmip_node *req_pl,
			       struct kmip_node **req)
{
	struct kmip_node *req_bi = NULL, *req_hdr = NULL;
	int rc = 0;

	req_bi = kmip_new_request_batch_item(operation, NULL, 0, req_pl);
	// CHECK_ERROR(req_bi1 == NULL, rc, -ENOMEM, "Allocate KMIP node failed",
	// 	    ph, out);

	req_hdr = kmip_new_request_header(NULL, 0, NULL, NULL, false, NULL,
					  KMIP_BATCH_ERR_CONT_STOP, true, 1);
	// CHECK_ERROR(req_hdr == NULL, rc, -ENOMEM, "Allocate KMIP node failed",
	// 	    ph, out);

	*req = kmip_new_request_va(req_hdr, 1, req_bi);
	// CHECK_ERROR(*req == NULL, rc, -ENOMEM, "Allocate KMIP node failed",
	// 	    ph, out);

out:
	kmip_node_free(req_bi);
	kmip_node_free(req_hdr);

	return rc;
}


/**
 * Perform a KMIP request with up to 2 operations and payloads.
 * Returns the response payloads.
 *
 * @param ph                the plugin handle
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
static int _perform_kmip_request(
	struct kmip_connection *connection,
	enum kmip_operation operation,
	struct kmip_node *req_pl,
	struct kmip_node **resp_pl)
{
	struct kmip_node *req = NULL, *resp = NULL;
	int rc;
	bool verbose;

	rc = _build_kmip_request(operation, req_pl,
				  &req);
	if (rc != 0)
		goto out;

	verbose = false;
	rc = kmip_connection_perform(connection, req, &resp,
				     verbose);
	// if (rc != 0) {
	// 	_set_error(ph, "Failed to perform KMIP request: %s",
	// 		   strerror(-rc));
	// }

	//rc  = _check_kmip_response(resp, 0, operation, resp_pl);
	if (rc != 0)
		goto out;

out:
	kmip_node_free(req);
	kmip_node_free(resp);

	return rc;
}


/**
 * Retrieves an AES key from the KMIP server. The key is wrapped with the
 * RSA wrapping key.
 *
 * @param ph                the plugin handle
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

	rc = _perform_kmip_request(connection, KMIP_OPERATION_GET, req_pl, &resp_pl);
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



/***********************************************/
/* Send the RSA public key to KMIP             */
/***********************************************/





int main(int argc, char *argv[])
{
    CK_RV rc = CKR_OK;

	// TODO: parse args
    
    

    
    return rc;
}

int passwd_callback(char *pcszBuff,int size,int rwflag, void *pPass)
{
    size_t unPass = strlen((char*)pPass);
    if(unPass > (size_t)size)
        unPass = (size_t)size;
    memcpy(pcszBuff, pPass, unPass);
    return (int)unPass;
}
