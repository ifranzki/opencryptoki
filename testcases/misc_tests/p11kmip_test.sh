#!/bin/bash
#
# COPYRIGHT (c) International Business Machines Corp. 2020
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php

# sudo -E ./p11kmip_test.sh

DIR=$(dirname "$0")

status=0


echo "** Now executing 'p11kmip_test.sh'"

PKCS11_SECRET_KEY_LABEL="local-secret-key"
PKCS11_PUBLIC_KEY_LABEL="local-public-key"
PKCS11_PRIVATE_KEY_LABEL="local-private-key"

KMIP_PUBLIC_KEY_NAME="tst00292ad2f000000001"
KMIP_PRIVATE_KEY_NAME="tst00292ad2f000000000"

P11KMIP_TMP="/tmp/p11kmip"
P11KMIP_UNIQUE_NAME="$(uname -n)-$(date +%s)"
P11KMIP_UNIQUE_NAME="${P11KMIP_UNIQUE_NAME^^}"

P11KMIP_CONF_FILE="${P11KMIP_TMP}/p11kmip.conf"

# Prepare PKCS11 variables
echo "** Setting SLOT=30 to the Softtoken unless otherwise set - 'p11kmip_test.sh'"

SLOT=${SLOT:-30}

echo "** Using Slot $SLOT with PKCS11_USER_PIN $PKCS11_USER_PIN and PKCSLIB $PKCSLIB - 'p11sak_test.sh'"

# Prepare KMIP variables

echo "** Setting KMIP_REST_URL=https://\${KMIP_IP}:19443 unless otherwise set - 'p11kmip_test.sh'"
echo "** Setting KMIP_SERVER=\${KMIP_IP}:5696 unless otherwise set - 'p11kmip_test.sh'"

echo "Dirpath: $DIR"
KMIP_CLIENT_CERT=$DIR/p11kmip_client_cert.pem
KMIP_KEY_CERT=$DIR/p11kmip_client_key.pem

KMIP_REST_URL="${KMIP_REST_URL:-https://${KMIP_IP}:19443}"
KMIP_HOSTNAME="${KMIP_SERVER:-${KMIP_IP}:5696}"

echo "** Using KMIP server $KMIP_REST_URL with KMIP_REST_USER $KMIP_REST_USER and KMIP_REST_PASSWORD $KMIP_REST_PASSWORD"

mkdir -p $P11KMIP_TMP

setup_kmip_client() {
  RETRY_COUNT=0
  LOGIN_DONE=0
  UPLOAD_CERT_DONE=0
  CREATE_CLIENT_DONE=0
  ASSIGN_CERT_DONE=0

  while true; do
		if [[ $RETRY_COUNT -gt 100 ]] ; then
			echo "error: Too many login retries"
			break
		fi
		RETRY_COUNT=$((RETRY_COUNT+1))

		if [[ $LOGIN_DONE -eq 0 ]] ; then
			# Get a login authorization ID from SKLM
			curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/ckms/login" \
				--header "Content-Type: application/json" \
				--data "{\"userid\":\"$KMIP_REST_USER\", \"password\":\"$KMIP_REST_PASSWORD\"}" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_get_login_authid_stdout 2>$P11KMIP_TMP/curl_get_login_authid_stderr
			RC=$?
			echo "rc:" $RC
			if [[ $RC -ne 0 ]] ; then
				cat $P11KMIP_TMP/curl_get_login_authid_stdout
				cat $P11KMIP_TMP/curl_get_login_authid_stderr
				break
			fi

			# Parse the response data and extract the authorization id token
			# Expected to return: {"UserAuthId":"xxxxxx"}
			AUTHID=`jq .UserAuthId $P11KMIP_TMP/curl_get_login_authid_stdout -r`
			echo "AuthID:" $AUTHID
			if [[ $LOGIN_DONE -eq 0 ]]; then
				echo "succeeded: curl_get_login_authid"
			fi
			if [[ $RC -ne 0 ]] ; then
				break
				cat $P11KMIP_TMP/curl_get_login_authid_stderr
			fi
			LOGIN_DONE=1
		fi

		# Upload the client certificate to SKLM
		if [[ $UPLOAD_CERT_DONE -eq 0 ]] ; then
			curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/filetransfer/upload/objectfiles" \
				--header "accept: application/json" --header "Content-Type: multipart/form-data" \
				--form "fileToUpload=@$KMIP_CLIENT_CERT" --form "destination=" --header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_upload_cert_stdout 2>$P11KMIP_TMP/curl_upload_cert_stderr
			RC=$?
			echo "rc:" $RC

			# Expected to return: {"code":"0","status":"CTGKM3465I File xxxx is uploaded.","messageId":"CTGKM3465I"}
			RC=`jq .code $P11KMIP_TMP/curl_upload_cert_stdout -r`
			MSG=`jq .status $P11KMIP_TMP/curl_upload_cert_stdout -r`
			if [[ "$RC" == "CTGKM6004E" ]]; then
				echo "warning: Login token expired, re-login and retry"
				continue
			fi
			if [[ "$MSG" == "CTGKM3466E Cannot upload the file $(basename $KMIP_CLIENT_CERT) because a file with the same name already exists on the server." ]]; then
				echo "info: Client certificate already uploaded to server"
				UPLOAD_CERT_DONE=1
				continue
			fi
			if [[ "$MSG" != "CTGKM3465I File $(basename $KMIP_CLIENT_CERT) is uploaded." ]]; then
				RC=1
				echo "error: Status not as expected"
				cat $P11KMIP_TMP/curl_upload_cert_stdout
				cat $P11KMIP_TMP/curl_upload_cert_stderr
			fi
			UPLOAD_CERT_DONE=1
			#echo "succeeded: curl_upload_cert"
		fi

		# Create a client in SKLM
		if [[ $CREATE_CLIENT_DONE -eq 0 ]] ; then
			KMIP_CLIENT_NAME=$(echo ${P11KMIP_UNIQUE_NAME^^} | sed -r 's/[ .,;:#+*$%-]+/_/g')
			echo "clientname:" $KMIP_CLIENT_NAME

			curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/clients" \
				--header "Content-Type: application/json" \
				--data "{\"clientName\":\"$KMIP_CLIENT_NAME\"}" \
				--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_create_client_stdout 2>$P11KMIP_TMP/curl_create_client_stderr
			RC=$?
			echo "rc:" $RC

			# Expected to return: {"message":"CTGKM3411I Successfully created client xxxx .","messageId":"CTGKM3411I"}
			MSG=`jq .message $P11KMIP_TMP/curl_create_client_stdout -r`
			if [[ "$MSG" == "CTGKM6004E User is not authenticated or has already logged out." ]]; then
				echo "warning: Login token expired, re-login and retry"
				continue
			fi
			if [[ "$MSG" != "CTGKM3411I Successfully created client $KMIP_CLIENT_NAME ." ]]; then
				RC=1
				echo "error: Message not as expected"
				cat $P11KMIP_TMP/curl_create_client_stdout
				cat $P11KMIP_TMP/curl_create_client_stderr
			fi
			CREATE_CLIENT_DONE=1
			# echo "succeeded: curl_create_client"
		fi

		# Assign the certificate with the client
		if [[ $ASSIGN_CERT_DONE -eq 0 ]] ; then
			curl --fail-with-body --location --request PUT "$KMIP_REST_URL/SKLM/rest/v1/clients/$KMIP_CLIENT_NAME/assignCertificate" \
				--header "Content-Type: application/json" \
				--data "{\"certUseOption\":\"IMPORT_CERT\",\"certAlias\":\"$P11KMIP_UNIQUE_NAME\",\"importPath\":\"$(basename $KMIP_CLIENT_CERT)\"}" \
				--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_assign_cert_stdout 2>$P11KMIP_TMP/curl_assign_cert_stderr
			RC=$?
			echo "rc:" $RC

			# Expected to return: {"message":"CTGKM3409I Successfully assigned certificate to client.","messageId":"CTGKM3409I"}
			MSG=`jq .message $P11KMIP_TMP/curl_assign_cert_stdout -r`
			if [[ "$MSG" == "CTGKM6004E User is not authenticated or has already logged out." ]]; then
				echo "warning: Login token expired, re-login and retry"
				continue
			fi
			if [[ "$MSG" != "CTGKM3409I Successfully assigned certificate to client." ]]; then
				RC=1
				echo "error: Message not as expected"
				cat $P11KMIP_TMP/curl_assign_cert_stdout
				cat $P11KMIP_TMP/curl_assign_cert_stderr
			fi
			ASSIGN_CERT_DONE=1
			# echo "succeeded: curl_assign_cert"
		fi

		break
	done
}

setup_pkcs11_keys() {
	# AES key for exporting
	p11sak import-key aes --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_SECRET_KEY_LABEL --file $DIR/aes.key --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))

	# RSA keys for wrapping and importing
	p11sak import-key rsa private --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_PRIVATE_KEY_LABEL --file $DIR/rsa-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	p11sak import-key rsa public --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_PUBLIC_KEY_LABEL --file $DIR/rsa-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
}

setup_kmip_keys() {
	curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/objects/keypair" \
		--header "accept: application/json" --header "Content-Type: application/json" \
		--data "{\"clientName\":\"$P11KMIP_UNIQUE_NAME\", \"prefixName\":\"tst\", \"numberOfObjects\": \"1\", \"publicKeyCryptoUsageMask\":\"Wrap_Unwrap\", \"privateKeyCryptoUsageMask\":\"Wrap_Unwrap\"}" \
		--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
		--insecure --silent --show-error >$P11KMIP_TMP/curl_generate_keys_stdout 2>$P11KMIP_TMP/curl_generate_keys_stderr
	
	PUBKEY_ID=`jq .publicKeyId $P11KMIP_TMP/curl_generate_keys_stdout -r`

	curl --fail-with-body --location --request GET "$KMIP_REST_URL/SKLM/rest/v1/objects/$KMIP_PUBKEY_ID" \
		--header "accept: application/json" --header "Content-Type: application/json" \
		--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
		--insecure --silent --show-error >$P11KMIP_TMP/curl_get_pubkey_stdout 2>$P11KMIP_TMP/curl_get_pubkey_stderr
	
	KMIP_PUBKEY_LABEL=`jq .managedObject.alias $P11KMIP_TMP/curl_get_pubkey_stdout -r`
	KMIP_PUBKEY_LABEL=${KMIP_PUBKEY_LABEL:1:21}
}

key_import_tests() {
	################################################################
	# Using configuration file options                             #
	################################################################

	# Build a standard configuration
	[[ -f $P11KMIP_CONF_FILE ]] && rm $P11KMIP_CONF_FILE
    echo "kmip {                                              " >> $P11KMIP_CONF_FILE
    echo "    host = \"${KMIP_HOSTNAME}\"                         " >> $P11KMIP_CONF_FILE
    echo "    tls_client_cert = \"${KMIP_CLIENT_CERT}\"       " >> $P11KMIP_CONF_FILE
    echo "    tls_client_key = \"${KMIP_KEY_CERT}\"           " >> $P11KMIP_CONF_FILE
    echo "                                                    " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_format = \"PKCS1\"                     " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_algorithm = \"RSA\"                    " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_size = 2048                            " >> $P11KMIP_CONF_FILE
    echo "    wrap_padding_method = \"PKCS1.5\"               " >> $P11KMIP_CONF_FILE
    echo "    wrap_hashing_algorithm = \"SHA-1\"              " >> $P11KMIP_CONF_FILE
    echo "}                                                   " >> $P11KMIP_CONF_FILE
    echo "pkcs11 {                                            " >> $P11KMIP_CONF_FILE
    echo "    slot_number = ${PKCS11_SLOT_ID}                 " >> $P11KMIP_CONF_FILE
    echo "}                                                   " >> $P11KMIP_CONF_FILE

	echo "*** Running test using configuration options"

	p11kmip import-key --pin $PKCS11_USER_PIN  \
		--send-wrapkey \
		--targkey-label $PKCS11_SECRET_KEY_LABEL \
		--wrapkey-label $PKCS11_PRIVATE_KEY_LABEL

	echo "rc = $?"

	################################################################
	# Using environment variables                                  #
	################################################################

	# PKCS11_USER_PIN  set externally
	# PKCS11_SLOT_PIN  set externally
	# KMIP_HOSTNAME        set externally
	# KMIP_CLIENT_CERT set externally
	# KMIP_CLIENT_KEY  set externally

	# Fill the configuration file with bogus values
	[[ -f $P11KMIP_CONF_FILE ]] && rm $P11KMIP_CONF_FILE
    echo "kmip {                                           " >> $P11KMIP_CONF_FILE
    echo "    host = \"255.255.255.255:0\"                 " >> $P11KMIP_CONF_FILE
    echo "    tls_client_cert = \"/dev/null\"              " >> $P11KMIP_CONF_FILE
    echo "    tls_client_key = \"/dev/null\"               " >> $P11KMIP_CONF_FILE
    echo "                                                 " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_format = \"PKCS1\"                  " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_algorithm = \"RSA\"                 " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_size = 2048                         " >> $P11KMIP_CONF_FILE
    echo "    wrap_padding_method = \"PKCS1.5\"            " >> $P11KMIP_CONF_FILE
    echo "    wrap_hashing_algorithm = \"SHA-1\"           " >> $P11KMIP_CONF_FILE
    echo "}                                                " >> $P11KMIP_CONF_FILE
    echo "pkcs11 {                                         " >> $P11KMIP_CONF_FILE
    echo "    slot_number = 0                              " >> $P11KMIP_CONF_FILE
    echo "}                                                " >> $P11KMIP_CONF_FILE

	echo "*** Running test using environment variables"

	p11kmip import-key --targkey-label $PKCS11_SECRET_KEY_LABEL \
	--wrapkey-label $KMIP_PUBLIC_KEY_NAME

	echo "rc = $?"

	################################################################
	# Using only commandline options                               #
	################################################################

	# Stash real variables in temporary variables
	__PKCS11_USER_PIN=$PKCS11_USER_PIN
	__PKCS11_SLOT_ID=$PKCS11_SLOT_ID
	__KMIP_HOSTNAME=$KMIP_HOSTNAME
	__KMIP_CLIENT_CERT=$KMIP_CLIENT_CERT
	__KMIP_CLIENT_KEY=$KMIP_CLIENT_KEY	

	# Unset environment variables
	unset PKCS11_USER_PIN
	unset PKCS11_SLOT_ID
	unset KMIP_HOSTNAME
	unset KMIP_CLIENT_CERT
	unset KMIP_CLIENT_KEY

	echo "*** Running test using command line options"

	p11kmip import-key --slot $__PKCS11_SLOT_ID --pin $__PKCS11_USER_PIN  \
		--send-wrapkey \
		--kmip-host $__KMIP_HOSTNAME \
		--tls-client-cert $__KMIP_CLIENT_CERT \
		--tls-client-key $__KMIP_CLIENT_KEY \
		--targkey-label $__PKCS11_SECRET_KEY_LABEL \
		--wrapkey-label $__PKCS11_PRIVATE_KEY_LABEL
	
	echo "rc = $?"

	# Restore environment variables from stashed values
	PKCS11_USER_PIN=$__PKCS11_USER_PIN
	PKCS11_SLOT_ID=$__PKCS11_SLOT_ID
	KMIP_HOSTNAME=$__KMIP_HOSTNAME
	KMIP_CLIENT_CERT=$__KMIP_CLIENT_CERT
	KMIP_CLIENT_KEY=$__KMIP_CLIENT_KEY	
}

key_export_tests() {
	# Build a standard configuration
	[[ -f $P11KMIP_CONF_FILE ]] && rm $P11KMIP_CONF_FILE
    echo "kmip {                                              " >> $P11KMIP_CONF_FILE
    echo "    host = \"${KMIP_HOSTNAME}\"                         " >> $P11KMIP_CONF_FILE
    echo "    tls_client_cert = \"${KMIP_CLIENT_CERT}\"       " >> $P11KMIP_CONF_FILE
    echo "    tls_client_key = \"${KMIP_KEY_CERT}\"           " >> $P11KMIP_CONF_FILE
    echo "                                                    " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_format = \"PKCS1\"                     " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_algorithm = \"RSA\"                    " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_size = 2048                            " >> $P11KMIP_CONF_FILE
    echo "    wrap_padding_method = \"PKCS1.5\"               " >> $P11KMIP_CONF_FILE
    echo "    wrap_hashing_algorithm = \"SHA-1\"              " >> $P11KMIP_CONF_FILE
    echo "}                                                   " >> $P11KMIP_CONF_FILE
    echo "pkcs11 {                                            " >> $P11KMIP_CONF_FILE
    echo "    slot_number = ${PKCS11_SLOT_ID}                 " >> $P11KMIP_CONF_FILE
    echo "}                                                   " >> $P11KMIP_CONF_FILE

	echo "*** Running test using configuration options"

	p11kmip export-key --pin $PKCS11_USER_PIN  \
		--targkey-label $PKCS11_SECRET_KEY_LABEL \
		--wrapkey-label $KMIP_PUBLIC_KEY_NAME
	
	echo "rc = $?"
}

echo "** Setting up KMIP client on KMIP server - 'p11kmip_test.sh'"

setup_kmip_client

echo "** Setting up remote and local test keys - 'p11kmip_test.sh'"

setup_kmip_keys

setup_pkcs11_keys

echo "** Running key import tests - 'p11kmip_test.sh'"

key_import_tests

echo "** Running key export tests - 'p11kmip_test.sh'"

key_export_tests