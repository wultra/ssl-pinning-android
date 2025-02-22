#!/bin/bash

TOP=$(dirname $0)
PROJECT_FOLDER="${TOP}/.."

FOLDER="${PROJECT_FOLDER}/pinningtool"
TOOL="ssl-pinning-tool.jar"
KEYPAIR="keypair.pem"
PASSWORD="password"
CERT="cert.pem"
OUTPUT="output.json"
PUBKEY="pub.key"
TEMPPUBKEY="temppub.key"

TESTFOLDER="../library/src/test/resources"
TARGETJSONFILE="${TESTFOLDER}/valid_github.json"
TARGETPUBKEYFILE="${TESTFOLDER}/pub.key"
TARGETCERTFILE="${TESTFOLDER}/cert.pem"

rm -rf "${FOLDER}"
mkdir "${FOLDER}"

pushd "${FOLDER}"

# DOWNLOAD TOOL
if ! [ -f "${TOOL}" ]; then
  curl -L -o "${TOOL}" "https://github.com/wultra/ssl-pinning-tool/releases/download/1.9.0/ssl-pinning-tool.jar"
fi

# DOWNLOAD CERTIFICATE
openssl s_client -showcerts -connect github.com:443 -servername github.com < /dev/null | openssl x509 -outform PEM > "${CERT}"

# GENERATE SIGNING KEY-PAIR
java -jar "${TOOL}" keygen -o "${KEYPAIR}" -p "${PASSWORD}"

# GENERATE OUTPUT FILE
java -jar "${TOOL}" sign -k "${KEYPAIR}" -c "${CERT}" -o "${OUTPUT}" -p "${PASSWORD}"

# GENERATE PUBLIC KEY TO FILE
java -jar "${TOOL}" export -k "${KEYPAIR}" -p "${PASSWORD}"  2> "${TEMPPUBKEY}" &&  awk -F' - ' '{print $2}' < "${TEMPPUBKEY}" > "${PUBKEY}" && rm "${TEMPPUBKEY}"

mkdir -p "${TESTFOLDER}"
cp "${OUTPUT}" "${TARGETJSONFILE}"
cp "${PUBKEY}" "${TARGETPUBKEYFILE}"
cp "${CERT}" "${TARGETCERTFILE}"

popd