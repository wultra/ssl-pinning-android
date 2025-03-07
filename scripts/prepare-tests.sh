#!/bin/bash

set -e

TOP=$(dirname $0)
PROJECT_FOLDER="${TOP}/.."

# required parameters
URL=""
APPNAME=""
MUS_USERNAME=""
MUS_PASSWORD=""

TEST_CREDS_FILE="${PROJECT_FOLDER}/configs/private-integration-tests.properties"

while [[ $# -gt 0 ]]; do
  opt="$1"
  case "$opt" in
    --url)
      URL=${2}
      shift
      ;;
    --app)
      APPNAME=${2}
      shift
      ;;
    --username)
      MUS_USERNAME=${2}
      shift
      ;;
    --password)
      MUS_PASSWORD=${2}
      shift
      ;;
    *)
      echo "Unknown parameter ${1}"
      USAGE 1
      ;;
  esac
  shift
done

if [[ "${URL}" == "" || "${APPNAME}" == "" ]]; then
  echo "Missing parameter. Parameters '--url MUS_URL --app APP_NAME are required to provide."
  if [[ -f "${TEST_CREDS_FILE}" ]]; then
    echo "but test file ${TEST_CREDS_FILE} exists, so let's continue..."
  else
    exit 1
  fi
else
  # create test file
  echo -e "test.sslPinning.baseUrl=${URL}\ntest.sslPinning.appName=${APPNAME}" > "${TEST_CREDS_FILE}"
fi

if [[ "${MUS_USERNAME}" == "" || "${MUS_PASSWORD}" == "" ]]; then
  echo ""
  echo "Missing parameter. Parameters '--username ADMIN_USERNAME --password ADMIN_PASSWORD' are needed to autoupdate the github.com certificate on the server - tests might fail."
  echo ""
else
  # update github cert on the MUS server
  RENEW_CERT_URL="${URL}/admin/apps/${APPNAME}/certificates/auto"
  AUTH_TOKEN=$( echo -n "${MUS_USERNAME}:${MUS_PASSWORD}" | base64 )
  JSON_BODY="{\"domain\":\"github.com\"}"

  echo "Calling ${RENEW_CERT_URL} url with ${JSON_BODY}"

  # not that even if the update failes on server logic (non-existing app for example), it will return 200 so the script will continue
  curl -X POST "${RENEW_CERT_URL}" \
     -H "Content-Type: application/json" \
     -H "Authorization: Basic ${AUTH_TOKEN}" \
     -d "${JSON_BODY}"
fi

# create temp folder amd move into it
FOLDER="${PROJECT_FOLDER}/pinningtool"
mkdir -p "${FOLDER}"
pushd "${FOLDER}"

# set variables needed
TOOL="ssl-pinning-tool.jar"
KEYPAIR="keypair.pem"
PASSWORD="password"
CERT="cert.pem"
OUTPUT="output.json"
PUBKEY="pub.key"
TEMPPUBKEY="temppub.key"

# output for unit tests
TESTFOLDER="../library/src/test/resources"
TARGETJSONFILE="${TESTFOLDER}/valid_github.json"
TARGETPUBKEYFILE="${TESTFOLDER}/pub.key"
TARGETCERTFILE="${TESTFOLDER}/cert.pem"

# output for android tests
ANDROIDTESTFOLDER="../library/src/androidTest/assets"
ANDROIDTARGETJSONFILE="${ANDROIDTESTFOLDER}/valid_github.json"

# download pinning tool
if ! [ -f "${TOOL}" ]; then
  curl -L -o "${TOOL}" "https://github.com/wultra/ssl-pinning-tool/releases/download/1.9.0/ssl-pinning-tool.jar"
fi

# download github certificate
openssl s_client -showcerts -connect github.com:443 -servername github.com < /dev/null | openssl x509 -outform PEM > "${CERT}"

# generate signing key pair
java -jar "${TOOL}" keygen -o "${KEYPAIR}" -p "${PASSWORD}"

# generate github signature JSON
java -jar "${TOOL}" sign -k "${KEYPAIR}" -c "${CERT}" -o "${OUTPUT}" -p "${PASSWORD}"

# generate public key
java -jar "${TOOL}" export -k "${KEYPAIR}" -p "${PASSWORD}"  2> "${TEMPPUBKEY}" &&  awk -F' - ' '{print $2}' < "${TEMPPUBKEY}" > "${PUBKEY}" && rm "${TEMPPUBKEY}"

# copy files to unit tests
mkdir -p "${TESTFOLDER}"
cp "${OUTPUT}" "${TARGETJSONFILE}"
cp "${PUBKEY}" "${TARGETPUBKEYFILE}"
cp "${CERT}" "${TARGETCERTFILE}"

# copy files to android tests
mkdir -p "${ANDROIDTESTFOLDER}"
cp "${OUTPUT}" "${ANDROIDTARGETJSONFILE}"

popd