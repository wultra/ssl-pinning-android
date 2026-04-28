#!/bin/bash

#set -x
set -e

KTLINT_VERSION="0.50.0"
NO_ERROR=false

TOP=$(dirname $0)
pushd "${TOP}/.."

function download
{
    curl -sSLO "https://github.com/pinterest/ktlint/releases/download/${KTLINT_VERSION}/ktlint" && chmod +x ktlint
}

while [[ $# -gt 0 ]]
do
    opt="$1"
    case "$opt" in
        -ne | --no-error)
            NO_ERROR=true
            ;;
    esac
    shift
done

echo ""
echo "##################################"
echo "       CUSTOM KTLINT SCRIPT       "
echo "##################################"
echo ""

if [ ! -f "ktlint" ]; then
    echo "downloading ktlint ${KTLINT_VERSION}..."
    download
else
    current=$(./ktlint -V)
    # current="0.48.2"
    if [ "${KTLINT_VERSION}" != "${current}" ]; then
        echo "ktlint ${current} already downloaded, but ${KTLINT_VERSION} is required, removing and downloading."
        rm "ktlint"
        download
    else
        echo "ktlint ${KTLINT_VERSION} already downloaded."
    fi
fi

EXIT_CODE=0
./ktlint "**/*.kt" "**/*.kts" || EXIT_CODE=$?


echo ""
echo "##################################"
if [ $EXIT_CODE -eq 0 ]; then
    echo "         NO KTLINT ERRORS         "
else
    echo "     THERE ARE KTLINT ERRORS!     "
    if [ $NO_ERROR == true ]; then
        echo "       (ignoring exit code)"
        EXIT_CODE=0
    else
        echo "       (exiting with error)"
        EXIT_CODE=1
    fi
fi
echo "##################################"
echo ""

exit $EXIT_CODE