#!/bin/bash
###############################################################################
# Include common functions...
# -----------------------------------------------------------------------------
TOP=$(dirname $0)
SRC_ROOT="`( cd \"$TOP/..\" && pwd )`"
pushd "${SRC_ROOT}"

./gradlew clean assemblePowerauthRelease
./gradlew clean assembleBasicRelease