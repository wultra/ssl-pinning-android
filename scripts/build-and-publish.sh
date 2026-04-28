#!/bin/bash

set -e # stop script when error occurs
set -u # stop when undefined variable is used
set -o pipefail # stop when any command in a pipe fails

##############################
#
# This script will build and publish the library to the specified repository.
#
# Usage:
#   ./scripts/build-and-publish.sh <repository>
#    where <repository> is either "central" or "local"
#
# To be able to publish to Maven Central, you need `.credentials` file in your home directory
# with required properties or optionally in "~/.wultra/.credentials".
#
# Internally, this script invokes Gradle tasks define by the android-release-gradle-plugin.
#
##############################

TOP=$(dirname $0)
SRC_ROOT="`( cd \"${TOP}/..\" && pwd )`"

pushd "${SRC_ROOT}" # move to the repo root

TARGET_REPO=$1 # assume first argument is the target repository

source "library/gradle.properties" # load project properties to get version and artifact id

# print info about what is going to be published for better visibility
echo -e "\n|----------------------------------------------------------"
echo "| Publishing $ARTIFACT_ID to $TARGET_REPO repository"
echo "| Version: $VERSION_NAME"
echo -e "|----------------------------------------------------------\n"

unset VERSION_NAME GROUP_ID ARTIFACT_ID # Clean up environment from loaded properties

# determine which Gradle task to use for publishing (define by the android-release-gradle-plugin)
if [ "${TARGET_REPO}" == "central" ] ; then
    PUBLISH_GRADLE_TASK="publishReleasePublicationToSonatypeRepository"
elif [ "${TARGET_REPO}" == "local" ] ; then
    PUBLISH_GRADLE_TASK="publishReleasePublicationToMavenLocal"
else
    echo "You must specify repository where publish to."
    exit 1
fi

GRADLE_CMD_LINE="assembleRelease $PUBLISH_GRADLE_TASK"
./gradlew $GRADLE_CMD_LINE

popd
