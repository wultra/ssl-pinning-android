#!/bin/bash
###############################################################################
# Include common functions...
# -----------------------------------------------------------------------------
TOP=$(dirname $0)
source "${TOP}/common-functions.sh"
source "${TOP}/deploy.cfg.sh"
SRC_ROOT="`( cd \"$TOP/..\" && pwd )`"

# -----------------------------------------------------------------------------
# USAGE prints help and exits the script with error code from provided parameter
# Parameters:
#   $1   - error code to be used as return code from the script
# -----------------------------------------------------------------------------
function USAGE
{
    echo ""
    echo "Usage:  $CMD [options] version"
    echo ""
    echo "    This tool helps with library publication to $DEPLOY_REMOTE_NAME"
    echo ""
    echo "Where:"
    echo ""
    echo "    version           Is new library version in x.y.z format"
    echo ""
    echo "options:"
    echo ""
    echo "    -v0               turn off all prints to stdout"
    echo "    -v1               print only basic log about build progress"
    echo "    -v2               print full build log with rich debug info"
    echo "    -h | --help       print this help information"
    echo ""
    exit $1
}

VERBOSE_SWITCH=''

while [[ $# -gt 0 ]]
do
    opt="$1"
    case "$opt" in
        -h | --help)
            USAGE 0 ;;
        -v*)
            VERBOSE_SWITCH=$opt
            SET_VERBOSE_LEVEL_FROM_SWITCH $opt ;;
        *)
            VALIDATE_AND_SET_VERSION_STRING $opt ;;
    esac
    shift
done

# make sure that new version and build unmber is available
if [ "$VERSION" == "" ]; then
    FAILURE "You have to specify version in X.Y.Z format."
fi

REQUIRE_COMMAND git

LOG "Configuring version..."
"${TOP}/android-publish-build.sh" $VERBOSE_SWITCH -r $VERSION

LOG "Publishing release to $DEPLOY_REMOTE_NAME..."
"${TOP}/android-publish-build.sh" $VERBOSE_SWITCH remote

# Apply changes to git

LOG "Creating version in git..."
PUSH_DIR "$SRC_ROOT"

# Commit changes
git commit -m "Version bump to ${VERSION}"
git push
# Create tag
git tag "${VERSION}"
git push --tags

POP_DIR

EXIT_SUCCESS