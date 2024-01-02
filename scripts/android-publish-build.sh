#!/bin/bash
###############################################################################
# Include common functions...
# -----------------------------------------------------------------------------
TOP=$(dirname $0)
source "${TOP}/common-functions.sh"
source "${TOP}/deploy.cfg.sh"

[[ -z "$SRC_ROOT" ]] && FAILURE "Missing SRC_ROOT in deploy.cfg.sh"

# -----------------------------------------------------------------------------
# USAGE prints help and exits the script with error code from provided parameter
# Parameters:
#   $1   - error code to be used as return code from the script
# -----------------------------------------------------------------------------
function USAGE
{
    echo ""
    echo "Usage:  $CMD [options] repository"
    echo ""
    echo "    This tool helps with library publication to $DEPLOY_REMOTE_NAME"
    echo "    or to local maven cache."
    echo ""
    echo "repository is:"
    echo ""
    echo "  remote              Publish Android SDK to $DEPLOY_REMOTE_NAME"
    echo "  local               Publish Android SDK to local Maven cache"
    echo ""
    echo "options:"
    echo ""
    echo "    -s version | --snapshot version"
    echo "                      Set version to 'version-SNAPSHOT' and exit"
    echo ""
    echo "    -r version | --release version"
    echo "                      Set version to 'version' and exit"
    echo ""
    echo "    -nc | --no-clean"
    echo "                      Don't clean build before publishing"
    if [ x$DEPLOY_ALLOW_SIGN == x1 ]; then
        echo ""
        echo "    -ns | --no-sign"
        echo "                      Don't sign artifacts when publishing"
        echo "                      to local Maven cache"
    fi
    echo ""
    echo "    -v0               turn off all prints to stdout"
    echo "    -v1               print only basic log about build progress"
    echo "    -v2               print full build log with rich debug info"
    echo "    -h | --help       print this help information"
    echo ""
    exit $1
}

# -----------------------------------------------------------------------------
# MAKE_VER sets version or version-SNAPSHOT to gradle.properties file
# Parameters:
#   $1   - version to set
#   $2   - version suffix, for example "SNAPSHOT", or empty
# -----------------------------------------------------------------------------
function MAKE_VER
{
    local VER=$1
    local VER_SUFFIX=$2
    if [ ! -z "$VER_SUFFIX" ]; then
        VER_SUFFIX="-$VER_SUFFIX"
    fi
    local NEW_VER=${VER}${VER_SUFFIX}
    
    VALIDATE_AND_SET_VERSION_STRING "$VER"
    
    LOG "Changing version to:"
    
    for PROP_FILE in "${DEPLOY_VERSION_FILES[@]}"
    do
        local PROP_PATH="$SRC_ROOT/${PROP_FILE}"
        
        local VERSION=$(GET_PROPERTY "$PROP_PATH" "VERSION_NAME")
        local GROUP_ID=$(GET_PROPERTY "$PROP_PATH" "GROUP_ID")
        local ARTIFACT_ID=$(GET_PROPERTY "$PROP_PATH" "ARTIFACT_ID")
        
        [[ -z "$VERSION" ]] && FAILURE "Failed to load VERSION_NAME from gradle.properties file."
        [[ -z "$GROUP_ID" ]] && FAILURE "Failed to load GROUP_ID from gradle.properties file."
        [[ -z "$ARTIFACT_ID" ]] && FAILURE "Failed to load ARTIFACT_ID from gradle.properties file."

        local CUR_VER=$VERSION
    
        PUSH_DIR "${SRC_ROOT}"
        #### 
        sed -e "s/$CUR_VER/$NEW_VER/g" "${PROP_PATH}" > "${PROP_PATH}.new"
        $MV "${PROP_PATH}.new" "${PROP_PATH}"
        git add ${PROP_FILE}
        ####
        POP_DIR
    
        LOG_LINE
        LOG " - Version     : ${NEW_VER}"
        LOG " - Dependency  : ${GROUP_ID}:${ARTIFACT_ID}:${NEW_VER}" 
        LOG_LINE
    done
}

# -----------------------------------------------------------------------------
# PRINT_CURRENT_VERSION loads and prints rich version info from gradle.properties
# file. Parameters:
#   $1   - target repository (local | remote)
# -----------------------------------------------------------------------------
function PRINT_CURRENT_VERSION
{
    local REPO=$1
    for PROP_FILE in "${DEPLOY_VERSION_FILES[@]}"
    do
        local PROP_PATH="$SRC_ROOT/${PROP_FILE}"
    
        local VERSION=$(GET_PROPERTY "$PROP_PATH" "VERSION_NAME")
        local GROUP_ID=$(GET_PROPERTY "$PROP_PATH" "GROUP_ID")
        local ARTIFACT_ID=$(GET_PROPERTY "$PROP_PATH" "ARTIFACT_ID")
        
        [[ -z "$VERSION" ]] && FAILURE "Failed to load VERSION_NAME from gradle.properties file."
        [[ -z "$GROUP_ID" ]] && FAILURE "Failed to load GROUP_ID from gradle.properties file."
        [[ -z "$ARTIFACT_ID" ]] && FAILURE "Failed to load ARTIFACT_ID from gradle.properties file."
    
        LOG " - Version     : ${VERSION}"
        LOG " - Dependency  : ${GROUP_ID}:${ARTIFACT_ID}:${VERSION}" 
    done
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
DO_CLEAN='clean'
DO_PUBLISH=''
DO_SIGN=$DEPLOY_ALLOW_SIGN
DO_REPO=''
GRADLE_PARAMS=''
GRADLE_ROOT=${GRADLE_ROOT:-$SRC_ROOT}

REQUIRE_COMMAND git

while [[ $# -gt 0 ]]
do
    opt="$1"
    case "$opt" in
        -s | --snapshot)
            MAKE_VER "$2" 'SNAPSHOT'
            EXIT_SUCCESS
            ;;
        -r | --release)
            MAKE_VER "$2" ""
            EXIT_SUCCESS
            ;;
        -nc | --no-clean)
            DO_CLEAN='' ;;
        -ns | --no-sign)
            [[ x$DEPLOY_ALLOW_SIGN == x0 ]] && FAILURE "'--no-sign' option is not available for this library"
            DO_SIGN=0 ;;
        remote | local)
            DO_REPO=$opt ;;
        -v*)
            SET_VERBOSE_LEVEL_FROM_SWITCH $opt ;;
        -h | --help)
            USAGE 0 ;;
        *)
            USAGE 1 ;;
    esac
    shift
done

case "$DO_REPO" in
    local)
        DO_PUBLISH='publishReleasePublicationToMavenLocal'
        ;;  
    remote)
        DO_PUBLISH="$DEPLOY_REMOTE_TASK"
        ;;
    *)
        FAILURE "You must specify repository where publish to."
esac

if [ $VERBOSE == 2 ]; then
    GRADLE_PARAMS+=' --debug'
fi

# Load signing and releasing credentials
if [ "$DO_REPO" == 'remote' ] || [ x$DO_SIGN == x1 ]; then
    [[ x$DO_SIGN == x0 ]] && [[ x$DEPLOY_ALLOW_SIGN == x1 ]] && FAILURE "Signing is required for publishing to $DEPLOY_REMOTE_NAME."
    DEPLOY_PREPARE_GRADLE_PARAMS
fi

LOG_LINE
if [ $DO_REPO == 'local' ]; then
    LOG "Going to publish library to local Maven cache"
else
    LOG "Going to publish library to $DEPLOY_REMOTE_NAME"
fi
PRINT_CURRENT_VERSION $DO_REPO
if [ x$DO_CLEAN == x ]; then
    LOG " - Clean build : NO"
else
    LOG " - Clean build : YES"
fi
if [ x$DEPLOY_ALLOW_SIGN == x1 ]; then
    if [ x$DO_SIGN == x1 ]; then
        LOG " - Signed      : YES"
    else
        LOG " - Signed      : NO"
    fi
fi
LOG_LINE


PUSH_DIR "${GRADLE_ROOT}"
####
GRADLE_CMD_LINE="$GRADLE_PARAMS $DO_CLEAN assembleRelease $DO_PUBLISH"
DEBUG_LOG "Gradle command line >> ./gradlew $GRADLE_CMD_LINE"
./gradlew $GRADLE_CMD_LINE
####
POP_DIR

EXIT_SUCCESS -l