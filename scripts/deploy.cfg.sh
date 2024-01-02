# gradle.properties file where library version is stored
DEPLOY_VERSION_FILES=("library/gradle.properties")
# Name of remote repository. Variable is used in communication with user.
DEPLOY_REMOTE_NAME="Maven Central"
# Gradle task to publish library to remote repository
DEPLOY_REMOTE_TASK="publishReleasePublicationToSonatypeRepository"
# Set 0 / 1 whether signing is allowed
DEPLOY_ALLOW_SIGN=1

# Sources root
SRC_ROOT="`( cd \"$TOP/..\" && pwd )`"

# -----------------------------------------------------------------------------
# Function that adjusts GRADLE_PARAMS global variable with parameters required
# for proper library deployment to remote repository.
# -----------------------------------------------------------------------------
function DEPLOY_PREPARE_GRADLE_PARAMS
{
    # Find proper signing tool
    set +e
    local HAS_GPG=`which gpg`
    local HAS_GPG2=`which gpg2`
    set -e
    
    [[ -z $HAS_GPG ]] && [[ -z $HAS_GPG2 ]] && FAILURE "gpg or gpg2 tool is missing."
    
    # Load and validate API credentials
    LOAD_API_CREDENTIALS
    [[ x$NEXUS_USER == x ]] && FAILURE "Missing NEXUS_USER variable in API credentials."
    [[ x$NEXUS_PASSWORD == x ]] && FAILURE "Missing NEXUS_PASSWORD variable in API credentials."
    [[ x$SIGN_GPG_KEY_ID == x ]] && FAILURE "Missing SIGN_GPG_KEY_ID variable in API credentials."
    [[ x$SIGN_GPG_KEY_PASS == x ]] && FAILURE "Missing SIGN_GPG_KEY_PASS variable in API credentials."
    #[[ x$NEXUS_STAGING_PROFILE_ID == x ]] && FAILURE "Missing NEXUS_STAGING_PROFILE_ID variable in API credentials."

    # Configure gpg for gradle task
    GRADLE_PARAMS+=" -Psigning.gnupg.keyName=$SIGN_GPG_KEY_ID"
    GRADLE_PARAMS+=" -Psigning.gnupg.passphrase=$SIGN_GPG_KEY_PASS"
    if [ ! -z $HAS_GPG ] && [ -z $HAS_GPG2 ]; then
        GRADLE_PARAMS+=" -Psigning.gnupg.executable=gpg"
    fi
    # Configure nexus credentials
    GRADLE_PARAMS+=" -Pnexus.user=${NEXUS_USER}"
    GRADLE_PARAMS+=" -Pnexus.password=${NEXUS_PASSWORD}"
    #GRADLE_PARAMS+=" -Pnexus.stagingProfileId=${NEXUS_STAGING_PROFILE_ID}"
}
