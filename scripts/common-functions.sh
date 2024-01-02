#!/bin/bash
###############################################################################
# Global scope:  
#    Sets default script processing to very paranoid mode 
#    and turns off command echoing.
#    
# Defines
#  $VERBOSE  - as level of information prints
#     0  - disables logging to stdout
#     1  - default logging to stdout
#     2  - debug logging to stdout (depends on script)
# -----------------------------------------------------------------------------
set -e
set +v
VERBOSE=1
LAST_LOG_IS_LINE=0
###############################################################################
# Self update function
#
# Why?
#  - We have copy of this script in several repositiories, so it would be great
#    to simply self update it from one central point
# How?
#  - type:  sh common-functions.sh selfupdate
 # -----------------------------------------------------------------------------
function __COMMON_FUNCTIONS_SELF_UPDATE
{
	local self=$0
	local backup=$self.backup
	local remote="https://raw.githubusercontent.com/wultra/library-deploy/master/common-functions.sh"
	LOG_LINE
	LOG "This script is going to update itself:"
	LOG "  source : $remote"
	LOG "    dest : $self"
	LOG_LINE
	PROMPT_YES_FOR_CONTINUE
	cp $self $backup
	wget $remote -O $self
	LOG_LINE
	LOG "Update looks good. Now you can:"
	LOG "  - press CTRL+C to cancel next step" 
	LOG "  - or type 'y' to remove backup file"
	LOG_LINE
	PROMPT_YES_FOR_CONTINUE "Would you like to remove backup file?"
	rm $backup
}
# -----------------------------------------------------------------------------
# FAILURE prints error to stderr and exits the script with error code 1
# -----------------------------------------------------------------------------
function FAILURE
{
	echo "$CMD: Error: $@" 1>&2
	exit 1
}
# -----------------------------------------------------------------------------
# WARNING prints warning to stderr
# -----------------------------------------------------------------------------
function WARNING
{
	echo "$CMD: Warning: $@" 1>&2
	LAST_LOG_IS_LINE=0
}
# -----------------------------------------------------------------------------
# LOG 
#    Prints all parameters to stdout if VERBOSE is greater than 0
# LOG_LINE 
#    prints dashed line to stdout if VERBOSE is greater than 0
#    Function also prevents that two lines will never be displayed subsequently
# DEBUG_LOG 
#    Prints all parameters to stdout if VERBOSE is greater than 1
# EXIT_SUCCESS
#    print dashed line and "Success" text and exit process with code 0
#    if -l parameter is provided, then always prints dashed line 
# -----------------------------------------------------------------------------
function LOG
{
	if [ $VERBOSE -gt 0 ]; then
		echo "$CMD: $@"
		LAST_LOG_IS_LINE=0
	fi
}
function LOG_LINE
{
	if [ $LAST_LOG_IS_LINE -eq 0 ] && [ $VERBOSE -gt 0 ]; then
		echo "$CMD: -----------------------------------------------------------------------------"
		LAST_LOG_IS_LINE=1
	fi
}
function DEBUG_LOG
{
	if [ $VERBOSE -gt 1 ]; then
		echo "$CMD: $@"
		LAST_LOG_IS_LINE=0
	fi	
}
function EXIT_SUCCESS
{
    [[ x$1 == 'x-l' ]] && LAST_LOG_IS_LINE=0
    LOG_LINE
    LOG "Success"
    exit 0
}
# -----------------------------------------------------------------------------
# PROMPT_YES_FOR_CONTINUE asks user whether script should continue
#
# Parameters:
# - $@ optional prompt
# -----------------------------------------------------------------------------
function PROMPT_YES_FOR_CONTINUE
{
	local prompt="$@"
	local answer
	if [ -z "$prompt" ]; then
		prompt="Would you like to continue?"
	fi
	read -p "$prompt (type y or yes): " answer
	case "$answer" in
		y | yes | Yes | YES)
			LAST_LOG_IS_LINE=0
			return
			;;
		*)
			FAILURE "Aborted by user."
			;;
	esac
}
# -----------------------------------------------------------------------------
# REQUIRE_COMMAND uses "which" buildin command to test existence of requested
# tool on the system.
#
# Parameters:
# - $1 - tool to test (for example fastlane, pod, etc...)
# -----------------------------------------------------------------------------
function REQUIRE_COMMAND
{
	set +e
	local tool=$1
	local path=`which $tool`
	if [ -z $path ]; then
		FAILURE "$tool: required command not found."
	fi
	set -e
	DEBUG_LOG "$tool: found at $path"
}
# -----------------------------------------------------------------------------
# REQUIRE_COMMAND_PATH is similar to REQUIRE_COMMAND, but on success, prints
# path to stdout. You can use this function to check tool and acquire path to 
# variable: TOOL_PATH=$(REQUIRE_COMMAND_PATH tool)
#
# Parameters:
# - $1 - tool to test (for example fastlane, pod, etc...)
# -----------------------------------------------------------------------------
function REQUIRE_COMMAND_PATH
{
	set +e
	local tool=$1
	local path=`which $tool`
	if [ -z $path ]; then
		FAILURE "$tool: required command not found."
	fi
	set -e
	echo $path
}
# -----------------------------------------------------------------------------
# Validates "verbose" command line switch and adjusts VERBOSE global variable
# according to desired level
# -----------------------------------------------------------------------------
function SET_VERBOSE_LEVEL_FROM_SWITCH
{
	case "$1" in
		-v0) VERBOSE=0 ;;
		-v1) VERBOSE=1 ;;
		-v2) VERBOSE=2 ;;
		*) FAILURE "Invalid verbose level $1" ;;
	esac
	UPDATE_VERBOSE_COMMANDS
}
# -----------------------------------------------------------------------------
# Updates verbose switches for common commands. Function will create following
# global variables:
#  - $MD = mkdir -p [-v]
#  - $RM = rm -f [-v]
#  - $CP = cp [-v]
#  - $MV = mv [-v]
# -----------------------------------------------------------------------------
function UPDATE_VERBOSE_COMMANDS
{
	if [ $VERBOSE -lt 2 ]; then
		# No verbose
		CP="cp"
		RM="rm -f"
		MD="mkdir -p"
		MV="mv"
	else
		# verbose
		CP="cp -v"
		RM="rm -f -v"
		MD="mkdir -p -v"
		MV="mv -v"
	fi
}
# -----------------------------------------------------------------------------
# Validate if $1 as VERSION has valid format: x.y.z
# Also sets global VERSION to $1 if VERSION string is empty.
# -----------------------------------------------------------------------------
function VALIDATE_AND_SET_VERSION_STRING
{
	if [ -z "$1" ]; then
		FAILURE "Version string is empty"
	fi
	local rx='^([0-9]+\.){2}(\*|[0-9]+)$'
	if [[ ! "$1" =~ $rx ]]; then
	 	FAILURE "Version string is invalid: '$1'"
	fi
	if [ -z "$VERSION" ]; then
		VERSION=$1
		DEBUG_LOG "Changing version to $VERSION"
	else
		FAILURE "Version string is already set to $VERSION"
	fi
}
# -----------------------------------------------------------------------------
# Loads shared credentials, like API keys & logins. The function performs
# lookup in following order:
#   if LIME_CREDENTIALS == 1 then does nothing, credentials are loaded
#   if file exists at ${LIME_CREDENTIALS_FILE}, then loads the file
#   if file exists at ~/.lime/credentials, then loads the file
#   if file exists at .lime-credentials, then loads the file
# -----------------------------------------------------------------------------
function LOAD_API_CREDENTIALS
{
	if [ x${API_CREDENTIALS} == x1 ]; then
		DEBUG_LOG "Credentials are already set."
	elif [ ! -z "${API_CREDENTIALS_FILE}" ]; then
		source "${API_CREDENTIALS_FILE}"
	elif [ -f "${HOME}/.lime/credentials" ]; then
		source "${HOME}/.lime/credentials"
	elif [ -f ".lime-credentials" ]; then
		source ".lime-credentials"
	else
		FAILURE "Unable to locate credentials file."
	fi
	if [ x${LIME_CREDENTIALS} != x1 ]; then
		FAILURE "Credentials file must set LIME_CREDENTIALS variable to 1"
	fi
}

# -----------------------------------------------------------------------------
# PUSH_DIR & POP_DIR functions works just like pushd & popd builtin commands,
# but doesn't print a current directory, unless the VERBOSE level is 2.
# -----------------------------------------------------------------------------
function PUSH_DIR
{
	if [ $VERBOSE -gt 1 ]; then
		pushd "$1"
	else
		pushd "$1" > /dev/null
	fi
}
function POP_DIR
{
	if [ $VERBOSE -gt 1 ]; then
		popd
	else
		popd > /dev/null
	fi
}

# -----------------------------------------------------------------------------
# SHA256, SHA384, SHA512 calculates appropriate SHA hash for given file and 
# prints the result hash to stdout. Example: $(SHA256 my-file.txt)
#
# Parameters:
#   $1   - input file
# -----------------------------------------------------------------------------
function SHA256
{
	local HASH=( `shasum -a 256 "$1"` )
	echo ${HASH[0]}
}
function SHA384
{
	local HASH=( `shasum -a 384 "$1"` )
	echo ${HASH[0]}
}
function SHA512
{
	local HASH=( `shasum -a 512 "$1"` )
	echo ${HASH[0]}
}

# -----------------------------------------------------------------------------
# Prints Xcode version into stdout or -1 in case of error.
# Parameters:
#   $1   - optional switch, can be:
#          '--full'  - prints a full version of Xcode (e.g. 11.7.1)
#          '--split' - prints a full, space separated version of Xcode (e.g. 11 7 1)
#          '--major' - prints only a major version (e.g. 11)
#          otherwise prints first line from `xcodebuild -version` result
# -----------------------------------------------------------------------------
function GET_XCODE_VERSION
{
    local xcodever=(`xcodebuild -version | grep ^Xcode`)
    local ver=${xcodever[1]}
    if [ -z "$ver" ]; then
        echo -1
        return
    fi
    local ver_array=( ${ver//./ } )
    case $1 in
        --full) echo $ver ;;
        --split) echo ${ver_array[@]} ;;
        --major) echo ${ver_array[0]} ;;
        *) echo ${xcodever[*]} ;;
    esac
}

###############################################################################
# Global scope
#   Gets full path to current directory and exits with error when 
#   folder is not valid.
#
# Defines
#  $CMD         - as current command name
#  $TOP         - path to $CMD
# -----------------------------------------------------------------------------
CMD=$(basename $0)
TOP="`( cd \"$TOP\" && pwd )`"
UPDATE_VERBOSE_COMMANDS
if [ -z "$TOP" ]; then
    FAILURE "Current dir is not accessible."
fi

if [ "$CMD" == "common-functions.sh" ] && [ "$1" == "selfupdate" ]; then
	__COMMON_FUNCTIONS_SELF_UPDATE
fi
