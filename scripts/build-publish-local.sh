#!/bin/sh

TOP=$(dirname $0)
opt=${1:--nc -ns}
"${TOP}/android-publish-build.sh" ${opt} local

