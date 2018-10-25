#!/bin/sh

DIR=`dirname $0`
$DIR/../gradlew clean build publishToMavenLocal
