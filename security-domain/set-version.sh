#!/bin/bash
mvn versions:set -DnewVersion="$1" -DgenerateBackupPoms=false
#mvn versions:set-property -Dproperty=security-domain.version -DnewVersion="$1" -DgenerateBackupPoms=false -f ../pom.xml
