#!/bin/bash
VERSION="$1"

mvn versions:set \
  -DnewVersion="$VERSION" \
  -pl security-domain \
  -am \
  -DprocessParent=false \
  -DgenerateBackupPoms=false

mvn versions:set-property \
  -Dproperty=security-domain.version \
  -DnewVersion="$VERSION" \
  -DgenerateBackupPoms=false
