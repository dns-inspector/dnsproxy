#!/bin/bash
set -e
set -x

/usr/bin/rpmbuild -ba --target=${ARCH} --define "_version ${VERSION}" dnsproxy.spec