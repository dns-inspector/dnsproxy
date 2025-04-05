#!/bin/bash
set -e

VERSION=${1:?Version required}
BUILD_DATE=$(date -uIseconds)
BUILD_REVISION=$(git rev-parse HEAD)
DOCKER_CMD=${DOCKER:-"podman"}

rm -rf workdir
mkdir workdir

cp ../../artifacts/dnsproxy-${VERSION}-linux-amd64.gz ../../dnsproxy.conf workdir
cp dnsproxy.service postinst.sh workdir
cat dnsproxy.control | sed "s/%%VERSION%%/${VERSION}/g" > workdir/dnsproxy.control

${DOCKER_CMD} build -t localhost/dnsproxy_build_deb:latest .
${DOCKER_CMD} run --rm --user root -v $(readlink -f workdir):/workdir:Z -e "VERSION=${VERSION}" localhost/dnsproxy_build_deb:latest
