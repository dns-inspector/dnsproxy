#!/bin/bash
set -e

VERSION=${1:?Version required}
BUILD_DATE=$(date -uIseconds)
BUILD_REVISION=$(git rev-parse HEAD)
DOCKER_CMD=${DOCKER:-"podman"}

rm -rf workdir
mkdir workdir

cp ../../artifacts/dnsproxy-${VERSION}-linux-amd64.gz workdir
cp dnsproxy.control dnsproxy.service workdir

${DOCKER_CMD} build -t localhost/dnsproxy_build_deb:latest .
${DOCKER_CMD} run --rm --user root -v $(readlink -f workdir):/dnsproxy:Z -e "VERSION=${VERSION}" localhost/dnsproxy_build_deb:latest
