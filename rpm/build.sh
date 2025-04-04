#!/bin/bash
set -e

VERSION=${1:?Version required}
BUILD_DATE=$(date -uIseconds)
BUILD_REVISION=$(git rev-parse HEAD)
DOCKER_CMD=${DOCKER:-"podman"}

rm -rf dnsproxy-${VERSION}
mkdir dnsproxy-${VERSION}

cp -r dnsproxy.service ../cmd ../*.go ../monitoring ../go.mod ../go.sum ../dnsproxy.conf dnsproxy-${VERSION}
tar -czf dnsproxy-${VERSION}.tar.gz dnsproxy-${VERSION}
rm -rf dnsproxy-${VERSION}

rm -rf rpms
mkdir rpms

${DOCKER_CMD} build -t localhost/dnsproxy_build:latest --build-arg "GOLANG_VERSION=$(go version | cut -d ' ' -f 3 | sed 's/go//')" .
${DOCKER_CMD} run --rm --user root -v $(readlink -f rpms):/root/rpmbuild/RPMS:Z -e "VERSION=${VERSION}" -e "BUILD_DATE=${BUILD_DATE}" -e BUILD_REVISION=${BUILD_REVISION} localhost/dnsproxy_build:latest
