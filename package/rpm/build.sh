#!/bin/bash
set -e

ARCH=${1:?Arch required}
VERSION=$(cat ../../dnsproxy.version)
BUILD_DATE=$(date -uIseconds)
BUILD_REVISION=$(git rev-parse HEAD)
DOCKER_CMD=${DOCKER:-"podman"}

RPM_ARCH="x86_64"
if [[ "${ARCH}" == "arm64" ]]; then
    RPM_ARCH="aarch64"
fi

rm -rf dnsproxy-${VERSION}
mkdir dnsproxy-${VERSION}

cp ../../artifacts/dnsproxy-${VERSION}-linux-${ARCH}.gz dnsproxy-${VERSION}/
cd dnsproxy-${VERSION}/
gzip -d dnsproxy-${VERSION}-linux-${ARCH}.gz
mv dnsproxy-${VERSION}-linux-${ARCH} dnsproxy
cp ../dnsproxy.service ../../../dnsproxy.conf .
cd ../
tar -czf dnsproxy-${VERSION}.tar.gz dnsproxy-${VERSION}
rm -rf dnsproxy-${VERSION}

rm -rf rpms
mkdir -p rpms

${DOCKER_CMD} build -t localhost/dnsproxy_build_rpm:latest .
${DOCKER_CMD} run --rm --user root -v $(readlink -f rpms):/root/rpmbuild/RPMS:Z -e "VERSION=${VERSION}" -e "ARCH=${RPM_ARCH}" -e BUILD_REVISION=${BUILD_REVISION} localhost/dnsproxy_build_rpm:latest
