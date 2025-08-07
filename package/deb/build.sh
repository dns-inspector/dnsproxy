#!/bin/bash
set -e

ARCH=${1:?Arch required}
VERSION=$(cat ../../dnsproxy.version)
BUILD_DATE=$(date -uIseconds)
BUILD_REVISION=$(git rev-parse HEAD)
DOCKER_CMD=${DOCKER:-"podman"}

rm -rf workdir
mkdir workdir

cp ../../artifacts/dnsproxy-${VERSION}-linux-${ARCH}.gz ../../dnsproxy.conf ../../10-udpbuf.conf workdir
cp dnsproxy.service postinst.sh preinst.sh postrm.sh workdir
cat dnsproxy.control | sed "s/%%VERSION%%/${VERSION}/g" | sed "s/%%ARCH%%/${ARCH}/g" > workdir/dnsproxy.control

${DOCKER_CMD} build -t localhost/dnsproxy_build_deb:latest .
${DOCKER_CMD} run --rm --user root -v $(readlink -f workdir):/workdir:Z -e "VERSION=${VERSION}" -e "ARCH=${ARCH}" localhost/dnsproxy_build_deb:latest
