#!/bin/bash
set -e

VERSION=${1:?Version required}
BUILD_DATE=$(date -uIseconds)
BUILD_REVISION=$(git rev-parse HEAD)

mkdir -p artifacts
cd cmd/dnsproxy
rm -f dnsproxy

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOAMD64=v2 go build -ldflags="-s -w -X 'dnsproxy.Version=${VERSION}' -X 'dnsproxy.BuiltOn=${BUILD_DATE}' -X 'dnsproxy.Revision=${BUILD_REVISION}'" -trimpath
gzip dnsproxy
mv dnsproxy.gz ../../artifacts/dnsproxy-${VERSION}-linux-amd64.gz

cd ../../package/rpm
./build.sh ${VERSION}
mv rpms/x86_64/*.rpm ../../artifacts

cd ../../package/deb
./build.sh ${VERSION}
mv workdir/*.deb ../../artifacts
