#!/bin/bash
set -e

VERSION=$(cat dnsproxy.version)
BUILD_DATE=$(date -uIseconds)
BUILD_REVISION=$(git rev-parse HEAD)

mkdir -p artifacts
cd cmd/dnsproxy
rm -f dnsproxy

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOAMD64=v3 go build -ldflags="-s -w -X 'dnsproxy.Version=${VERSION}' -X 'dnsproxy.BuiltOn=${BUILD_DATE}' -X 'dnsproxy.Revision=${BUILD_REVISION}'" -trimpath
gzip dnsproxy
mv dnsproxy.gz ../../artifacts/dnsproxy-${VERSION}-linux-amd64.gz

GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w -X 'dnsproxy.Version=${VERSION}' -X 'dnsproxy.BuiltOn=${BUILD_DATE}' -X 'dnsproxy.Revision=${BUILD_REVISION}'" -trimpath
gzip dnsproxy
mv dnsproxy.gz ../../artifacts/dnsproxy-${VERSION}-linux-arm64.gz

cd ../../package/rpm
./build.sh amd64
mv rpms/x86_64/*.rpm ../../artifacts
./build.sh arm64
mv rpms/aarch64/*.rpm ../../artifacts


cd ../../package/deb
./build.sh amd64
mv workdir/*.deb ../../artifacts
./build.sh arm64
mv workdir/*.deb ../../artifacts
