#!/bin/bash
set -e
set -x

pwd
dpkg-deb --build --root-owner-group dnsproxy
mv ./dnsproxy.deb ./dnsproxy/dnsproxy-${VERSION}.amd64.deb
