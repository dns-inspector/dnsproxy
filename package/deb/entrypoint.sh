#!/bin/bash
set -e
set -x

mkdir -p /dnsproxy/DEBIAN
mkdir -p /dnsproxy/usr/sbin
mkdir -p /dnsproxy/lib/systemd/system
mkdir -p /dnsproxy/etc/dnsproxy

cd /workdir
gzip -d dnsproxy-${VERSION}-linux-amd64.gz
mv dnsproxy-${VERSION}-linux-amd64 /dnsproxy/usr/sbin
mv dnsproxy.service /dnsproxy/lib/systemd/system
mv dnsproxy.control /dnsproxy/DEBIAN/control
mv postinst.sh /dnsproxy/DEBIAN/postinst
mv dnsproxy.conf /dnsproxy/etc/dnsproxy/dnsproxy.conf.example

chmod +x /dnsproxy/DEBIAN/postinst

cd /
dpkg-deb --build --root-owner-group dnsproxy
mv ./dnsproxy.deb ./workdir/dnsproxy-${VERSION}.amd64.deb
