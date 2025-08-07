#!/bin/bash
set -e
set -x

mkdir -p /dnsproxy/DEBIAN
mkdir -p /dnsproxy/usr/sbin
mkdir -p /dnsproxy/lib/systemd/system
mkdir -p /dnsproxy/etc/dnsproxy
mkdir -p /dnsproxy/etc/sysctl.d

cd /workdir
gzip -d dnsproxy-${VERSION}-linux-${ARCH}.gz
mv dnsproxy-${VERSION}-linux-${ARCH} /dnsproxy/usr/sbin
mv dnsproxy.service /dnsproxy/lib/systemd/system
mv dnsproxy.control /dnsproxy/DEBIAN/control
mv preinst.sh /dnsproxy/DEBIAN/preinst
mv postinst.sh /dnsproxy/DEBIAN/postinst
mv postrm.sh /dnsproxy/DEBIAN/postrm
mv dnsproxy.conf /dnsproxy/etc/dnsproxy/dnsproxy.conf.example
mv 10-udpbuf.conf /dnsproxy/etc/sysctl.d

chmod +x /dnsproxy/DEBIAN/preinst /dnsproxy/DEBIAN/postinst /dnsproxy/DEBIAN/postrm

cd /
dpkg-deb --build --root-owner-group dnsproxy
mv ./dnsproxy.deb ./workdir/dnsproxy-${VERSION}.${ARCH}.deb
