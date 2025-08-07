#!/bin/sh
set -e

getent group dnsproxy >/dev/null 2>&1 || groupadd -r -g 172 dnsproxy
id dnsproxy >/dev/null 2>&1 || useradd -M -g dnsproxy -r -s /sbin/nologin dnsproxy
mkdir -p /var/log/dnsproxy
chown root:dnsproxy /var/log/dnsproxy
chmod 0775 /var/log/dnsproxy
sysctl --system >/dev/null