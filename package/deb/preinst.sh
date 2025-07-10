#!/bin/sh
set -e

getent group dnsproxy >/dev/null 2>&1 || groupadd -r -g 172 dnsproxy
id dnsproxy >/dev/null 2>&1 || useradd -M -g dnsproxy -r -s /sbin/nologin dnsproxy
