#!/bin/sh
set -e

userdel -f dnsproxy >/dev/null 2>&1 || true
groupdel -f dnsproxy >/dev/null 2>&1 || true