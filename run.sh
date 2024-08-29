#!/bin/bash

cd cmd/dnsproxy
go build
cd ../../
mv cmd/dnsproxy/dnsproxy .
./dnsproxy server -c dnsproxy_test.conf
rm dnsproxy
