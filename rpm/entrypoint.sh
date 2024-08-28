#!/bin/bash

/usr/bin/rpmbuild -ba --define "_version ${VERSION}" --define "_date ${BUILD_DATE}" --define "_revision ${BUILD_REVISION}" dnsproxy.spec