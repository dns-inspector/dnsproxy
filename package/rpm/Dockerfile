FROM docker.io/library/rockylinux:9

# Install rpm requirements
RUN dnf -y install rpm-build rpmdevtools systemd-rpm-macros

# Build RPM
WORKDIR /root/rpmbuild
ADD dnsproxy.spec .
RUN mkdir SOURCES
COPY dnsproxy-*.tar.gz SOURCES/
ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME /root/rpmbuild/RPMS

ENV [ VERSION="", ARCH="" ]

ENTRYPOINT /entrypoint.sh
