FROM docker.io/library/rockylinux:9

# Install rpm requirements
RUN dnf -y install git rpm-build rpmdevtools systemd-rpm-macros

# Install Golang
ARG GOLANG_VERSION=""
ARG GOLANG_ARCH="amd64"
WORKDIR /usr/local
RUN curl -L https://dl.google.com/go/go${GOLANG_VERSION}.linux-${GOLANG_ARCH}.tar.gz | tar -xzf - && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \
    ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt

# Build RPM
WORKDIR /root/rpmbuild
ADD dnsproxy.spec .
RUN mkdir SOURCES
COPY dnsproxy-*.tar.gz SOURCES/
ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME /root/rpmbuild/RPMS

ENV [ VERSION="", BUILD_DATE="", BUILD_REVISION="" ]

ENTRYPOINT /entrypoint.sh
