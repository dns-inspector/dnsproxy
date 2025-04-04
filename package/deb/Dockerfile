FROM docker.io/library/debian:stable

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install curl

VOLUME [ "/dnsproxy" ]
WORKDIR /

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]