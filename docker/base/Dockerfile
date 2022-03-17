FROM ubuntu:20.04

################################################################################
# Code from p4.org
# Install dependencies and some useful tools.
ENV NET_TOOLS iputils-arping \
              iputils-ping \
              iputils-tracepath \
              net-tools \
              nmap \
              python3-ipaddr \
              python3-scapy \
              tcpdump \
              traceroute \
              tshark

ENV MININET_DEPS automake \
                 build-essential \
                 cgroup-tools \
                 ethtool \
                 gcc \
                 help2man \
                 iperf \
                 iproute2 \
                 libtool \
                 make \
                 pkg-config \
                 psmisc \
                 socat \
                 ssh \
                 sudo \
                 telnet \
                 pep8 \
                 pyflakes3 \
                 pylint \
                 python3-pexpect \
                 python3-setuptools

ENV DEV_TOOLS cmake flex curl gpg

# Ignore questions when installing with apt-get:
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates $NET_TOOLS $MININET_DEPS $DEV_TOOLS

# Fix to get tcpdump working
# RUN mv /usr/sbin/tcpdump /usr/bin/tcpdump # This breaks Scapy.
RUN ln /usr/sbin/tcpdump /usr/bin/tcpdump

################################################################################

WORKDIR /root
