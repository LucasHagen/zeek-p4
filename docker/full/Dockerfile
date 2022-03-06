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

# End of code from p4.org.
################################################################################

# Installing Zeek.
# Reference:
#   https://github.com/zeek/zeek/wiki/Binary-Packages
#   https://software.opensuse.org//download.html?project=security%3Azeek&package=zeek-lts

RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

RUN apt-get update && \
    apt-get install -y zeek-rc

ENV PATH="/opt/zeek-rc/bin:/opt/zeek-aux/plugin-support:${PATH}"

RUN cd /opt && \
    git clone --recursive https://github.com/zeek/zeek-aux && \
    cd zeek-aux && \
    ./configure && make -j8 && make install

WORKDIR /root

ENTRYPOINT ["/bin/bash"]
