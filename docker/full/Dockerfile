FROM lucashagen/zeek-base

ARG ZEEK_PACKAGE=zeek-lts
ARG ZEEK_PATH=/opt/zeek

# Installing Zeek.
# Reference:
#   https://github.com/zeek/zeek/wiki/Binary-Packages
#   https://software.opensuse.org//download.html?project=security%3Azeek&package=zeek-lts

RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

RUN apt-get update && \
    apt-get install -y $ZEEK_PACKAGE

ENV PATH="/opt/zeek-rc/bin:/opt/zeek-aux/plugin-support:${PATH}"
ENV ZEEK_HOME="$ZEEK_PATH"

RUN cd /opt && \
    git clone --recursive https://github.com/zeek/zeek-aux && \
    cd zeek-aux && \
    ./configure && make -j8 && make install

WORKDIR /root

ENTRYPOINT ["/bin/bash"]
