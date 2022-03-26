FROM lucashagen/zeek-base

ARG ZEEK_VERSION=4.0.5
ARG ZEEK_VERSION_TAG="v${ZEEK_VERSION}"

ARG BUILD_CORES=8

ENV ZEEK_HOME="/opt/zeek"
ENV ZEEK_DIST="/opt/zeek-dist"

ADD zeek /opt/zeek-dist

RUN cd /opt/zeek-dist && \
    ./configure --prefix=${ZEEK_HOME} && \
    make install -j ${BUILD_CORES}
#
# RUN git clone --recursive https://github.com/zeek/zeek-aux /opt/zeek-aux && \
#     cd /opt/zeek-aux && \
#     ./configure && make -j8 && make install

ENV PATH="${ZEEK_HOME}/bin:${PATH}"

WORKDIR /root

ENTRYPOINT ["/bin/bash"]
