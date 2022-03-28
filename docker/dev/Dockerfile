FROM lucashagen/zeek-base

ARG ZEEK_VERSION=4.0.5
ARG ZEEK_VERSION_TAG="v${ZEEK_VERSION}"

ARG BUILD_CORES=8

ENV ZEEK_HOME="/opt/zeek"
ENV ZEEK_DIST="/opt/zeek-dist"

ADD deps/zeek ${ZEEK_DIST}

RUN cd /opt/zeek-dist && \
    ./configure --prefix=${ZEEK_HOME} && \
    make install -j ${BUILD_CORES}

ENV PATH="${ZEEK_HOME}/bin:${PATH}"
ENV PATH="${ZEEK_DIST}/auxil/zeek-aux/plugin-support:${PATH}"

WORKDIR /root

ENTRYPOINT ["/bin/bash"]
