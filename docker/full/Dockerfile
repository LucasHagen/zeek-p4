FROM lucashagen/zeek-base

ARG ZEEK_PACKAGE=zeek-lts
ARG ZEEK_PATH=/opt/zeek
ARG ZEEK_DIST_SOURCE=deps/zeek

ARG ZEEK_DIST="/opt/zeek-dist"

ENV ZEEK_HOME="$ZEEK_PATH"

# Installing Zeek.
# Reference:
#   https://github.com/zeek/zeek/wiki/Binary-Packages
#   https://software.opensuse.org//download.html?project=security%3Azeek&package=zeek-lts

RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

RUN apt-get update && \
    apt-get install -y $ZEEK_PACKAGE && \
    apt-get autoremove -y && apt-get clean -y

COPY deps/zeek ${ZEEK_DIST}

ENV PATH="${ZEEK_PATH}/bin:${PATH}"
ENV PATH="${ZEEK_DIST}/auxil/zeek-aux/plugin-support:${PATH}"

RUN test "${ZEEK_PATH}" != "/opt/zeek" && ln -s ${ZEEK_PATH} /opt/zeek

# Can't use unless zeek repo has been fully built (which is not the case for this image)
# RUN sed -i "s~zeek_dist=~zeek_dist=${ZEEK_DIST}~" ${ZEEK_PATH}/bin/zeek-config

WORKDIR /root

ENTRYPOINT ["/bin/bash"]
