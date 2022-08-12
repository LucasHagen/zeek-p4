FROM lucashagen/zeek-dev

ARG ZEEK_PATH=/opt/zeek
ARG ZEEK_DIST="/opt/zeek-dist"

ARG ZEEK_DIST_SOURCE=deps/zeek


ENV ZEEK_HOME="$ZEEK_PATH"

RUN apt-get install -y git python3-pip && \
    pip3 install GitPython semantic-version && \
    zkg install --force corelight/pingback && \
    zkg install --force dopheide/zeek-ntp-monlist

# Disable signature detection in detect-traceroute
RUN sed -i 's/require_low_ttl_packets = T/require_low_ttl_packets = F/g' \
    /opt/zeek/share/zeek/policy/misc/detect-traceroute/main.zeek

WORKDIR /root
