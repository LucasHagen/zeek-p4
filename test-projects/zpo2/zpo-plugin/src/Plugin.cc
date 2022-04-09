#include "Plugin.h"

#include "ZpoEth.h"
#include "ZpoIp.h"
#include "ZpoEventHdr.h"
#include "icmp/ICMP.h"
#include "zeek/packet_analysis/Component.h"

namespace plugin {
namespace BR_INF_UFRGS_ZPO {
Plugin plugin;
}
}  // namespace plugin

using namespace plugin::BR_INF_UFRGS_ZPO;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new zeek::packet_analysis::Component(
        "ZPO_ETH", zeek::packet_analysis::BR_INF_UFRGS_ZPO::ZpoEth::Instantiate));
    AddComponent(new zeek::packet_analysis::Component(
        "ZPO_IP", zeek::packet_analysis::BR_INF_UFRGS_ZPO::ZpoIp::Instantiate));
    AddComponent(new zeek::packet_analysis::Component(
        "ZPO_ICMP", zeek::packet_analysis::BR_INF_UFRGS_ZPO::ICMP::ZpoIcmpAnalyzer::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "BR_INF_UFRGS::ZPO";
    config.description = "This is a test plugin";
    config.version.major = 0;
    config.version.minor = 1;
    config.version.patch = 0;
    return config;
}
