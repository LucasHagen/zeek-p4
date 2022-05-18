#include "Plugin.h"

#include "ZpoEth.h"
#include "ZpoEventHdr.h"
#include "ZpoIp.h"
#include "constants.h"
#include "zeek/analyzer/Component.h"
#include "zeek/packet_analysis/Component.h"

namespace plugin {
namespace BR_UFRGS_INF_ZPO {
Plugin plugin;
}
}  // namespace plugin

using namespace plugin::BR_UFRGS_INF_ZPO;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new zeek::packet_analysis::Component(
        "ZPO_ETH", zeek::packet_analysis::BR_UFRGS_INF_ZPO::ZpoEth::Instantiate));
    AddComponent(new zeek::packet_analysis::Component(
        "ZPO_IP", zeek::packet_analysis::BR_UFRGS_INF_ZPO::ZpoIp::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "BR_UFRGS_INF::ZPO";
    config.description = "This is a test plugin";
    config.version.major = VERSION_1;
    config.version.minor = VERSION_2;
    config.version.patch = VERSION_3;
    return config;
}
