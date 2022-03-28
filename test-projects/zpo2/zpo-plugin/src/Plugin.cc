#include "Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "ZPO.h"

namespace plugin { namespace BR_INF_UFRGS_ZPO { Plugin plugin; } }

using namespace plugin::BR_INF_UFRGS_ZPO;

zeek::plugin::Configuration Plugin::Configure() {
	AddComponent(new zeek::packet_analysis::Component("ZPO",
	 				zeek::packet_analysis::BR_INF_UFRGS_ZPO::ZPO::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "BR_INF_UFRGS::ZPO";
	config.description = "This is a test plugin";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
}
