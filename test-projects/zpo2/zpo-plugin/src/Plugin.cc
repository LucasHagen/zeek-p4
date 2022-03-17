
#include "Plugin.h"

namespace plugin { namespace INF_UFRGS_ZPO2 { Plugin plugin; } }

using namespace plugin::INF_UFRGS_ZPO2;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "INF_UFRGS::ZPO2";
	config.description = "<Insert description>";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}
