
#include "Plugin.h"

namespace plugin { namespace ZPO_ZPO { Plugin plugin; } }

using namespace plugin::ZPO_ZPO;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "ZPO::ZPO";
	config.description = "<Insert description>";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}
