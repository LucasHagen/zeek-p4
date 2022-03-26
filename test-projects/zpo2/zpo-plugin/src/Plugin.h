
#pragma once


#include <zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h>

#include <zeek/plugin/Plugin.h>

namespace plugin {
namespace BR_INF_UFRGS_ZPO {

class Plugin : public zeek::plugin::Plugin {

protected:
	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;

};

extern Plugin plugin;

}
}
