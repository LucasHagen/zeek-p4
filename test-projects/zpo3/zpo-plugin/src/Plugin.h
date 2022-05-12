#pragma once

#include <zeek/plugin/Plugin.h>

namespace plugin::BR_INF_UFRGS_ZPO {

class Plugin : public zeek::plugin::Plugin {
protected:
    // Overridden from zeek::plugin::Plugin.
    zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}  // namespace plugin::BR_INF_UFRGS_ZPO
