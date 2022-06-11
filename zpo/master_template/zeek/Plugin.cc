#include "Plugin.h"

#include "constants.h"
#include "RnaAnalyzer.h"
#include "RnaOffloaderAnalyzer.h"
#include "zeek/packet_analysis/Component.h"

@@INCLUDE_ANALYZERS@@

namespace plugin {
namespace BR_UFRGS_INF::RNA {
Plugin plugin;
}
}  // namespace plugin

using namespace plugin::BR_UFRGS_INF::RNA;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new zeek::packet_analysis::Component(
        "RNA", zeek::packet_analysis::BR_UFRGS_INF::RNA::RnaAnalyzer::Instantiate));
    AddComponent(new zeek::packet_analysis::Component(
        "RNA_OFFLOADER", zeek::packet_analysis::BR_UFRGS_INF::RNA::RnaOffloaderAnalyzer::Instantiate));

@@REGISTER_ANALYZERS@@

    zeek::plugin::Configuration config;
    config.name = "BR_UFRGS_INF::RNA";
    config.description = "Zeek-P4 Offloader Plugin";
    config.version.major = RNA_VERSION_1;
    config.version.minor = RNA_VERSION_2;
    config.version.patch = RNA_VERSION_3;
    return config;
}
