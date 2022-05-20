import os
from typing import List
from zpo.event_template import EventTemplate
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.p4.event_uid_definition import EventUidDefinition, NoEventDefinition
from zpo.template_graph import TemplateGraph
from zpo.utils import indent
from zpo.zpo_settings import ZpoSettings

INCLUDE_ANALYZERS = "@@INCLUDE_ANALYZERS@@"
REGISTER_ANALYZERS = "@@REGISTER_ANALYZERS@@"


class PluginCcFile(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.zeek_master_template_dir, "Plugin.cc"),
            os.path.join(
                settings.zeek_output_dir,
                "src",
                "Plugin.cc")
        )

        self.settings: ZpoSettings = settings
        self.add_marker(INCLUDE_ANALYZERS, _include_analyzers)
        self.add_marker(REGISTER_ANALYZERS, _register_analyzers)


def _include_analyzers(template_graph: TemplateGraph, _: PluginCcFile) -> str:
    events: List[EventTemplate] = template_graph.events_by_priority()
    files = []

    for event in events:
        for file in event.zeek_header_files:
            files.append("#include \"%s/%s\"" % (event.id, file))

    return "\n".join(files)


def _register_analyzers(template_graph: TemplateGraph, _: PluginCcFile) -> str:
    def _register_analyzer(event: EventTemplate):
        return """
AddComponent(new zeek::packet_analysis::Component(
    "%s", %s::%s::Instantiate));
""".strip() % (event.zeek_analyzer_id, event.zeek_analyzer_namespace, event.zeek_analyzer_class)

    return indent("\n".join(map(_register_analyzer, template_graph.events_by_priority())))
