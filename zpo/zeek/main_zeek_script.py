import os
from zpo.event_template import EventTemplate
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.p4.event_uid_definition import EventUidDefinition, NoEventDefinition
from zpo.template_graph import TemplateGraph
from zpo.utils import indent
from zpo.zpo_settings import ZpoSettings

REGISTER_EVENTS = "@@REGISTER_EVENTS@@"


class MainZeekFile(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.zeek_master_template_dir, "main.zeek"),
            os.path.join(
                settings.zeek_output_dir,
                "scripts",
                "BR_UFRGS_INF",
                "ZPO",
                "main.zeek")
        )

        self.settings: ZpoSettings = settings
        self.add_marker(REGISTER_EVENTS, _get_register_events)


def _register_event(event: EventTemplate):
    parent_analyzer = "ZPO_IP" if event.is_ip_based else "ZPO_ETH"

    return """
PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_%s, %d, PacketAnalyzer::ANALYZER_%s);
""".strip() % (parent_analyzer, event.uid, event.zeek_analyzer_id)


def _get_register_events(template_graph: TemplateGraph, _: MainZeekFile) -> str:
    return indent("\n".join(map(
        _register_event,
        template_graph.events_by_priority()
    )))
