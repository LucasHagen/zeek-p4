import os
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.p4.event_constructor import EventConstructor
from zpo.p4.event_identificators import EventIdentificators
from zpo.p4.ingress_processor import IngressProcessor
from zpo.p4.parser_state import ParserState
from zpo.template_graph import TemplateGraph
from zpo.utils import indent, lmap
from zpo.zpo_settings import ZpoSettings

PROTOCOL_INGRESS_PROCESSORS = "@@PROTOCOL_INGRESS_PROCESSORS@@"
EVENT_IDENTIFICATION = "@@EVENT_IDENTIFICATION@@"
EVENT_CONSTRUCTORS = "@@EVENT_CONSTRUCTORS@@"


class MainP4FileGenerator(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.p4_master_template_dir, "main.p4"),
            os.path.join(settings.p4_output_dir, "main.p4")
        )

        self.add_marker(PROTOCOL_INGRESS_PROCESSORS,
                        _get_protocol_ingress_processors)
        self.add_marker(EVENT_IDENTIFICATION, _get_event_identification)
        self.add_marker(EVENT_CONSTRUCTORS, _get_event_constructors)


def _get_protocol_ingress_processors(template_graph: TemplateGraph, _: MainP4FileGenerator) -> str:
    processors = [IngressProcessor(
        p) for p in template_graph.protocols_by_priority() if p.has_ingress_processor()]
    return "\n".join(map(str, processors))


def _get_event_identification(template_graph: TemplateGraph, _: MainP4FileGenerator) -> str:
    return str(EventIdentificators(template_graph.protocols_by_priority()))


def _get_event_constructors(template_graph: TemplateGraph, _: MainP4FileGenerator) -> str:
    event_constructors = map(
        EventConstructor, template_graph.events_by_priority())

    return indent(" else ".join(map(str, event_constructors)), spaces=16)
