import os
from zpo.file_gen_stats import FileGenerationStats
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.p4.offloader_splicer import OffloaderSplicer
from zpo.p4.offloader_triggers import OffloaderTriggers
from zpo.p4.ingress_processor import IngressProcessor
from zpo.p4.parser_state import ParserState
from zpo.exec_graph import ExecGraph
from zpo.utils import indent, lmap
from zpo.zpo_settings import ZpoSettings

PROTOCOL_INGRESS_PROCESSORS = "@@PROTOCOL_INGRESS_PROCESSORS@@"
OFFLOADER_TRIGGERS = "@@OFFLOADER_TRIGGERS@@"
OFFLOADER_SPLICERS = "@@OFFLOADER_SPLICERS@@"


class MainP4FileGenerator(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings, stats: FileGenerationStats = None):
        super().__init__(
            os.path.join(settings.p4_master_template_dir, "main.p4"),
            os.path.join(settings.p4_output_dir, "main.p4"),
            stats,
        )

        self.add_marker(PROTOCOL_INGRESS_PROCESSORS,
                        _get_protocol_ingress_processors)
        self.add_marker(OFFLOADER_TRIGGERS, _get_offloader_triggers)
        self.add_marker(OFFLOADER_SPLICERS, _get_offloader_splicers)


def _get_protocol_ingress_processors(template_graph: ExecGraph, gen: MainP4FileGenerator) -> str:
    processors = [str(IngressProcessor(
        p)) for p in template_graph.protocols_by_depth() if p.has_ingress_processor()]

    gen.stats.auto_increament_protocol_template(processors)
    gen.stats.increament_protocol_template(- (len(processors) + 1))
    gen.stats.increament_generated(len(processors) + 1)

    return "\n".join(processors)


def _get_offloader_triggers(template_graph: ExecGraph, gen: MainP4FileGenerator) -> str:
    return str(OffloaderTriggers(template_graph.protocols_by_depth(), gen.stats))


def _get_offloader_splicers(template_graph: ExecGraph, gen: MainP4FileGenerator) -> str:
    offloaders_splicers = map(
        lambda o: OffloaderSplicer(o, gen.stats),
        template_graph.offloaders_by_priority(),
    )

    return indent(" else ".join(map(str, offloaders_splicers)), spaces=16)
