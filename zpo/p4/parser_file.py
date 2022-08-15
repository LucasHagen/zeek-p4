import os
from zpo.file_gen_stats import FileGenerationStats
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.p4.parser_state import ParserState
from zpo.exec_graph import ExecGraph
from zpo.utils import lmap
from zpo.zpo_settings import ZpoSettings


PARSING_STATE_MARKER = "@@PARSING_STATES@@"


class ParserFileGenerator(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings, stats: FileGenerationStats = None):
        super().__init__(
            os.path.join(settings.p4_master_template_dir, "parser.p4"),
            os.path.join(settings.p4_output_dir, "parser.p4"),
            stats
        )

        self.add_marker(PARSING_STATE_MARKER, _get_parsing_states)


def _get_parsing_states(template_graph: ExecGraph, gen: ParserFileGenerator) -> str:
    parser_states = map(ParserState, template_graph.protocols_by_depth())
    states_str = "\n\n".join(map(str, parser_states))

    gen.stats.auto_increament_generated(states_str)

    return states_str
