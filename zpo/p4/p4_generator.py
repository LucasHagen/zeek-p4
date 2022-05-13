import os
from typing import List

from zpo.p4.parser_state import ParserState
from zpo.template_graph import TemplateGraph
from zpo.zpo_settings import ZpoSettings

PARSING_STATE_MARKER = "@@PARSING_STATES@@"


class P4Generator:

    def __init__(self, settings: ZpoSettings):
        self.settings: ZpoSettings = settings
        self.master_p4_template = os.path.join(
            self.settings.master_template, "p4")
        self.output_p4 = self.settings.p4_output_dir

    def create_p4_folders(self):
        if not os.path.exists(self.settings.output_dir):
            os.mkdir(self.settings.output_dir)

        if not os.path.exists(self.output_p4):
            os.mkdir(self.output_p4)

    def generate_parser(self, template_graph: TemplateGraph):
        master_parser_template_path = os.path.join(
            self.master_p4_template, "parser.p4")

        output_path = os.path.join(self.output_p4, "parser.p4")

        required_markers = [PARSING_STATE_MARKER]

        content = ""
        with open(master_parser_template_path, 'r') as file:
            content = file.read()

        for marker in required_markers:
            if marker not in content:
                raise ValueError(
                    f"Marker '{marker}' not found in parser template")

        parser_states = list(map(
            lambda p: ParserState(p),
            template_graph.protocols.values()))

        content = content.replace(PARSING_STATE_MARKER, "\n".join(
            [str(state) for state in parser_states]))

        with open(output_path, 'w') as file:
            file.write(content)
