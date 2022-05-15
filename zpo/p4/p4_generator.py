import logging
import os
from typing import Iterable, List
from zpo.p4.headers_struct import HeadersStruct

from zpo.p4.parser_state import ParserState
from zpo.template import Template
from zpo.template_graph import TemplateGraph
from zpo.utils import lmap
from zpo.zpo_settings import ZpoSettings

PARSING_STATE_MARKER = "@@PARSING_STATES@@"
HEADER_DEFINITIONS = "@@HEADER_DEFINITIONS@@"
HEADERS_STRUCT = "@@HEADERS_STRUCT@@"


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

        parser_states = lmap(
            lambda p: ParserState(p),
            template_graph.protocols_by_priority())

        content = content.replace(PARSING_STATE_MARKER, "\n\n".join(
            [str(state) for state in parser_states]))

        with open(output_path, 'w') as file:
            file.write(content)

        logging.info("Generated parser.p4")

    def _read_headers_from_templates(self, templates: Iterable[Template]) -> str:
        return "\n".join(map(lambda t: t.read_p4_header(), templates))

    def generate_headers(self, template_graph: TemplateGraph):
        master_header_template_path = os.path.join(
            self.master_p4_template, "headers.p4")

        output_path = os.path.join(self.output_p4, "headers.p4")

        required_markers = [HEADER_DEFINITIONS, HEADERS_STRUCT]

        content = ""
        with open(master_header_template_path, 'r') as file:
            content = file.read()

        for marker in required_markers:
            if marker not in content:
                raise ValueError(
                    f"Marker '{marker}' not found in headers template")

        content = content.replace(
            HEADER_DEFINITIONS, self._read_headers_from_templates(
                template_graph.protocols_by_priority() +
                template_graph.events_by_priority()
            ))

        content = content.replace(
            HEADERS_STRUCT, str(HeadersStruct(template_graph)))

        with open(output_path, 'w') as file:
            file.write(content)

        logging.info("Generated headers.p4")
