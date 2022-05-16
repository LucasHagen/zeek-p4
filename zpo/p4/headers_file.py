

import os
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.p4.headers_struct import HeadersStruct
from zpo.p4.parser_file import ParserFileGenerator
from zpo.p4.parser_state import ParserState
from zpo.protocol_template import ProtocolTemplate
from zpo.template_graph import TemplateGraph
from zpo.utils import lmap
from zpo.zpo_settings import ZpoSettings


HEADER_DEFINITIONS = "@@HEADER_DEFINITIONS@@"
HEADERS_STRUCT = "@@HEADERS_STRUCT@@"
LOADED_PROTOCOLS = "@@LOADED_PROTOCOLS@@"


class HeadersFileGenerator(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.p4_master_template_dir, "headers.p4"),
            os.path.join(settings.p4_output_dir, "headers.p4")
        )

        self.set_marker(HEADER_DEFINITIONS, _merge_headers_definitions)
        self.set_marker(HEADERS_STRUCT, _generate_headers_struct)
        self.set_marker(LOADED_PROTOCOLS, _get_loaded_protocols)


def _get_loaded_protocols(template_graph: TemplateGraph, _: ParserFileGenerator) -> str:
    def define_proto(proto: ProtocolTemplate):
        return "#define ZPO_PROTOCOL_%s\n" % proto.id.upper()

    return "".join(map(define_proto, template_graph.protocols_by_priority()))


def _merge_headers_definitions(template_graph: TemplateGraph, _: ParserFileGenerator) -> str:
    return "\n".join(map(lambda t: t.read_p4_header(),
                         template_graph.protocols_by_priority() + template_graph.events_by_priority()
                         ))


def _generate_headers_struct(template_graph: TemplateGraph, _: ParserFileGenerator) -> str:
    return str(HeadersStruct(template_graph))
