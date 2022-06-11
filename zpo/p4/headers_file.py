

import os
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.p4.event_uid_definition import EventUidDefinition, NoEventDefinition
from zpo.p4.headers_struct import HeadersStruct
from zpo.p4.parser_file import ParserFileGenerator
from zpo.model.protocol import ProtocolComponent
from zpo.model.component import Component
from zpo.exec_graph import ExecGraph
from zpo.utils import lmap
from zpo.zpo_settings import ZpoSettings


LOADED_PROTOCOLS = "@@LOADED_PROTOCOLS@@"
HEADER_DEFINITIONS = "@@HEADER_DEFINITIONS@@"
HEADERS_STRUCT = "@@HEADERS_STRUCT@@"


class HeadersFileGenerator(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.p4_master_template_dir, "headers.p4"),
            os.path.join(settings.p4_output_dir, "headers.p4")
        )
        self.settings = settings

        self.add_marker(LOADED_PROTOCOLS, _get_loaded_protocols)
        self.add_marker(HEADER_DEFINITIONS, _merge_headers_definitions)
        self.add_marker(HEADERS_STRUCT, _generate_headers_struct)


def _get_loaded_protocols(template_graph: ExecGraph, gen: HeadersFileGenerator) -> str:
    def define_proto(proto: ProtocolComponent):
        return "#define RNA_PROTOCOL_%s" % proto.id.upper()

    # TODO: add version hash
    random_definitions = [
        "#define RNA_VERSION 0",
    ]

    protocols_definitions = list(
        map(define_proto, template_graph.protocols_by_depth()))
    events_uids = [str(NoEventDefinition())]
    events_uids = events_uids + list(map(
        lambda e: str(EventUidDefinition(e)),
        template_graph.offloaders_by_priority())
    )

    return "\n".join(random_definitions + protocols_definitions + events_uids)


def _merge_headers_definitions(template_graph: ExecGraph, _: HeadersFileGenerator) -> str:
    return "\n".join(map(_read_p4_header,
                         template_graph.protocols_by_depth() + template_graph.offloaders_by_priority()
                         ))


def _generate_headers_struct(template_graph: ExecGraph, _: HeadersFileGenerator) -> str:
    return str(HeadersStruct(template_graph))


def _read_p4_header(template: Component):
    return "\n".join([
        f"// Header for {template.type_str()} template '{template.id}':",
        "",
        template.read_p4_header(),
        ""
    ])
