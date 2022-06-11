from typing import List
from zpo.model.offloader import OffloaderComponent
from zpo.model.protocol import ProtocolComponent
from zpo.p4.transition import Transition, TransitionAccept, TransitionSelector
from zpo.exec_graph import ExecGraph
from zpo.utils import indent, lmap


class HeaderStructEntry:

    def __init__(self, struct: str, name: str):
        self.struct = struct
        self.name = name

    def __str__(self):
        return indent("%s %s;" % (self.struct, self.name))


class ProtocolHeaderStructEntry(HeaderStructEntry):

    def __init__(self, protocol: ProtocolComponent):
        super().__init__(
            protocol.header_struct, protocol.id
        )


class OffloaderHeaderStructEntry(HeaderStructEntry):

    def __init__(self, offloader: OffloaderComponent):
        super().__init__(
            offloader.header_struct, offloader.id
        )


class HeadersStruct:

    def __init__(self, template_graph: ExecGraph):
        self.declarations = lmap(
            lambda p: ProtocolHeaderStructEntry(p),
            template_graph.protocols_by_depth())

        self._add_offloader_protocol_hdr()

        self.declarations = self.declarations + \
            lmap(lambda e: OffloaderHeaderStructEntry(
                e), template_graph.offloaders.values())

    def _add_offloader_protocol_hdr(self):
        self.declarations.append(
            HeaderStructEntry("rna_h", "rna")
        )
        self.declarations.append(
            HeaderStructEntry("offloader_h", "offloader")
        )

    def __str__(self):
        return """
struct headers {
%s
}
        """.strip() % ("\n".join(map(str, self.declarations)))
