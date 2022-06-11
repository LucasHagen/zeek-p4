from zpo.model.parser import ProtocolComponent
from zpo.p4.transition import Transition, TransitionAccept, TransitionSelector
from zpo.utils import indent


class ParserState:

    def __init__(self, protocol: ProtocolComponent):
        self.is_root = protocol.is_root
        self.state_name = "start" if self.is_root else f"parse_{protocol.id}"
        self.header_accessor = protocol.struct_accessor

        self.next_transition: Transition = TransitionAccept() if len(
            protocol.children) == 0 else TransitionSelector(protocol)

        self.packet_extractor = indent(
            "packet.extract(%s);" % self.header_accessor)

    def __str__(self):
        return indent("""
state %s {
%s
%s
}
        """.strip() % (self.state_name, self.packet_extractor, str(self.next_transition)))
