from zpo.protocol_template import ProtocolTemplate
from zpo.p4.transition import Transition, TransitionAccept, TransitionSelector


class ParserState:

    def __init__(self, protocol: ProtocolTemplate):
        self.is_root = protocol.is_root
        self.state_name = "start" if self.is_root else f"parse_{protocol.id}"
        self.header_accessor = protocol.struct_accessor

        self.next_transition: Transition = TransitionAccept() if len(
            protocol.children) == 0 else TransitionSelector(protocol)

    def __str__(self):
        return """
state %s {
packet.extract(%s);
%s
}
        """.strip() % (self.state_name, self.header_accessor, str(self.next_transition))
