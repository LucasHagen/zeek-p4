

from zpo.protocol_template import ProtocolTemplate
from zpo.event_template import EventTemplate
from zpo.utils import indent


class EventIdentificators:

    def __init__(self, protocol_templates):
        self.protocols = []

        for protocol in protocol_templates:
            if len(protocol.events) <= 0:
                continue

            event_identifiers = " else ".join(map(
                _event_identifier,
                protocol.events.values()
            ))
            self.protocols.append(_protocol_guard(protocol, event_identifiers))

    def __str__(self):
        return indent("\n".join(self.protocols), spaces=12)


def _event_identifier(event: EventTemplate):
    return """
if(%s) {
    meta.event_type = %s;
}
""".strip() % (event.read_p4_identifier(), event.uid_constant)


def _protocol_guard(protocol: ProtocolTemplate, content: str):
    return """
if (%s.isValid()) {
%s
}
""".strip() % (protocol.struct_accessor, indent(content))