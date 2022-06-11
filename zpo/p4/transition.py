from typing import List

from zpo.exceptions import ZpoException
from zpo.p4.transition_case import TransitionCase, DefaultTransitionCase, ProtocolTransitionCase
from zpo.model.protocol import ProtocolComponent
from zpo.utils import indent, lmap


def _make_protocol_transition(parent: ProtocolComponent, child: ProtocolComponent) -> ProtocolTransitionCase:
    return ProtocolTransitionCase(parent, child)


class Transition:

    def __str__(self):
        raise ZpoException("Unspecified Transition")


class TransitionAccept(Transition):

    def __str__(self):
        return indent("transition accept;")


class TransitionSelector(Transition):

    def __init__(self, protocol: ProtocolComponent):
        self.selector_field = "%s.%s" % (
            protocol.struct_accessor, protocol.next_protocol_selector)
        self.selector_cases: List[TransitionCase] = [
            _make_protocol_transition(protocol, c) for c in protocol.children.values()]
        # Always add an accept case in the end
        self.selector_cases.append(DefaultTransitionCase())

    def cases_to_str(self):
        return "\n".join(lmap(str, self.selector_cases))

    def __str__(self):
        return indent("""
transition select(%s) {
%s
}
        """.strip() % (self.selector_field, self.cases_to_str()))
