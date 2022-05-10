from typing import List

from zpo_compiler.p4.transition_case import TransitionCase, DefaultTransitionCase, ProtocolTransitionCase
from zpo_compiler.protocol_template import ProtocolTemplate


def _make_protocol_transition(protocol: ProtocolTemplate) -> ProtocolTransitionCase:
    return ProtocolTransitionCase(protocol)


class Transition:

    def __str__(self):
        raise ValueError("Unspecified Transition")


class TransitionAccept(Transition):

    def __str__(self):
        return "transition accept;"


class TransitionSelector(Transition):

    def __init__(self, protocol: ProtocolTemplate):
        self.selector_field = "%s.%s" % (
            protocol.struct_accessor, protocol.next_protocol_selector)
        self.selector_cases: List[TransitionCase] = list(map(
            _make_protocol_transition, protocol.children.values()))
        # Always add an accept case in the end
        self.selector_cases.append(DefaultTransitionCase())

    def cases_to_str(self):
        return "\n".join(list(map(str, self.selector_cases)))

    def __str__(self):
        return """
transition select(%s) {
%s
}
        """.strip() % (self.selector_field, self.cases_to_str())
