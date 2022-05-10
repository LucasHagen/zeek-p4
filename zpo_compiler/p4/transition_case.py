from zpo_compiler.protocol_template import ProtocolTemplate

class TransitionCase:

    def __str__(self):
        raise NotImplementedError()

class DefaultTransitionCase(TransitionCase):

    def __str__(self):
        return "default: accept;"

class ProtocolTransitionCase(TransitionCase):

    def __init__(self, protocol: ProtocolTemplate):
        self.case = "%s: %s;" % (protocol.identifier_for_parent_protocol, protocol.parsing_state)

    def __str__(self):
        return self.case
