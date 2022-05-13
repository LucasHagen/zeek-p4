from zpo.protocol_template import ProtocolTemplate


class TransitionCase:

    def __str__(self):
        raise NotImplementedError()


class DefaultTransitionCase(TransitionCase):

    def __str__(self):
        return "default: accept;"


class ProtocolTransitionCase(TransitionCase):

    def __init__(self, parent: ProtocolTemplate, child: ProtocolTemplate):
        id_for_parent = child.parent_protocols[parent.id].id_for_parent_protocol

        self.case = "%s: %s;" % (id_for_parent, child.parsing_state)

    def __str__(self):
        return self.case
