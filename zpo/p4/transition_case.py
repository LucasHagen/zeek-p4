from zpo.model.protocol import ProtocolComponent
from zpo.utils import indent

INDENTATION = 4 * " "


class TransitionCase:

    def __init__(self, cond, action):
        self.cond = cond
        self.action = action

    def __str__(self):
        return indent("%s: %s;" % (self.cond, self.action))


class DefaultTransitionCase(TransitionCase):

    def __init__(self):
        super().__init__("default", "accept")


class ProtocolTransitionCase(TransitionCase):

    def __init__(self, parent: ProtocolComponent, child: ProtocolComponent):
        super().__init__(
            child.parent_protocols[parent.id].id_for_parent_protocol,
            child.parsing_state
        )
