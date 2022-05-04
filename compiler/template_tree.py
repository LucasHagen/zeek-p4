import logging

from typing import List

from protocol_template import ProtocolTemplate
from event_template import EventTemplate
from template import Template


class TemplateTree:

    def __init__(self, templates: List[Template]):
        """Constructs a TemplateTree

        Args:
            templates (List[Template]): a list of Templates

        Raises:
            ValueError: if the tree is not valid
        """
        self.protocol_list = [
            t for t in templates if type(t) == ProtocolTemplate]
        self.event_list = [t for t in templates if type(t) == EventTemplate]

        self.protocols = dict([(t.id, t) for t in self.protocol_list])
        self.events = dict([(t.id, t) for t in self.event_list])

        self.root = self.find_root()

        # Set references for parent and children objects
        for id, p in self.protocols.items():
            parent_id = p.parent_protocol_id

            if(parent_id == "!root"):
                continue

            if(parent_id not in self.protocols):
                raise ValueError(
                    f"Parent protocol '{parent_id}' not found for protocol '{id}'")

            parent = self.protocols[parent_id]

            p.parent = parent
            parent.children.append(p)

        self.validate_protocol_tree()

        logging.debug("Protocol Tree validated")

    def find_root(self) -> ProtocolTemplate:
        """Finds the root protocol
        """
        roots = [
            p for p in self.protocol_list if p.data["parent_protocol"] == "!root"]
        if(len(roots) != 1):
            raise ValueError(f"Expected 1 root protocol, found {len(roots)}")

        return roots[0]

    def validate_protocol_tree(self):
        visited = set()

        def validate_aux(protocol):
            if(protocol in visited):
                raise ValueError("Circular dependency found in protocol tree")

            visited.add(protocol)
            for child in protocol.children:
                validate_aux(child)

        validate_aux(self.root)

        if(visited != set(self.protocol_list)):
            raise ValueError("Unreachable protocol found")
