import logging

from typing import List
from zpo_settings import ZPO_ARGS

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

        self.root = self.find_root_protocol()

        # Set references for parent and children objects
        for id, p in self.protocols.items():
            parent_id = p.parent_protocol_id

            if(parent_id == "!root"):
                continue

            if(parent_id not in self.protocols):
                raise ValueError(
                    f"Parent protocol '{parent_id}' not found for protocol '{id}'")

            parent = self.protocols[parent_id]

            parent.add_child(p)

        self.validate_protocol_tree()
        self.attach_events()
        self.trim_unused_protocols()
        self.print_tree()

    def find_root_protocol(self) -> ProtocolTemplate:
        """Finds the root protocol.

        Raises:
            ValueError: if no root or more than one root is found.
        """
        roots = [
            p for p in self.protocol_list if p.data["parent_protocol"] == "!root"]
        if(len(roots) != 1):
            raise ValueError(f"Expected 1 root protocol, found {len(roots)}")

        return roots[0]

    def validate_protocol_tree(self):
        """Checks if the protocol tree is valid.

        Raises:
            ValueError: Circular dependency found.
            ValueError: Unreachable protocol found.
        """
        visited = set()

        def validate_aux(protocol):
            if(protocol in visited):
                raise ValueError("Circular dependency found in protocol tree")

            visited.add(protocol)
            for child in protocol.children.values():
                validate_aux(child)

        validate_aux(self.root)

        if(visited != set(self.protocol_list)):
            raise ValueError("Unreachable protocol found")

        logging.debug("Protocol tree validated")

    def attach_events(self):
        """Attach only **REQUIRED** (from ZPO_ARGS) EventTemplates to the ProtocolTemplate object.

        Raises:
            ValueError: if protocol not found
        """
        global ZPO_ARGS
        for event in self.events.values():
            # Ignore events that are not interested for this compilation run
            if event.id not in ZPO_ARGS["events"]:
                continue

            if event.protocol_id not in self.protocols:
                raise ValueError(
                    f"Event '{event.id}' requires protocol '{event.protocol_id}'")

            self.protocols[event.protocol_id].add_event(event)
        logging.debug("Events attached to protocol templates")

    def print_tree(self):
        """
        Prints the current protocol tree, showing all protocol and the events associated with
        them.
        """
        def print_aux(node, depth):
            spacing = " " * depth * 4

            if(depth != 0):
                logging.debug(f"{spacing} |")
            logging.debug(
                f"{spacing} |- {node.id}: [{', '.join(node.events)}]")

            for child in node.children.values():
                print_aux(child, depth + 1)

        logging.debug("Current Template Tree:")
        print_aux(self.root, 0)

    def trim_unused_protocols(self):
        """
        Removes ProtocolTemplates (nodes) that have no events associated to them or to any of
        their children (or to their children's children and so on....).
        """
        def aux_trim_unused(template: ProtocolTemplate):
            amount = len(template.events)
            removed_protocols = 0
            for child in set(template.children.values()):
                child_amount, child_removed = aux_trim_unused(child)
                amount += child_amount
                removed_protocols += child_removed

                # remove `child`, if `child_amount` < 0
                if child_amount <= 0:
                    template.rem_child(child)
                    removed_protocols += 1

            return (amount, removed_protocols)

        total_events, removed_protocols = aux_trim_unused(self.root)

        logging.debug(
            f"Trimmed unused protocols from tree ({removed_protocols} protocols)")
