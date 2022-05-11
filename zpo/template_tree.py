import logging
from re import T
from typing import List, Dict

from zpo.p4.parser_state import ParserState

from zpo.protocol_template import ProtocolTemplate
from zpo.event_template import EventTemplate
from zpo.template import Template
from zpo.zpo_settings import ZpoSettings


def _filter_by_type(template_list: List[Template], template_type) -> List[Template]:
    return [t for t in template_list if type(t) == template_type]


def _make_template_dict(template_list) -> Dict[str, Template]:
    return dict([(t.id, t) for t in template_list])


class TemplateTree:

    def __init__(self, settings: ZpoSettings, templates: List[Template]):
        """Constructs a TemplateTree

        Args:
            templates (List[Template]): a list of Templates

        Raises:
            ValueError: if the tree is not valid
        """
        self.settings = settings

        self.validate_templates_version(templates)

        self.protocol_list = _filter_by_type(templates, ProtocolTemplate)
        self.event_list = _filter_by_type(templates, EventTemplate)

        self.protocols = _make_template_dict(self.protocol_list)
        self.events = _make_template_dict(self.event_list)

        self.root = self.find_root_protocol()

        self.build_tree()

        self.validate_protocol_tree()
        self.attach_events()
        self.trim_unused_protocols()
        self.print_tree()

    def build_tree(self):
        """Builds the tree by setting the references of parents and children properly.

        Raises:
            ValueError: if parent protocol is not found.
        """
        for id, protocol in self.protocols.items():
            parent_id = protocol.parent_protocol_id

            if(parent_id == "!root"):
                continue

            if(parent_id not in self.protocols):
                raise ValueError(
                    f"Parent protocol '{parent_id}' not found for protocol '{id}'")

            parent = self.protocols[parent_id]
            parent.add_child(protocol)

    def validate_templates_version(self, templates: List[Template]):
        """Validates the versions of all templates.

        Raises:
            ValueError: wrong version
        """
        bad_version = list(
            filter(lambda t: not self.settings.validate_version(t.version), templates))

        if len(bad_version) > 0:
            raise ValueError(
                f"Expected templates with version '{self.settings.version}', but wrong the wrong version was found in: %s" %
                ", ".join(f"{t.id} ({t.version})" for t in bad_version))

    def find_root_protocol(self) -> ProtocolTemplate:
        """Finds the root protocol.

        Raises:
            ValueError: if no root or more than one root is found.
        """
        roots = [
            p for p in self.protocol_list if p.is_root_protocol()]
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
        """Attach only **REQUIRED** (from settings) EventTemplates to the ProtocolTemplate object.

        Raises:
            ValueError: if protocol not found
        """
        for event in self.events.values():
            # Ignore events that are not interested for this compilation run
            if event.id not in self.settings.events:
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
