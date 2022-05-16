import logging
from re import T
from typing import List, Dict, Set

from zpo.p4.parser_state import ParserState

from zpo.protocol_template import ProtocolTemplate
from zpo.event_template import EventTemplate
from zpo.template import Template
from zpo.zpo_settings import ZpoSettings


def _filter_list(cond, list: List) -> List:
    return [e for e in list if cond(e)]


def _filter_list_by_type(template_list: List[Template], template_type) -> List[Template]:
    return _filter_list(lambda t: type(t) == template_type, template_list)


def _make_template_dict(template_list) -> Dict[str, Template]:
    return dict([(t.id, t) for t in template_list])


class TemplateGraph:

    def __init__(self, settings: ZpoSettings, templates: List[Template]):
        """Constructs a TemplateTree

        Args:
            templates (List[Template]): a list of Templates

        Raises:
            ValueError: if the tree is not valid
        """
        self.settings = settings

        self.validate_templates_version(templates)

        protocol_list = _filter_list_by_type(templates, ProtocolTemplate)
        event_list = _filter_list_by_type(templates, EventTemplate)

        # Remove events not requested by the user
        event_list = _filter_list(
            lambda e: e.id in self.settings.events, event_list)

        self.protocols = _make_template_dict(protocol_list)
        self.events = _make_template_dict(event_list)

        self.root = self.find_root_protocol()

        self.build_graph()
        self.attach_events()
        self.check_for_cycles()
        self.trim_unused_protocols()
        self.remove_unreachable_protocols()

        self.set_protocol_priorities()
        self.set_events_int_ids()

        self.print_tree()

    def build_graph(self):
        """Builds the tree by setting the references of parents and children properly.
        """
        for id, protocol in self.protocols.items():
            if protocol.is_root:
                continue

            parents = protocol.parent_protocols

            for parent_id in parents:
                if(parent_id not in self.protocols):
                    logging.warning(
                        f"Parent protocol '{parent_id}' not found for protocol '{id}'")
                else:
                    parent = self.protocols[parent_id]
                    parent.add_child(protocol)

    def set_events_int_ids(self):
        next_event_uid = 0

        for e in self.events_by_priority():
            e.uid = next_event_uid
            next_event_uid += 1

    def set_protocol_priorities(self):
        queue = []

        queue.append((self.root, 0))

        while len(queue) != 0:
            node, depth = queue.pop(0)

            if node.priority == None:
                node.priority = depth
            else:
                node.priority = max(node.priority, depth)

            # At this stage there are no more cycles, so there is no need to check for it again
            for child in node.children.values():
                queue.append((child, depth + 1))

        self._protocols_by_priority = list(self.protocols.values())
        self._protocols_by_priority.sort(key=lambda p: p.priority)

        self._events_by_priority = []
        for protocol in self._protocols_by_priority:
            for e in protocol.events.values():
                self._events_by_priority.append(e)

        self._events_by_priority_reversed = list(self._events_by_priority)
        self._events_by_priority_reversed.reverse()

    def protocols_by_priority(self) -> List[ProtocolTemplate]:
        return self._protocols_by_priority

    def events_by_priority(self) -> List[EventTemplate]:
        return self._events_by_priority

    def events_by_priority_reversed(self) -> List[EventTemplate]:
        return self._events_by_priority_reversed

    def remove_unreachable_protocols(self):
        unreachable_protocols = set(self.protocols.keys())

        def aux_reachable(protocol):
            if protocol.id not in unreachable_protocols:
                return

            unreachable_protocols.remove(protocol.id)

            for child in protocol.children.values():
                aux_reachable(child)

        aux_reachable(self.root)

        logging.debug(
            f"Checked for unreachable protocols: {len(unreachable_protocols)} unreachable protocols found")

        if len(unreachable_protocols) > 0:
            for protocol_id in unreachable_protocols:
                self.protocols.pop(protocol_id)

    def check_for_cycles(self):
        visited = set()
        rec_stack = set()

        def has_cycle(protocol):
            visited.add(protocol.id)
            rec_stack.add(protocol.id)

            for child in protocol.children.values():
                if child.id not in visited:
                    if has_cycle(child):
                        return True
                else:
                    if child.id in rec_stack:
                        return True

            rec_stack.remove(protocol.id)

        for p in self.protocols.values():
            if has_cycle(p):
                raise ValueError("Cycle detected in protocol graph")

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
        roots = _filter_list(lambda p: p.is_root, self.protocols.values())
        if(len(roots) != 1):
            raise ValueError(f"Expected 1 root protocol, found {len(roots)}")

        return roots[0]

    def attach_events(self):
        """Attach only **REQUIRED** (from settings) EventTemplates to the ProtocolTemplate object.

        Raises:
            ValueError: if protocol not found
        """
        for event_id in self.settings.events:
            if event_id not in self.events:
                raise ValueError(f"Event template for '{event_id}' not found'")

            event = self.events[event_id]

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

            if depth != 0:
                logging.debug(f"{spacing} |")

            if len(node.events) > 0:
                logging.debug(
                    f"{spacing} |- {node.id} ({node.priority}): [{', '.join(node.events)}]")
            else:
                logging.debug(
                    f"{spacing} |- {node.id} ({node.priority})")

            for child in node.children.values():
                print_aux(child, depth + 1)

        logging.debug("Current Template Tree:")
        print_aux(self.root, 0)

    def trim_unused_protocols(self):
        """
        Removes ProtocolTemplates (nodes) that have no events associated to them or to any of
        their children (or to their children's children and so on....).
        """
        unreachable_events: Set[str] = set(self.events.keys())
        visited_protocols: Set[str] = set()
        removed_protocols: Set[str] = set()

        def aux_trim_unused(template: ProtocolTemplate):
            """Returns true if template should be removed.
            """
            if template.id in visited_protocols:
                return template.id in removed_protocols

            visited_protocols.add(template.id)

            for child in set(template.children.values()):
                to_remove = aux_trim_unused(child)

                if to_remove:
                    template.rem_child(child)
                    removed_protocols.add(child.id)

            for event_id in template.events:
                if event_id in unreachable_events:
                    unreachable_events.remove(event_id)

            return len(template.events) <= 0 and len(template.children) <= 0

        aux_trim_unused(self.root)

        if len(unreachable_events) > 0:
            raise ValueError("One or more events are unreachable with the current loaded protocols: %s" % ", ".join(
                unreachable_events))

        for to_remove in removed_protocols:
            self.protocols.pop(to_remove)

        logging.debug(
            f"Checked for unused protocols ({len(removed_protocols)} protocol(s) removed)")
