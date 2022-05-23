import logging
from re import T
from typing import List, Dict, Set

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
        """Constructor

        Args:
            templates (List[Template]): a list of Templates

        Raises:
            ValueError: if the tree is not valid
        """
        self.settings = settings
        self.raw_templates = templates

    def build(self):
        """Builds the graph and validates it.
        """
        self._validate_templates_list(self.raw_templates)

        protocol_list = _filter_list_by_type(
            self.raw_templates, ProtocolTemplate)
        event_list = _filter_list_by_type(self.raw_templates, EventTemplate)

        # Remove events not requested by the user
        event_list = _filter_list(
            lambda e: e.id in self.settings.events, event_list)

        self.protocols = _make_template_dict(protocol_list)
        self.events = _make_template_dict(event_list)

        self.root = self._find_root_protocol()

        self._link_graph()
        self._attach_events()
        self._check_for_cycles()
        self._trim_unused_protocols()
        self._remove_unreachable_protocols()

        self._set_protocol_priorities()
        self._set_events_int_ids()

    def protocols_by_priority(self) -> List[ProtocolTemplate]:
        """A list of all ProtocolTemplates sorted by priority.

        Priority is the depth in the protocol graph:

        TLDR: lower level protocol first, higher level protocols last.
        """
        return self._protocols_by_priority

    def events_by_priority(self) -> List[EventTemplate]:
        """A list of all EventTemplates sorted by it's protocol priority, then
        by id (alphabetical order).

        Priority is the depth of the protocol in the protocol graph:

        TLDR: lower level protocol first, higher level protocols last. If same
        protocol priority, sorted by alphabetical order.
        """
        return self._events_by_priority

    def events_by_priority_reversed(self) -> List[EventTemplate]:
        """A list of all EventTemplates sorted (DESCENDING) by it's protocol priority, then
        by id (alphabetical order).

        Priority is the depth of the protocol in the protocol graph:

        TLDR: high level protocols first, lower level protocols last. If same
        protocol priority, sorted by (reversed) alphabetical order.
        """
        return self._events_by_priority_reversed

    def print_tree(self, print_method=logging.debug):
        """
        Prints the current protocol graph as a tree, showing all protocol and
        the events associated with them. The protocols that have more than one
        parent protocol will show up twice, once for each parent.
        """
        def print_aux(node, depth):
            spacing = " " * depth * 4

            if depth != 0:
                print_method(f"{spacing} |")

            if len(node.events) > 0:
                print_method(
                    f"{spacing} |- {node.id} ({node.priority}): [{', '.join(node.events)}]")
            else:
                print_method(
                    f"{spacing} |- {node.id} ({node.priority})")

            for child in node.children.values():
                print_aux(child, depth + 1)

        print_method("Current Template Tree:")
        print_aux(self.root, 0)

    def _validate_templates_list(self, templates: List[Template]):
        """Validates the versions of all templates and checks for duplicate ids.

        Raises:
            ValueError: wrong version
        """
        bad_version = list(
            filter(lambda t: not self.settings.validate_version(t.version), templates))

        if len(bad_version) > 0:
            raise ValueError(
                f"Expected templates with version '{self.settings.version}', but wrong the wrong version was found in: %s" %
                ", ".join(f"{t.id} ({t.version})" for t in bad_version))

        # Check for duplicated keys
        seen = set()
        duplicates = set(
            [t.id for t in templates if t.id in seen or seen.add(t.id)])

        if len(duplicates) > 0:
            raise ValueError(
                "Found duplicated ids in templates: %s" % duplicates)

    def _find_root_protocol(self) -> ProtocolTemplate:
        """Finds the root protocol.

        Simple search on the protocols list.

        Raises:
            ValueError: if no root or more than one root is found.
        """
        roots = _filter_list(lambda p: p.is_root, self.protocols.values())
        if(len(roots) != 1):
            raise ValueError(f"Expected 1 root protocol, found {len(roots)}")

        return roots[0]

    def _link_graph(self):
        """Builds the graph by setting the references of parents and children properly.
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

    def _attach_events(self):
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

    def _check_for_cycles(self):
        """Checks for cycles in the graph.

        Based on: https://www.geeksforgeeks.org/detect-cycle-in-a-graph/
        """
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

    def _trim_unused_protocols(self):
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

    def _remove_unreachable_protocols(self):
        """DFS through the graph until all reachable nodes have been marked visisted.

        The nodes not marked "visited" are removed.
        """
        unreachable_protocols = set(self.protocols.keys())

        def aux_reachable(protocol):
            if protocol.id not in unreachable_protocols:
                return

            unreachable_protocols.remove(protocol.id)

            for child in protocol.children.values():
                aux_reachable(child)

        aux_reachable(self.root)

        logging.debug("Checked for unreachable protocols: %s unreachable protocols found" % len(
            unreachable_protocols))

        if len(unreachable_protocols) > 0:
            for protocol_id in unreachable_protocols:
                self.protocols.pop(protocol_id)

    def _set_protocol_priorities(self):
        """BFS through the graph setting protocol priority/depth. The highest depth is kept.
        """
        queue = []

        queue.append((self.root, 0))

        while len(queue) != 0:
            node, depth = queue.pop(0)

            new_priority = depth if node.priority == None else max(
                node.priority, depth)

            if node.priority != new_priority:
                node.priority = new_priority
                for e in node.children.values():
                    e.protocol_priority = new_priority

            # At this stage there are no more cycles, so there is no need to check for it again
            for child in node.children.values():
                queue.append((child, depth + 1))

        self._protocols_by_priority = list(self.protocols.values())
        self._protocols_by_priority.sort(key=lambda p: p.priority)

        self._events_by_priority = []
        for protocol in self._protocols_by_priority:
            events = list(protocol.events.values())
            events.sort(key=lambda e: e.id)

            for e in protocol.events.values():
                self._events_by_priority.append(e)

        self._events_by_priority_reversed = list(self._events_by_priority)
        self._events_by_priority_reversed.reverse()

    def _set_events_int_ids(self):
        """Sets events ids in order of priority.
        """
        next_event_uid = 1

        for e in self.events_by_priority():
            e.uid = next_event_uid
            next_event_uid += 1
