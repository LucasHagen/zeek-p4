import hashlib
import logging
from re import T
from typing import List, Dict, Protocol, Set
from zpo.exceptions import ZpoException

from zpo.model.protocol import ProtocolComponent
from zpo.model.offloader import OffloaderComponent
from zpo.model.component import Component
from zpo.zpo_settings import ZpoSettings


def _filter_list(cond, list: List) -> List:
    return [e for e in list if cond(e)]


def _filter_list_by_type(template_list: List[Component], template_type) -> List[Component]:
    return _filter_list(lambda t: type(t) == template_type, template_list)


def _make_template_dict(template_list) -> Dict[str, Component]:
    return dict([(t.id, t) for t in template_list])


class ExecGraph:

    def __init__(self, settings: ZpoSettings, components: List[Component]):
        """Constructor

        Args:
            components (List[Component]): a list of Components

        Raises:
            ZpoException: if the graph is not valid
        """
        self.settings: ZpoSettings = settings
        self.raw_components = components
        self.is_built = False
        self._hash_cache = None

    def build(self):
        """Builds the graph and validates it.
        """
        self._validate_component_list(self.raw_components)

        protocol_list = _filter_list_by_type(
            self.raw_components, ProtocolComponent)
        offloader_list = _filter_list_by_type(
            self.raw_components, OffloaderComponent)

        # Remove offloaders not requested by the user
        offloader_list = _filter_list(
            lambda offloader: offloader.id in self.settings.offloaders, offloader_list)

        self.protocols: Dict[str, ProtocolComponent] = _make_template_dict(
            protocol_list)
        self.offloaders: Dict[str, OffloaderComponent] = _make_template_dict(
            offloader_list)

        self.root = self._find_root_protocol()

        self._link_graph()
        self._attach_offloaders()
        self._check_for_cycles()
        self._trim_unused_protocols()
        self._remove_unreachable_protocols()

        self._set_protocol_depths()
        self._sort_protocols()
        self._sort_offloaders()
        self._set_offloaders_uids()

        self.is_built = True

    def protocols_by_depth(self) -> List[ProtocolComponent]:
        """A list of all ProtocolComponents sorted by depth (increasing).

        TLDR: lower level protocol first, higher level protocols last.
        """
        return self._protocols_by_depth

    def offloaders_by_depth_and_priority(self) -> List[OffloaderComponent]:
        """A list of all OffloaderComponents sorted by it's protocol depth, then
        by priority, then id (alphabetical order).

        TLDR: lower level protocol first, higher level protocols last. If same
        protocol priority, sorted by alphabetical order.
        """
        return self._offloaders_by_depth_and_priority

    def offloaders_by_priority(self) -> List[OffloaderComponent]:
        """A list of all OffloaderComponents sorted by it's priority, then id
        (alphabetical order).
        """
        return self._offloaders_by_priority

    def print_tree(self, print_method=logging.debug):
        """
        Prints the current protocol graph as a tree, showing all protocol and
        the offloaders associated with them. The protocols that have more than one
        parent protocol will show up twice, once for each parent.
        """
        def print_aux(node: ProtocolComponent, depth):
            spacing = " " * depth * 4

            if depth != 0:
                print_method(f"{spacing} |")

            if len(node.offloaders) > 0:
                print_method(
                    f"{spacing} |- {node.id} ({node.depth}): [{', '.join(node.offloaders)}]")
            else:
                print_method(
                    f"{spacing} |- {node.id} ({node.depth})")

            for child in sorted(node.children.values(), key=lambda p: p.id):
                print_aux(child, depth + 1)

        print_method("Current Template Tree:")
        print_aux(self.root, 0)

    def compute_hash(self) -> bytes:
        if not self.is_built:
            raise ZpoException(
                "Can't compute hash, template tree hasn't been built.")

        if self._hash_cache is None:
            m = hashlib.sha256()

            m.update(self.settings.compute_hash())
            # print("Hash [Settings]:", self.settings.compute_hash().hex())

            for protocol in self.protocols_by_depth():
                # print("Hash [%s]:" % protocol.id, protocol.compute_hash().hex())
                m.update(protocol.compute_hash())

            for offloader in self.offloaders_by_priority():
                # print("Hash [%s]:" % offloader.id, offloader.compute_hash().hex())
                m.update(offloader.compute_hash())

            self._hash_cache = m.digest()

        return self._hash_cache

    def compute_hash_hex(self) -> str:
        return self.compute_hash().hex()

    def _validate_component_list(self, components: List[Component]):
        """Validates the versions of all components and checks for duplicate ids.

        Raises:
            ZpoException: wrong version
        """
        bad_version = list(
            filter(lambda t: not self.settings.validate_version(t.version), components))

        if len(bad_version) > 0:
            raise ZpoException(
                f"Expected templates with version '{self.settings.version}', but wrong the wrong version was found in: %s" %
                ", ".join(f"{t.id} ({t.version})" for t in bad_version))

        # Check for duplicated keys
        seen = set()
        duplicates = set(
            [t.id for t in components if t.id in seen or seen.add(t.id)])

        if len(duplicates) > 0:
            raise ZpoException(
                "Found duplicated ids in templates: %s" % duplicates)

    def _find_root_protocol(self) -> ProtocolComponent:
        """Finds the root protocol.

        Simple search on the protocols list.

        Raises:
            ZpoException: if no root or more than one root is found.
        """
        roots = _filter_list(lambda p: p.is_root, self.protocols.values())
        if(len(roots) != 1):
            raise ZpoException(f"Expected 1 root protocol, found {len(roots)}")

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

        logging.debug("Graph has been linked")

    def _attach_offloaders(self):
        """Attach only **REQUIRED** Offloaders (from settings) to the Protocol object.

        Raises:
            ZpoException: if protocol not found
        """
        for offloader_id in self.settings.offloaders:
            if offloader_id not in self.offloaders:
                raise ZpoException(
                    f"Offloader template for '{offloader_id}' not found'")

            offloader = self.offloaders[offloader_id]

            if offloader.protocol_id not in self.protocols:
                raise ZpoException(
                    f"Offloader '{offloader.id}' requires protocol '{offloader.protocol_id}'")

            self.protocols[offloader.protocol_id].add_offloader(offloader)

        logging.debug("Offloaders attached to protocols")

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
                raise ZpoException("Cycle detected in protocol graph")

    def _trim_unused_protocols(self):
        """
        Removes ProtocolTemplates (nodes) that have no offloaders associated to them or to any of
        their children (or to their children's children and so on....).
        """
        unreachable_offloaders: Set[str] = set(self.offloaders.keys())
        visited_protocols: Set[str] = set()
        removed_protocols: Set[str] = set()

        def aux_trim_unused(template: ProtocolComponent):
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

            for offloader_id in template.offloaders:
                if offloader_id in unreachable_offloaders:
                    unreachable_offloaders.remove(offloader_id)

            return len(template.offloaders) <= 0 and len(template.children) <= 0

        aux_trim_unused(self.root)

        if len(unreachable_offloaders) > 0:
            raise ZpoException("One or more offloaders are unreachable with the current loaded protocols: %s" % ", ".join(
                unreachable_offloaders))

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

    def _set_protocol_depths(self):
        """BFS through the graph setting protocol priority/depth. The highest depth is kept.
        """
        queue = []

        queue.append((self.root, 0))

        while len(queue) != 0:
            protocol, depth = queue.pop(0)
            protocol: ProtocolComponent

            new_depth = depth if protocol.depth == None else max(
                protocol.depth, depth)

            if protocol.depth != new_depth:
                protocol.depth = new_depth
                for e in protocol.offloaders.values():
                    e: OffloaderComponent
                    e.protocol_depth = new_depth

            # At this stage there are no more cycles, so there is no need to check for it again
            for child in protocol.children.values():
                queue.append((child, depth + 1))

    def _sort_protocols(self):
        self._protocols_by_depth = list(self.protocols.values())
        self._protocols_by_depth.sort(key=lambda p: (p.depth, p.id))

        self._protocols_by_depth_reversed = reversed(self._protocols_by_depth)

    def _sort_offloaders(self):
        self._offloaders_by_depth_and_priority = []

        for protocol in self._protocols_by_depth:
            offloaders: List[OffloaderComponent] = list(
                protocol.offloaders.values())
            offloaders.sort(key=lambda o: o.id)
            offloaders.sort(key=lambda o: o.priority, reverse=True)

            for o in offloaders:
                self._offloaders_by_depth_and_priority.append(o)

        self._offloaders_by_priority: List[OffloaderComponent] = list(
            self.offloaders.values())
        self._offloaders_by_priority.sort(key=lambda o: (o.id))
        self._offloaders_by_priority.sort(
            key=lambda o: (o.priority), reverse=True)

    def _set_offloaders_uids(self):
        """Sets the offloaders ids in order of priority.
        """
        next_offloader_uid = 1

        for e in self.offloaders_by_priority():
            e.uid = next_offloader_uid
            next_offloader_uid += 1
