import os
from typing import Dict

from zpo.template import Template
from zpo.event_template import EventTemplate


class ParentProtocol:
    """A class to store a parent protocol, and an id that will be used to identify
    the child protocol.

    Used as a simple (but typed and named) pair.
    """

    def __init__(self, parent_id: str, id_for_parent_protocol: str or int):
        self.parent_id = parent_id
        self.id_for_parent_protocol = id_for_parent_protocol


class ProtocolTemplate(Template):
    """A template for a protocol
    """

    def __init__(self, path: str, hjson_data: str):
        """Constructs a template

        Args:
            path (str): path to the hjson template file
            hjson_data (str): hjson parsed data

        Raises:
            ValueError: if the template is invalid
        """
        if (hjson_data["zpo_type"] != "PROTOCOL"):
            raise ValueError(
                "Wrong file format, 'zpo_type' doesn't match PROTOCOL")

        self.path = path
        self._data = hjson_data
        self.children = {}
        self.events = {}

        self.id = self._data["id"]
        self.version = self._data["zpo_version"]
        self.is_root = self._check_if_is_root()
        self.parent_protocols = self._parse_parent_protocols()
        self.struct_accessor = f"hdr.{self.id}"
        self.next_protocol_selector = self._data["next_protocol_selector"]
        self.parsing_state = f"parse_{self.id}"
        self.header_struct = self._data["header"]["header_struct"]
        self.priority = None
        self.header_file_path = os.path.join(
            os.path.dirname(path), self._data["header"]["header_file"])

        if "ingress_processor" in self._data:
            self.ingress_processor_file_path = os.path.join(
                os.path.dirname(path), self._data["ingress_processor"])
        else:
            self.ingress_processor_file_path = None

        if (self.is_root and len(self.parent_protocols) > 0):
            raise ValueError(
                f"Root protocol ({self.id}) can't have parent protocols")

    def _parse_parent_protocols(self) -> Dict[str, ParentProtocol]:
        """Parses the parent protocols in the hjson data and returns a Dict with the
        `ParentProtocol`s indexed by the parent id.
        """
        protocols = dict()

        if("parent_protocols" not in self._data):
            return protocols

        for p in self._data["parent_protocols"]:
            parent = ParentProtocol(p["id"], p["id_for_parent_protocol"])
            protocols[parent.parent_id] = parent

        return protocols

    def _check_if_is_root(self) -> bool:
        """Internal use. For public usage, use the `is_root` variable
        """
        return self._data["is_root_protocol"] if "is_root_protocol" in self._data else False

    def add_child(self, child: Template):
        """Adds a child to the children list.

        Args:
            child (ProtocolTemplate): the child protocol.
        """
        self.children[child.id] = child

    def rem_child(self, child: Template):
        """Removes a child protocol.

        Args:
            child (ProtocolTemplate): the child protocol to be removed.
        """
        self.children.pop(child.id)

    def add_event(self, event: EventTemplate):
        """Adds an event to this protocol. The event should be added only to the last protocol of
        it's stack.

        Args:
            event (EventTemplate): the event template
        """
        self.events[event.id] = event

    def type_str(self) -> str:
        return "protocol"

    def has_ingress_processor(self) -> bool:
        """Return whether this template has an ingress processor (file).
        """
        return self.ingress_processor_file_path != None and len(self.ingress_processor_file_path) > 0

# Example of a PROTOCOL template:
#
# {
#     "zpo_type": "PROTOCOL",
#     "zpo_version": "0.0.1",
#     "id": "arp",
#     "parent_protocols": [
#         {
#             "id": "ethernet",
#             "id_for_parent_protocol": 2054 // DECIMAL id to identify this protocol in the parent protocol
#         }
#     ],
#     "header": {
#         "header_file": "arp_header.p4",
#         "header_struct": "arp_h"
#     },
#     "next_protocol_selector": "proto_type" // A field of the header template provided
# }
