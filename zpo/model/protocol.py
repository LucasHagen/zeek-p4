import json
import os
import hashlib
from typing import Dict
from zpo.exceptions import ZpoException

from zpo.model.component import Component
from zpo.model.offloader import OffloaderComponent

PROTOCOL_TYPE_STR = "PROTOCOL"


class ParentProtocol:
    """A class to store a parent protocol, and an id that will be used to identify
    the child protocol.

    Used as a simple (but typed and named) pair.
    """

    def __init__(self, parent_id: str, id_for_parent_protocol: str or int):
        self.parent_id = parent_id
        self.id_for_parent_protocol = id_for_parent_protocol


class ProtocolComponent(Component):
    """A template for a protocol
    """

    def __init__(self, path: str, hjson_data: str):
        """Constructs a template

        Args:
            path (str): path to the hjson template file
            hjson_data (str): hjson parsed data

        Raises:
            ZpoException: if the template is invalid
        """
        super().__init__(path, hjson_data)

        if (hjson_data["zpo_type"] != PROTOCOL_TYPE_STR):
            raise ZpoException(
                "Wrong file format, 'zpo_type' doesn't match PROTOCOL")

        self.children = {}
        self.offloaders = {}

        self.is_root = self.read_opt_data("is_root_protocol", convert=bool)
        self.parent_protocols = self._parse_parent_protocols()
        self.struct_accessor = f"hdr.{self.id}"
        self.next_protocol_selector = self.read_data("next_protocol_selector")
        self.parsing_state = f"parse_{self.id}"
        self.header_struct = self.read_data("header", "header_struct")
        self.header_file_path = self.read_rel_path_data(
            "header", "header_file")

        self.ingress_processor_file_path = self.read_opt_rel_path_data(
            "ingress_processor")

        self.custom_parser_file_path = self.read_opt_rel_path_data(
            "custom_parser")

        if (self.is_root and len(self.parent_protocols) > 0):
            raise ZpoException(
                f"Root protocol ({self.id}) can't have parent protocols")

        self.depth = None
        self._hash_cache = None

    def _parse_parent_protocols(self) -> Dict[str, ParentProtocol]:
        """Parses the parent protocols in the hjson data and returns a Dict with the
        `ParentProtocol`s indexed by the parent id.
        """
        protocols = dict()

        if("parent_protocols" not in self._data):
            return protocols

        for p in self.read_data("parent_protocols"):
            parent = ParentProtocol(p["id"], p["id_for_parent_protocol"])
            protocols[parent.parent_id] = parent

        return protocols

    def add_child(self, child: Component):
        """Adds a child to the children list.

        Args:
            child (ProtocolTemplate): the child protocol.
        """
        self.children[child.id] = child

    def rem_child(self, child: Component):
        """Removes a child protocol.

        Args:
            child (ProtocolTemplate): the child protocol to be removed.
        """
        self.children.pop(child.id)

    def add_offloader(self, offloader: OffloaderComponent):
        """Adds an offloader to this protocol. The offloader should be added only to the last protocol of
        it's stack.

        Args:
            offloader (OffloaderComponent): the offloader
        """
        self.offloaders[offloader.id] = offloader

    def type_str(self) -> str:
        return "protocol"

    def has_ingress_processor(self) -> bool:
        """Return whether this template has an ingress processor (file).
        """
        return self.ingress_processor_file_path != None and len(self.ingress_processor_file_path) > 0

    def has_custom_parser(self) -> bool:
        """Return whether this template has a custom parser (file).
        """
        return self.custom_parser_file_path != None and len(self.custom_parser_file_path) > 0

    def read_p4_ingress_processor(self) -> str:
        """Reads the P4 ingress processor file for the template.

        Returns:
            str: file content
        """
        if not self.has_ingress_processor():
            return ""

        with open(self.ingress_processor_file_path, 'r') as file:
            return file.read().strip()

    def read_p4_custom_parser(self) -> str:
        """Reads the P4 custom parser file for the template.

        Returns:
            str: file content
        """
        if not self.has_custom_parser():
            return ""

        with open(self.custom_parser_file_path, 'r') as file:
            return file.read().strip()

    def compute_hash(self) -> bytes:
        if self._hash_cache is None:
            m = hashlib.sha256()

            m.update(json.dumps(self._data, sort_keys=True).encode())
            m.update(self.read_p4_header().encode('utf-8'))
            m.update(self.read_p4_ingress_processor().encode('utf-8'))

            self._hash_cache = m.digest()

        return self._hash_cache


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
