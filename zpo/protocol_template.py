from zpo.template import Template
from zpo.event_template import EventTemplate

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
        self.path = path
        self._data = hjson_data
        self.parent = None
        self.children = {}
        self.events = {}

        if (self._data["zpo_type"] != "PROTOCOL"):
            raise ValueError(
                "Wrong file format, 'zpo_type' doesn't match PROTOCOL")

        self.id = self._data["id"]
        self.version = self._data["zpo_version"]
        self.parent_protocol_id = self._data["parent_protocol"]
        self.struct_accessor = f"hdr.{self.id}"
        self.next_protocol_selector = self._data["next_protocol_selector"]
        self.identifier_for_parent_protocol = self._data["identifier_for_parent_protocol"]
        self.parsing_state = f"parse_{self.id}"

    def add_child(self, child):
        self.children[child.id] = child
        child.parent = self

    def rem_child(self, child):
        self.children.pop(child.id)
        child.parent = None

    def add_event(self, event: EventTemplate):
        self.events[event.id] = event

    def is_root_protocol(self):
        return self._data["parent_protocol"] == "!root"

# Example of a PROTOCOL template:
#
# {
#     "zpo_type": "PROTOCOL",
#     "zpo_version": "0.0.1",
#     "id": "arp",
#     "parent_protocol": "ethernet",
#     "identifier_for_parent_protocol": 2054, // DECIMAL id to identify this protocol in the parent protocol
#     "header": {
#         "header_file": "arp_header.p4",
#         "header_struct": "arp_h"
#     },
#     "next_protocol_selector": "proto_type" // A field of the header template provided
# }
