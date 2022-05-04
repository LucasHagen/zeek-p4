from zpo_settings import ZPO_ARGS
from template import Template


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
        global ZPO_ARGS

        self.path = path
        self.data = hjson_data
        self.parent = None
        self.children = []

        if (self.data["zpo_type"] != "PROTOCOL"):
            raise ValueError(
                "Wrong file format, 'zpo_type' doesn't match PROTOCOL")

        if (self.data["zpo_version"] != ZPO_ARGS["version"]):
            raise ValueError(
                f"Wrong file version, expected {ZPO_ARGS['version']} was {self.data['zpo_version']}")

        self.id = self.data["id"]
        self.parent_protocol_id = self.data["parent_protocol"]

# Example of a PROTOCOL template:
#
# {
#     "zpo_type": "PROTOCOL",
#     "zpo_version": "0.0.1",
#     "id": "arp",
#     "parent_protocol": "ethernet", // Special marker to say it's the root protocol
#     "header": {
#         "header_file": "arp_header.p4",
#         "header_struct": "arp_h"
#     },
#     "protocol_selector": "proto_type" // A field of the header template provided
# }
