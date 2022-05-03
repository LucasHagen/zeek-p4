from zpo_settings import ZPO_ARGS


class ProtocolTemplate:

    def __init__(self, path, hjson_data):
        global ZPO_ARGS

        self.path = path
        self.data = hjson_data

        if (self.data["zpo_type"] != "PROTOCOL"):
            raise ValueError(
                "Wrong file format, 'zpo_type' doesn't match PROTOCOL")

        if (self.data["zpo_version"] != ZPO_ARGS["version"]):
            raise ValueError(
                f"Wrong file version, expected {ZPO_ARGS['version']} was {self.data['zpo_version']}")

        self.id = self.data["protocol_name"]

# Example of a PROTOCOL template:
#
# {
#     "zpo_type": "PROTOCOL",
#     "zpo_version": "0.0.1",
#     "protocol_name": "arp",
#     "parent_protocol": "ethernet", // Special marker to say it's the root protocol
#     "header": {
#         "header_file": "arp_header.p4",
#         "header_struct": "arp_h"
#     },
#     "protocol_selector": "proto_type" // A field of the header template provided
# }
