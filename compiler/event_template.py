from template import Template
from zpo_settings import ZPO_ARGS


class EventTemplate(Template):
    """A template for an event
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

        if (self.data["zpo_type"] != "EVENT"):
            raise ValueError(
                "Wrong file format, 'zpo_type' doesn't match EVENT")

        if (self.data["zpo_version"] != ZPO_ARGS["version"]):
            raise ValueError(
                f"Wrong file version, expected {ZPO_ARGS['version']} was {self.data['zpo_version']}")

        self.id = self.data["id"]

# Example of an EVENT template:
#
# {
#     "zpo_type": "EVENT",
#     "zpo_version": "0.0.1",
#     "protocol": "arp_ipv4",
#     "event_header": {
#         "header_file": "arp_reply_event.p4",
#         "header_struct": "arp_reply_event_h",
#         "constructor": "constructor.p4",
#         "identifier": "identifier.p4"
#     },
#     "zeek": {
#         "analyzer_namespace": "zeek::packet_analysis::BR_INF_UFRGS_ZPO::ARP",
#         "analyzer_class": "ZpoArpReplyAnalyzer",
#         "header_files": [
#             "ArpReply.h"
#         ],
#         "cc_files": [
#             "ArpReply.cc"
#         ]
#     }
# }
