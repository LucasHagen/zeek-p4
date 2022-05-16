import os
from zpo.template import Template


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

        self.path = path
        self._data = hjson_data

        if (self._data["zpo_type"] != "EVENT"):
            raise ValueError(
                "Wrong file format, 'zpo_type' doesn't match EVENT")

        self.id = self._data["id"]
        self.version = self._data["zpo_version"]
        self.protocol_id = self._data["protocol"]
        self.header_struct = self._data["event_header"]["header_struct"]
        self.header_file_path = os.path.join(
            os.path.dirname(path), self._data["event_header"]["header_file"])
        self.identifier_file_path = os.path.join(
            os.path.dirname(path), self._data["event_header"]["identifier"])
        self.constructor_file_path = os.path.join(
            os.path.dirname(path), self._data["event_header"]["constructor"])
        self.uid = None
        self.uid_constant = "ZPO_%s_EVENT_UID" % self.id.upper()

    def type_str(self):
        return "event"

    def read_p4_identifier(self) -> str:
        if not os.path.exists(self.identifier_file_path):
            raise ValueError("P4 identifier file (%s) not found for protocol template %s" % (
                self.identifier_file_path, self.id))

        with open(self.identifier_file_path, 'r') as file:
            return file.read().strip()

    def read_p4_header_constructor(self) -> str:
        if not os.path.exists(self.constructor_file_path):
            raise ValueError("P4 header constructor file (%s) not found for protocol template %s" % (
                self.constructor_file_path, self.id))

        with open(self.constructor_file_path, 'r') as file:
            return file.read().strip()

# Example of an EVENT template:
#
# {
#     "zpo_type": "EVENT",
#     "zpo_version": "0.0.1",
#     "id": "arp_reply",
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
