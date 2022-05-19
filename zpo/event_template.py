import os
from zpo.template import Template
from zpo.utils import lmap


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
        self.path_dir = os.path.dirname(self.path)
        self._data = hjson_data

        if (self._data["zpo_type"] != "EVENT"):
            raise ValueError(
                "Wrong file format, 'zpo_type' doesn't match EVENT")

        self.id = self._data["id"]
        self.version = self._data["zpo_version"]
        self.protocol_id = self._data["protocol"]
        self.header_struct = self._data["event_header"]["header_struct"]
        self.header_file_path = os.path.join(
            self.path_dir, self._data["event_header"]["header_file"])
        self.identifier_file_path = os.path.join(
            self.path_dir, self._data["event_header"]["identifier"])
        self.constructor_file_path = os.path.join(
            self.path_dir, self._data["event_header"]["constructor"])
        self.uid = None
        self.uid_constant = "ZPO_%s_EVENT_UID" % self.id.upper()
        self.is_ip_based = bool(
            self._data["is_ip_based"]) if "is_ip_based" in self._data else False

        self.zeek_header_files = self._data["zeek"]["header_files"]
        self.zeek_cc_files = self._data["zeek"]["cc_files"]
        self.zeek_files = self.zeek_header_files + self.zeek_cc_files
        self.zeek_analyzer_id = self._data["zeek"]["analyzer_id"]
        self.zeek_analyzer_namespace = self._data["zeek"]["analyzer_namespace"]
        self.zeek_analyzer_class = self._data["zeek"]["analyzer_class"]

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
#     "is_ip_based": false,
#     "event_header": {
#         "header_file": "arp_reply_event.p4",
#         "header_struct": "arp_reply_event_h",
#         "constructor": "constructor.p4",
#         "identifier": "identifier.p4"
#     },
#     "zeek": {
#         "analyzer_namespace": "zeek::packet_analysis::BR_INF_UFRGS_ZPO::ARP",
#         "analyzer_class": "ZpoArpReplyAnalyzer",
#         "analyzer_id": "ZPO_ARP_REP",
#         "header_files": [
#             "ArpReply.h"
#         ],
#         "cc_files": [
#             "ArpReply.cc"
#         ]
#     }
# }
