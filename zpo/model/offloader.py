import os
import hashlib
import json
from zpo.exceptions import BadConfigException, ZpoException
from zpo.model.component import Component

OFFLOADER_TYPE_STR = "OFFLOADER"


class OffloaderComponent(Component):
    """An Offloader.
    """

    def __init__(self, path: str, hjson_data: str):
        """Constructs an Offloader.

        Args:
            path (str): path to the hjson template file
            hjson_data (str): hjson parsed data

        Raises:
            ZpoException: if the template is invalid
        """
        super().__init__(path, hjson_data)

        if (self.read_data("zpo_type") != OFFLOADER_TYPE_STR):
            raise ZpoException(
                f"Wrong file format, 'zpo_type' doesn't match {OFFLOADER_TYPE_STR}")

        self.protocol_id = self.read_data("protocol")
        self.priority = self.read_opt_data("priority", convert=lambda p: 0 if p is None else int(p))
        self.is_ip_based = self.read_opt_data("is_ip_based", convert=bool)

        # P4
        self.header_struct = self.read_data("p4", "header_struct_name")
        self.header_file_path = self.read_rel_path_data("p4", "header_file")
        self.splicer_file_path = self.read_rel_path_data("p4", "splicer_file")
        self.trigger_file_path = self.read_rel_path_data("p4", "trigger_file")

        # Zeek
        self.zeek_analyzer_id = self.read_data("zeek", "analyzer_id")
        self.zeek_analyzer_class = self.read_data("zeek", "analyzer_class")
        self.zeek_analyzer_namespace = self.read_data(
            "zeek", "analyzer_namespace")
        self.zeek_header_files = self.read_data("zeek", "header_files")
        self.zeek_cc_files = self.read_data("zeek", "cc_files")
        self.zeek_offloaded_events = self.read_data(
            "zeek", "offloaded_event_ids")

        self.zeek_files = self.zeek_header_files + self.zeek_cc_files
        self.uid_constant = "RNA_%s_UID" % self.id.upper()

        # Set later when the TemplateGraph is built
        self.uid = None
        self.protocol_depth = None

        self._hash_cache = None

    def type_str(self) -> str:
        return "offloader"

    def read_p4_trigger(self) -> str:
        """Reads the P4 Identifier file and returns it's content.

        Raises:
            ZpoException: file not found

        Returns:
            str: file content
        """
        if not os.path.exists(self.trigger_file_path):
            raise ZpoException("P4 identifier file (%s) not found for protocol template %s" % (
                self.trigger_file_path, self.id))

        with open(self.trigger_file_path, 'r') as file:
            return file.read().strip()

    def read_p4_header_constructor(self) -> str:
        """Reads the P4 Header file and returns it's content.

        Raises:
            ZpoException: file not found

        Returns:
            str: file content
        """
        if not os.path.exists(self.splicer_file_path):
            raise ZpoException("P4 header constructor file (%s) not found for protocol template %s" % (
                self.splicer_file_path, self.id))

        with open(self.splicer_file_path, 'r') as file:
            return file.read().strip()

    def compute_hash(self) -> bytes:
        if self._hash_cache is None:
            m = hashlib.sha256()

            m.update(json.dumps(self._data, sort_keys=True).encode())
            m.update(self.read_p4_header().encode('utf-8'))
            m.update(self.read_p4_trigger().encode('utf-8'))
            m.update(self.read_p4_header_constructor().encode('utf-8'))

            for relative_path in self.zeek_files:
                path = os.path.join(self.path_dir, relative_path)

                with open(path, 'r') as file:
                    m.update(file.read().strip().encode('utf-8'))

            self._hash_cache = m.digest()

        return self._hash_cache

# Example of OFFLOADER config:
#
# {
#     "zpo_type": "OFFLOADER",
#     "zpo_version": "0.0.1",
#     "id": "arp_reply",
#     "protocol": "arp_ipv4",
#     "p4": { // transcriber and splicer
#         "header_struct_name": "arp_reply_event_h",
#         "header_file": "arp_reply_header.p4",
#         "splicer_file": "constructor.p4",
#         "trigger_file": "identifier.p4"
#     },
#     "zeek": { // translator
#         "analyzer_namespace": "zeek::packet_analysis::BR_UFRGS_INF::RNA::ARP",
#         "analyzer_class": "RnaArpReplyAnalyzer",
#         "analyzer_id": "RNA_ARP_REP",
#         "header_files": [
#             "ArpReply.h"
#         ],
#         "cc_files": [
#             "ArpReply.cc"
#         ],
#         "offloaded_event_ids": [
#             "arp_reply"
#         ]
#     }
# }
