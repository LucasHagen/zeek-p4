import hashlib
import json
import os
from tabnanny import verbose
from typing import List


class ZpoSettings:

    def __init__(self,
                 version: str,
                 output_dir: str,
                 events: List[str],
                 template_folders: List[str],
                 pwd: str,
                 debug: bool = False,
                 override: bool = False,
                 ):
        self.version: str = version
        self.output_dir: str = output_dir
        self.events: List[str] = events
        self.template_folders: List[str] = template_folders
        self.pwd: str = pwd
        self.debug: bool = debug
        self.override: bool = override
        self.master_template: str = os.path.join(
            os.path.dirname(__file__), "master_template")

        self.p4_master_template_dir = os.path.join(self.master_template, "p4")
        self.p4_output_dir: str = os.path.join(output_dir, "zpo.p4app")

        self.zeek_master_template_dir = os.path.join(
            self.master_template, "zeek")
        self.zeek_output_dir: str = os.path.join(output_dir, "zpo.zeek")

    def validate_version(self, other_version):
        return self.version == other_version

    def compute_hash(self) -> bytes:
        m = hashlib.sha256()

        m.update(self.version.encode('utf-8'))
        m.update(json.dumps(sorted(self.events),
                 sort_keys=True).encode('utf-8'))

        return m.digest()

    def __str__(self):
        return json.dumps(vars(self), indent=4)
