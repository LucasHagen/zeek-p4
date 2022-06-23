import hashlib
import json
import os
from typing import List


class ZpoSettings:

    def __init__(self,
                 version: str,
                 output_dir: str,
                 offloaders: List[str],
                 template_folders: List[str],
                 required_events: List[str],
                 pwd: str,
                 debug: bool = False,
                 override: bool = False,
                 ):
        self.version: str = version
        self.output_dir: str = output_dir
        self.offloaders: List[str] = sorted(offloaders)
        self.template_folders: List[str] = sorted(template_folders)
        self.required_events: List[str] = sorted(required_events)
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
        m.update(json.dumps(sorted(self.offloaders),
                 sort_keys=True).encode('utf-8'))
        m.update(json.dumps(sorted(self.required_events),
                 sort_keys=True).encode('utf-8'))

        return m.digest()

    def __str__(self):
        return json.dumps(vars(self), indent=4)
