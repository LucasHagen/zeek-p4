
from typing import List


class ZpoSettings:

    def __init__(self,
                 version: str,
                 output_dir: str,
                 events: List[str],
                 template_folders: List[str],
                 pwd: str,
                 main_py: str,
                 debug: bool = False,
                 ):
        self.version: str = version
        self.output_dir: str = output_dir
        self.events: List[str] = events
        self.template_folders: List[str] = template_folders
        self.pwd: str = pwd
        self.main_py: str = main_py
        self.debug: bool = debug

    def validate_version(self, other_version):
        return self.version == other_version
