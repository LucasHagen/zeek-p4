import os
from typing import List
from zpo.model.offloader import OffloaderComponent
from zpo.file_generator import FileGenerator
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.exec_graph import ExecGraph
from zpo.utils import indent
from zpo.zpo_settings import ZpoSettings

class VersionFile(FileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.zeek_output_dir, "VERSION")
        )

        self.version = settings.version

    def generate(self):
        self.write_file("%s\n" % self.version)
