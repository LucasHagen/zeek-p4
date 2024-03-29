import os
from typing import List
from zpo.model.offloader import OffloaderComponent
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.exec_graph import ExecGraph
from zpo.utils import indent
from zpo.zpo_settings import ZpoSettings

CC_FILES = "@@CC_FILES@@"


class CMakeListsFile(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.zeek_master_template_dir, "CMakeLists.txt"),
            os.path.join(settings.zeek_output_dir, "CMakeLists.txt")
        )

        self.settings: ZpoSettings = settings
        self.add_marker(CC_FILES, _include_ccs)


def _include_ccs(template_graph: ExecGraph, _: CMakeListsFile) -> str:
    offloaders: List[OffloaderComponent] = template_graph.offloaders_by_priority()
    files = []

    for offloader in offloaders:
        offloader_output_dir = "src/%s" % offloader.id

        for file in offloader.zeek_cc_files:
            files.append("%s/%s" % (offloader_output_dir, file))

    return indent("\n".join(files))
