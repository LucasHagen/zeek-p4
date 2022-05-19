import os
from typing import List
from zpo.event_template import EventTemplate
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.template_graph import TemplateGraph
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
        self.set_marker(CC_FILES, _include_ccs)


def _include_ccs(template_graph: TemplateGraph, _: CMakeListsFile) -> str:
    events: List[EventTemplate] = template_graph.events_by_priority()
    files = []

    for event in events:
        event_output_dir = "src/%s" % event.id

        for file in event.zeek_cc_files:
            files.append("%s/%s" % (event_output_dir, file))

    return indent("\n".join(files))
