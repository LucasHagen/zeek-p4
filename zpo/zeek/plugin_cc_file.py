import os
from typing import List
from zpo.model.offloader import OffloaderComponent
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.p4.offloader_uid_definition import OffloaderUidDefinition, NoOffloaderDefinition
from zpo.exec_graph import ExecGraph
from zpo.utils import indent
from zpo.zpo_settings import ZpoSettings

INCLUDE_ANALYZERS = "@@INCLUDE_ANALYZERS@@"
REGISTER_ANALYZERS = "@@REGISTER_ANALYZERS@@"


class PluginCcFile(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.zeek_master_template_dir, "Plugin.cc"),
            os.path.join(
                settings.zeek_output_dir,
                "src",
                "Plugin.cc")
        )

        self.settings: ZpoSettings = settings
        self.add_marker(INCLUDE_ANALYZERS, _include_analyzers)
        self.add_marker(REGISTER_ANALYZERS, _register_analyzers)


def _include_analyzers(graph: ExecGraph, _: PluginCcFile) -> str:
    offloaders: List[OffloaderComponent] = graph.offloaders_by_priority()
    files = []

    for offloader in offloaders:
        for file in offloader.zeek_header_files:
            files.append("#include \"%s/%s\"" % (offloader.id, file))

    return "\n".join(files)


def _register_analyzers(graph: ExecGraph, _: PluginCcFile) -> str:
    def _register_analyzer(offloader: OffloaderComponent):
        return """
AddComponent(new zeek::packet_analysis::Component(
    "%s", %s::%s::Instantiate));
""".strip() % (offloader.zeek_analyzer_id, offloader.zeek_analyzer_namespace, offloader.zeek_analyzer_class)

    return indent("\n".join(map(_register_analyzer, graph.offloaders_by_priority())))
