import os
from zpo.model.offloader import OffloaderComponent
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.exec_graph import ExecGraph
from zpo.utils import indent
from zpo.zpo_settings import ZpoSettings

REGISTER_OFFLOADERS = "@@REGISTER_OFFLOADERS@@"


class MainZeekFile(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.zeek_master_template_dir, "main.zeek"),
            os.path.join(
                settings.zeek_output_dir,
                "scripts",
                "BR_UFRGS_INF",
                "RNA",
                "main.zeek")
        )

        self.settings: ZpoSettings = settings
        self.add_marker(REGISTER_OFFLOADERS, _get_register_offloaders)


def _register_offloader(offloader: OffloaderComponent):
    return """
PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_RNA_OFFLOADER, %d, PacketAnalyzer::ANALYZER_%s);
""".strip() % (offloader.uid, offloader.zeek_analyzer_id)


def _get_register_offloaders(template_graph: ExecGraph, _: MainZeekFile) -> str:
    return indent("\n".join(map(
        _register_offloader,
        template_graph.offloaders_by_priority()
    )))
