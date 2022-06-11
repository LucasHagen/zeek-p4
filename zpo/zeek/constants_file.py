import os
from zpo.exceptions import ZpoException
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.p4.offloader_uid_definition import OffloaderUidDefinition, NoOffloaderDefinition
from zpo.exec_graph import ExecGraph
from zpo.zpo_settings import ZpoSettings

OFFLODER_IDS = "@@OFFLOADER_IDS@@"
VERSION_CONSTANTS = "@@VERSION_CONSTANTS@@"


class ConstantsFile(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.zeek_master_template_dir, "constants.h"),
            os.path.join(settings.zeek_output_dir, "src/constants.h")
        )

        self.settings: ZpoSettings = settings
        self.add_marker(OFFLODER_IDS, _get_offloader_ids)
        self.add_marker(VERSION_CONSTANTS, _get_version_constants)


def _get_offloader_ids(template_graph: ExecGraph, _: ConstantsFile) -> str:
    offloader_uids = [str(NoOffloaderDefinition())]
    offloader_uids = offloader_uids + list(map(
        lambda e: str(OffloaderUidDefinition(e)),
        template_graph.offloaders_by_priority())
    )

    return "\n".join(offloader_uids).strip()


def _get_version_constants(_: ExecGraph, generator: ConstantsFile) -> str:
    version = generator.settings.version
    version_array = version.split(".")

    if len(version_array) != 3:
        raise ZpoException(f"Version in invalid format (X.X.X): '{version}'")

    return """
#define RNA_VERSION "%s"
#define RNA_VERSION_1 %d
#define RNA_VERSION_2 %d
#define RNA_VERSION_3 %d
""".strip() % (version, int(version_array[0]), int(version_array[1]), int(version_array[2]))
