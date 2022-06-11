import os
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.p4.event_uid_definition import EventUidDefinition, NoEventDefinition
from zpo.exec_graph import ExecGraph
from zpo.zpo_settings import ZpoSettings

EVENT_IDS = "@@EVENT_IDS@@"
VERSION_CONSTANTS = "@@VERSION_CONSTANTS@@"


class ConstantsFile(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.zeek_master_template_dir, "constants.h"),
            os.path.join(settings.zeek_output_dir, "src/constants.h")
        )

        self.settings: ZpoSettings = settings
        self.add_marker(EVENT_IDS, _get_event_ids)
        self.add_marker(VERSION_CONSTANTS, _get_version_constants)


def _get_event_ids(template_graph: ExecGraph, _: ConstantsFile) -> str:
    events_uids = [str(NoEventDefinition())]
    events_uids = events_uids + list(map(
        lambda e: str(EventUidDefinition(e)),
        template_graph.offloaders_by_priority())
    )

    return "\n".join(events_uids).strip()


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
