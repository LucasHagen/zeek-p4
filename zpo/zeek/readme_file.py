import os
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.model.offloader import OffloaderComponent
from zpo.p4.offloader_uid_definition import OffloaderUidDefinition, NoOffloaderDefinition
from zpo.exec_graph import ExecGraph
from zpo.zpo_settings import ZpoSettings

OFFLOADERS_LIST = "@@OFFLOADERS_LIST@@"
OFFLOADED_EVENTS_LIST = "@@OFFLOADED_EVENTS_LIST@@"


class ReadmeFile(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.zeek_master_template_dir, "README"),
            os.path.join(settings.zeek_output_dir, "README")
        )

        self.add_marker(OFFLOADERS_LIST, _get_offloaders_list)
        self.add_marker(OFFLOADED_EVENTS_LIST, _get_offloaded_events)


def _get_offloaders_list(graph: ExecGraph, _: TemplateBasedFileGenerator) -> str:
    def offloader_list(o: OffloaderComponent):
        return "- %s" % o.id

    return "\n".join(map(offloader_list, graph.offloaders_by_priority())).strip()


def _get_offloaded_events(graph: ExecGraph, _: TemplateBasedFileGenerator) -> str:
    events = []

    for offloader in graph.offloaders_by_priority():
        for event in offloader.zeek_offloaded_events:
            events.append(f"- {event}")

    return "\n".join(events).strip()
