import os
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.p4.event_uid_definition import EventUidDefinition, NoEventDefinition
from zpo.template_graph import TemplateGraph
from zpo.zpo_settings import ZpoSettings

EVENTS_LIST = "@@EVENTS_LIST@@"


class ReadmeFile(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings):
        super().__init__(
            os.path.join(settings.zeek_master_template_dir, "README"),
            os.path.join(settings.zeek_output_dir, "README")
        )

        self.add_marker(EVENTS_LIST, _get_events_list)


def _get_events_list(template_graph: TemplateGraph, _: TemplateBasedFileGenerator) -> str:
    def event_list(event):
        return "- %s" % event.id

    return "\n".join(map(event_list, template_graph.events_by_priority())).strip()
