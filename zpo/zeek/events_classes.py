
import logging
import os
from typing import List
from zpo.event_template import EventTemplate
from zpo.template_graph import TemplateGraph
from zpo.utils import copy_file
from zpo.zpo_settings import ZpoSettings


class EventsFilesCopier:

    def __init__(self, settings: ZpoSettings):
        self.settings = settings

    def copy_files(self, template_graph: TemplateGraph):
        events: List[EventTemplate] = template_graph.events_by_priority()

        for event in events:
            event_template_dir = event.path_dir
            event_output_dir = os.path.join(
                self.settings.zeek_output_dir,
                "src",
                event.id
            )

            os.mkdir(event_output_dir)

            for file in event.zeek_files:
                copy_file(
                    os.path.join(event_template_dir, file),
                    os.path.join(event_output_dir, file)
                )
                logging.debug(" - Copied file: %s -> %s" %
                              (os.path.join(event_template_dir, file),
                               os.path.join(event_output_dir, file)))

        logging.info("Copied all C++ files from event templates.")
