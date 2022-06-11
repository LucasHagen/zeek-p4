
import logging
import os
from typing import List
from zpo.model.offloader import OffloaderComponent
from zpo.exec_graph import ExecGraph
from zpo.utils import copy_file
from zpo.zpo_settings import ZpoSettings


class EventsFilesCopier:

    def __init__(self, settings: ZpoSettings):
        self.settings = settings

    def copy_files(self, template_graph: ExecGraph):
        events: List[OffloaderComponent] = template_graph.offloaders_by_priority()

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
