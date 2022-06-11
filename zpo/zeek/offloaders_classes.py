
import logging
import os
from typing import List
from zpo.model.offloader import OffloaderComponent
from zpo.exec_graph import ExecGraph
from zpo.utils import copy_file
from zpo.zpo_settings import ZpoSettings


class OffloadersFilesCopier:

    def __init__(self, settings: ZpoSettings):
        self.settings = settings

    def copy_files(self, template_graph: ExecGraph):
        offloaders: List[OffloaderComponent] = template_graph.offloaders_by_priority()

        for offloader in offloaders:
            offloader_template_dir = offloader.path_dir
            offloader_output_dir = os.path.join(
                self.settings.zeek_output_dir,
                "src",
                offloader.id
            )

            os.mkdir(offloader_output_dir)

            for file in offloader.zeek_files:
                copy_file(
                    os.path.join(offloader_template_dir, file),
                    os.path.join(offloader_output_dir, file)
                )
                logging.debug(" - Copied file: %s -> %s" %
                              (os.path.join(offloader_template_dir, file),
                               os.path.join(offloader_output_dir, file)))

        logging.info("Copied all C++ files from offloader templates.")
