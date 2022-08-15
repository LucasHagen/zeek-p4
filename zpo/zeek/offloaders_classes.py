
import logging
import os
from typing import List
from zpo.file_gen_stats import FileGenerationStats
from zpo.model.offloader import OffloaderComponent
from zpo.exec_graph import ExecGraph
from zpo.utils import copy_file
from zpo.zpo_settings import ZpoSettings


class OffloadersFilesCopier:

    def __init__(self, settings: ZpoSettings, stats: FileGenerationStats = None):
        self.settings = settings
        self.stats = stats

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

                self.stats.auto_increament_offloader_template(
                    _read_file(os.path.join(offloader_template_dir, file))
                )

                logging.debug(" - Copied file: %s -> %s" %
                              (os.path.join(offloader_template_dir, file),
                               os.path.join(offloader_output_dir, file)))

        logging.info("Copied all C++ files from offloader templates.")


def _read_file(path) -> str:
    with open(path, 'r') as file:
        return file.read()
