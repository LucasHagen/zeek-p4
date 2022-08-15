import logging
import shutil
import os
from zpo.model.offloader import OffloaderComponent
from zpo.model.protocol import ProtocolComponent
from zpo.exec_graph import ExecGraph
from zpo.templates import load_templates
from zpo.utils import is_dir_empty
from zpo.p4.p4_generator import P4Generator
from zpo.zeek.zeek_generator import ZeekGenerator

from zpo.zpo_settings import ZpoSettings


class Zpo:

    def __init__(self, settings: ZpoSettings):
        self.settings = settings

    def run(self):
        logging.debug(f"Settings: {self.settings}\n")

        if not self.check_output_dir():
            return

        logging.info(f"Starting ZPO for '{self.settings.output_dir}'")

        templates = load_templates(self.settings.template_folders)

        logging.debug("Templates:")
        logging.debug(f" - Protocols: %s",
                      [t.id for t in templates if type(t) == ProtocolComponent])
        logging.debug(f" - Offloaders: %s",
                      [t.id for t in templates if type(t) == OffloaderComponent])

        graph = ExecGraph(self.settings, templates)
        graph.build()
        graph.print_tree()

        p4_generator = P4Generator(self.settings)
        p4_stats = p4_generator.generate_all(graph)

        zeek_generator = ZeekGenerator(self.settings)
        zeek_stats = zeek_generator.generate_all(graph)

        logging.debug(f"Gen stats: {p4_stats.merged_with(zeek_stats)}")

        logging.info("Execution hash: %s" % graph.compute_hash_hex())

        logging.info("Done!")

    def check_output_dir(self) -> bool:
        if os.path.exists(self.settings.output_dir):
            if (not self.settings.override) and (not os.path.isdir(self.settings.output_dir) or not is_dir_empty(self.settings.output_dir)):
                logging.error(
                    "Output path '%s' already exists. If you want to override ir, use '-o' or '--override'." % self.settings.output_dir)
                return False
            else:
                if os.path.isdir(self.settings.output_dir):
                    shutil.rmtree(os.path.join(self.settings.output_dir))
                else:
                    os.remove(self.settings.output_dir)

        return True
