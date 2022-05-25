import logging
import shutil
import os
from zpo.event_template import EventTemplate
from zpo.p4.p4_generator import P4Generator
from zpo.protocol_template import ProtocolTemplate
from zpo.template_graph import TemplateGraph
from zpo.templates import load_templates
from zpo.utils import is_dir_empty
from zpo.zeek.zeek_generator import ZeekGenerator

from zpo.zpo_settings import ZpoSettings


class Zpo:

    def __init__(self, settings: ZpoSettings):
        self.settings = settings

    def run(self):
        logging.debug(f"Settings: {self.settings}\n")

        if not self.check_output_dir():
            return

        logging.info(f"Starting ZPO for '{self.settings.output_dir}'\n")

        templates = load_templates(self.settings.template_folders)

        logging.debug("Templates:")
        logging.debug(f" - Protocols: %s",
                      [t.id for t in templates if type(t) == ProtocolTemplate])
        logging.debug(f" - Events: %s",
                      [t.id for t in templates if type(t) == EventTemplate])

        template_graph = TemplateGraph(self.settings, templates)
        template_graph.build()
        template_graph.print_tree()

        p4_generator: P4Generator = P4Generator(self.settings)
        p4_generator.generate_all(template_graph)

        zeek_generator: ZeekGenerator = ZeekGenerator(self.settings)
        zeek_generator.generate_all(template_graph)

        logging.info("Execution hash: %s" % template_graph.compute_hash_hex())

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
