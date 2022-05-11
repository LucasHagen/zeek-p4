import logging
from zpo.event_template import EventTemplate
from zpo.protocol_template import ProtocolTemplate
from zpo.template_tree import TemplateTree
from zpo.templates import load_templates

from zpo.zpo_settings import ZpoSettings


class Zpo:

    def __init__(self, settings: ZpoSettings):
        self.settings = settings

    def run(self):
        logging.debug(f"Settings: {self.settings}\n")

        logging.info(f"Starting ZPO for '{self.settings.output_dir}'\n")

        templates = load_templates(self.settings.template_folders)

        logging.debug("Templates:")
        logging.debug(f" - Protocols: %s",
                      [t.id for t in templates if type(t) == ProtocolTemplate])
        logging.debug(f" - Events: %s",
                      [t.id for t in templates if type(t) == EventTemplate])

        TemplateTree(self.settings, templates)

        logging.info("Done!")
