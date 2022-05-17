import logging
import os

from zpo.template_graph import TemplateGraph
from zpo.zpo_settings import ZpoSettings


class ZeekGenerator:

    def __init__(self, settings: ZpoSettings):
        self.settings: ZpoSettings = settings
        self.master_zeek_template = self.settings.zeek_master_template_dir
        self.output_zeek = self.settings.zeek_output_dir

    def generate_all(self, template_graph: TemplateGraph):
        self.create_zeek_folders()
        pass

    def create_zeek_folders(self):
        if not os.path.exists(self.settings.output_dir):
            os.mkdir(self.settings.output_dir)

        if not os.path.exists(self.output_zeek):
            os.mkdir(self.output_zeek)
