import logging
import os
from typing import Iterable, List
from zpo.p4.headers_file import HeadersFileGenerator
from zpo.p4.headers_struct import HeadersStruct
from zpo.p4.main_p4_file import MainP4FileGenerator
from zpo.p4.parser_file import ParserFileGenerator

from zpo.p4.parser_state import ParserState
from zpo.template import Template
from zpo.template_graph import TemplateGraph
from zpo.utils import lmap
from zpo.zpo_settings import ZpoSettings


class P4Generator:

    def __init__(self, settings: ZpoSettings):
        self.settings: ZpoSettings = settings
        self.master_p4_template = self.settings.p4_master_template_dir
        self.output_p4 = self.settings.p4_output_dir

    def generate_all(self, template_graph: TemplateGraph):
        self.create_p4_folders()
        self.generate_headers(template_graph)
        self.generate_parser(template_graph)
        self.generate_main_p4(template_graph)

    def create_p4_folders(self):
        if not os.path.exists(self.output_p4):
            os.makedirs(self.output_p4)

    def generate_headers(self, template_graph: TemplateGraph):
        HeadersFileGenerator(self.settings).generate(template_graph)

    def generate_parser(self, template_graph: TemplateGraph):
        ParserFileGenerator(self.settings).generate(template_graph)

    def generate_main_p4(self, template_graph: TemplateGraph):
        MainP4FileGenerator(self.settings).generate(template_graph)
