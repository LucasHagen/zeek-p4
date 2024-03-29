import os
from zpo.p4.headers_file import HeadersFileGenerator
from zpo.p4.main_p4_file import MainP4FileGenerator
from zpo.p4.parser_file import ParserFileGenerator

from zpo.exec_graph import ExecGraph
from zpo.utils import lmap
from zpo.zpo_settings import ZpoSettings


class P4Generator:

    def __init__(self, settings: ZpoSettings):
        self.settings: ZpoSettings = settings
        self.master_p4_template = self.settings.p4_master_template_dir
        self.output_p4 = self.settings.p4_output_dir

    def generate_all(self, template_graph: ExecGraph):
        self.create_p4_folders()
        self.generate_headers(template_graph)
        self.generate_parser(template_graph)
        self.generate_main_p4(template_graph)

    def create_p4_folders(self):
        if not os.path.exists(self.output_p4):
            os.makedirs(self.output_p4)

    def generate_headers(self, template_graph: ExecGraph):
        HeadersFileGenerator(self.settings).generate(template_graph)

    def generate_parser(self, template_graph: ExecGraph):
        ParserFileGenerator(self.settings).generate(template_graph)

    def generate_main_p4(self, template_graph: ExecGraph):
        MainP4FileGenerator(self.settings).generate(template_graph)
