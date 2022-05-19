import logging
import os
from re import template

from zpo.template_graph import TemplateGraph
from zpo.utils import copy_file, copy_tree
from zpo.zeek.changes_file import ChangesFile
from zpo.zeek.constants_file import ConstantsFile
from zpo.zeek.events_classes import EventsFilesCopier
from zpo.zeek.main_zeek_script import MainZeekFile
from zpo.zeek.plugin_cc_file import PluginCcFile
from zpo.zeek.readme_file import ReadmeFile
from zpo.zpo_settings import ZpoSettings


class ZeekGenerator:

    def __init__(self, settings: ZpoSettings):
        self.settings: ZpoSettings = settings
        self.master_zeek_template = self.settings.zeek_master_template_dir
        self.output_zeek = self.settings.zeek_output_dir

    def generate_all(self, template_graph: TemplateGraph):
        self.create_zeek_folders()
        self.copy_noedit_files()
        self.generate_constants_file(template_graph)
        self.generate_readme_file(template_graph)
        self.generate_changes_file(template_graph)
        self.copy_events_classes(template_graph)
        self.generate_main_zeek_file(template_graph)
        self.generate_plugin_cc_file(template_graph)

    def create_zeek_folders(self):
        if not os.path.exists(self.settings.output_dir):
            os.mkdir(self.settings.output_dir)

        if not os.path.exists(self.output_zeek):
            os.mkdir(self.output_zeek)

    def copy_noedit_files(self):
        no_edit = os.path.join(
            self.master_zeek_template,
            "noedit"
        )
        copy_tree(no_edit, self.output_zeek, dirs_exist_ok=True)
        logging.info("Done coping no-edit zeek files")

    def generate_constants_file(self, template_graph: TemplateGraph):
        ConstantsFile(self.settings).generate(template_graph)

    def generate_readme_file(self, template_graph: TemplateGraph):
        ReadmeFile(self.settings).generate(template_graph)

    def generate_changes_file(self, template_graph: TemplateGraph):
        ChangesFile(self.settings).generate(template_graph)

    def copy_events_classes(self, template_graph: TemplateGraph):
        EventsFilesCopier(self.settings).copy_files(template_graph)

    def generate_main_zeek_file(self, template_graph):
        MainZeekFile(self.settings).generate(template_graph)

    def generate_plugin_cc_file(self, template_graph):
        PluginCcFile(self.settings).generate(template_graph)
