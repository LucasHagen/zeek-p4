import logging
import os
from re import template

from zpo.exec_graph import ExecGraph
from zpo.file_gen_stats import FileGenerationStats
from zpo.utils import copy_file, copy_tree
from zpo.zeek.changes_file import ChangesFile
from zpo.zeek.cmakelists_file import CMakeListsFile
from zpo.zeek.constants_file import ConstantsFile
from zpo.zeek.offloaders_classes import OffloadersFilesCopier
from zpo.zeek.main_zeek_script import MainZeekFile
from zpo.zeek.plugin_cc_file import PluginCcFile
from zpo.zeek.readme_file import ReadmeFile
from zpo.zeek.version_file import VersionFile
from zpo.zpo_settings import ZpoSettings


class ZeekGenerator:

    def __init__(self, settings: ZpoSettings):
        self.settings: ZpoSettings = settings
        self.master_zeek_template = self.settings.zeek_master_template_dir
        self.output_zeek = self.settings.zeek_output_dir

    def generate_all(self, template_graph: ExecGraph):
        self.stats = FileGenerationStats()

        self.create_zeek_folders()
        self.copy_noedit_files()
        self.generate_constants_file(template_graph)
        self.generate_readme_file(template_graph)
        self.generate_changes_file(template_graph)
        self.copy_offloaders_classes(template_graph)
        self.generate_main_zeek_file(template_graph)
        self.generate_plugin_cc_file(template_graph)
        self.generate_cmakelists_file(template_graph)
        self.generate_version_file()

        return self.stats

    def create_zeek_folders(self):
        if not os.path.exists(self.output_zeek):
            os.makedirs(self.output_zeek)

    def copy_noedit_files(self):
        no_edit = os.path.join(
            self.master_zeek_template,
            "noedit"
        )
        copy_tree(no_edit, self.output_zeek, dirs_exist_ok=True)
        logging.info("Done copying no-edit zeek files")

    def generate_constants_file(self, template_graph: ExecGraph):
        ConstantsFile(self.settings, self.stats).generate(template_graph)

    def generate_readme_file(self, template_graph: ExecGraph):
        ReadmeFile(self.settings, self.stats).generate(template_graph)

    def generate_changes_file(self, template_graph: ExecGraph):
        ChangesFile(self.settings, self.stats).generate(template_graph)

    def copy_offloaders_classes(self, template_graph: ExecGraph):
        OffloadersFilesCopier(self.settings, self.stats).copy_files(template_graph)

    def generate_main_zeek_file(self, template_graph: ExecGraph):
        MainZeekFile(self.settings, self.stats).generate(template_graph)

    def generate_plugin_cc_file(self, template_graph: ExecGraph):
        PluginCcFile(self.settings, self.stats).generate(template_graph)

    def generate_cmakelists_file(self, template_graph: ExecGraph):
        CMakeListsFile(self.settings, self.stats).generate(template_graph)

    def generate_version_file(self):
        VersionFile(self.settings, self.stats).generate()
