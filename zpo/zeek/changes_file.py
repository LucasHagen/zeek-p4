import os
from zpo.file_gen_stats import FileGenerationStats
from zpo.file_generator_template import TemplateBasedFileGenerator
from zpo.zpo_settings import ZpoSettings


class ChangesFile(TemplateBasedFileGenerator):

    def __init__(self, settings: ZpoSettings, stats: FileGenerationStats = None):
        super().__init__(
            os.path.join(settings.zeek_master_template_dir, "CHANGES"),
            os.path.join(settings.zeek_output_dir, "CHANGES"),
            stats,
        )
