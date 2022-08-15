from ..file_gen_stats import FileGenerationStats
from zpo.model.offloader import OffloaderComponent
from zpo.utils import indent


class OffloaderSplicer:

    def __init__(self, offloader: OffloaderComponent, stats: FileGenerationStats = None):
        self.offloader_uid = offloader.uid_constant
        self.constructor = offloader.read_p4_header_constructor()

        stats.auto_increament_offloader_template(self.constructor)
        stats.increament_generated(2) # if lines

    def __str__(self):
        return """
if (meta.offloader_type == %s) {
%s
}
""".strip() % (self.offloader_uid, indent(self.constructor))
