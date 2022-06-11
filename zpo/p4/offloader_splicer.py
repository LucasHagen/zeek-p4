from zpo.model.offloader import OffloaderComponent
from zpo.utils import indent


class OffloaderSplicer:

    def __init__(self, offloader: OffloaderComponent):
        self.offloader_uid = offloader.uid_constant
        self.constructor = offloader.read_p4_header_constructor()

    def __str__(self):
        return """
if (meta.offloader_type == %s) {
%s
}
""".strip() % (self.offloader_uid, indent(self.constructor))
