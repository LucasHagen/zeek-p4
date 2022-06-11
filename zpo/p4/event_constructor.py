from zpo.model.offloader import OffloaderComponent
from zpo.utils import indent


class EventConstructor:

    def __init__(self, event: OffloaderComponent):
        self.event_uid = event.uid_constant
        self.constructor = event.read_p4_header_constructor()

    def __str__(self):
        return """
if (meta.event_type == %s) {
%s
}
""".strip() % (self.event_uid, indent(self.constructor))
