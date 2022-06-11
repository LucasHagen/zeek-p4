from zpo.model.offloader import OffloaderComponent


class NoEventDefinition:

    def __str__(self):
        return "#define RNA_NO_EVENT_UID 0"


class EventUidDefinition:

    def __init__(self, event: OffloaderComponent):
        self.event_uid = event.uid
        self.event_id = event.uid_constant

    def __str__(self):
        return "#define %s %s" % (self.event_id, self.event_uid)
