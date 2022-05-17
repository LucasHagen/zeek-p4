from zpo.event_template import EventTemplate


class NoEventDefinition:

    def __str__(self):
        return "#define ZPO_NO_EVENT_UID 0"


class EventUidDefinition:

    def __init__(self, event: EventTemplate):
        self.event_uid = event.uid
        self.event_id = event.uid_constant

    def __str__(self):
        return "#define %s %s" % (self.event_id, self.event_uid)
