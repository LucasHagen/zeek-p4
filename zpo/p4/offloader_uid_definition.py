from zpo.model.offloader import OffloaderComponent


class NoOffloaderDefinition:

    def __str__(self):
        return "#define RNA_NO_OFFLOADER_UID 0"


class OffloaderUidDefinition:

    def __init__(self, offloader: OffloaderComponent):
        self.name = offloader.uid_constant
        self.uid = offloader.uid

    def __str__(self):
        return "#define %s %s" % (self.name, self.uid)
