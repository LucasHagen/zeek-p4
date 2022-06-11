class ZpoException(Exception):

    def __init__(self, *args: object):
        super().__init__(*args)


class BadConfigException(ZpoException):

    def __init__(self, config: str, *ids: str):
        super().__init__(
            "Bad configuration file. Key '%s' not found in file '%s'" % (
                ".".join(ids), config
            )
        )
