import os

from zpo.exceptions import BadConfigException, ZpoException


class Component:
    """A class to represent a ZPO component. Either a parser or an offloader.
    """

    def __init__(self, path, hjson_data):
        self.path = path
        self.path_dir = os.path.dirname(self.path)
        self._data = hjson_data

        self.id = self.read_data("id")
        self.version = self.read_data("zpo_version")

    def read_data(self, *ids: str, convert=lambda x: x):
        """Reads the variable at [ids] from the hjson data.

        If one or more ids are not found, an exception is raised.

        Args:
            convert (lambda, optional): applies to the final value before returned
        """
        value = None
        for index, id in enumerate(ids):
            source = self._data if index == 0 else value

            if id not in source:
                raise BadConfigException(self.path, ids)

            value = source[id]

        return convert(value)

    def read_rel_path_data(self, *ids: str) -> str:
        """Reads the path at ids and makes it relative to the hjson config file.

        If one or more ids are not found, an exception is raised.

        Args:
            convert (lambda, optional): applies to the final value before returned
        """
        return os.path.join(self.path_dir, self.read_data(*ids))

    def read_opt_data(self, *ids: str, convert=lambda x: x, convert_if_none=True):
        """Reads the variable at [ids] from the hjson data.

        If one or more ids are not found, None is returned.

        Args:
            convert (lambda, optional): applies to the final value before returned
        """
        value = None
        for index, id in enumerate(ids):
            source = self._data if index == 0 else value

            if id not in source:
                value = None
                break

            value = source[id]

        return value if value is None and not convert_if_none else convert(value)

    def read_opt_rel_path_data(self, *ids: str) -> str:
        """Reads the path at ids and makes it relative to the hjson config file.

        If one or more ids are not found, None is returned.

        Args:
            convert (lambda, optional): applies to the final value before returned
        """
        rel_path = self.read_opt_data(*ids)
        return None if rel_path is None else os.path.join(self.path_dir, rel_path)

    def read_p4_header(self) -> str:
        """Reads the P4 header file for the component.

        Raises:
            ZpoException: file not found

        Returns:
            str: file content
        """
        if not os.path.exists(self.header_file_path):
            raise ZpoException("P4 header file (%s) not found for protocol template %s" % (
                self.header_file_path, self.id))

        with open(self.header_file_path, 'r') as file:
            return file.read().strip()

    def type_str(self) -> str:
        """Returns a readable string of the type of the template.

        Returns:
            str: template readable type
        """
        pass

    def compute_hash(self) -> bytes:
        """Computes and returns the hash of this template. If the hash has
        already been computed once, it will be cached.
        """
        pass
