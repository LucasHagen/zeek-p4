import os


class Template:
    """A class for templates for events and protocols
    """

    def read_p4_header(self) -> str:
        """Reads the P4 header file for the template.

        Raises:
            ValueError: file not found

        Returns:
            str: file content
        """
        if not os.path.exists(self.header_file_path):
            raise ValueError("P4 header file (%s) not found for protocol template %s" % (
                self.header_file_path, self.id))


        with open(self.header_file_path, 'r') as file:
            return "\n".join([
                f"// Header for {self.type_str()} template '{self.id}':",
                "",
                file.read().strip(),
                ""
            ])

    def type_str(self) -> str:
        """Returns a readable string of the type of the template.

        Returns:
            str: template readable type
        """
        pass
