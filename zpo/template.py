import os


class Template:
    """A class for templates for events and protocols
    """

    def read_p4_header(self) -> str:
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
