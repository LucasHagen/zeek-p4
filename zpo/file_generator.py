class FileGenerator:
    """A simple file generator that writes a string a file.
    """

    def __init__(self, output_path: str) -> None:
        self.output_path = output_path

    def write_file(self, content: str):
        """Writes the `content` to the `output_path`.

        Args:
            content (str): output file content
        """
        with open(self.output_path, 'w') as file:
            file.write(content)
