from zpo.file_gen_stats import FileGenerationStats


class FileGenerator:
    """A simple file generator that writes a string a file.
    """

    def __init__(self, output_path: str, stats: FileGenerationStats = None) -> None:
        self.output_path = output_path
        self.stats = stats

    def write_file(self, content: str):
        """Writes the `content` to the `output_path`.

        Args:
            content (str): output file content
        """
        with open(self.output_path, 'w') as file:
            file.write(content)
