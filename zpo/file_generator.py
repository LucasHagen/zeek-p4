class FileGenerator:

    def __init__(self, output_path) -> None:
        self.output_path = output_path

    def write_file(self, content):
        with open(self.output_path, 'w') as file:
            file.write(content)
