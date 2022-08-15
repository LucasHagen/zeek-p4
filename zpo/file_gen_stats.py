from ast import List
import json


class FileGenerationStats:

    def __init__(self,
                 master_template_lines: int = 0,
                 protocol_template_lines: int = 0,
                 offloader_template_lines: int = 0,
                 generated_lines: int = 0,
                 ):
        self.master_template_lines = master_template_lines
        self.protocol_template_lines = protocol_template_lines
        self.offloader_template_lines = offloader_template_lines
        self.generated_lines = generated_lines

    def increament_master_template(self, increament=1):
        self.master_template_lines += increament

    def increament_protocol_template(self, increament=1):
        self.protocol_template_lines += increament

    def increament_offloader_template(self, increament=1):
        self.offloader_template_lines += increament

    def increament_generated(self, increament=1):
        self.generated_lines += increament

    def auto_increament_master_template(self, lines: str or List[str], mult: int = 1):
        self.master_template_lines += (_count_lines(lines) * mult)

    def auto_increament_protocol_template(self, lines: str or List[str], mult: int = 1):
        self.protocol_template_lines += (_count_lines(lines) * mult)

    def auto_increament_offloader_template(self, lines: str or List[str], mult: int = 1):
        self.offloader_template_lines += (_count_lines(lines) * mult)

    def auto_increament_generated(self, lines: str or List[str], mult: int = 1):
        self.generated_lines += (_count_lines(lines) * mult)

    def merged_with(self, other):
        """Creates a new instance with data merged from this stats with the other.
        """
        return FileGenerationStats(
            self.master_template_lines + other.master_template_lines,
            self.protocol_template_lines + other.protocol_template_lines,
            self.offloader_template_lines + other.offloader_template_lines,
            self.generated_lines + other.generated_lines,
        )

    def __str__(self):
        return json.dumps(
            {
                "generated_lines": self.generated_lines,
                "master_template_lines": self.master_template_lines,
                "protocol_template_lines": self.protocol_template_lines,
                "offloader_template_lines": self.offloader_template_lines,
                "total": self.generated_lines + self.master_template_lines + self.protocol_template_lines + self.offloader_template_lines,
            }, indent=4)


def _count_lines(lines: str or List[str]) -> int:
    if type(lines) == str:
        return len(lines.splitlines())

    count = 0
    for part in lines:
        count += len(part.splitlines())

    return count
