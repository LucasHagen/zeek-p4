from typing import List

from zpo_compiler.p4.parser_state import ParserState

PARSING_STATE_MARKER = "@@PARSING_STATES@@"


def generate_parser(master_parser_template_path: str, output_path: str, parser_states: List[ParserState]):
    required_markers = [PARSING_STATE_MARKER]

    content = ""
    with open(master_parser_template_path, 'r') as file:
        content = file.read()

    for marker in required_markers:
        if marker not in content:
            raise ValueError(f"Marker '{marker}' not found in parser template")

    content.replace(PARSING_STATE_MARKER, "\n".join([str(state) for state in parser_states]))

    with open(output_path, 'w') as file:
        file.write(content)
