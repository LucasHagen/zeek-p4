import os
import glob
import hjson

from typing import List

from zpo_compiler.template import Template
from zpo_compiler.protocol_template import ProtocolTemplate
from zpo_compiler.event_template import EventTemplate


def load_templates(paths: List[str]) -> List[Template]:
    """Loads the templates from all

    Args:
        paths (List[str]): paths to folders where templates should be searched for

    Returns:
        List[Template]: A list of templates
    """
    candidates = set()
    for template_root in paths:
        for walk in os.walk(template_root):
            for filepath in glob.glob(os.path.join(walk[0], '*.hjson')):
                candidates.add(os.path.abspath(filepath))

    return [load_template(path) for path in candidates]


def load_template(path: str) -> Template:
    """Loads a template from a .hjson file path

    Args:
        path (str): the path to the .hjson file

    Returns:
        Template: a template (event or protocol)
    """
    with open(path, "r") as file:
        raw_contents = file.read()
        data = hjson.loads(raw_contents)

        if("zpo_type" not in data):
            return None

        if(data["zpo_type"] == "PROTOCOL"):
            return ProtocolTemplate(path, data)
        elif(data["zpo_type"] == "EVENT"):
            return EventTemplate(path, data)
        else:
            raise ValueError(
                f"File ({path}) has wrong 'zpo_type': '{data['zpo_type']}'")
