import os
import glob
import hjson

from typing import List
from zpo.exceptions import ZpoException

from zpo.model.component import Component
from zpo.model.protocol import PROTOCOL_TYPE_STR, ProtocolComponent
from zpo.model.offloader import OFFLOADER_TYPE_STR, OffloaderComponent


def load_templates(paths: List[str]) -> List[Component]:
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


def load_template(path: str) -> Component:
    """Loads a template from a .hjson file path

    Args:
        path (str): the path to the .hjson file

    Returns:
        Component: a component (offloader or protocol)
    """
    with open(path, "r") as file:
        raw_contents = file.read()
        data = hjson.loads(raw_contents)

        if("zpo_type" not in data):
            return None

        if(data["zpo_type"] == PROTOCOL_TYPE_STR):
            return ProtocolComponent(path, data)
        elif(data["zpo_type"] == OFFLOADER_TYPE_STR):
            return OffloaderComponent(path, data)
        else:
            raise ZpoException(
                f"File ({path}) has wrong 'zpo_type': '{data['zpo_type']}'")
