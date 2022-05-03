from ntpath import join
import os
import glob
import hjson

from protocol_template import ProtocolTemplate
from event_template import EventTemplate

def load_templates(paths):
    candidates = []
    for template_root in paths:
        for walk in os.walk(template_root):
            for filepath in glob.glob(os.path.join(walk[0], '*.hjson')):
                candidates.append(filepath)

    return [load_template(path) for path in candidates]

def load_template(path):
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
            raise ValueError(f"File ({path}) has wrong 'zpo_type': '{data['zpo_type']}'")
