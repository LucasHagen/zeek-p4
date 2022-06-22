from operator import ne
import os
from typing import Any, List
from zeekscript.script import Script
from zeekscript.node import Node
from zpo.exceptions import ZpoException

IGNORED_ZEEK_EVENTS = [
    "zeek_init"
]


def _get_content(script: Script, node: Node):
    return script.source[node.start_byte:node.end_byte].decode('utf-8')


def _get_id(script: Script, node: Node or Any, nesting):
    if node.type != "event" or not node.is_named:
        raise ZpoException("Node is not a valid event definition node")

    ids: List[Node] = [
        child for child in node.children if child.type == "id" and child.is_named]

    if len(ids) != 1:
        raise ZpoException(
            "Node is not a valid event definition node: no id node found")

    id_node = ids[0]

    return _get_content(script, id_node)


def read_events_from_file(file_path: str):
    script = Script(file_path or '-')

    if not script.parse():
        raise ZpoException("Couldn't parse script '%s'" % file_path)

    events: List[str] = []

    for node, nesting in script.traverse():
        if not node.is_named:
            continue

        if node.type == "event":
            id = _get_id(script, node, nesting)

            if id not in IGNORED_ZEEK_EVENTS:
                events.append(id)

    return events
