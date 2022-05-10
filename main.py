import argparse
import logging
import json
import os
from zpo_compiler.template_tree import TemplateTree
from zpo_compiler.templates import load_templates
from zpo_compiler.zpo_settings import ZPO_ARGS
from zpo_compiler.protocol_template import ProtocolTemplate
from zpo_compiler.event_template import EventTemplate

def main():
    global ZPO_ARGS

    parser = argparse.ArgumentParser(
        description="Process and compile a Zeek-P4 Offloader (ZPO).")
    parser.add_argument("-d", "--debug", help="enable debug mode",
                        action="store_true")
    parser.add_argument("-t", "--template", type=str, action="append",
                        help="template folders", default=[])
    parser.add_argument("output", nargs=1, metavar="OUTPUT", type=str,
                        help="output folder.")
    parser.add_argument("event", nargs="+", metavar="EVENT",
                        help="Event(s) of interrest, which will be offloaded.")

    args = parser.parse_args()

    ZPO_ARGS["output"] = args.output[0]
    ZPO_ARGS["events"] = args.event
    ZPO_ARGS["template_folders"] = args.template
    ZPO_ARGS["debug"] = args.debug
    ZPO_ARGS["pwd"] = os.getcwd()
    ZPO_ARGS["main_py"] = os.path.dirname(__file__)

    logging.basicConfig(
        format='[%(levelname)s] %(message)s',
        level=logging.DEBUG if ZPO_ARGS["debug"] else logging.INFO)

    logging.debug(f"ZPO_ARGS: {json.dumps(ZPO_ARGS, indent=4)}\n")

    print(f"Starting ZPO for '{ZPO_ARGS['output']}'\n")

    templates = load_templates(ZPO_ARGS["template_folders"])

    logging.debug("Templates:")
    logging.debug(f" - Protocols: %s", [t.id for t in templates if type(t) == ProtocolTemplate])
    logging.debug(f" - Events: %s", [t.id for t in templates if type(t) == EventTemplate])

    TemplateTree(templates)

    print("Done!")


if (__name__ == "__main__"):
    main()
