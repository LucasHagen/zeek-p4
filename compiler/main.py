import argparse
import json
import os
from templates import load_templates
from zpo_settings import ZPO_ARGS
from protocol_template import ProtocolTemplate
from event_template import EventTemplate

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

    DEBUG = ZPO_ARGS["debug"]

    if (DEBUG):
        print(f"ZPO_ARGS: {json.dumps(ZPO_ARGS, indent=4)}\n")

    print(f"Starting ZPO for '{ZPO_ARGS['output']}':")

    templates = load_templates(ZPO_ARGS["template_folders"])

    if DEBUG:
        print("Templates:")
        print(f" - Protocols:", [t.id for t in templates if type(t) == ProtocolTemplate])
        print(f" - Events:", [t.id for t in templates if type(t) == EventTemplate])



if (__name__ == "__main__"):
    main()
