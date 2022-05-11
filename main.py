import argparse
import logging
import json
import os
from zpo_compiler.template_tree import TemplateTree
from zpo_compiler.templates import load_templates
from zpo_compiler.zpo_settings import ZpoSettings
from zpo_compiler.protocol_template import ProtocolTemplate
from zpo_compiler.event_template import EventTemplate

CURRENT_VERSION = "0.0.1"

def main():

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

    settings = ZpoSettings(CURRENT_VERSION,
                args.output[0],
                args.event,
                args.template,
                os.getcwd(),
                os.path.dirname(__file__),
                args.debug)

    logging.basicConfig(
        format='[%(levelname)s] %(message)s',
        level=logging.DEBUG if settings.debug else logging.INFO)

    logging.debug(f"Settings: {settings}\n")

    print(f"Starting ZPO for '{settings.output_dir}'\n")

    templates = load_templates(settings.template_folders)

    logging.debug("Templates:")
    logging.debug(f" - Protocols: %s", [t.id for t in templates if type(t) == ProtocolTemplate])
    logging.debug(f" - Events: %s", [t.id for t in templates if type(t) == EventTemplate])

    TemplateTree(settings, templates)

    print("Done!")


if (__name__ == "__main__"):
    main()
