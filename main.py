import argparse
import logging
import json
import os
from zpo.zpo import Zpo
from zpo.zpo_settings import ZpoSettings
from zpo.protocol_template import ProtocolTemplate
from zpo.event_template import EventTemplate

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
                args.debug)

    logging.basicConfig(
        format='[%(levelname)s] %(message)s',
        level=logging.DEBUG if settings.debug else logging.INFO)

    zpo = Zpo(settings)

    zpo.run()


if (__name__ == "__main__"):
    main()
