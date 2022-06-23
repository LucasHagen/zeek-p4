import argparse
import logging
import json
import os
from typing import List

from pkg_resources import require
from zpo.exceptions import ZpoException
from zpo.script_interpreter import read_events_from_script
from zpo.zpo import Zpo
from zpo.zpo_settings import ZpoSettings

CURRENT_VERSION = "0.0.1"


def main():

    parser = argparse.ArgumentParser(
        description="Process and compile a Zeek-P4 Offloader (ZPO).")
    parser.add_argument("-d", "--debug", help="enable debug mode",
                        action="store_true")
    parser.add_argument("-t", "--template", type=str, action="append",
                        help="template folders", default=[])
    parser.add_argument("-s", "--script", type=str, action="append",
                        help="zeek script file to be supported", default=[])
    parser.add_argument("output", nargs=1, metavar="OUTPUT", type=str,
                        help="output folder.")
    parser.add_argument("offloader", nargs="*", metavar="OFFLOADER",
                        help="Offloaders that will be active.")
    parser.add_argument("-o", "--override", help="overrides output dir, if it exists",
                        action="store_true")

    args = parser.parse_args()

    logging.basicConfig(
        format='[%(levelname)s] %(message)s',
        level=logging.DEBUG if args.debug else logging.INFO)

    settings = ZpoSettings(CURRENT_VERSION,
                           args.output[0],
                           args.offloader,
                           # Also add current folder
                           args.template + [os.getcwd()],
                           _read_required_events(args.script),
                           os.getcwd(),
                           args.debug,
                           args.override)

    zpo = Zpo(settings)

    zpo.run()


def _read_required_events(scripts: List[str]):
    required_events = set()

    logging.debug("Reading scripts to check which events are required")

    for script_path in scripts:
        required_events |= set(read_events_from_script(script_path))

    return required_events


if (__name__ == "__main__"):
    main()
