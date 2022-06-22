import argparse
import logging
import json
import os
from zpo.read_events import read_events_from_file
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
                        help="zeek script file", default=[])
    parser.add_argument("output", nargs=1, metavar="OUTPUT", type=str,
                        help="output folder.")
    parser.add_argument("offloader", nargs="+", metavar="OFFLOADER",
                        help="Offloaders that will be active.")
    parser.add_argument("-o", "--override", help="overrides output dir, if it exists",
                        action="store_true")

    args = parser.parse_args()

    settings = ZpoSettings(CURRENT_VERSION,
                args.output[0],
                args.offloader,
                args.template,
                os.getcwd(),
                args.debug,
                args.override)

    logging.basicConfig(
        format='[%(levelname)s] %(message)s',
        level=logging.DEBUG if settings.debug else logging.INFO)


    if len(args.script) > 0:
        events = set()

        for script_path in args.script:
            try:
                for e in read_events_from_file(script_path):
                    events.add(e)
            except:
                continue

        print(events)
        return

    zpo = Zpo(settings)

    zpo.run()


if (__name__ == "__main__"):
    main()
