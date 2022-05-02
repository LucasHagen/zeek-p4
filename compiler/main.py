import argparse
import json


ZPO_ARGS = {
    "output": 'output',
    "events": [],
    "template_folders": [],
    "debug": False,
}


def main():
    parser = argparse.ArgumentParser(
        description="Process and compile a Zeek-P4 Offloader (ZPO).")
    parser.add_argument("-d", "--debug", help="enable debug mode",
                        action="store_true")
    parser.add_argument("-t", "--template", type=str, action="append",
                        help="template folders")
    parser.add_argument("output", nargs=1, metavar="OUTPUT", type=str,
                        help="output folder.")
    parser.add_argument("event", nargs="+", metavar="EVENT",
                        help="Event(s) of interrest, which will be offloaded.")

    args = parser.parse_args()

    ZPO_ARGS["output"] = args.output[0]
    ZPO_ARGS["events"] = args.event
    ZPO_ARGS["template_folders"] = args.template
    ZPO_ARGS["debug"] = args.debug

    if (ZPO_ARGS["debug"]):
        print(f"ZPO_ARGS: {json.dumps(ZPO_ARGS, indent=4)}\n")

    print(f"Starting ZPO for '{ZPO_ARGS['output']}':")


if (__name__ == "__main__"):
    main()
