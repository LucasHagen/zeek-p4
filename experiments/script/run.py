#!/usr/bin/env python3

import os
import sys
import time
import psutil
import signal
import logging
import argparse
import datetime
import subprocess

SCRIPTS = ["site/pingback",
           "site/zeek-ntp-monlist",
           "policy/protocols/ftp/detect-bruteforcing",
           "policy/misc/detect-traceroute"]

SCRIPTS_RNA = ["scripts",
               "site/pingback",
               "site/zeek-ntp-monlist",
               "policy/protocols/ftp/detect-bruteforcing",
               "policy/misc/detect-traceroute"]

zeek = None


def signal_handler(sig, frame):
    global zeek
    print("Terminating zeek...")
    zeek.kill()
    exit(1)


def main():
    global zeek

    parser = argparse.ArgumentParser(
        description="Run zeek and tcpreplay + monitoring.")
    parser.add_argument("-d", "--debug", help="enable debug mode",
                        action="store_true")
    parser.add_argument("--rna", help="enable rna",
                        action="store_true")
    parser.add_argument("-x", "--multiplier", metavar="multiplier", type=str, default=1,
                        help="speed multiplier")
    parser.add_argument("-M", "--mbps", metavar="multiplier", type=str, default=None,
                        help="replay speed in Mbps")
    parser.add_argument("interface", nargs=1, type=str,
                        help="interface.")
    parser.add_argument("dataset", nargs=1, type=str,
                        help="input dataset.")

    args = parser.parse_args()

    logging.basicConfig(
        format='[%(levelname)s] %(message)s',
        level=logging.DEBUG if args.debug else logging.INFO)

    input_dataset = args.dataset[0]
    interface = args.interface[0]
    is_rna = args.rna
    speed_mult = float(args.multiplier)
    mbps = args.mbps if args.mbps is not None else None

    if not os.path.exists(input_dataset):
        logging.error("Input dataset doesn't exist: %s" % input_dataset)
        exit(1)

    logging.info(
        f"Starting zeek in interface {interface} for dataset {input_dataset} (x{speed_mult})")

    signal.signal(signal.SIGINT, signal_handler)

    zeek_cmd = ["zeek", "-i", interface] + \
        (SCRIPTS_RNA if is_rna else SCRIPTS)
    tcpreplay_cmd = ["tcpreplay", "-i", interface] + \
        (["-x", speed_mult] if speed_mult != 1 else []) + \
        (["-M", mbps] if mbps is not None else []) + \
        [input_dataset]

    logging.debug(f"Zeek comand: {zeek_cmd}")
    logging.debug(f"Tcpreplay comand: {tcpreplay_cmd}")

    zeek = subprocess.Popen(
        zeek_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    zeek_pid = zeek.pid

    if zeek_pid is None:
        logging.error("Error running zeek")
        exit(1)
    else:
        logging.info(f"Zeek started with pid {zeek_pid}")

    # Sleeping to ensure Zeek has been properly initialized
    logging.info("Waiting 5s for zeek to initialize.")
    time.sleep(5)

    zeek_process = psutil.Process(zeek_pid)

    logging.info("Starting tcpreplay")
    print_status_format()

    starttime = get_timestamp()
    tcpreplay_process = subprocess.Popen(
        tcpreplay_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while True:
        status = tcpreplay_process.poll()
        if status == None:
            print_status(zeek_process, starttime)
        elif status == 0:
            logging.info("Tcpreplay finished")
            break
        else:
            logging.warning("Tcpreplay finished: unexpected status")
            break
        time.sleep(0.1)

    zeek.terminate()
    logging.info("Finished after %0.2fs" % (get_timestamp() - starttime))


def get_timestamp():
    return datetime.datetime.now().timestamp()


def print_status(process, starttime):
    logging.info("%i\t%.1f\t%.1f" % (
        (get_timestamp() - starttime)*1000,
        process.memory_info()[0]/2.**20,
        process.cpu_percent()
    ))


def print_status_format():
    logging.info("t\tMem\tCPU")


if (__name__ == "__main__"):
    main()
