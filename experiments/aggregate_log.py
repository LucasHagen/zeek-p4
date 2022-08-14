#!/usr/bin/env python3

import json
import numpy as np
import os
import re
import csv
import logging
import argparse
import statistics
from typing import List

SCRIPT_PATH = os.path.abspath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_PATH)
SCRIPT_NAME = os.path.basename(SCRIPT_PATH)


def main():
    global docker_client
    parser = argparse.ArgumentParser(
        description="Aggregate experiment log.")

    parser.add_argument("-d", "--debug", help="enable debug mode",
                        action="store_true")

    parser.add_argument("log_dir", nargs=1, type=str,
                        help="the log directory.")

    args = parser.parse_args()

    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    log_dir = str(args.log_dir[0])

    if not os.path.exists(log_dir) or not os.path.isdir(log_dir):
        logging.error(f"Invalid log directory: {log_dir}")
        exit(1)

    output = {}

    iteractions = read_iteraction_count(log_dir)
    logging.info(f"Iteractions: {iteractions}")

    dropped_p = get_all_dropped_packets_count(log_dir, iteractions)

    output["iteractions"] = iteractions
    output["dropped_packets"] = {
        "average": statistics.mean(dropped_p),
        "median": statistics.median(dropped_p)
    }

    aggregate_zeek_perf(log_dir, iteractions)

    with open(os.path.join(log_dir, "aggregated.json"), 'w') as file:
        file.write(json.dumps(output, sort_keys=True, indent=4))

    print(output)


def read_iteraction_count(log_dir):
    general_log = os.path.join(log_dir, "general.log")

    if not os.path.exists(general_log):
        logging.error("General log not found")
        exit(1)

    content = ""
    with open(general_log, 'r') as file:
        content = file.read()

    result = re.search(r"Finished all (\d+) iterations", content)
    if not result:
        logging.error("Error finding iteractions")
        exit(1)

    return int(result.group(1))


def get_all_dropped_packets_count(log_dir: str, iteractions: int) -> List[float]:
    counts = []

    for i in range(iteractions):
        counts.append(read_zeek_log(os.path.join(log_dir, f"zeek_it_{i}.log")))

    logging.info(f"Dropped packets: {counts}")
    return counts


def read_zeek_log(zeek_log_path):
    if not os.path.exists(zeek_log_path):
        logging.error(f"'{zeek_log_path}' log not found")
        exit(1)

    content = ""
    with open(zeek_log_path, 'r') as file:
        content = file.read()

    result = re.search(
        r"packets received on interface [^ ,]+, \d+ \(([0-9.]+)%\) dropped", content)
    if not result:
        logging.error(f"Error dropped packets in {zeek_log_path}")
        exit(1)

    return float(result.group(1))


def aggregate_zeek_perf(log_dir, iteractions):
    counts = []

    TIME_MAX = 10100
    TIME_STEP = 100

    COLUMNS = int(TIME_MAX/TIME_STEP)

    mem_matrix = np.zeros((COLUMNS, iteractions))
    cpu_matrix = np.zeros((COLUMNS, iteractions))

    for i in range(iteractions):
        perf = read_zeek_perf(os.path.join(log_dir, f"zeek_perf_{i}.csv"))

        for row in perf:
            ms, mem, cpu, comment = row
            ms = int(ms)
            ms -= TIME_STEP
            time_index = int(ms/TIME_STEP)

            if time_index < 0:
                continue

            if time_index >= COLUMNS:
                break

            mem_matrix[time_index, i] = float(mem)
            cpu_matrix[time_index, i] = float(cpu)

    mem_average = mem_matrix.mean(1)
    cpu_average = cpu_matrix.mean(1)

    average = np.zeros((COLUMNS, 3))

    for t in range(0, COLUMNS):
        ms = t*TIME_STEP
        average[t, 0] = ms

    average[:, 1] = mem_average
    average[:, 2] = cpu_average

    np.savetxt(os.path.join(log_dir, "aggregated_perf.csv"), average,
               delimiter=",", fmt='%i,%0.2f,%0.2f', header="Time (ms),Memory (Mb),CPU (%)")

    return average


def read_zeek_perf(perf_log):
    output = []

    with open(perf_log, 'r') as file:
        csvreader = csv.reader(file)
        next(csvreader)
        for row in csvreader:
            output.append(row)

    return output


if (__name__ == "__main__"):
    main()
