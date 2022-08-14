#!/usr/bin/env python3


import matplotlib.pyplot as plt
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

TIME_INDEX = 0
MEM_INDEX = 1
CPU_INDEX = 2


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
    is_rna = read_is_rna(log_dir)
    logging.info(f"Iteractions: {iteractions}")
    logging.info(f"Is RNA: {is_rna}")

    dropped_p = get_all_dropped_packets_count(log_dir, iteractions)

    output["iteractions"] = iteractions
    output["dropped_packets"] = {
        "average": statistics.mean(dropped_p),
        "median": statistics.median(dropped_p)
    }
    output["is_rna"] = is_rna

    averages = aggregate_zeek_perf(log_dir, iteractions)
    plot_mem_graph(averages, log_dir, is_rna)
    plot_cpu_graph(averages, log_dir, is_rna)

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


def read_is_rna(log_dir):
    general_log = os.path.join(log_dir, "general.log")

    if not os.path.exists(general_log):
        logging.error("General log not found")
        exit(1)

    content = ""
    with open(general_log, 'r') as file:
        content = file.read()

    result = re.search(r"Params \([^)]*rna: ([a-zA-Z+])[^)]*\)", content)
    if not result:
        logging.error("Error finding RNA")
        exit(1)

    return result.group(1).lower() == "true"


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


def aggregate_zeek_perf(log_dir: str, iteractions: int) -> np.ndarray:
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
        average[t, TIME_INDEX] = ms

    average[:, MEM_INDEX] = mem_average
    average[:, CPU_INDEX] = cpu_average

    np.savetxt(os.path.join(log_dir, "aggregated_perf.csv"), average,
               delimiter=",", fmt='%i,%0.2f,%0.2f', header="Time (ms),Memory (Mb),CPU (%)")

    return average


def read_zeek_perf(perf_log: str) -> List[List]:
    output = []

    with open(perf_log, 'r') as file:
        csvreader = csv.reader(file)
        next(csvreader)
        for row in csvreader:
            output.append(row)

    return output


def plot_mem_graph(averages: np.ndarray, log_dir: str, is_rna: bool):
    plt.style.use('_mpl-gallery')

    # make data
    x = averages[:, TIME_INDEX] / 1000
    y = averages[:, MEM_INDEX]

    # plot
    fig, ax = plt.subplots(1, 1)
    fig.set_tight_layout(True)
    fig.set_size_inches(5, 5)

    ax.plot(x, y, linewidth=2.0, color='gray')

    ax.set(
        title=f"Memory usage by time (with{'' if is_rna else 'out'} RNA)",
        xlim=(0, 10), xticks=np.arange(0, 11), xlabel="Time (s)",
        ylim=(0, 1000), yticks=np.arange(0, 1100, 100), ylabel="Memory (Mb)",
    )

    plt.savefig(os.path.join(log_dir, "mem_plot.pdf"))
    plt.show()


def plot_cpu_graph(averages: np.ndarray, log_dir: str, is_rna: bool):
    plt.style.use('_mpl-gallery')

    # make data
    x = averages[:, TIME_INDEX] / 1000
    y = averages[:, CPU_INDEX]

    # plot
    fig, ax = plt.subplots(1, 1)
    fig.set_tight_layout(True)
    fig.set_size_inches(5, 5)

    ax.plot(x, y, linewidth=2.0, color="gray")

    ax.set(
        title=f"CPU usage by time (with{'' if is_rna else 'out'} RNA)",
        xlim=(0, 10), xticks=np.arange(0, 11), xlabel="Time (s)",
        ylim=(0, 130), yticks=np.arange(0, 140, 10), ylabel="CPU (%)",
    )

    plt.savefig(os.path.join(log_dir, "cpu_plot.pdf"))
    plt.show()


if (__name__ == "__main__"):
    main()
