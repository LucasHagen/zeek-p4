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

    parser.add_argument("log_dir", nargs=2, type=str,
                        help="the log directory.")

    args = parser.parse_args()

    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    log_dir1 = str(args.log_dir[0])
    log_dir2 = str(args.log_dir[1])

    if not os.path.exists(log_dir1) or not os.path.isdir(log_dir1):
        logging.error(f"Invalid log directory: {log_dir1}")
        exit(1)

    if not os.path.exists(log_dir2) or not os.path.isdir(log_dir2):
        logging.error(f"Invalid log directory: {log_dir2}")
        exit(1)

    output = {}

    is_rna1 = read_is_rna(log_dir1)
    is_rna2 = read_is_rna(log_dir2)

    if is_rna1 == is_rna2:
        logging.error("Logs must be a combination of WITH RNA and WITHOUT RNA")
        exit(1)

    if is_rna1:
        averages_rna = read_zeek_perf(log_dir1)
        averages_full = read_zeek_perf(log_dir2)
    elif is_rna2:
        averages_full = read_zeek_perf(log_dir1)
        averages_rna = read_zeek_perf(log_dir2)

    plot_mem_graph(averages_rna, averages_full, SCRIPT_DIR)
    plot_cpu_graph(averages_rna, averages_full, SCRIPT_DIR)

    print(output)


def read_is_rna(log_dir):
    general_log = os.path.join(log_dir, "general.log")

    if not os.path.exists(general_log):
        logging.error("General log not found")
        exit(1)

    content = ""
    with open(general_log, 'r') as file:
        content = file.read()

    result = re.search(r"Params \([^)]*rna: ([a-zA-Z+]+)[^)]*\)", content)
    if not result:
        logging.error("Error finding RNA")
        exit(1)

    logging.info("RNA RNA: " + result.group(1))

    return result.group(1).lower() == "true"


def read_zeek_perf(log_dir: str) -> List[List]:
    output = []

    return np.genfromtxt(os.path.join(log_dir, "aggregated_perf.csv"), delimiter=',')


def plot_mem_graph(averages_rna: np.ndarray, averages_full: np.ndarray, log_dir: str):
    plt.style.use('_mpl-gallery')

    # make data
    x_rna = averages_rna[:, TIME_INDEX] / 1000
    y_rna = averages_rna[:, MEM_INDEX]

    x_full = averages_full[:, TIME_INDEX] / 1000
    y_full = averages_full[:, MEM_INDEX]

    # plot
    fig, ax = plt.subplots(1, 1)
    fig.set_tight_layout(True)
    fig.set_size_inches(6, 6)

    ax.plot(x_rna, y_rna, linewidth=2.0, color='black', label="With RNA")
    ax.plot(x_full, y_full, linewidth=1.0, color='gray', label="Without RNA")

    ax.legend()

    ax.set(
        # title=f"Memory usage by time (with{'' if is_rna else 'out'} RNA)",
        xlim=(0, 10), xticks=np.arange(0, 11), xlabel="Time (s)",
        ylim=(0, 1000), yticks=np.arange(0, 1100, 100), ylabel="Memory (Mb)",
    )

    plt.savefig(os.path.join(
        log_dir, f"aggregated_memory_plot.pdf"))
    plt.show()


def plot_cpu_graph(averages_rna: np.ndarray, averages_full: np.ndarray, log_dir: str):
    plt.style.use('_mpl-gallery')

    # make data
    x_rna = averages_rna[:, TIME_INDEX] / 1000
    y_rna = averages_rna[:, CPU_INDEX]

    x_full = averages_full[:, TIME_INDEX] / 1000
    y_full = averages_full[:, CPU_INDEX]

    # plot
    fig, ax = plt.subplots(1, 1)
    fig.set_tight_layout(True)
    fig.set_size_inches(6, 6)

    ax.plot(x_rna, y_rna, linewidth=2.0, color='black', label="With RNA")
    ax.plot(x_full, y_full, linewidth=1.0, color='gray', label="Without RNA")

    ax.legend()

    ax.set(
        # title=f"CPU usage by time (with{'' if is_rna else 'out'} RNA)",
        xlim=(0, 10), xticks=np.arange(0, 11), xlabel="Time (s)",
        ylim=(0, 130), yticks=np.arange(0, 140, 10), ylabel="CPU (%)",
    )

    plt.savefig(os.path.join(
        log_dir, f"aggregated_cpu_plot.pdf"))
    plt.show()


if (__name__ == "__main__"):
    main()
