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

    args = parser.parse_args()

    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    plot_graph(SCRIPT_DIR)


def plot_graph(log_dir: str):
    plt.style.use('_mpl-gallery')

    # make data
    x = [1,
         2,
         3,
         4,
         ]
    y = [
        2125,
        2422,
        2703,
        2967,
    ]

    # plot
    fig, ax = plt.subplots(1, 1)
    fig.set_tight_layout(True)
    fig.set_size_inches(6, 6)

    ax.bar(x, y, width=0.5, edgecolor="white", linewidth=0.7, color="gray")

    # ax.legend()

    ax.set(
        # title=f"CPU usage by time (with{'' if is_rna else 'out'} RNA)",
        xlim=(0, 5), xticks=np.arange(1, 5), xlabel="Script Count",
        ylim=(0, 4000), yticks=np.arange(0, 4800, 800), ylabel="Generated Line Count",
    )

    plt.savefig(os.path.join(
        log_dir, f"generated_lines.pdf"))
    plt.show()


if (__name__ == "__main__"):
    main()
