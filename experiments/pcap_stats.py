#!/usr/bin/env python3

import signal
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
from scapy.all import *

SCRIPT_PATH = os.path.abspath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_PATH)
SCRIPT_NAME = os.path.basename(SCRIPT_PATH)

TIME_INDEX = 0
PACKET_COUNT_INDEX = 1


def main():
    global docker_client
    parser = argparse.ArgumentParser(
        description="Aggregate experiment log.")

    parser.add_argument("-d", "--debug", help="enable debug mode",
                        action="store_true")

    parser.add_argument("pcap_stats_dir", nargs=1, type=str,
                        help="the path to the pcap stats dir.")

    args = parser.parse_args()

    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    signal.signal(signal.SIGINT, signal_handler)

    stats_dir = str(args.pcap_stats_dir[0])

    if not os.path.exists(stats_dir) or not os.path.isdir(stats_dir):
        logging.error(f"Invalid stats dir: {stats_dir}")
        exit(1)

    pps = parse_stats(stats_dir)
    plot_mem_graph(pps, stats_dir)


counter = None
processed = 0


def parse_stats(stats_dir):
    global counter
    file_paths = [os.path.join(stats_dir, f)
                  for f in os.listdir(stats_dir)
                  if f.endswith(".stats") and os.path.isfile(os.path.join(stats_dir, f))]

    file_paths.sort()

    counter = np.zeros((100, 2))

    start_time = None

    for file_path in file_paths:
        content = ""
        with open(file_path, 'r') as file:
            content = file.read()

        time = get_start_time(content)
        if start_time is None:
            start_time = time

        time_diff_s = (time - start_time).total_seconds()
        time_diff_ms = int(time_diff_s*1000)

        index = int(time_diff_s * 10)

        counter[index, 0] = time_diff_ms
        counter[index, 1] = int(get_packet_count(content))

    return counter


def plot_mem_graph(averages: np.ndarray, stats_dir: str):
    plt.style.use('_mpl-gallery')

    # make data
    x = averages[:, TIME_INDEX] / 1000
    y = averages[:, PACKET_COUNT_INDEX]

    # plot
    fig, ax = plt.subplots(1, 1)
    fig.set_tight_layout(True)
    fig.set_size_inches(5, 5)

    ax.plot(x, y, linewidth=2.0, color='gray')

    # ax.scatter([0,1,3], [90000, 90000, 90000], s=10, c='b', marker="s", label='first')

    ax.set(
        # title=f"PPS in time",
        xlim=(0, 10), xticks=np.arange(0, 11), xlabel="Time (s)",
        ylim=(0, 100000), yticks=np.arange(0, 110000, 10000), ylabel="Packets per second (pps)",
    )

    plt.gca().set_yticklabels([f"{int(x/1000)}{' k' if x != 0 else ''}" for x in range(0, 110000, 10000)])

    plt.savefig(os.path.join(
        stats_dir, f"pps_in_time.pdf"))
    plt.show()


def get_start_time(content: str):
    # First packet time:   2016-04-06 10:07:30,000004
    result = re.search(
        r"First packet time:[ \t]*([0-9 -:,]+)",
        content)

    if not result:
        logging.error(f"Error getting start time from stats")
        exit(1)

    date_time_str = result.group(1)  # '18/09/19 01:55:19'

    return datetime.strptime(date_time_str, '%Y-%m-%d %H:%M:%S,%f')


def get_packet_count(content: str) -> int:
    # Number of packets:   55 k
    result = re.search(
        r"Number of packets:   (\d+)[ \t]*([a-z]?)",
        content)

    if not result:
        logging.error(f"Error getting start time from stats")
        exit(1)

    packets = int(result.group(1))

    if result.group(2) == "k":
        packets = packets * 1000
    elif result.group(2) == "":
        pass
    else:
        logging.error(f"Error reading packet count: {content}")

    return packets


# def parse_pcap(stats_dir):
#     p = None
#     for packet in PcapReader(stats_dir):
#         try:
#             p = packet
#             processed += 1
#             # index = (packet.time - start_time) * 10
#             # print(index)
#             # index = int(index)
#             # counter[index, 0] += 1
#             # print(index)
#             # exit(1)
#             # if packet[TCP].dport == 80:
#             #     payload = bytes(packet[TCP].payload)
#             #     url = get_url_from_payload(payload)
#             #     urls_output.write(url.encode())
#         except Exception as e:
#             pass

#     print(f"Last {p.time-start_time}")


def signal_handler(sig, frame):
    global counter
    print(counter)
    print(f"Processed: {processed}")
    exit(1)


if (__name__ == "__main__"):
    main()
