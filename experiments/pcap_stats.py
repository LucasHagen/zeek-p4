#!/usr/bin/env python3

import signal
import matplotlib.pyplot as plt
import numpy as np
import os
import re
import logging
import argparse
from typing import List
from scapy.all import *

SCRIPT_PATH = os.path.abspath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_PATH)
SCRIPT_NAME = os.path.basename(SCRIPT_PATH)

TIME_INDEX = 0
PACKET_COUNT_INDEX = 1

ATTACK_CATEGORIES = [
    "ntp",
    "pingback",
    "ftp_bruteforce",
    "traceroute",
]


ATTACK_NAMES = [
    "NTP Monlist",
    "Pingback Tunnel",
    "FTP Bruteforce",
    "Traceroute",
]


def main():
    global docker_client
    parser = argparse.ArgumentParser(
        description="Aggregate experiment log.")

    parser.add_argument("-d", "--debug", help="enable debug mode",
                        action="store_true")

    parser.add_argument("pcap_stats_dir", nargs=1, type=str,
                        help="the path to the pcap stats dir.")

    parser.add_argument("--attacks", metavar="attacks_dir", nargs=1, type=str, default=None, required=False,
                        help="the path to the atack pcaps dir.")

    args = parser.parse_args()

    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    stats_dir = str(args.pcap_stats_dir[0])
    attacks_dir = str(args.attacks[0]) if args.attacks is not None else None

    if not os.path.exists(stats_dir) or not os.path.isdir(stats_dir):
        logging.error(f"Invalid stats dir: {stats_dir}")
        exit(1)

    if attacks_dir is not None and (not os.path.exists(attacks_dir) or not os.path.isdir(attacks_dir)):
        logging.error(f"Invalid attacks dir: {attacks_dir}")
        exit(1)

    pps = parse_stats(stats_dir)
    if attacks_dir is None:
        times = None
    else:
        times = get_attack_packets(attacks_dir)

    plot_pps(pps, stats_dir, times)

    logging.info("Done")


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
        counter[index, 1] = int(get_pps(content))

    return counter


def plot_pps(averages: np.ndarray, stats_dir: str, times=None):
    plt.style.use('_mpl-gallery')

    # make data
    x = averages[:, TIME_INDEX] / 1000
    y = averages[:, PACKET_COUNT_INDEX]

    # plot
    fig, ax = plt.subplots(2, gridspec_kw={'height_ratios': [1, 5]})
    fig.set_tight_layout(True)
    fig.set_size_inches(8, 8)

    ax[1].plot(x, y, linewidth=2.0, color='black')

    ax[1].set(
        title=f"PPS in time",
        xlim=(0, 10), xticks=np.arange(0, 11), xlabel="Time (s)",
        ylim=(0, pow(10, 6)), yticks=np.arange(0, pow(10, 6) + 100000, 100000), ylabel="Packets per second (pps)",
    )

    plt.gca().set_yticklabels([format_number(x)
                               for x in range(0, pow(10, 6) + 100000, 100000)])

    if times is not None:
        for category in ATTACK_CATEGORIES:
            attack_x = times[category]
            count = len(attack_x)
            attack_y = get_ys(count)

            # category_color = get_color()
            category_color = 'black'

            height = attack_y[0]
            ax[0].scatter(attack_x, attack_y, s=1, marker="s",
                          color=category_color, label=get_label(category))

    ax[0].set(
        title=f"Attack packets in time",
        xlim=(0, 10), xticks=np.arange(0, 11), xlabel="Time (s)",
        ylim=(1, -4), yticks=[0, -1, -2, -3], yticklabels=ATTACK_NAMES,
    )

    # plt.gca().set_yticklabels(attack_names)

    plt.savefig(os.path.join(
        stats_dir, f"pps_in_time.pdf"))
    plt.show()


attack_y_index = 0


def get_ys(amount: int):
    global attack_y_index
    value = [attack_y_index for i in range(0, amount)]
    attack_y_index -= 1
    return value


color_index = 0
colors = ['orange', 'blue', 'green', 'red']


def get_color():
    global color_index, colors
    color = colors[color_index % len(colors)]
    color_index += 1
    return color


def format_number(number: float or int) -> str:
    n = number
    letter = ""

    if n/1000 >= 1:
        n = n/1000
        letter = " k"

    if n/1000 >= 1:
        n = n/1000
        letter = " M"

    return f"{int(n)}{letter}"


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
        logging.error(f"Error getting packet count")
        exit(1)

    packets = int(result.group(1))

    if result.group(2) == "k":
        packets = packets * 1000
    elif result.group(2) == "":
        pass
    else:
        logging.error(f"Error reading packet count: {content}")

    return packets


def get_pps(content: str) -> int:
    # Average packet rate: 546 kpackets/s
    result = re.search(
        r"Average packet rate:[ \t]*([0-9.]+)[ \t]+([a-zA-Z]?)packets/s",
        content)

    if not result:
        logging.error(f"Error getting pps")
        exit(1)

    packets = int(result.group(1))

    if result.group(2) == "k":
        packets = packets * 1000
    elif result.group(2) == "":
        pass
    else:
        logging.error(f"Error reading pps: {content}")

    return packets


def get_attack_packets(attacks_dir):
    file_paths = [os.path.join(attacks_dir, f)
                  for f in os.listdir(attacks_dir)
                  if (f.endswith(".pcap") or f.endswith(".pcapng")) and os.path.isfile(os.path.join(attacks_dir, f))]

    file_paths.sort()

    times: Dict[List] = {}
    for category in ATTACK_CATEGORIES:
        times[category] = []

    for file_path in file_paths:
        category = get_category(file_path)
        for packet in PcapReader(file_path):
            times[category].append(packet.time - 1459948050)

    return times


def get_category(file: str) -> str:
    for cat in ATTACK_CATEGORIES:
        if cat in file:
            return cat

    logging.error(f"Category not found for file: {file}")
    exit(1)


def get_label(category: str) -> str:
    if category == "ftp_bruteforce":
        return "FTP Bruteforce"
    elif category == "ntp":
        return "NTP Monlist"
    elif category == "pingback":
        return "Pingback Tunnel"
    elif category == "traceroute":
        return "Traceroute"

    logging.error(f"Label not found for category {category}")
    exit(1)


if (__name__ == "__main__"):
    main()
