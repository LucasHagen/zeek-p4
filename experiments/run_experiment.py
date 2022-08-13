#!/usr/bin/env python3

import os
import sys
import time
import psutil
import signal
import shutil
import docker
from docker import DockerClient
import logging
import argparse
import datetime
import subprocess
import netifaces
from datetime import datetime

SCRIPTS = ["site/pingback",
           "site/zeek-ntp-monlist",
           "policy/protocols/ftp/detect-bruteforcing",
           "policy/misc/detect-traceroute"]

SCRIPTS_RNA = ["scripts",
               "site/pingback",
               "site/zeek-ntp-monlist",
               "policy/protocols/ftp/detect-bruteforcing",
               "policy/misc/detect-traceroute"]

SCRIPT_PATH = os.path.abspath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_PATH)
SCRIPT_NAME = os.path.basename(SCRIPT_PATH)

START_TIME = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

LOG_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "logs", START_TIME))
GENERAL_LOG_FILE = os.path.join(LOG_DIR, "general.log")

docker_client: DockerClient = None
zeek_container = None

p_zeek = None
p_tcpreplay = None

zeek_log_file = None
zeek_perf_log = None
tcpreplay_log_file = None

terminating = False


def signal_handler(sig, frame):
    global terminating

    if not terminating:
        terminating = True
        terminate()


def terminate(code=0):
    global docker_client
    global zeek_container
    global p_zeek
    global p_tcpreplay

    if docker_client is not None and zeek_container is not None:
        print("Terminating docker...")
        zeek_container.kill()

    if p_zeek is not None:
        print("Terminating zeek...")
        p_zeek.kill()

    if p_tcpreplay is not None:
        print("Terminating tcpreplay...")
        p_tcpreplay.kill()

    exit(int(code))


def interface_exists(interface_name) -> bool:
    try:
        return netifaces.AF_INET in netifaces.ifaddresses(interface_name)
    except:
        return False


def main():
    global docker_client
    parser = argparse.ArgumentParser(
        description="Run zeek and tcpreplay + monitoring.")

    parser.add_argument("-d", "--debug", help="enable debug mode",
                        action="store_true")

    parser.add_argument("--rna", help="enable RNA",
                        action="store_true")

    parser.add_argument("-i", metavar="iterations", type=int, default=1,
                        help="number of times to execute the experiment")

    parser.add_argument("-x", metavar="multiplier", type=float, default=1,
                        help="replay speed multiplier")

    parser.add_argument("-M", "--mbps", metavar="mbps", type=int, default=None,
                        help="replay speed in Mbps")

    parser.add_argument("--rna_path", metavar="rna_path", type=str, default=None,
                        help="path to RNA autogen folder")

    parser.add_argument("interface", nargs=1, type=str,
                        help="interface.")

    parser.add_argument("dataset", nargs=1, type=str,
                        help="input dataset.")

    args = parser.parse_args()

    setup_log(args.debug)

    input_dataset = str(args.dataset[0])
    interface = str(args.interface[0])
    is_rna = bool(args.rna)
    iterations = int(args.i)
    speed_mult = float(args.x)
    mbps = int(args.mbps) if args.mbps is not None else None
    rna_path = os.path.abspath(SCRIPT_DIR + "/../output") \
        if args.rna_path is None else os.path.abspath(args.rna_path)

    if not os.path.exists(input_dataset):
        logging.error("Input dataset doesn't exist: %s" % input_dataset)
        exit(1)

    if not interface_exists(interface):
        logging.error("Interface is not up: %s" % interface)
        exit(1)

    if not os.path.exists(rna_path) or not os.path.isdir(rna_path):
        logging.error(f"Invalid Zeek (RNA) folder: {rna_path}")
        exit(1)

    docker_client = docker.from_env()

    signal.signal(signal.SIGINT, signal_handler)

    logging.info(f"Starting experiments")
    logging.info(
        f"Params (iface: {interface}; dataset: {input_dataset}; x: {speed_mult}; mbps: {mbps}; it: {iterations})")

    try:
        for it in range(iterations):
            run_iteration(input_dataset,
                          interface,
                          is_rna,
                          speed_mult,
                          mbps,
                          rna_path,
                          it)
    except Exception as e:
        logging.error(e)
    logging.info(f"Finished all {iterations} iterations")

    terminate(0)


def setup_log(debug: bool):
    os.makedirs(LOG_DIR)

    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG if debug else logging.INFO,
                        handlers=[
                            logging.FileHandler(GENERAL_LOG_FILE),
                            logging.StreamHandler(sys.stdout)
                        ])


def setup_perf_log(iteration):
    global zeek_perf_log
    zeek_perf_log = open(os.path.join(
        LOG_DIR, f"zeek_perf_{iteration}.csv"), 'a')
    zeek_perf_log.write("t,Mem,Cpu,Comment\n")


def is_container_running(container_name):
    try:
        return docker_client.containers.get(container_name) is not None
    except:
        return False


def start_docker(rna_path):
    global docker_client
    global zeek_container

    logging.info("Starting docker")

    if is_container_running("zeek-experiment"):
        logging.error("Container is already running")
        exit(1)

    zeek_container = docker_client.containers.run(
        "lucashagen/zeek-scripts",
        name="zeek-experiment",
        network="host",
        volumes=[
            f"{rna_path}/zpo.zeek:/root/plugin"
        ],
        working_dir="/root/plugin",
        auto_remove=True,
        detach=True,
        stdin_open=True,
    )

    logging.debug(f"Docker container id: {zeek_container.id}")

    clean_log = zeek_container.exec_run(
        "./clean",
        stdout=True,
        stderr=True,
        stdin=False,
        workdir="/root/plugin",
    )

    if clean_log[0] != 0:
        logging.error("Error deleting zeek logs and build folder")
        terminate()
    # else:
    #     logging.info("RM log: %s" % (rm_log[1].decode('utf-8')))


def install_rna():
    global docker_client
    global zeek_container

    cmd_exec = zeek_container.exec_run(
        "./install",
        stdout=True,
        stderr=True,
        stdin=False,
        workdir="/root/plugin",
    )

    if cmd_exec[0] != 0:
        logging.error("Error installing RNA")
        terminate()
    # else:
        # logging.info("Install log %s" % (cmd_exec[1].decode('utf-8')))

    logging.info("Installed RNA")


def run_zeek(interface: str,
             is_rna: bool,
             iteration: int,
             ):
    # global docker_client
    # global zeek_container
    # global p_zeek
    global zeek_log_file

    zeek_cmd = ["docker", "exec", "zeek-experiment",
                "zeek", "-i", interface] + \
        (SCRIPTS_RNA if is_rna else SCRIPTS)

    logging.info("Zeek command: %s" % " ".join(zeek_cmd))

    zeek_log_file = open(os.path.join(
        LOG_DIR, f"zeek_it_{iteration}.log"), 'a')
    return subprocess.Popen(zeek_cmd, stdin=subprocess.PIPE, stdout=zeek_log_file, stderr=zeek_log_file)


def run_tcpreplay(input_dataset: str,
                  interface: str,
                  speed_mult: float,
                  mbps: int,
                  iteration: int
                  ):
    global tcpreplay_log_file

    tcpreplay_cmd = ["tcpreplay", "-i", interface] + \
        ([f"--multiplier={speed_mult}"] if speed_mult != 1 else []) + \
        ([f"--mbps={mbps}"] if mbps is not None else []) + \
        [input_dataset]

    logging.info("Tcpreplay command: %s" % " ".join(tcpreplay_cmd))

    tcpreplay_log_file = open(os.path.join(
        LOG_DIR, f"tcpreplay_it_{iteration}.log"), 'a')
    return subprocess.Popen(tcpreplay_cmd, stdin=subprocess.PIPE, stdout=tcpreplay_log_file, stderr=tcpreplay_log_file)


def get_zeek_pid():
    global docker_client
    global zeek_container

    top_info = zeek_container.top()
    for top_line in top_info["Processes"]:
        # Line structure: 'UID', 'PID', 'PPID', 'C', 'STIME', 'TTY', 'TIME', 'CMD'
        if top_line[7].startswith("zeek"):
            return int(top_line[1])

    return None


def run_iteration(
        input_dataset: str,
        interface: str,
        is_rna: bool,
        speed_mult: float or None,
        mbps: int or None,
        rna_path: str,
        iteration: int):
    global p_zeek
    global zeek_log_file
    global zeek_perf_log
    global tcpreplay_log_file
    logging.info(f"Starting iteration #{iteration}")

    start_docker(rna_path)

    if is_rna:
        install_rna()

    zeek_process = run_zeek(interface, is_rna, iteration)

    # Sleeping to ensure Zeek has been properly initialized
    logging.info("Waiting 5s for zeek to initialize.")
    time.sleep(5)

    zeek_pid = get_zeek_pid()
    if zeek_pid is None:
        logging.error("Error running zeek")
        terminate()
    else:
        logging.info(f"Zeek started with pid {zeek_pid}")

    p_zeek = psutil.Process(zeek_pid)

    logging.info("Starting tcpreplay")
    setup_perf_log(iteration)

    starttime = get_timestamp()
    p_tcpreplay = run_tcpreplay(input_dataset,
                                interface,
                                speed_mult,
                                mbps,
                                iteration,
                                )

    while True:
        status = p_tcpreplay.poll()
        if status == None:
            print_status(zeek_perf_log, p_zeek, starttime)
            time.sleep(0.1)
        elif status == 0:
            print_status(zeek_perf_log, p_zeek,
                         starttime, "tcpreplay finished")
            p_tcpreplay = None
            time.sleep(0.1)
            break
        else:
            p_tcpreplay = None
            print_status(zeek_perf_log, p_zeek, starttime,
                         "tcpreplay finished: unexpected status")
            time.sleep(0.1)
            break

    endtime = (get_timestamp() - starttime)
    logging.info("Tcpreplay finished at %ims" % (endtime*1000))

    while ((get_timestamp() - starttime) - endtime) <= 1:
        print_status(zeek_perf_log, p_zeek, starttime)
        time.sleep(0.1)

    p_zeek.send_signal(signal.SIGINT)
    print_status(zeek_perf_log, p_zeek, starttime, "zeek terminated")
    logging.info("Zeek terminated at %i" %
                 ((get_timestamp() - starttime)*1000))

    notice_path = os.path.join(rna_path, "zpo.zeek", "notice.log")
    if os.path.exists(notice_path):
        shutil.copyfile(notice_path, os.path.join(
            LOG_DIR, f"notice_{iteration}.log"))
    else:
        logging.error(f"Notice log not found for iteration #{iteration}")

    clean_iteration()
    logging.info(f"Finished iteration {iteration}")


def clean_iteration():
    global docker_client
    global zeek_container
    global p_zeek
    global p_tcpreplay
    global zeek_log_file
    global zeek_perf_log
    global tcpreplay_log_file

    if docker_client is not None and zeek_container is not None:
        zeek_container.kill()
        zeek_container = None

    if p_zeek is not None:
        p_zeek = None

    if p_tcpreplay is not None:
        p_tcpreplay = None

    try:
        zeek_log_file.close()
        zeek_perf_log.close()
        tcpreplay_log_file.close()
    except:
        logging.error("Error closing log files")


def get_timestamp():
    return datetime.now().timestamp()


def print_status(log_file, process, starttime, comment=""):
    log_file.write("%i,%.1f,%.1f,%s\n" % (
        (get_timestamp() - starttime)*1000,
        process.memory_info()[0]/2.**20,
        process.cpu_percent(),
        comment,
    ))


if (__name__ == "__main__"):
    main()
