# zeek-p4

This is the repository for the development of the Graduation Project (TCC in pt-BR) of Lucas Hagen.

Oriented by:
- Prof. Luciano Gaspary ([@lpgaspary](https://github.com/lpgaspary))
- Jonatas Marques ([@jonadmark](https://github.com/jonadmark))
- Alexandre Ilha ([@asilha](https://github.com/asilha))

## How to run

```bash

# Initialize all submodules of this repo
./init-submodules

# OPTIONAL: if you don't want to download the docker images from docker hub, you can build them:
./build-images full

# Verify if you have installed the dependencies for ZPO (python)
sudo pip3 install -r ./zpo/requirements.txt

# Run ZPO, here is an example with the built-in templates/events:
python3 zpo.py output -t templates/ arp_reply arp_request icmp_echo_request icmp_echo_reply

# Prepare the previously created output to be run:
./prepare-output output

# In two different terminals, run the p4app and zeek:

# Terminal 1:
./output/run_p4app

# Terminal 2:
./output/run_zeek
./run

```

### Requirements:

Main requirements are:
- Docker
- Python 3

## Prototypes

The prototypes aim to help finding problems to be solved and getting experience with the frameworks.

### Prototype 2: test-projects/zpo2

Offloading zeek events (`ICMP_ECHO_REPLY` and `ICMP_ECHO_REQUEST`) to a p4 switch.

Click [here](test-projects/zpo2) for more info.

### Prototype 1: test-projects/zpo1

Simple zeek script displaying messages on ICMP packets.

Click [here](test-projects/zpo1) for more info.
