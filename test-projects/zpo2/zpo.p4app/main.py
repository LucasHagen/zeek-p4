from mininet.cli import CLI
from p4app import P4Mininet
from mininet.topo import SingleSwitchTopo

import sys
print(sys.version)

N = 2

nodes = [
    {
        "ip": "10.0.0.1"
    },
    {
        "ip": "10.0.0.2"
    }
]


topo = SingleSwitchTopo(N)
net = P4Mininet(program='zpo.p4', topo=topo)
net.start()

table_entries = []
for i, node in enumerate(nodes, start=1):
    table_entries.append(dict(table_name='ingress.ipv4_lpm',
                              match_fields={
                                  'hdr.ipv4.dst_addr': [node["ip"], 32]
                              },
                              action_name='ingress.ipv4_forward',
                              action_params={'dst_addr': net.get('h%d'%i).intfs[0].MAC(),
                                             'port': i}))

sw = net.get('s1')
for table_entry in table_entries:
    sw.insertTableEntry(table_entry)

sw.printTableEntries()
# sw.command("mirroring_add 1 3") # ??

loss = net.pingAll()
assert loss == 0

# Start the mininet CLI to interactively run commands in the network:
CLI(net)

print("OK")


# Old config:
#
# reset_state
# mirroring_add 1 3
# table_add send_frame rewrite_mac 1 => 00:aa:bb:00:00:00
# table_add send_frame rewrite_mac 2 => 00:aa:bb:00:00:01
# table_add forward set_dmac 10.0.0.10 => 00:04:00:00:00:00
# table_add forward set_dmac 10.0.1.10 => 00:04:00:00:00:01
# table_add ipv4_lpm set_nhop 10.0.0.10/32 => 10.0.0.10 1
# table_add ipv4_lpm set_nhop 10.0.1.10/32 => 10.0.1.10 2
