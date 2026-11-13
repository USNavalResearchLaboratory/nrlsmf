"""with-frr polls stay off the forwarding thread.

Topology:

  r0 -- lan0
    `-- lan1

eth0 is in the default VRF with IGMP. eth1 is in VRF red. nrlsmf is
started with-frr. The test checks three things:

- ping on the control socket returns within a few seconds while pimd
  and zebra are stopped
- a local IGMP membership on eth0 shows up in show igmp groups
- VRF red is learned from zebra and recorded in the nrlsmf log
"""

from munet.mutest.userapi import script_dir
from munet.mutest.userapi import section
from munet.mutest.userapi import step
from munet.mutest.userapi import test_step
from munet.mutest.userapi import wait_step

import sys

sys.path.insert(0, str(script_dir().parent))
from smf_cli import wait_em_managed

NODE = "r0"
INST = "frrpoll"
GROUP = "239.1.2.3"
ETH0 = "eth0"
ETH1 = "eth1"


section("Wait for zebra and pimd")

wait_step(
    NODE,
    "pgrep -a zebra",
    match="zebra",
    desc=f"{NODE} zebra is running",
    timeout=30,
)
wait_step(
    NODE,
    "pgrep -a pimd",
    match="pimd",
    desc=f"{NODE} pimd is running",
    timeout=30,
)

section("Put eth1 in kernel VRF red")

# Zebra learns the l3mdev from netlink. Creating the VRF here is more
# reliable than "interface eth1 vrf red" in frr.conf, which does not
# move an interface that already exists in the default VRF.
step(NODE, "ip link add red type vrf table 10")
step(NODE, "ip link set red up")
step(NODE, "ip link set eth1 master red")
step(NODE, "ip addr add 10.1.0.1/24 dev eth1")
step(NODE, "ip link set eth1 up")
wait_step(
    NODE,
    "vtysh -c 'show vrf'",
    match="red",
    desc=f"{NODE} zebra has VRF red",
    timeout=20,
)
wait_step(
    NODE,
    "vtysh -c 'show interface vrf red brief'",
    match=ETH1,
    desc=f"{NODE} zebra lists {ETH1} in VRF red",
    timeout=20,
)

section("Start nrlsmf with-frr")

step(
    NODE,
    f"nrlsmf debug 6 instance {INST} with-frr "
    f"add net,cf,{ETH0},{ETH1} elastic net &> nrlsmf.log &",
)
wait_step(
    NODE,
    f'pgrep -af "nrlsmf.*instance {INST}"',
    match=f"instance {INST}",
    desc=f"nrlsmf instance {INST} is running",
)

section("Control socket answers while FRR is stalled")

# Freeze pimd and zebra so each poll waits out the VTY timeout. The
# polls run on worker threads, so ping must still answer promptly.
step(NODE, "pkill -STOP -x pimd; pkill -STOP -x zebra; sleep 6")
out = step(
    NODE,
    "for i in 1 2 3 4 5 6 7 8; do "
    f"timeout 3 nrlsmf --cli -i {INST} -c ping | grep -q pong && echo ok; "
    "done",
)
step(NODE, "pkill -CONT -x pimd; pkill -CONT -x zebra")
test_step(
    out.split().count("ok") == 8,
    f"{NODE} ping returned pong 8/8 within 3s with pimd and zebra stopped",
    target=NODE,
)

section("IGMP membership is applied")

step(
    NODE,
    "python3 -c 'import socket,struct,time; "
    "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
    "mreq=struct.pack(\"4s4s\", socket.inet_aton(\"%s\"), socket.inet_aton(\"10.0.0.1\")); "
    "s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq); "
    "time.sleep(180)' >/tmp/igmp-join.log 2>&1 &" % GROUP,
)
wait_step(
    NODE,
    "vtysh -c 'show ip igmp groups'",
    match=GROUP,
    desc=f"{NODE} pimd learned {GROUP}",
    timeout=30,
)
wait_em_managed(NODE, INST, ETH0, GROUP, timeout=25)

section("VRF red is learned from zebra")

wait_step(
    NODE,
    "grep -F 'vrf name = red' nrlsmf.log",
    match="vrf name = red",
    desc=f"{NODE} nrlsmf log records VRF red",
    timeout=30,
)
wait_step(
    NODE,
    "grep -F -A4 'vrf name = red' nrlsmf.log",
    match=ETH1,
    desc=f"{NODE} VRF red includes {ETH1}",
    timeout=10,
)
