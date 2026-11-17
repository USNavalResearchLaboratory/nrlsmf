"""with-frr polls stay off the forwarding thread.

Topology:

  r0 -- lan0
    `-- lan1

eth0 is in the default VRF with IGMP. eth1 is in VRF red. nrlsmf is
started with-frr. The test checks:

- ping on the control socket returns within a few seconds while pimd
  and zebra are stopped
- a local IGMP membership on eth0 shows up in show igmp groups, and
  leaves again when the receiver socket closes
- eth0 stays a relay member while it has IGMP; a separate host LAN
  still gets push and rpush
- an operator remove of that IGMP interface is undone on a later poll
- VRF red is learned from zebra, and eth1 leaving red is learned too
"""

import json
import sys
import time

from munet.mutest.userapi import script_dir
from munet.mutest.userapi import section
from munet.mutest.userapi import step
from munet.mutest.userapi import test_step
from munet.mutest.userapi import wait_step

sys.path.insert(0, str(script_dir().parent))
from smf_cli import cli_cmd
from smf_cli import expect_ok
from smf_cli import group_row
from smf_cli import iface_row
from smf_cli import parse_json_blob
from smf_cli import show_json
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
    "time.sleep(180)' >/tmp/igmp-join.log 2>&1 & echo $! > /tmp/igmp-join.pid" % GROUP,
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


def wait_until(desc, predicate, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            test_step(True, desc, target=NODE)
            return True
        time.sleep(1)
    test_step(False, desc, target=NODE)
    return False


def show_rows(show_cmd):
    try:
        data = parse_json_blob(cli_cmd(NODE, f"{show_cmd} json", INST))
    except (json.JSONDecodeError, ValueError):
        return None
    return data


def group_names():
    grouping = show_rows("show interface grouping")
    if not isinstance(grouping, list):
        return set()
    return {g.get("GroupName") for g in grouping if isinstance(g, dict)}


section("Relay radio with IGMP keeps the mesh")

# eth0 is already in the relay group and IGMP-up. Adding more relay
# members must not turn eth0 into an rpush source. A later host-only
# interface still gets push from the radios and rpush back.
step(NODE, "modprobe dummy || true")
step(NODE, "ip link add late0 type dummy || true")
step(NODE, "ip link add late1 type dummy || true")
step(NODE, "ip link set late0 up")
step(NODE, "ip link set late1 up")
expect_ok(NODE, "add net,cf,late0", INST)
expect_ok(NODE, "add net,cf,late1", INST)
grouping = show_json(NODE, "show interface grouping", INST)
net = group_row(grouping, "net")
have = set((net or {}).get("Interfaces") or [])
for iface in (ETH0, ETH1, "late0", "late1"):
    test_step(iface in have, f"{NODE} net includes {iface}", target=NODE)
radio_push = group_row(grouping, "push:eth0")
radio_ifaces = set((radio_push or {}).get("Interfaces") or [])
test_step(
    radio_push is not None and radio_ifaces <= {ETH0},
    f"{NODE} {ETH0} keeps its implicit push group and does not rpush to other radios",
    target=NODE,
)
conflicts = step(NODE, "grep -F 'previous rpush' nrlsmf.log || true")
test_step(
    "previous rpush" not in (conflicts or ""),
    f"{NODE} relay update did not stop on an rpush conflict",
    target=NODE,
)

HOST = "host0"
# A dummy is not an IGMP-up interface to pimd. A veth is.
step(NODE, f"ip link add {HOST} type veth peer name {HOST}p")
step(NODE, f"ip link set {HOST} up")
step(NODE, f"ip link set {HOST}p up")
step(NODE, f"ip addr add 10.9.0.1/24 dev {HOST}")
step(
    NODE,
    "vtysh -c 'configure terminal' "
    f"-c 'interface {HOST}' -c 'ip igmp' -c 'end'",
)
wait_step(
    NODE,
    f"vtysh -c 'show ip igmp interface {HOST}'",
    match="up",
    desc=f"{NODE} pimd has IGMP up on {HOST}",
    timeout=20,
)


def host_plumbed():
    # rpush,<host>,<radio> is stored as group rpush:<host>.
    # push,<radio>,<host> adds the host to the radio's push:<radio> group.
    names = group_names()
    if "rpush:host0" not in names:
        return False
    grouping = show_rows("show interface grouping")
    radio = group_row(grouping, "push:eth0")
    dests = set((radio or {}).get("Interfaces") or [])
    return HOST in dests


wait_until(
    f"{NODE} host LAN {HOST} is pushed from {ETH0} and has rpush",
    host_plumbed,
    timeout=25,
)
grouping = show_json(NODE, "show interface grouping", INST)
net = group_row(grouping, "net")
have = set((net or {}).get("Interfaces") or [])
test_step(HOST not in have, f"{NODE} {HOST} stays out of the relay group", target=NODE)
test_step(ETH0 in have, f"{NODE} {ETH0} stays in the relay group", target=NODE)
wait_em_managed(NODE, INST, ETH0, GROUP, timeout=15)

section("IGMP leave is applied")

# Drop the receiver socket first, or its next report puts the group back.
# Kill by pid. pkill -f matches the shell running that command and can
# exit before the sleeper is signaled.
# clear ip igmp drops the learned group without removing ip igmp, so the
# interface stays in the IGMP-up set and SMF does not delete it.
step(NODE, "if [ -s /tmp/igmp-join.pid ]; then kill -9 $(cat /tmp/igmp-join.pid) || true; fi")
step(NODE, "vtysh -c 'clear ip igmp interfaces'")


def pimd_dropped_group():
    # Text "show ip igmp groups" can be empty while the JSON poll SMF
    # reads still lists the group. Check that same JSON.
    out = step(NODE, "vtysh -c 'show ip igmp vrf all groups json' || true")
    return GROUP not in (out or "")


def smf_dropped_group():
    rows = show_rows("show igmp groups")
    if not isinstance(rows, list):
        return False
    for row in rows:
        if not isinstance(row, dict) or row.get("Interface") != ETH0:
            continue
        groups = row.get("Groups") if isinstance(row.get("Groups"), list) else []
        return GROUP not in groups
    return True


wait_until(f"{NODE} pimd dropped {GROUP}", pimd_dropped_group, timeout=30)
wait_until(f"{NODE} show igmp groups dropped {GROUP}", smf_dropped_group, timeout=30)

section("Removed IGMP interface is added again")

expect_ok(NODE, f"remove {ETH0}", INST)
listing = show_json(NODE, "show interface", INST)
test_step(
    iface_row(listing, ETH0) is None,
    f"{NODE} {ETH0} is gone after remove",
    target=NODE,
)


def eth0_managed_again():
    row = iface_row(show_rows("show interface"), ETH0)
    return row is not None and row.get("Managed") is True


wait_until(
    f"{NODE} {ETH0} is back and managed",
    eth0_managed_again,
    timeout=20,
)

section("eth1 leaving VRF red is learned")

log_end = "".join(ch for ch in step(NODE, "wc -c < nrlsmf.log") if ch.isdigit())
step(NODE, "ip link set eth1 nomaster")


def red_without_eth1():
    new = step(NODE, f"tail -c +{int(log_end) + 1} nrlsmf.log || true")
    blocks = []
    current = None
    for line in (new or "").splitlines():
        if "vrf name = red" in line:
            current = []
            blocks.append(current)
            continue
        if current is None:
            continue
        if "vrf name =" in line or "VRF table" in line:
            current = None
            continue
        current.append(line)
    if not blocks:
        return False
    return not any(ETH1 in line.split() for line in blocks[-1])


wait_until(f"{NODE} VRF red no longer includes {ETH1}", red_without_eth1, timeout=25)
