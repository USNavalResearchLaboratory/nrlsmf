"""Single-node nrlsmf config parse check.

Topology:

  r0 -- lan0
    `-- lan1

No traffic. Start nrlsmf, send config over --cli, and assert show json
matches what was parsed. A missing iface is kept as a stub, then a
dummy with that name is added and SMF must bind it. Invalid syntax
still fails.
"""

from munet.mutest.userapi import script_dir
from munet.mutest.userapi import section
from munet.mutest.userapi import step
from munet.mutest.userapi import test_step
from munet.mutest.userapi import wait_step

import sys

sys.path.insert(0, str(script_dir().parent))
from smf_cli import check_common_show
from smf_cli import check_show_tunnel
from smf_cli import expect_failed
from smf_cli import expect_ok
from smf_cli import group_row
from smf_cli import iface_row
from smf_cli import show_json

NODE = "r0"
INST = "smf-cfg"
ETH0 = "eth0"
ETH1 = "eth1"
GRE = "gre1"
STUB = "pending0"
GROUP = "net"
LOCAL = "10.0.0.1"
REMOTE = "10.0.0.2"
OVERLAY = "172.16.0.1"
UJOIN = "239.1.1.1"
JOIN = "239.0.0.1"


def flags_of(row):
    return (row or {}).get("Flags") or ""


section("Bring up interfaces")

step(NODE, f"ethtool -K {ETH0} rx off tx off || true")
step(NODE, f"ethtool -K {ETH1} rx off tx off || true")
step(NODE, f"ip addr add {LOCAL}/24 dev {ETH0} || true")
step(NODE, f"ip addr add 10.0.1.1/24 dev {ETH1} || true")
step(NODE, f"ip link set {ETH0} up")
step(NODE, f"ip link set {ETH1} up")
step(
    NODE,
    f"ip link add {GRE} type gre local {LOCAL} remote {REMOTE} ttl 255 || true",
)
step(NODE, f"ip addr add {OVERLAY}/24 dev {GRE} || true")
step(NODE, f"ip link set {GRE} up")

wait_step(
    NODE,
    f"ip -br addr show dev {ETH0}",
    match=LOCAL,
    desc=f"{NODE} {ETH0} has {LOCAL}",
)
wait_step(
    NODE,
    f"ip -br link show dev {GRE}",
    match="UP",
    desc=f"{NODE} {GRE} is up",
)

section("Start nrlsmf")

step(NODE, f"nrlsmf debug 4 instance {INST} &> nrlsmf.log &")
wait_step(
    NODE,
    f'pgrep -af "nrlsmf.*instance {INST}"',
    match=f"instance {INST}",
    desc=f"nrlsmf instance {INST} is running",
)

check_common_show(NODE, instance=INST)

section("Config a group that includes a missing iface")

expect_ok(NODE, f"add {GROUP},cf,{ETH0},{ETH1},{GRE},{STUB}", INST)
expect_ok(NODE, f"elastic {GROUP}", INST)
expect_ok(NODE, "advertise", INST)

grouping = show_json(NODE, "show interface grouping", INST)
row = group_row(grouping, GROUP)
test_step(row is not None, f"{NODE} grouping includes {GROUP}", target=NODE)
if row is not None:
    have = set(row.get("Interfaces") or [])
    for iface in (ETH0, ETH1, GRE, STUB):
        test_step(iface in have, f"{NODE} {GROUP} includes {iface}", target=NODE)
    test_step(row.get("RelayType") == "cf", f"{NODE} {GROUP} RelayType is cf", target=NODE)
    test_step(
        row.get("ForwardingMode") == "Relay",
        f"{NODE} {GROUP} ForwardingMode is Relay",
        target=NODE,
    )
    test_step(row.get("Elastic") is True, f"{NODE} {GROUP} Elastic is true", target=NODE)

listing = show_json(NODE, "show interface", INST)
stub = iface_row(listing, STUB)
test_step(stub is not None, f"{NODE} interface list includes stub {STUB}", target=NODE)
if stub is not None:
    test_step(
        stub.get("FwdMethod") == "Advertise",
        f"{NODE} stub {STUB} FwdMethod is Advertise",
        target=NODE,
    )

section("Dummy appears; stub binds to the real iface")

step(NODE, "modprobe dummy || true")
step(NODE, f"ip link add {STUB} type dummy")
step(NODE, f"ip addr add 10.0.2.1/24 dev {STUB} || true")
step(NODE, f"ip link set {STUB} up")
step(NODE, f"ethtool -K {STUB} rx off tx off || true")

wait_step(
    NODE,
    f"ip -br addr show dev {STUB}",
    match="10.0.2.1",
    desc=f"{NODE} dummy {STUB} is up",
)
wait_step(
    NODE,
    f'grep "binding stub" nrlsmf.log',
    match=STUB,
    desc=f"nrlsmf bound stub {STUB}",
)

grouping = show_json(NODE, "show interface grouping", INST)
row = group_row(grouping, GROUP)
have = set((row or {}).get("Interfaces") or [])
test_step(STUB in have, f"{NODE} {GROUP} still includes {STUB} after bind", target=NODE)

listing = show_json(NODE, "show interface", INST)
stub = iface_row(listing, STUB)
test_step(stub is not None, f"{NODE} interface list still includes {STUB}", target=NODE)
if stub is not None:
    test_step(
        stub.get("FwdMethod") == "Advertise",
        f"{NODE} bound {STUB} FwdMethod is Advertise",
        target=NODE,
    )

expect_ok(NODE, f"layered {STUB}", INST)
listing = show_json(NODE, "show interface", INST)
stub = iface_row(listing, STUB)
test_step(
    stub is not None and "L" in flags_of(stub),
    f"{NODE} bound {STUB} accepts layered",
    target=NODE,
)

stats = show_json(NODE, "show statistics", INST)
stat_names = {r.get("Interface") for r in (stats or []) if isinstance(r, dict)}
test_step(STUB in stat_names, f"{NODE} statistics includes bound {STUB}", target=NODE)

section("Remaining interface config")

expect_ok(NODE, f"layered {ETH0}", INST)
expect_ok(NODE, f"igmpProxy {ETH1}", INST)
expect_ok(NODE, f"etx {ETH0}", INST)
expect_ok(NODE, f"reliable {ETH0}", INST)

listing = show_json(NODE, "show interface", INST)
eth0 = iface_row(listing, ETH0)
eth1 = iface_row(listing, ETH1)
test_step(eth0 is not None, f"{NODE} interface list includes {ETH0}", target=NODE)
test_step(eth1 is not None, f"{NODE} interface list includes {ETH1}", target=NODE)
if eth0 is not None:
    test_step(
        eth0.get("FwdMethod") == "Advertise",
        f"{NODE} {ETH0} FwdMethod is Advertise",
        target=NODE,
    )
    test_step("L" in flags_of(eth0), f"{NODE} {ETH0} Flags include L (layered)", target=NODE)
if eth1 is not None:
    test_step("I" in flags_of(eth1), f"{NODE} {ETH1} Flags include I (igmpProxy)", target=NODE)

section("Tunnel, underlay join, and EM join")

expect_ok(NODE, f"map {GRE},{LOCAL},{REMOTE}", INST)
check_show_tunnel(NODE, INST, GRE, local=LOCAL, remotes=(REMOTE,), want_c=True)

expect_ok(NODE, f"ujoin {UJOIN},{ETH0}", INST)
expect_ok(NODE, f"join {JOIN}", INST)
memberships = show_json(NODE, "show groups memberships", INST)
maddrs = {r.get("MCastAddr") for r in (memberships or []) if isinstance(r, dict)}
test_step(JOIN in maddrs, f"{NODE} memberships include {JOIN}", target=NODE)

section("Global options")

for cmd in (
    "hash CRC32",
    "ihash MD5",
    "idpd on",
    "window on",
    "forward on",
    "relay on",
    "rate 8000",
    f"rate {ETH0},16000",
    "queue 8",
    f"queue {ETH0},16",
    "delayoff 0",
    "boost on",
    "filterDups on",
    "debug 3",
    "allow 239.2.2.2",
    "deny 239.3.3.3",
    f"vrf red,10,{ETH1}",
    "utos 8",
    "with-frr",
):
    expect_ok(NODE, cmd, INST)

expect_ok(NODE, "save /tmp/nrlsmf-saved.json", INST)

section("Invalid config is rejected")

expect_failed(NODE, f"add {GROUP},notalgo,{ETH0}", INST)
expect_failed(NODE, "hash NOHASH", INST)
expect_failed(NODE, "relay maybe", INST)
expect_failed(NODE, "forward maybe", INST)
expect_failed(NODE, f"ujoin {LOCAL},{ETH0}", INST)
expect_failed(NODE, f"map {GRE}", INST)
expect_failed(NODE, "add", INST)

section("Cleanup")

step(NODE, "pkill nrlsmf || true")
wait_step(
    NODE,
    'pgrep -af "nrlsmf" || true',
    match="",
    desc="nrlsmf stopped",
)

saved = step(NODE, "cat /tmp/nrlsmf-saved.json")
test_step(
    GROUP in saved or ETH0 in saved,
    f"{NODE} save wrote config mentioning {GROUP} or {ETH0}",
    target=NODE,
)

test_step(True, "nrlsmf config parse mutest completed")
