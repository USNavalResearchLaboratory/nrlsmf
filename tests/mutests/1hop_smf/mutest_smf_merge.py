"""Example: nrlsmf `merge` -- forced relay between two host LANs.

Topology (shared with other tests in this directory):

  h0 -- lan0 --\\
                 r0
  h1 -- lan1 --/

What `merge` means here
--------------------------
`merge <ifaceList>` is a "Gateway Command": it forces relay of packets
from any interface in the list to all the others, subject to normal
duplicate-packet detection and TTL limits, but -- unlike classical
flooding (`cf`, see mutest_smf_cf.py) -- it never retransmits a packet
back out the interface it arrived on. For a simple two-interface case
like this one, that distinction doesn't show up in the traffic pattern
(there's only one "other" interface to relay to either way), but it
matters in gateway-style setups with more than two interfaces, where
`cf` would flood back out every interface including ones that clearly
don't need it.

This test uses `merge eth0,eth1` on r0 to bridge multicast traffic
between h0's LAN and h1's LAN: h0 sends multicast, r0 relays it across,
h1 receives it.

What this example covers
-------------------------
* nrlsmf started with `merge eth0,eth1` on r0.
* An iperf UDP multicast flow from h0 to 239.0.0.1, relayed across to
  h1's LAN by nrlsmf and received there.

See mutest_smf_cli.py (CLI sanity checks, no traffic), mutest_smf_cf.py
(classical flooding), mutest_smf_elastic.py (elastic/rate-limited
multicast), and mutest_smf_advertise.py (EM_ADV control messages) for
the other nrlsmf modes on this same topology.
"""

from munet.mutest.userapi import script_dir
from munet.mutest.userapi import section
from munet.mutest.userapi import step
from munet.mutest.userapi import test_step
from munet.mutest.userapi import wait_step

import sys

sys.path.insert(0, str(script_dir()))
sys.path.insert(0, str(script_dir().parent))
from onehop_hosts import cleanup_iperf
from onehop_hosts import setup_mcast_route
from onehop_hosts import start_mcast_client
from onehop_hosts import start_mcast_server
from onehop_hosts import wait_mcast_receiver
from smf_cli import check_common_show
from smf_cli import show_json

MCAST_GROUP = "239.0.0.1"

section("Verify interfaces are ready")

for node in ("h0", "h1", "r0"):
    step(node, "ethtool -K eth0 rx off tx off")

step("r0", "ethtool -K eth1 rx off tx off")

wait_step(
    "h0",
    "ip -br addr show dev eth0",
    match="10.0.0.2/24",
    desc="h0 has address 10.0.0.2/24",
)
wait_step(
    "h1",
    "ip -br addr show dev eth0",
    match="10.0.1.2/24",
    desc="h1 has address 10.0.1.2/24",
)

section("Start nrlsmf merge eth0,eth1 on r0")

step("r0", "nrlsmf debug 4 merge eth0,eth1 &> nrlsmf-merge.log &")

wait_step(
    "r0",
    'pgrep -af "nrlsmf.*merge eth0,eth1"',
    match="merge eth0,eth1",
    desc="nrlsmf is started with merge eth0,eth1",
)

wait_step(
    "r0",
    'grep "regular group" nrlsmf-merge.log',
    match='"merge" eth0,eth1',
    desc="nrlsmf-merge.log contains merge group for eth0,eth1",
)

section("nrlsmf --cli show commands (json)")

check_common_show("r0", group_name="merge", ifaces=("eth0", "eth1"))
ver = show_json("r0", "show ver")
test_step(isinstance(ver, dict) and bool(ver.get("Version")),
          "r0 show ver json matches show version", target="r0")
wait_step(
    "r0",
    'nrlsmf --cli -c "show i"',
    match="ambiguous command",
    desc="nrlsmf --cli show i is ambiguous (interface vs igmp)",
    timeout=10,
)
tunnels = show_json("r0", "show tunnel")
test_step(isinstance(tunnels, list) and len(tunnels) == 0,
          "r0 show tunnel json is empty (no GRE mappings)", target="r0")
neighbors = show_json("r0", "show tunnel neighbors")
test_step(isinstance(neighbors, list) and len(neighbors) == 0,
          "r0 show tunnel neighbors json is empty (no GRE)", target="r0")
wait_step(
    "r0",
    'nrlsmf --cli -c "show version json" -c "show statistics json"',
    match="Version",
    desc="nrlsmf --cli multiple -c commands (json)",
    timeout=10,
)

section("Multicast from h0 reaches h1 via merge relay on r0")

setup_mcast_route(step)
start_mcast_server(step)
start_mcast_client(step, wait_step)
wait_mcast_receiver(
    wait_step,
    match="8 pps",
    desc=f"h1 receiving {MCAST_GROUP} at full rate of 8 pps",
)

section("Cleanup")

cleanup_iperf(step)
step("r0", "pkill nrlsmf || true")

wait_step(
    "r0",
    'pgrep -af "nrlsmf" || true',
    match="",
    desc="r0 nrlsmf stopped",
)

test_step(True, "nrlsmf merge mutest completed")
