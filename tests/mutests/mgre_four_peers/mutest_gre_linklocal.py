"""Link-local multicast on a point-to-point GRE tunnel.

Topology (shared with the other tests in this directory). Only the
r0<->r1 pair is used.

         h0 -- r0 -- lan0 --\\
                             u0
              r1 -- lan1 ---/

nrlsmf runs a tunnel group on eth1 and gre1, so packets are forwarded
between the host LAN and the GRE device without a TTL decrement. The
group is elastic, then the same routers are restarted with advertise.

Link-local multicast (224.0.0.0/24) is forwarded at the send rate.
Other multicast on the same group stays under elastic flow control.
"""

from munet.mutest.userapi import script_dir
from munet.mutest.userapi import section
from munet.mutest.userapi import step
from munet.mutest.userapi import test_step
from munet.mutest.userapi import wait_step

import sys
import time

sys.path.insert(0, str(script_dir()))
sys.path.insert(0, str(script_dir().parent))
from four_peer_hosts import SOURCE_HOST
from four_peer_hosts import cleanup_iperf
from four_peer_hosts import count_overlay_mcast_pkts
from four_peer_hosts import restart_overlay_mcast_servers
from four_peer_hosts import setup_host_lan
from four_peer_hosts import start_host_mcast_client
from four_peer_hosts import start_overlay_mcast_servers
from smf_cli import check_group_elastic

UNDERLAY = {
    "r0": "10.0.0.2",
    "r1": "10.0.1.2",
}
OVERLAY = {
    "r0": "172.16.0.1",
    "r1": "172.16.0.2",
}
GRE_DEV = "gre1"
ROUTERS = ("r0", "r1")
RECEIVERS = ("h1",)
GLOBAL_MCAST = "239.0.0.1"
LINKLOCAL_MCAST = "224.0.0.9"


def start_smf(advertise):
    flag = "advertise " if advertise else ""
    for name in ROUTERS:
        step(name, "pkill nrlsmf || true")
    for name in ROUTERS:
        step(
            name,
            "nrlsmf debug 4 "
            f"instance smf-{name} "
            f"{flag}tunnel eth1,{GRE_DEV} "
            "elastic tunnel "
            f"layered {GRE_DEV} "
            "&> nrlsmf-linklocal.log &",
        )
        wait_step(
            name,
            f'pgrep -af "nrlsmf.*instance smf-{name}"',
            match=f"smf-{name}",
            desc=f"{name} nrlsmf is running",
            timeout=20,
        )
        check_group_elastic(
            name, f"smf-{name}", "tunnel", enabled=True,
            ifaces=("eth1", GRE_DEV),
            method="Advertise" if advertise else "Elastic",
        )


def steady_pps(mcast, ttl):
    restart_overlay_mcast_servers(step, RECEIVERS, mcast)
    step(SOURCE_HOST, "pkill iperf || true")
    # A dying iperf writes "Sent N datagrams" on its old log fd after the
    # next iperf has truncated the file, so tail -n1 would see that line
    # instead of a rate.
    wait_step(
        SOURCE_HOST,
        "pgrep iperf >/dev/null && echo running || echo stopped",
        match="stopped",
        desc="h0 iperf has exited",
        timeout=10,
    )
    start_host_mcast_client(step, wait_step, mcast, ttl=ttl)
    # Skip the first intervals. A shaped flow can still pass its
    # initial bucket before settling.
    time.sleep(4)
    # tcpdump spends about a second starting inside `timeout`, so a
    # 2 second timeout only counts about 1 second of packets.
    window = 5
    n = count_overlay_mcast_pkts(step, "h1", mcast, window_s=window)
    return n / float(window - 1)


section("Disable offloads and wait for underlay addresses")

for name in UNDERLAY:
    step(name, "ethtool -K eth0 rx off tx off || true")
    wait_step(
        name,
        "ip -br addr show dev eth0",
        match=UNDERLAY[name],
        desc=f"{name} underlay address {UNDERLAY[name]}",
        timeout=30,
    )

for ifname, addr in (("eth0", "10.0.0.1"), ("eth1", "10.0.1.1")):
    step("u0", f"ethtool -K {ifname} rx off tx off || true")
    wait_step(
        "u0",
        f"ip -br addr show dev {ifname}",
        match=addr,
        desc=f"u0 {ifname} address {addr}",
        timeout=30,
    )

setup_host_lan(step, wait_step)
step("u0", "sysctl -w net.ipv4.ip_forward=1")

section("Underlay reachability and point-to-point GRE")

wait_step(
    "r0",
    f"ping -c1 -W2 {UNDERLAY['r1']}",
    match="1 received",
    desc="r0 ping underlay r1",
    timeout=20,
)
wait_step(
    "r1",
    f"ping -c1 -W2 {UNDERLAY['r0']}",
    match="1 received",
    desc="r1 ping underlay r0",
    timeout=20,
)

for local, remote in (("r0", "r1"), ("r1", "r0")):
    step(local, "ip addr flush dev gre0 2>/dev/null || true")
    step(local, "ip link set gre0 down 2>/dev/null || true")
    step(local, f"ip link del {GRE_DEV} 2>/dev/null || true")
    step(
        local,
        f"ip link add name {GRE_DEV} type gre "
        f"local {UNDERLAY[local]} remote {UNDERLAY[remote]} ttl 64",
    )
    step(local, f"ip addr add {OVERLAY[local]}/30 dev {GRE_DEV}")
    step(local, f"ip link set {GRE_DEV} multicast on")
    step(local, f"ip link set {GRE_DEV} up")
    wait_step(
        local,
        f"ip -br link show {GRE_DEV}",
        match="UP",
        desc=f"{local} {GRE_DEV} is UP",
    )

wait_step(
    "r0",
    f"ping -c1 -W3 {OVERLAY['r1']}",
    match="1 received",
    desc="r0 ping overlay r1",
    timeout=20,
)

section("Elastic tunnel group")

start_smf(advertise=False)

section("Other multicast stays under elastic flow control")

pps = steady_pps(GLOBAL_MCAST, "16")
test_step(
    pps <= 2.0,
    f"h1 receives {GLOBAL_MCAST} at {pps:.1f} pps under elastic flow control",
    target="h1",
)

section("Link-local multicast is forwarded at the send rate")

pps = steady_pps(LINKLOCAL_MCAST, "1")
test_step(
    pps >= 6.0,
    f"h1 receives {LINKLOCAL_MCAST} at {pps:.1f} pps on an elastic tunnel",
    target="h1",
)

section("Advertise mode still forwards link-local multicast")

start_smf(advertise=True)
pps = steady_pps(GLOBAL_MCAST, "16")
test_step(
    pps <= 2.0,
    f"h1 receives {GLOBAL_MCAST} at {pps:.1f} pps under advertise flow control",
    target="h1",
)
pps = steady_pps(LINKLOCAL_MCAST, "1")
test_step(
    pps >= 6.0,
    f"h1 receives {LINKLOCAL_MCAST} at {pps:.1f} pps with advertise",
    target="h1",
)

section("Cleanup")

cleanup_iperf(step, RECEIVERS)
for name in ROUTERS:
    step(name, "pkill nrlsmf || true")
    wait_step(
        name,
        "pgrep -x nrlsmf >/dev/null && echo running || echo stopped",
        match="stopped",
        desc=f"{name} nrlsmf stopped",
        timeout=15,
    )

test_step(True, "GRE link-local multicast mutest completed")
