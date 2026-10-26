"""Advertise mode: an attached host is originated, then forwarded.

Topology:

                 r3
                 |
  h0 -- lan0 -- r0 -- net0 -- r1 -- lan1 -- h1
                |             |
               net1          net2
                | \\           |
               r4  r2 ---------+

h0 is not an nrlsmf router. It sends 239.0.0.1. r0 is the first router
on that LAN, so it must originate EM_ADV on each of its router links
(advertiser = that link's address, hop count 1, metric 0, TTL = the TTL
h0 sent). r2 is a longer path to r1. r3 is another router on net0 and
r4 is another router on net1, so those LANs have more than one
forwarder. r0 must keep originating for h0. The hop-2 advertisement on
net0 must come from r1, and the hop-2 advertisement on net1 must come
from r2.

1hop_smf/mutest_smf_advertise.py only checks that some UDP/5555 packet
to 224.0.0.55 exists. This test checks the fields.

Capture starts after a few advertisement intervals. That is the case
the origination fix is about: once the other routers have advertised
back, r0 must still be originating for h0, because h0's TTL is closer
than those advertisements.
"""

from munet.mutest.userapi import log
from munet.mutest.userapi import script_dir
from munet.mutest.userapi import section
from munet.mutest.userapi import step
from munet.mutest.userapi import test_step
from munet.mutest.userapi import wait_step

import sys

sys.path.insert(0, str(script_dir()))
from emadv import advs_from_tcpdump_xx
from emadv import format_adv

MCAST = "239.0.0.1"
H0 = "10.0.0.2"
R0_NET0 = "10.0.2.1"  # r0 eth1 on net0, direct link to r1
R1_NET0 = "10.0.2.2"  # r1 eth0 on net0
R3_NET0 = "10.0.2.3"  # r3 eth0 on net0
R0_NET1 = "10.0.3.1"  # r0 eth2 on net1, link to r2
R2_NET1 = "10.0.3.2"  # r2 eth0 on net1
R4_NET1 = "10.0.3.3"  # r4 eth0 on net1
# iperf -T. r0 observes this TTL and puts it in the originated EM_ADV.
ORIGIN_TTL = 16
UDP = 17

# r3 is only on net0. r4 is only on net1. r2 joins net1 to net2.
ROUTERS = {
    "r0": "eth0,eth1,eth2",
    "r1": "eth0,eth1,eth2",
    "r2": "eth0,eth1",
    "r3": "eth0",
    "r4": "eth0",
}

section("Verify interfaces are ready")

for node in ("h0", "h1", "r0", "r1", "r2", "r3", "r4"):
    step(node, "ethtool -K eth0 rx off tx off")

for node in ("r0", "r1", "r2"):
    step(node, "ethtool -K eth1 rx off tx off")

for node in ("r0", "r1"):
    step(node, "ethtool -K eth2 rx off tx off")

wait_step("h0", "ip -br addr show dev eth0", match=f"{H0}/24", desc="h0 address")
wait_step("r0", "ip -br addr show dev eth1", match=f"{R0_NET0}/24", desc="r0 net0 address")
wait_step("r0", "ip -br addr show dev eth2", match=f"{R0_NET1}/24", desc="r0 net1 address")
wait_step("r1", "ip -br addr show dev eth0", match=f"{R1_NET0}/24", desc="r1 net0 address")
wait_step("r1", "ip -br addr show dev eth2", match="10.0.4.2/24", desc="r1 net2 address")
wait_step("r2", "ip -br addr show dev eth0", match=f"{R2_NET1}/24", desc="r2 net1 address")
wait_step("r3", "ip -br addr show dev eth0", match=f"{R3_NET0}/24", desc="r3 net0 address")
wait_step("r4", "ip -br addr show dev eth0", match=f"{R4_NET1}/24", desc="r4 net1 address")
wait_step("h1", "ip -br addr show dev eth0", match="10.0.1.2/24", desc="h1 address")

section("Start advertise mode on every router")

for node, ifaces in ROUTERS.items():
    # Distinct instance names: the nodes share /tmp, and the default
    # control socket /tmp/nrlsmf can be bound by only one of them.
    step(
        node,
        "nrlsmf debug 4 instance " + node + " advertise add net,cf," + ifaces +
        " elastic net &> nrlsmf-advertise.log &",
    )
    wait_step(
        node,
        'pgrep -af "nrlsmf.*instance ' + node + '"',
        match="advertise",
        desc=f"{node} nrlsmf advertise is running",
    )
    wait_step(
        node,
        'grep "regular group" nrlsmf-advertise.log',
        match=f'"net" {ifaces}',
        desc=f"{node} elastic group net is {ifaces}",
    )
    wait_step(
        node,
        "grep -c 'Couldn.t open default control pipe' nrlsmf-advertise.log || true",
        match="0",
        desc=f"{node} control socket opened",
    )

section("h0 sources a multicast flow")

for node, iface in (("h0", "eth0"), ("h1", "eth0")):
    step(node, f"ip route replace {MCAST}/32 dev {iface}")

step(
    "h1",
    f"iperf -u -T 4 -i 1 -s -e -B {MCAST}%eth0 > iperf-server.log 2>&1 &",
)
step(
    "h0",
    f"iperf -u -T {ORIGIN_TTL} -t 1000 -i 1 -b 8pps -l 1024 -e "
    f"-B {H0} -c {MCAST} &> iperf-client.log &",
)
wait_step(
    "h0",
    'grep "8 pps" iperf-client.log',
    match="8 pps",
    desc="h0 is sending",
    timeout=30,
)

# Let the other routers advertise back, including the longer path through r2.
# r0 must keep originating after that.
step("r0", "sleep 4")

section("EM_ADV on the direct and alternate paths")


def capture(node, iface):
    dump = step(
        node,
        "timeout 10 tcpdump -l -n -i " + iface + " -c 40 -xx "
        "'udp and dst port 5555 and dst host 224.0.0.55' || true",
    )
    advs = [
        adv
        for adv in advs_from_tcpdump_xx(dump)
        if adv["src"] == H0 and adv["dst"] == MCAST and adv["proto"] == UDP
    ]
    if advs:
        log(
            "EM_ADV on %s %s for %s -> %s:\n%s",
            node,
            iface,
            H0,
            MCAST,
            "\n".join(format_adv(a) for a in advs),
        )
    else:
        log(
            "no EM_ADV for %s -> %s on %s %s:\n%s",
            H0,
            MCAST,
            node,
            iface,
            dump[-2000:],
        )
    return advs


def is_origin(adv, advertiser):
    return (
        adv["adv"] == advertiser
        and adv["hops"] == 1
        and adv["metric"] == 0
        and adv["ttl"] == ORIGIN_TTL
    )


def is_forward(adv, advertiser, sender):
    return (
        adv["ip_src"] == sender
        and adv["adv"] == advertiser
        and adv["hops"] == 2
        and adv["metric"] == 1
        and adv["ttl"] == ORIGIN_TTL - 1
    )


net0 = capture("r0", "eth1")
net1 = capture("r0", "eth2")

test_step(
    any(is_origin(adv, R0_NET0) for adv in net0),
    f"r0 originates for attached host {H0} on net0: "
    f"advertiser {R0_NET0}, hop 1, metric 0, ttl {ORIGIN_TTL}",
    target="r0",
)
test_step(
    any(is_forward(adv, R0_NET0, R1_NET0) for adv in net0),
    f"r1 ({R1_NET0}) forwards the net0 advertisement, not r3 or the path via r2: "
    f"advertiser {R0_NET0}, hop 2, metric 1, ttl {ORIGIN_TTL - 1}",
    target="r1",
)
test_step(
    any(is_origin(adv, R0_NET1) for adv in net1),
    f"r0 also originates on net1 toward r2: advertiser {R0_NET1}, "
    f"hop 1, metric 0, ttl {ORIGIN_TTL}",
    target="r0",
)
test_step(
    any(is_forward(adv, R0_NET1, R2_NET1) for adv in net1),
    f"r2 ({R2_NET1}) forwards that advertisement on net1, not r4: "
    f"advertiser {R0_NET1}, hop 2, metric 1, ttl {ORIGIN_TTL - 1}",
    target="r2",
)

section("Cleanup")

step("h0", "pkill iperf || true")
step("h1", "pkill iperf || true")
for node in ROUTERS:
    step(node, "pkill nrlsmf || true")
step("r0", "pkill tcpdump || true")
