# GRE / mGRE four-router mutests

Four routers (r0..r3) building GRE/mGRE overlay tunnels across a shared
underlay router (u0).

```
       h0 -- r0 -- lan0 --\
       h1 -- r1 -- lan1 ---\
                            u0   (underlay: routes/relays between the LANs)
       h2 -- r2 -- lan2 ---/
       h3 -- r3 -- lan3 --/
```

`h0`..`h3` are application hosts off `r0`..`r3` (iperf source/receivers; not GRE/SMF nodes).
Each SMF router CFs its host LAN (`eth1`) plus its GRE iface so nrlsmf is
both the first hop onto the overlay and the last hop off it. Overlay GRE
ifaces are `layered` so a packet received on the tunnel is not flooded
back out of it, except the NHRP hub (`r3`): nhrpd only programs
spoke→hub and hub→spokes, so the hub must replicate overlay multicast.

`u0` is the "underlay" node — it plays the role of the WAN/network that
a real GRE tunnel would cross, and that the operator running the
overlay generally does *not* control. It runs no GRE/nrlsmf overlay of
its own except in the multicast-underlay test, where it stands in for
real underlay multicast routing (PIM) as a pure dataplane relay. It is
never given an NHRP role, for the same reason: NHRP is part of the
overlay's own control plane and belongs on operator-controlled
infrastructure, not on the untrusted transit network.

`r0`..`r3` are the routers that actually build tunnels and run nrlsmf.
In the NHRP test, `r3` additionally acts as the hub / NHRP Server —
still one of the operator's own four routers, just doing double duty.

## Tests

| File | Mode | What resolves "which peer?" |
|------|------|------------------------------|
| `mutest_gre_p2p.py` | Point-to-point GRE (two independent pairs: r0<->r1, r2<->r3) | N/A — each tunnel has exactly one fixed peer |
| `mutest_gre_linklocal.py` | Point-to-point GRE, r0<->r1, `tunnel` group with elastic and then advertise | N/A — one fixed peer. Link-local multicast is forwarded at the send rate; other multicast stays under elastic flow control |
| `mutest_mgre_static.py` | Multipoint GRE, static NBMA | Kernel `ip neigh` for overlay unicast; nrlsmf `map <gre>,<local>,dynamic` learns those dests for overlay multicast inject. Ends with runtime `with-frr` + `elastic overlay` on the same `eth1,gre1` group (keep h1, stop h2/h3; idle hosts at most 1 pps). |
| `mutest_mgre_nhrp.py` | Multipoint GRE, NHRP-resolved | FRR `nhrpd` programs kernel `ip neigh` (hub/NHS on `r3`, never `u0`); nrlsmf `map …,dynamic` learns those dests. Spokes are layered; the hub is not (overlay-mcast replicator). |
| `mutest_mgre_mcast.py` | Multipoint GRE, multicast underlay remote | Nothing — underlay multicast fan-out delivers to every peer from one transmission |
| `mutest_gre_external.py` | "External" (metadata) GRE | Per-destination lwtunnel routes for overlay unicast; nrlsmf overlay-multicast inject uses explicit `map <gre>,<local>,<peer>` (`dynamic` does not apply — no `ip neigh`). Skipped on Linux < 5.0. |

Each file's docstring explains its mode in detail, including how it
compares to the others and what it demonstrates about nrlsmf's `map`/
`ujoin`/`uleave` commands. Static NBMA and NHRP overlay multicast use
`map <gre>,<local>,dynamic` (learn from `ip neigh`; nhrpd fills that
table in the NHRP test, and the hub is the overlay-mcast replicator). Multicast-underlay mGRE uses `ujoin`.
External/metadata GRE uses explicit unicast `map`s because the device
has no endpoints to auto-discover and no `ip neigh` table to learn.
`0.0.0.0` is the kernel wildcard remote, not a learn switch.

None of these tests put the overlay on the kernel's fallback `gre0`
(remote any / local any). That device steals inbound GRE and the
overlay subnet if it is left addressed or up. Every variant creates a
dedicated tunnel (`gre1`, or `mgre0` for the multicast-remote case)
and flushes/`down`s `gre0` first.

## Run

From `tests/mutests` (requires root, FRR with `nhrpd` enabled, `nrlsmf` on PATH):

```bash
sudo mutest mgre_four_peers
# or one file:
sudo mutest mgre_four_peers/mutest_gre_p2p.py
sudo mutest mgre_four_peers/mutest_gre_linklocal.py
sudo mutest mgre_four_peers/mutest_mgre_static.py
sudo mutest mgre_four_peers/mutest_mgre_nhrp.py
sudo mutest mgre_four_peers/mutest_mgre_mcast.py
sudo mutest mgre_four_peers/mutest_gre_external.py
```
