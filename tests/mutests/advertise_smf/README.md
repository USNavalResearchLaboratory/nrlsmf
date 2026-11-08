# Advertise-mode mutest

The multicast source is an attached host, not an nrlsmf router. r2 is a longer path from r0 to r1. r3 is another router on the direct LAN, and r4 is another router on the LAN between r0 and r2.

```
                    r3
                    |
h0 -- lan0 -- r0 -- net0 -- r1 -- lan1 -- h1
              |             |
             net1          net2
              | \           |
             r4  r2 --------+
```

| Node | Interface | Address |
|------|-----------|---------|
| h0 | eth0 | 10.0.0.2/24 |
| r0 | eth0 (lan0), eth1 (net0), eth2 (net1) | 10.0.0.1/24, 10.0.2.1/24, 10.0.3.1/24 |
| r1 | eth0 (net0), eth1 (lan1), eth2 (net2) | 10.0.2.2/24, 10.0.1.1/24, 10.0.4.2/24 |
| r2 | eth0 (net1), eth1 (net2) | 10.0.3.2/24, 10.0.4.1/24 |
| r3 | eth0 (net0) | 10.0.2.3/24 |
| r4 | eth0 (net1) | 10.0.3.3/24 |
| h1 | eth0 | 10.0.1.2/24 |

`mutest_smf_advertise.py` starts `advertise` + `elastic` on every router. h0 sends 239.0.0.1. After a few advertisement intervals the test captures EM_ADV on r0's net0 and net1 interfaces and checks:

* On net0, r0 originates the flow (advertiser 10.0.2.1, hop 1, metric 0, TTL = the TTL h0 sent). h0 never sends EM_ADV.
* r1 (10.0.2.2) forwards that advertisement (same advertiser, hop 2, TTL decremented by one, metric 1). A hop-2 copy from r3 does not count as r1.
* On net1, r0 originates again (advertiser 10.0.3.1, hop 1, metric 0) and r2 (10.0.3.2) forwards it. A hop-2 copy from r4 does not count as r2.

## Run

From `tests/mutests` (requires root, FRR, `nrlsmf` on PATH):

```bash
sudo mutest advertise_smf
```
