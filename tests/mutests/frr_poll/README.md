# FRR poll mutest

One router. No forwarding traffic. nrlsmf is started with `with-frr`
and the test checks the poll threads.

```
r0 -- lan0
  `-- lan1
```

eth0 is in the default VRF with IGMP. eth1 is in VRF red.

## Tests

| File | What it covers |
|------|----------------|
| `mutest_smf_frr_poll.py` | Control-socket ping while pimd and zebra are stopped, an IGMP group applied on eth0, and VRF red learned from zebra |

## Run

From `tests/mutests` (requires root, FRR, an elastic `nrlsmf` on PATH):

```bash
sudo mutest frr_poll
```
