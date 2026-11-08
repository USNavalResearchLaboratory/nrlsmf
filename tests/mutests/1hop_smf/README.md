# Single-router nrlsmf mutests

One router (r0) bridging two host LANs, exercising nrlsmf's basic
forwarding modes and CLI.

```
h0 -- lan0 --\
              r0
h1 -- lan1 --/
```

## Tests

| File | What it covers |
|------|-----------------|
| `mutest_smf_cli.py` | nrlsmf command-line parsing sanity checks (`help`, `version`, invalid/ambiguous commands) — no host traffic |
| `mutest_smf_merge.py` | `merge eth0,eth1` — forced two-interface relay (Gateway Command) |
| `mutest_smf_cf.py` | `add net,cf,eth0,eth1` — classical flooding, including the implicit `push:eth0`/`push:eth1` sub-groups it creates |
| `mutest_smf_elastic.py` | Elastic Multicast (EM) overlaid on the same `cf` group — data-plane rate limiting instead of blind flooding |
| `mutest_smf_advertise.py` | EM `advertise` mode — confirms EM_ADV control messages are actually sent (224.0.0.55:5555). Field checks (attached-host origination and hop-by-hop forward) are in `advertise_smf/` |

Each file's docstring explains what its mode means and how it differs
from the others, and each is self-contained (starts and stops its own
nrlsmf instance and any iperf/tcpdump processes it needs).

## Run

From `tests/mutests` (requires root, FRR, `nrlsmf` on PATH):

```bash
sudo mutest 1hop_smf
# or one file:
sudo mutest 1hop_smf/mutest_smf_cli.py
sudo mutest 1hop_smf/mutest_smf_merge.py
sudo mutest 1hop_smf/mutest_smf_cf.py
sudo mutest 1hop_smf/mutest_smf_elastic.py
sudo mutest 1hop_smf/mutest_smf_advertise.py
```
