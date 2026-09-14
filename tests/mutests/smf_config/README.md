# Single-node nrlsmf config parse mutest

One host (`r0`) with two LAN interfaces. No forwarding traffic -- the
test starts nrlsmf, sends config commands over `--cli`, and checks
`show ... json` for the parsed result.

```
r0 -- lan0
  `-- lan1
```

## Tests

| File | What it covers |
|------|-----------------|
| `mutest_smf_config.py` | Runtime config over `--cli`, including a missing iface that is stubbed then bound when a dummy of that name appears |

## Run

From `tests/mutests` (requires root, `nrlsmf` on PATH):

```bash
sudo mutest smf_config
```
