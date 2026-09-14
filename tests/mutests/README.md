# Munet Tests

This directory is the home for new munet-based tests.

## Quick start

- Install munet with pip:

```bash
pip install munet
```

- To run the tests, change to the `tests/mutests` directory and run mutest:

```bash
cd tests/mutests
sudo mutest
```

- To run a single suite:

```bash
sudo mutest mgre_four_peers
sudo mutest 1hop_smf
sudo mutest smf_config
sudo mutest mgre_chained_clouds
```

## Repo venv (local munet on PATH)

`sudo mutest` will still use a local munet (pipx, `~/.local`, a
checkout). Point sudo at the repo venv binary instead:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install munet

cd tests/mutests
sudo ../../.venv/bin/mutest smf_config
```

## Suites

| Directory | Covers |
|-----------|--------|
| `smf_config/` | Single node: nrlsmf config commands parsed and reflected in show json |
| `1hop_smf/` | Single router, two host LANs: basic nrlsmf CLI and forwarding modes (merge, classical flooding, elastic, advertise) |
| `mgre_four_peers/` | Four routers across a shared underlay: every GRE/mGRE tunnel mode nrlsmf supports (point-to-point, static NBMA mGRE, NHRP-resolved mGRE, multicast-underlay mGRE, external/metadata GRE), one mode per test |
| `mgre_chained_clouds/` | All five of those modes chained together end to end across five segments, connected only by nrlsmf relaying (never IP routing) |

See each suite's own `README.md` for its topology and the list of
individual test files within it.
