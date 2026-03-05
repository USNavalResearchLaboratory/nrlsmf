"""Basic SMF mutest."""

import subprocess

from munet.mutest.userapi import match_step, step
from munet.mutest.userapi import section
from munet.mutest.userapi import test_step
from munet.mutest.userapi import wait_step


def pipe(cmd: str) -> subprocess.Popen:
    """Start a command and capture stdout/stderr through a pipe."""
    return subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def pipe_read(proc: subprocess.Popen, lines: int = 1) -> str:
    """Read up to 'lines' lines from a running process."""
    out = []
    if proc.stdout is None:
        return ""
    for _ in range(lines):
        line = proc.stdout.readline()
        if not line:
            break
        out.append(line)
    return "".join(out)


def pipe_close(proc: subprocess.Popen, timeout: int = 5) -> None:
    """Terminate a process cleanly, then force kill if needed."""
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


section("Verify interfaces are ready")

for node in ("h1", "h2", "r1"):
    step(node, "ethtool -K eth0 rx off tx off")

step("r1", "ethtool -K eth1 rx off tx off")

wait_step(
    "h1",
    "ip -br addr show dev eth0 ",
    match="10.0.1.2/24",
    desc="IP address assigned to eth0",
)
wait_step(
    "h2",
    "ip -br addr show dev eth0 ",
    match="10.0.2.2/24",
    desc="IP address assigned to eth0",
)

wait_step(
    "r1",
    "ip -br addr show dev eth0 ",
    match="10.0.1.1/24",
    desc="IP address assigned to eth1",
)

wait_step(
    "r1",
    "ip -br addr show dev eth1 ",
    match="10.0.2.1/24",
    desc="IP address assigned to eth1",
)

section("Validate simple nrlsmf CLI arguments")

help_output = step("r1", "sh -lc 'nrlsmf help; echo EXIT:$?'")
test_step("Usage: nrlsmf" in help_output, "nrlsmf help prints usage", target="r1")
test_step("EXIT:0" in help_output, "nrlsmf help exits successfully", target="r1")
test_step("forward             {on | off}" in help_output, "nrlsmf help lists forward option", target="r1")
test_step("relay               {on | off}" in help_output, "nrlsmf help lists relay option", target="r1")
test_step("resequence          {on | off}" in help_output, "nrlsmf help lists resequence option", target="r1")
test_step("window              {on | off}" in help_output, "nrlsmf help lists window option", target="r1")

version_output = step("r1", "nrlsmf version")
test_step(bool(version_output.strip()), "nrlsmf version prints non-empty output", target="r1")

version_abbrev_output = step("r1", "sh -lc 'nrlsmf ver; echo EXIT:$?'")
test_step("smf version:" in version_abbrev_output, "abbreviated 'ver' prints version", target="r1")
test_step("EXIT:0" in version_abbrev_output, "abbreviated 'ver' exits successfully", target="r1")

invalid_cmd_output = step("r1", "sh -lc 'nrlsmf nope; echo EXIT:$?'")
test_step("Usage: nrlsmf" in invalid_cmd_output, "invalid command prints usage", target="r1")
test_step("EXIT:0" not in invalid_cmd_output, "invalid command exits non-zero", target="r1")

ambiguous_cmd_output = step("r1", "sh -lc 'nrlsmf r; echo EXIT:$?'")
test_step("Usage: nrlsmf" in ambiguous_cmd_output, "ambiguous command prints usage", target="r1")
test_step("EXIT:0" not in ambiguous_cmd_output, "ambiguous command exits non-zero", target="r1")

# Merge flooding
section("Start nrlsmf merge eth0,eth1 on r1 ")

step("r1", "nrlsmf debug 4 merge eth0,eth1 &> nrlsmf-merge.log &")

wait_step(
    "r1",
    'pgrep -af "nrlsmf.*merge eth0,eth1"',
    match="merge eth0,eth1",
    desc="nrlsmf is started with merge eth0,eth1",
)

wait_step(
    "r1",
    'grep  "regular group" nrlsmf-merge.log',
    match='"merge" eth0,eth1',
    desc="nrlsmf-merge.log contains merge group for eth0,eth1",
)

step(
    "h1",
    "iperf -u -T 4 -t 1000 -i 1 -b 8pps -l 1024 -e -c 239.0.0.1 &> iperf-client.log &",
)

wait_step(
    "h1",
    "tail -n1 iperf-client.log",
    match="8 pps",
    desc="Sending 239.0.0.1 at 8 pps",
)

step("h2", "iperf -u -T 4 -i 1 -s -e -B 239.0.0.1 > iperf-server.log 2>&1 &")

wait_step(
    "h2",
    "tail -n1 iperf-server.log",
    match="8 pps",
    desc="Receiving 239.0.0.1 at full rate of 8 pps",
)

step("r1", "pkill nrlsmf")

wait_step(
    "r1",
    'pgrep -af "nrlsmf"',
    match="",
    desc="stopped nrlsmf",
)

# Classic flooding
section("Start nrlsmf with classic flooding on r1 ")
step(
    "r1",
    "nrlsmf debug 4 add net,cf,eth0,eth1 &> nrlsmf-cf.log &",
)

wait_step(
    "r1",
    'pgrep -af "nrlsmf.*net,cf,eth0,eth1"',
    match="net,cf,eth0,eth1",
    desc="nrlsmf is started with classic flooding group",
)

wait_step(
    "r1",
    'grep  "regular group" nrlsmf-cf.log',
    match='"net" eth0,eth1',
    desc='nrlsmf-cf.log contains group "net" eth0,eth1',
)

wait_step(
    "r1",
    'grep  "regular group" nrlsmf-cf.log',
    match='"push:eth0" eth0',
    desc='nrlsmf-cf.log contains group "push:eth0" eth0',
)
wait_step(
    "r1",
    'grep  "regular group" nrlsmf-cf.log',
    match='"push:eth1" eth1',
    desc='nrlsmf-cf.log contains group "push:eth1" eth1',
)

wait_step(
    "h2",
    "tail -n1 iperf-server.log",
    match="8 pps",
    desc="Receiving 239.0.0.1 at full rate of 8 pps",
)

# Elastic flooding
step("r1", "pkill nrlsmf")

wait_step(
    "r1",
    'pgrep -af "nrlsmf"',
    match="",
    desc="stopped nrlsmf",
)
section("Start nrlsmf with elastic flooding r1 ")
step(
    "r1",
    "nrlsmf debug 4 add net,cf,eth0,eth1 elastic net &> nrlsmf-elastic.log &",
)

wait_step(
    "r1",
    'pgrep -af "nrlsmf.*elastic net"',
    match="elastic net",
    desc="nrlsmf is started with elastic group net",
)

wait_step(
    "r1",
    'grep  "regular group" nrlsmf-cf.log',
    match='"net" eth0,eth1',
    desc='nrlsmf-elastic.log contains group "net" eth0,eth1',
)

wait_step(
    "r1",
    'grep  "regular group" nrlsmf-cf.log',
    match='"push:eth0" eth0',
    desc='nrlsmf-elastic.log contains group "push:eth0" eth0',
)
wait_step(
    "r1",
    'grep  "regular group" nrlsmf-cf.log',
    match='"push:eth1" eth1',
    desc='nrlsmf-elastic.log contains group "push:eth1" eth1',
)
# In Elastic flooding, the flow is rate limited to 1.00 KBytes per second.
wait_step(
    "h2",
    "tail -n4 iperf-server.log",
    match="1 pps",
    desc="Receiving 239.0.0.1 rate limited to 1 pps",
    timeout=30,
)
