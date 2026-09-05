"""Helpers to query a running nrlsmf via ``nrlsmf --cli`` JSON show commands."""

import json
import time

from munet.mutest.userapi import step
from munet.mutest.userapi import test_step


def cli_cmd(node, command, instance=None):
    inst = f"-i {instance} " if instance else ""
    return step(node, f"nrlsmf --cli {inst}-c {json.dumps(command)}")


def parse_json_blob(text):
    text = text.strip()
    start = None
    for i, ch in enumerate(text):
        if ch in "[{":
            start = i
            break
    if start is None:
        raise ValueError(f"no JSON object in {text[:200]!r}")
    text = text[start:]
    end_obj = text.rfind("}")
    end_arr = text.rfind("]")
    end = max(end_obj, end_arr)
    if end >= 0:
        text = text[: end + 1]
    return json.loads(text)


def show_json(node, show_cmd, instance=None):
    raw = cli_cmd(node, f"{show_cmd} json", instance)
    try:
        data = parse_json_blob(raw)
    except (json.JSONDecodeError, ValueError) as err:
        test_step(
            False,
            f"{node} '{show_cmd} json' parse failed: {err}: {raw[:240]!r}",
            target=node,
        )
        return None
    return data


def check_common_show(node, instance=None, group_name=None, ifaces=None):
    """Ping plus JSON show version/statistics/interface/grouping."""
    pong = cli_cmd(node, "ping", instance)
    test_step("pong" in pong, f"{node} --cli ping returns pong", target=node)

    ver = show_json(node, "show version", instance)
    if ver is not None:
        test_step(
            isinstance(ver, dict) and bool(ver.get("Version")),
            f"{node} show version json has Version",
            target=node,
        )

    stats = show_json(node, "show statistics", instance)
    if isinstance(stats, list):
        names = {row.get("Interface") for row in stats if isinstance(row, dict)}
        for iface in ifaces or ():
            test_step(iface in names, f"{node} statistics includes {iface}", target=node)

    listing = show_json(node, "show interface", instance)
    if isinstance(listing, list):
        names = {row.get("Interface") for row in listing if isinstance(row, dict)}
        for iface in ifaces or ():
            test_step(iface in names, f"{node} interface list includes {iface}", target=node)

    grouping = show_json(node, "show interface grouping", instance)
    if isinstance(grouping, list) and group_name:
        gnames = {g.get("GroupName") for g in grouping if isinstance(g, dict)}
        test_step(group_name in gnames,
                  f"{node} grouping includes {group_name}", target=node)


def check_group_elastic(node, instance, group_name, enabled, ifaces=None,
                        group_ifaces=None, absent_ifaces=None):
    """Assert show interface grouping/interface report Elastic on or off."""
    grouping = show_json(node, "show interface grouping", instance)
    if grouping is None:
        return
    groups = [g for g in grouping if isinstance(g, dict) and g.get("GroupName") == group_name]
    test_step(bool(groups), f"{node} grouping includes {group_name}", target=node)
    if groups:
        is_em = groups[0].get("Elastic") is True
        test_step(
            is_em is enabled,
            f"{node} grouping {group_name} Elastic is {enabled}",
            target=node,
        )
        have = set(groups[0].get("Interfaces") or [])
        for iface in group_ifaces or ():
            test_step(
                iface in have,
                f"{node} grouping {group_name} includes {iface}",
                target=node,
            )
        for iface in absent_ifaces or ():
            test_step(
                iface not in have,
                f"{node} grouping {group_name} omits {iface}",
                target=node,
            )
    listing = show_json(node, "show interface", instance)
    if listing is None or not ifaces:
        return
    want = "Elastic" if enabled else "Flood"
    for iface in ifaces:
        rows = [r for r in listing if isinstance(r, dict) and r.get("Interface") == iface]
        test_step(bool(rows), f"{node} interface list includes {iface}", target=node)
        if rows:
            test_step(
                rows[0].get("FwdMethod") == want,
                f"{node} {iface} FwdMethod is {want}",
                target=node,
            )


def check_show_groups(node, instance=None, mcast_addr=None):
    groups = show_json(node, "show groups", instance)
    if groups is None or not isinstance(groups, list):
        return
    if mcast_addr:
        addrs = {g.get("MCastAddr") for g in groups if isinstance(g, dict)}
        test_step(mcast_addr in addrs,
                  f"{node} show groups includes {mcast_addr}", target=node)


def _em_flow(groups, mcast_addr):
    if not isinstance(groups, list):
        return None
    for row in groups:
        if isinstance(row, dict) and row.get("MCastAddr") == mcast_addr:
            return row
    return None


def check_em_flow(node, instance, mcast_addr, ack=None, status=None, fwd_status=None):
    """Assert show groups fields for an EM flow (Ack / Status / FwdStatus)."""
    groups = show_json(node, "show groups", instance)
    flow = _em_flow(groups, mcast_addr)
    test_step(
        flow is not None,
        f"{node} show groups includes {mcast_addr}",
        target=node,
    )
    if flow is None:
        return None
    if ack is not None:
        have = flow.get("Ack")
        test_step(
            have == ack,
            f"{node} {mcast_addr} Ack is {have!r} (want {ack!r})",
            target=node,
        )
    if status is not None:
        have = flow.get("Status")
        test_step(
            have == status,
            f"{node} {mcast_addr} Status is {have!r} (want {status!r})",
            target=node,
        )
    if fwd_status is not None:
        have = flow.get("FwdStatus")
        test_step(
            have == fwd_status,
            f"{node} {mcast_addr} FwdStatus is {have!r} (want {fwd_status!r})",
            target=node,
        )
    return flow


def _igmp_iface(rows, iface):
    for row in rows or ():
        if isinstance(row, dict) and row.get("Interface") == iface:
            return row
    return None


def _igmp_has_group(rows, iface, group):
    row = _igmp_iface(rows, iface)
    if row is None or row.get("Managed") is not True:
        return False
    groups = row.get("Groups") if isinstance(row.get("Groups"), list) else []
    return group in groups


def wait_em_managed(node, instance, iface, group, timeout=20):
    """Poll show igmp groups until iface is Managed and lists group."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = parse_json_blob(cli_cmd(node, "show igmp groups json", instance))
        except (json.JSONDecodeError, ValueError):
            last = None
        if _igmp_has_group(last, iface, group):
            test_step(
                True,
                f"{node} show igmp groups {iface} has {group}",
                target=node,
            )
            return last
        time.sleep(1)
    test_step(
        False,
        f"{node} show igmp groups {iface} missing {group}",
        target=node,
    )
    return last


def wait_em_flow(node, instance, mcast_addr, ack=None, status=None, timeout=20):
    """Poll show groups until the flow exists and optional Ack/Status match."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = parse_json_blob(cli_cmd(node, "show groups json", instance))
        except (json.JSONDecodeError, ValueError):
            last = None
        flow = _em_flow(last, mcast_addr)
        if flow is not None:
            if ack is not None and flow.get("Ack") != ack:
                time.sleep(1)
                continue
            if status is not None and flow.get("Status") != status:
                time.sleep(1)
                continue
            return check_em_flow(
                node, instance, mcast_addr, ack=ack, status=status,
            )
        time.sleep(1)
    return check_em_flow(node, instance, mcast_addr, ack=ack, status=status)


def wait_show_groups(node, instance, mcast_addr, timeout=20):
    """Poll show groups until the EM FIB lists ``mcast_addr``."""
    wait_em_flow(node, instance, mcast_addr, timeout=timeout)


def _rows_for_iface(rows, iface):
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict) and r.get("Interface") == iface]


def check_show_tunnel(node, instance, iface, local=None, remotes=None, overlay_ip=None,
                      want_c=None):
    """Assert show tunnel json rows for iface (underlay Local/Remote, overlay IP)."""
    rows = show_json(node, "show tunnel", instance)
    if rows is None:
        return
    on_if = _rows_for_iface(rows, iface)
    test_step(bool(on_if), f"{node} show tunnel has {iface}", target=node)
    if local:
        test_step(any(r.get("Local") == local for r in on_if),
                  f"{node} show tunnel Local {local} on {iface}", target=node)
    if overlay_ip:
        test_step(any(r.get("IP") == overlay_ip for r in on_if),
                  f"{node} show tunnel IP {overlay_ip} on {iface}", target=node)
    if remotes:
        have = {r.get("Remote") for r in on_if}
        for remote in remotes:
            test_step(remote in have,
                      f"{node} show tunnel Remote {remote} on {iface}", target=node)
    if want_c is True:
        test_step(any("C" in (r.get("Flags") or "") for r in on_if),
                  f"{node} show tunnel Flags include C on {iface}", target=node)
    elif want_c is False:
        test_step(all("C" not in (r.get("Flags") or "") for r in on_if),
                  f"{node} show tunnel Flags omit C on {iface}", target=node)


def check_show_neighbors(node, instance, iface, remotes=None, neighbor_ips=None,
                         min_count=0, want_c=None):
    """Assert show tunnel neighbors json for iface (Neighbor IP / Remote)."""
    rows = show_json(node, "show tunnel neighbors", instance)
    if rows is None:
        return
    on_if = _rows_for_iface(rows, iface)
    test_step(len(on_if) >= min_count,
              f"{node} show tunnel neighbors has >= {min_count} row(s) on {iface}",
              target=node)
    if remotes:
        have = {r.get("Remote") for r in on_if}
        for remote in remotes:
            test_step(remote in have,
                      f"{node} neighbor Remote {remote} on {iface}", target=node)
    if neighbor_ips:
        have = {r.get("NeighborIP") for r in on_if}
        for nip in neighbor_ips:
            test_step(nip in have,
                      f"{node} Neighbor IP {nip} on {iface}", target=node)
    if want_c is True:
        test_step(any("C" in (r.get("Flags") or "") for r in on_if),
                  f"{node} neighbor Flags include C on {iface}", target=node)
