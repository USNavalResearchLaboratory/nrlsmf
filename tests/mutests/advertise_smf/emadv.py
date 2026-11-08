"""Parse EM_ADV messages out of a tcpdump -xx dump.

Wire layout for an IPv4 advertisement with a source address (see
include/elasticMsg.h, ElasticAdv). Offsets are from the start of the
EM message, which sits in the UDP payload. Several messages may be
bundled in one datagram.

    0     type (2 = ADV)
    1     length in 32-bit words
    2-3   id
    4     flags (high nibble) | address type (low nibble, 1 = IPv4)
    5     advertiser address type (low nibble)
    6     protocol
    7     traffic class
    8-11  destination
    12-15 source
    16    ttl
    17    hop count
    18-19 metric
    20-23 advertiser
"""

import re

ADV = 2
ADDR_IPV4 = 1
FLAG_SOURCE = 0x01
_HEX_LINE = re.compile(r"^\s*0x[0-9a-fA-F]+:\s+(.*)$")


def frames_from_tcpdump_xx(text):
    """Return captured frames (link header included) from tcpdump -xx."""
    frames = []
    current = bytearray()
    in_frame = False
    for line in text.splitlines():
        match = _HEX_LINE.match(line)
        if match:
            in_frame = True
            for word in match.group(1).split():
                if len(word) == 4:
                    current.append(int(word[0:2], 16))
                    current.append(int(word[2:4], 16))
                elif len(word) == 2:
                    current.append(int(word, 16))
            continue
        if in_frame and current:
            frames.append(bytes(current))
            current = bytearray()
            in_frame = False
    if current:
        frames.append(bytes(current))
    return frames


def _ipv4(raw):
    return ".".join(str(b) for b in raw)


def udp_payloads(frame):
    """UDP payloads of IPv4 frames. Yields nothing for non-IPv4."""
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return
    ihl = (frame[14] & 0x0F) * 4
    udp = 14 + ihl
    if ihl < 20 or len(frame) < udp + 8:
        return
    if frame[14 + 9] != 17:
        return
    yield frame[udp + 8 :]


def parse_em_advs(payload):
    """Yield dicts for each EM_ADV in a UDP payload."""
    index = 0
    while index + 4 <= len(payload):
        msg_type = payload[index]
        msg_len = payload[index + 1] << 2
        if msg_len < 4 or index + msg_len > len(payload):
            return
        msg = payload[index : index + msg_len]
        index += msg_len
        if msg_type != ADV or msg_len < 24:
            continue
        flags = msg[4] >> 4
        addr_type = msg[4] & 0x0F
        adv_type = msg[5] & 0x0F
        if addr_type != ADDR_IPV4 or adv_type != ADDR_IPV4:
            continue
        if not (flags & FLAG_SOURCE):
            continue
        yield {
            "proto": msg[6],
            "dst": _ipv4(msg[8:12]),
            "src": _ipv4(msg[12:16]),
            "ttl": msg[16],
            "hops": msg[17],
            "metric": (msg[18] << 8) | msg[19],
            "adv": _ipv4(msg[20:24]),
        }


def _ip_src(frame):
    """IPv4 source of an Ethernet frame, or None."""
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 0x0F) * 4
    if ihl < 20 or len(frame) < 14 + 16:
        return None
    return _ipv4(frame[14 + 12 : 14 + 16])


def advs_from_tcpdump_xx(text):
    found = []
    for frame in frames_from_tcpdump_xx(text):
        ip_src = _ip_src(frame)
        for payload in udp_payloads(frame):
            for adv in parse_em_advs(payload):
                adv["ip_src"] = ip_src
                found.append(adv)
    return found


def format_adv(adv):
    return (
        "ip_src={ip_src} src={src} dst={dst} adv={adv} hops={hops} "
        "ttl={ttl} metric={metric} proto={proto}".format(**adv)
    )
