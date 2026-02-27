from osi_diagnose.checks.base import parse_default_gateway, parse_network_quality_json
from osi_diagnose.checks.l3_network import parse_ping_output


ROUTE_SAMPLE = """
   route to: default
destination: default
       mask: default
gateway: 192.168.1.1
  interface: en0
"""

PING_SAMPLE = """
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 10.120/20.240/30.360/5.000 ms
"""


def test_parse_default_gateway() -> None:
    gw, iface = parse_default_gateway(ROUTE_SAMPLE)
    assert gw == "192.168.1.1"
    assert iface == "en0"


def test_parse_ping_output() -> None:
    parsed = parse_ping_output(PING_SAMPLE)
    assert parsed["tx"] == 4
    assert parsed["rx"] == 4
    assert parsed["loss_pct"] == 0.0
    assert parsed["avg_ms"] == 20.24
    assert parsed["jitter_ms"] == 5.0


def test_parse_network_quality_json() -> None:
    payload = '{"ul_throughput": 200, "dl_throughput": 500}'
    parsed = parse_network_quality_json(payload)
    assert parsed["ul_throughput"] == 200
    assert parsed["dl_throughput"] == 500
