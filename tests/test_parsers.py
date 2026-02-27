from osi_diagnose.checks.l1_physical import parse_ifconfig_status
from osi_diagnose.checks.l2_datalink import parse_arp_table
from osi_diagnose.checks.l3_network import parse_ping_stats
from osi_diagnose.checks.l5_session import parse_vpn_interfaces


def test_parse_ifconfig_status_active():
    sample = "en0: flags=8863\n\tstatus: active\n"
    assert parse_ifconfig_status(sample, "en0")["status"] == "active"


def test_parse_arp_table_rows():
    sample = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
    rows = parse_arp_table(sample)
    assert rows[0]["ip"] == "192.168.1.1"
    assert rows[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_parse_ping_stats():
    sample = "4 packets transmitted, 4 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 10.0/20.0/30.0/5.0 ms"
    stats = parse_ping_stats(sample)
    assert stats["packet_loss_percent"] == 0.0
    assert stats["rtt_avg_ms"] == 20.0


def test_parse_vpn_interfaces():
    sample = "utun0: flags\nen0: flags\nwg1: flags\n"
    assert parse_vpn_interfaces(sample) == ["utun0", "wg1"]
