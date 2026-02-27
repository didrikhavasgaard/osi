from osi_diagnose.rendering.redact import redact_payload


def test_redacts_ip_and_ssid():
    payload = {
        "context": {"local_ip": "192.168.1.77", "gateway": "192.168.1.1"},
        "layers": [{"checks": [{"metrics": {"ssid": "MyWifi"}}]}],
    }
    redacted = redact_payload(payload)
    assert redacted["context"]["local_ip"].endswith("x")
    assert redacted["context"]["gateway"].endswith("x")
    ssid_token = redacted["layers"][0]["checks"][0]["metrics"]["ssid"]
    assert ssid_token.startswith("ssid_hash:")
