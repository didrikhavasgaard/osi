from osi_diagnose.rendering.redact import mask_ipv4, redact_report_payload


def test_mask_ipv4() -> None:
    assert mask_ipv4("192.168.10.44") == "192.168.10.x"


def test_redact_payload() -> None:
    payload = {
        "context": {
            "hostname": "macbook-pro",
            "local_ip": "10.0.1.55",
            "gateway_ip": "10.0.1.1",
            "dns_servers": ["1.1.1.1", "8.8.8.8"],
        },
        "layers": [
            {
                "checks": [
                    {
                        "name": "Wi-Fi PHY",
                        "metrics": {"ssid": "OfficeWiFi", "ap": "10.0.1.8"},
                    }
                ]
            }
        ],
    }
    redacted = redact_report_payload(payload, allow_sensitive=False)
    assert redacted["context"]["local_ip"].endswith(".x")
    assert redacted["context"]["gateway_ip"].endswith(".x")
    assert str(redacted["context"]["hostname"]).startswith("hash:")
    assert str(redacted["layers"][0]["checks"][0]["metrics"]["ssid"]).startswith("hash:")
