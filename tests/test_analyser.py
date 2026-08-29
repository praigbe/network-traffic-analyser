from pathlib import Path

import analyser


def test_traffic_summary_detects_risky_ports():
    samples = [
        {"protocol": "TCP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 445},
        {"protocol": "TCP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 3389},
        {"protocol": "UDP", "src": "192.168.1.9", "dst": "192.168.1.1", "dst_port": 53},
    ]

    summary = analyser.summarise_traffic(samples)

    assert summary["total_packets"] == 3
    assert summary["risky_port_hits"] >= 2
    assert summary["protocol_counts"]["TCP"] >= 2


def test_assess_wifi_security_uses_encryption_strength():
    secure = analyser.assess_wifi_security("WPA3")
    weak = analyser.assess_wifi_security("WEP")

    assert secure["status"] == "secure"
    assert weak["status"] == "at_risk"
    assert "WEP" in weak["reason"].upper()


def test_port_scan_detection_flags_multiple_targets():
    report = analyser.detect_port_scan([
        {"src": "198.51.100.2", "dst_port": 22},
        {"src": "198.51.100.2", "dst_port": 80},
        {"src": "198.51.100.2", "dst_port": 443},
        {"src": "198.51.100.2", "dst_port": 8080},
        {"src": "198.51.100.2", "dst_port": 8443},
    ])

    assert report["alert"] is True
    assert report["src_ip"] == "198.51.100.2"
    assert report["ports_probed"] >= 4


def test_default_report_path_uses_documents_folder():
    report_path = analyser.get_default_report_path()
    assert "Documents" in str(report_path)
    assert report_path.name == "network_report.txt"
    assert isinstance(report_path, Path)


def test_release_bundle_directory_uses_project_release_folder():
    bundle_path = analyser.get_release_bundle_dir("windows")
    assert "release" in str(bundle_path).lower()
    assert bundle_path.name == "windows"
