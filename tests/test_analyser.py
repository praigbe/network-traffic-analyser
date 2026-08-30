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


def test_summarise_traffic_reports_host_activity_and_risk_level():
    packets = [
        {"protocol": "TCP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 445},
        {"protocol": "TCP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 3389},
        {"protocol": "UDP", "src": "192.168.1.9", "dst": "192.168.1.1", "dst_port": 53},
        {"protocol": "TCP", "src": "198.51.100.8", "dst": "192.168.1.45", "dst_port": 22},
    ]

    summary = analyser.summarise_traffic(packets)

    assert "top_talkers" in summary
    assert summary["top_talkers"][0]["ip"] == "10.0.0.5"
    assert summary["risk_level"] in {"low", "moderate", "high", "critical"}
    assert summary["risky_port_hits"] >= 3


def test_alerts_and_device_activity_are_exposed_in_summary():
    packets = [
        {"protocol": "TCP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 445},
        {"protocol": "TCP", "src": "198.51.100.8", "dst": "10.0.0.5", "dst_port": 22},
        {"protocol": "TCP", "src": "198.51.100.8", "dst": "10.0.0.5", "dst_port": 80},
        {"protocol": "TCP", "src": "198.51.100.8", "dst": "10.0.0.5", "dst_port": 443},
        {"protocol": "TCP", "src": "198.51.100.8", "dst": "10.0.0.5", "dst_port": 8443},
    ]

    summary = analyser.summarise_traffic(packets)

    assert any(alert["severity"] == "critical" for alert in summary["alerts"])
    assert any(device["ip"] == "10.0.0.5" for device in summary["device_activity"])


def test_describe_packet_exposes_port_details_and_risk_level():
    packet = {
        "protocol": "TCP",
        "src": "192.168.1.25",
        "dst": "10.0.0.8",
        "dst_port": 22,
        "ttl": 64,
    }

    details = analyser.describe_packet(packet)

    assert details["protocol"] == "TCP"
    assert details["destination"] == "10.0.0.8"
    assert details["port"] == 22
    assert details["risk_level"] in {"moderate", "high"}
    assert "ttl" in details


def test_summary_tracks_alert_history_and_severity_counts():
    packets = [
        {"protocol": "TCP", "src": "198.51.100.8", "dst": "10.0.0.5", "dst_port": 22},
        {"protocol": "TCP", "src": "198.51.100.8", "dst": "10.0.0.5", "dst_port": 80},
        {"protocol": "TCP", "src": "198.51.100.8", "dst": "10.0.0.5", "dst_port": 443},
        {"protocol": "TCP", "src": "198.51.100.8", "dst": "10.0.0.5", "dst_port": 8443},
        {"protocol": "TCP", "src": "198.51.100.8", "dst": "10.0.0.5", "dst_port": 8080},
    ]

    summary = analyser.summarise_traffic(packets)

    assert summary["alert_counts"]["critical"] >= 1
    assert summary["alert_history"][0]["title"] == "Port scan detected"


def test_capture_session_can_be_saved_and_loaded():
    packets = [
        {"timestamp": "2026-08-30 12:00:00", "protocol": "TCP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 22, "ttl": 64},
        {"timestamp": "2026-08-30 12:00:01", "protocol": "UDP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 53, "ttl": 64},
    ]

    session_path = analyser.save_capture_session(packets, "session_test.json")
    loaded = analyser.load_capture_session(session_path)

    assert loaded == packets
    assert session_path.exists()


def test_calculate_trend_snapshot_builds_packet_history_summary():
    packets = [
        {"timestamp": "2026-08-30 12:00:00", "protocol": "TCP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 80},
        {"timestamp": "2026-08-30 12:00:01", "protocol": "TCP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 443},
        {"timestamp": "2026-08-30 12:00:02", "protocol": "UDP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 53},
    ]

    trend = analyser.calculate_trend_snapshot(packets)

    assert trend["packet_count"] == 3
    assert trend["peak_interval_seconds"] >= 1
    assert "timeline" in trend


def test_device_discovery_adds_hostname_labels_and_network_roles():
    packets = [
        {"timestamp": "2026-08-30 12:00:00", "protocol": "TCP", "src": "192.168.1.10", "dst": "192.168.1.1", "dst_port": 80},
        {"timestamp": "2026-08-30 12:00:01", "protocol": "TCP", "src": "192.168.1.27", "dst": "192.168.1.1", "dst_port": 443},
    ]

    devices = analyser.discover_devices(packets)

    assert any(device["ip"] == "192.168.1.10" for device in devices)
    assert any("role" in device for device in devices)
    assert any("hostname" in device for device in devices)


def test_export_summary_generates_json_and_csv_outputs():
    summary = {
        "total_packets": 2,
        "risky_port_hits": 1,
        "risk_level": "moderate",
        "top_talkers": [{"ip": "10.0.0.5", "packets": 2}],
        "alerts": [{"title": "Port scan detected", "severity": "critical"}],
    }

    export_paths = analyser.export_summary(summary, "automation_test")

    assert all(path.exists() for path in export_paths.values())
    assert set(export_paths) == {"json", "csv"}


def test_build_user_friendly_summary_explains_capture_result():
    summary = {
        "total_packets": 12,
        "risky_port_hits": 5,
        "risk_level": "high",
        "port_scan_alert": {"alert": True, "src_ip": "198.51.100.8", "ports_probed": 6},
        "top_talkers": [{"ip": "10.0.0.5", "packets": 7}],
        "alerts": [{"severity": "critical", "title": "Port scan detected"}],
    }

    explanation = analyser.build_user_friendly_summary(summary)

    assert "high" in explanation.lower()
    assert "port scan" in explanation.lower()
    assert "198.51.100.8" in explanation
    assert "10.0.0.5" in explanation
