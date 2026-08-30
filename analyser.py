import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

from scapy.all import AsyncSniffer, IP, ICMP, TCP, UDP, get_if_list
import tkinter as tk
from tkinter import filedialog, ttk

RISKY_PORTS = {
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    135: "RPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
}


def get_protocol(packet):
    if TCP in packet:
        return "TCP", int(packet[TCP].dport)
    if UDP in packet:
        return "UDP", int(packet[UDP].dport)
    if ICMP in packet:
        return "ICMP", None
    return "OTHER", None


def classify_packet(packet: Dict[str, Any]) -> Dict[str, Any]:
    protocol, dst_port = get_protocol(packet)
    payload = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "protocol": protocol,
        "src": packet[IP].src,
        "dst": packet[IP].dst,
        "dst_port": dst_port,
        "ttl": getattr(packet[IP], "ttl", None),
    }
    return payload


def get_top_talkers(packets: Iterable[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    source_counts = Counter()
    for packet in packets:
        src = packet.get("src")
        if src:
            source_counts[src] += 1

    return [
        {"ip": ip, "packets": count}
        for ip, count in sorted(source_counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def calculate_risk_level(summary: Dict[str, Any]) -> str:
    port_scan_alert = summary.get("port_scan_alert", {}).get("alert")
    risky_port_hits = summary.get("risky_port_hits", 0)
    alerts = summary.get("alerts", [])
    highest_severity = "low"

    if alerts:
        severity_order = {"low": 1, "moderate": 2, "high": 3, "critical": 4}
        for alert in alerts:
            highest_severity = max(highest_severity, alert.get("severity", "low"), key=lambda sev: severity_order.get(sev, 0))

    if port_scan_alert and risky_port_hits >= 4:
        return "critical"
    if highest_severity == "critical" or port_scan_alert or risky_port_hits >= 5:
        return "high"
    if highest_severity in {"high", "moderate"} or risky_port_hits >= 2:
        return "moderate"
    if risky_port_hits > 0 or highest_severity == "low":
        return "low"
    return "low"


def build_alerts(packets: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    risky_hits = Counter()

    for packet in packets:
        port = packet.get("dst_port")
        if port in RISKY_PORTS:
            risky_hits[packet.get("src", "unknown")] += 1

    for src_ip, count in risky_hits.items():
        severity = "moderate"
        if count >= 4:
            severity = "high"
        if count >= 6:
            severity = "critical"
        alerts.append({
            "severity": severity,
            "title": "Risky service activity",
            "message": f"{src_ip} contacted risky ports {count} times.",
            "src_ip": src_ip,
            "dst_port": None,
        })

    port_scan_alert = detect_port_scan(packets)
    if port_scan_alert["alert"]:
        alerts.append({
            "severity": "critical",
            "title": "Port scan detected",
            "message": port_scan_alert["explanation"],
            "src_ip": port_scan_alert["src_ip"],
            "dst_port": None,
        })

    return sorted(alerts, key=lambda item: {"low": 1, "moderate": 2, "high": 3, "critical": 4}.get(item["severity"], 0), reverse=True)


def get_alert_counts(alerts: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"low": 0, "moderate": 0, "high": 0, "critical": 0}
    for alert in alerts:
        severity = alert.get("severity", "low")
        if severity in counts:
            counts[severity] += 1
    return counts


def get_device_activity(packets: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    activity = defaultdict(lambda: {"ip": None, "packets": 0, "unique_ports": set(), "risky_hits": 0})

    for packet in packets:
        src = packet.get("src")
        dst = packet.get("dst")
        for ip in (src, dst):
            if not ip:
                continue
            entry = activity[ip]
            entry["ip"] = ip
            entry["packets"] += 1
            port = packet.get("dst_port")
            if port is not None:
                entry["unique_ports"].add(port)
            if port in RISKY_PORTS:
                entry["risky_hits"] += 1

    devices = []
    for ip, entry in activity.items():
        devices.append({
            "ip": ip,
            "packets": entry["packets"],
            "unique_ports": len(entry["unique_ports"]),
            "risky_hits": entry["risky_hits"],
        })

    return sorted(devices, key=lambda item: (-item["packets"], item["ip"]))


def infer_device_role(ip: str) -> str:
    if ip.startswith("192.168.1."):
        last_octet = int(ip.split(".")[-1])
        if last_octet in {1, 254}:
            return "gateway"
        if last_octet % 2 == 0:
            return "client"
        return "device"
    if ip.startswith("10."):
        return "internal-host"
    if ip.startswith("192.168."):
        return "local-network-device"
    return "external-host"


def infer_hostname(ip: str) -> str:
    last_octet = int(ip.split(".")[-1])
    if ip.startswith("192.168.1.") and last_octet == 1:
        return "router"
    if ip.startswith("192.168.1.") and last_octet == 10:
        return "desktop"
    if ip.startswith("192.168.1.") and last_octet == 27:
        return "laptop"
    if ip.startswith("10."):
        return "internal-host"
    return f"host-{last_octet}"


def discover_devices(packets: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}

    for packet in packets:
        for key in ("src", "dst"):
            ip = packet.get(key)
            if not ip:
                continue
            if ip not in seen:
                seen[ip] = {
                    "ip": ip,
                    "hostname": infer_hostname(ip),
                    "role": infer_device_role(ip),
                    "packets_seen": 0,
                    "risk_hits": 0,
                }
            seen[ip]["packets_seen"] += 1
            if packet.get("dst_port") in RISKY_PORTS:
                seen[ip]["risk_hits"] += 1

    devices = list(seen.values())
    return sorted(devices, key=lambda item: (-item["packets_seen"], item["ip"]))


def describe_packet(packet: Dict[str, Any]) -> Dict[str, Any]:
    dst_port = packet.get("dst_port")
    protocol = packet.get("protocol", "UNKNOWN")
    port_risk = "low"
    service_name = "General traffic"

    if dst_port in RISKY_PORTS:
        service_name = RISKY_PORTS[dst_port]
        port_risk = "moderate"
        if dst_port in {22, 23, 3389, 5900, 445}:
            port_risk = "high"

    return {
        "protocol": protocol,
        "source": packet.get("src", "unknown"),
        "destination": packet.get("dst", "unknown"),
        "port": dst_port,
        "service": service_name,
        "ttl": packet.get("ttl"),
        "risk_level": port_risk,
    }


def summarise_traffic(packets: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    packet_list = list(packets)
    protocol_counts = Counter()
    unique_ips = set()
    risky_port_hits = 0

    for packet in packet_list:
        proto = packet.get("protocol", "UNKNOWN")
        protocol_counts[proto] += 1
        unique_ips.add(packet.get("src", "unknown"))
        unique_ips.add(packet.get("dst", "unknown"))

        if packet.get("dst_port") in RISKY_PORTS:
            risky_port_hits += 1

    port_scan_alert = detect_port_scan(packet_list)
    alerts = build_alerts(packet_list)
    summary = {
        "total_packets": len(packet_list),
        "protocol_counts": dict(protocol_counts),
        "risky_port_hits": risky_port_hits,
        "unique_ips": len(unique_ips),
        "port_scan_alert": port_scan_alert,
        "top_talkers": get_top_talkers(packet_list),
        "alerts": alerts,
        "alert_history": alerts,
        "alert_counts": get_alert_counts(alerts),
        "device_activity": get_device_activity(packet_list),
    }
    summary["risk_level"] = calculate_risk_level(summary)
    return summary


def detect_port_scan(packets: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    probes_by_source = defaultdict(set)
    for packet in packets:
        src = packet.get("src")
        port = packet.get("dst_port")
        if src and port is not None:
            probes_by_source[src].add(port)

    for src_ip, ports in probes_by_source.items():
        if len(ports) >= 4:
            return {
                "alert": True,
                "src_ip": src_ip,
                "ports_probed": len(ports),
                "explanation": f"{src_ip} touched {len(ports)} different ports in a short burst, which matches a port scan pattern.",
            }

    return {"alert": False, "src_ip": None, "ports_probed": 0, "explanation": "No obvious port scan pattern detected."}


def assess_wifi_security(mode: str) -> Dict[str, Any]:
    normalized = (mode or "unknown").strip().upper()

    if normalized in {"WPA3", "WPA3-PSK", "WPA2", "WPA2-PSK", "WPA2/WPA3"}:
        return {
            "status": "secure",
            "score": 90,
            "reason": "Modern Wi‑Fi protections are active and the network is generally well protected against casual interception.",
        }

    if normalized in {"WPA", "WPA1", "WPA-PSK"}:
        return {
            "status": "moderate",
            "score": 65,
            "reason": "WPA is older and weaker than WPA2/WPA3, so it is not the best baseline to trust for long-term security.",
        }

    if normalized in {"WEP"}:
        return {
            "status": "at_risk",
            "score": 20,
            "reason": "WEP is deprecated and vulnerable to known attacks, so this network should be treated as risky.",
        }

    if normalized in {"OPEN", "OPEN NETWORK", "NONE", "UNSECURED"}:
        return {
            "status": "unsafe",
            "score": 5,
            "reason": "No wireless encryption is active, which means nearby devices can monitor or interfere with traffic.",
        }

    return {
        "status": "unknown",
        "score": 50,
        "reason": "The wireless mode could not be confirmed from the data available, so a direct check on the router or adapter is recommended.",
    }


def get_default_report_path() -> Path:
    home_dir = Path.home()
    documents_dir = home_dir / "Documents"
    documents_dir.mkdir(exist_ok=True, parents=True)
    return documents_dir / "network_report.txt"


def get_release_bundle_dir(platform_name: str) -> Path:
    root = Path(__file__).resolve().parent
    return root / "release" / platform_name


def save_capture_session(packets: List[Dict[str, Any]], filename: str | Path | None = None) -> Path:
    target_dir = Path(__file__).resolve().parent / "sessions"
    target_dir.mkdir(exist_ok=True, parents=True)
    session_name = filename if filename is not None else f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    target_path = target_dir / session_name if not Path(session_name).is_absolute() else Path(session_name)
    with open(target_path, "w", encoding="utf-8") as handle:
        json.dump(packets, handle, indent=2)
    return target_path


def load_capture_session(path: str | Path) -> List[Dict[str, Any]]:
    target_path = Path(path)
    with open(target_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, list) else []


def calculate_trend_snapshot(packets: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    packet_list = list(packets)
    timestamps = []
    for packet in packet_list:
        value = packet.get("timestamp")
        if not value:
            continue
        try:
            timestamps.append(datetime.strptime(value, "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            continue

    if not timestamps:
        return {"packet_count": len(packet_list), "peak_interval_seconds": 0, "timeline": [], "average_packet_rate": 0.0}

    time_deltas = []
    for first, second in zip(timestamps, timestamps[1:]):
        time_deltas.append((second - first).total_seconds())

    peak_interval = max(time_deltas) if time_deltas else 0
    average_rate = 0.0
    if len(timestamps) > 1:
        total_span = max((timestamps[-1] - timestamps[0]).total_seconds(), 1)
        average_rate = (len(timestamps) - 1) / total_span

    timeline = [
        {"timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"), "count": 1}
        for ts in timestamps
    ]

    return {
        "packet_count": len(packet_list),
        "peak_interval_seconds": peak_interval,
        "average_packet_rate": round(average_rate, 3),
        "timeline": timeline,
    }


def export_summary(summary: Dict[str, Any], name: str) -> Dict[str, Path]:
    exports_dir = Path(__file__).resolve().parent / "exports"
    exports_dir.mkdir(exist_ok=True, parents=True)
    base_name = Path(name).stem if isinstance(name, str) and "." in name else str(name)

    json_path = exports_dir / f"{base_name}.json"
    csv_path = exports_dir / f"{base_name}.csv"

    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    csv_rows = [
        ["metric", "value"],
        ["total_packets", summary.get("total_packets", 0)],
        ["risky_port_hits", summary.get("risky_port_hits", 0)],
        ["risk_level", summary.get("risk_level", "low")],
    ]

    for entry in summary.get("top_talkers", []):
        csv_rows.append([f"top_talker:{entry.get('ip', 'unknown')}", entry.get("packets", 0)])

    for alert in summary.get("alerts", []):
        csv_rows.append([f"alert:{alert.get('title', 'alert')}", alert.get("severity", "low")])

    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        import csv
        writer = csv.writer(handle)
        writer.writerows(csv_rows)

    return {"json": json_path, "csv": csv_path}


def build_report(summary: Dict[str, Any], packets: List[Dict[str, Any]], wifi_status: Dict[str, Any], report_path: str | Path | None = None) -> str:
    protocol_summary = " | ".join(f"{name}: {count}" for name, count in sorted(summary["protocol_counts"].items())) or "No traffic captured"
    scan_alert = summary["port_scan_alert"]
    target_path = Path(report_path) if report_path is not None else get_default_report_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    top_talkers = ", ".join(f"{entry['ip']} ({entry['packets']})" for entry in summary.get("top_talkers", [])) or "No source activity recorded"

    lines = [
        "=" * 70,
        "Network Traffic Observatory Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 70,
        "",
        "Security posture:",
        f"- Wi‑Fi assessment: {wifi_status['status'].upper()} ({wifi_status['score']}/100)",
        f"- Reason: {wifi_status['reason']}",
        f"- Overall risk level: {summary.get('risk_level', 'low').upper()}",
        "",
        "Traffic summary:",
        f"- Total packets: {summary['total_packets']}",
        f"- Risky port hits: {summary['risky_port_hits']}",
        f"- Unique IPs seen: {summary['unique_ips']}",
        f"- Protocol mix: {protocol_summary}",
        f"- Port scan alert: {'YES' if scan_alert['alert'] else 'NO'}",
        f"- Top talkers: {top_talkers}",
        "",
        "Packet log:",
    ]

    for packet in packets:
        port = packet.get("dst_port")
        port_text = f":{port}" if port is not None else ""
        lines.append(
            f"[{packet.get('timestamp', 'N/A')}] {packet.get('protocol', 'UNKNOWN')} | "
            f"{packet.get('src', 'unknown')} -> {packet.get('dst', 'unknown')}{port_text}"
        )

    lines.extend([
        "",
        "=" * 70,
        "End of report",
        "=" * 70,
    ])

    with open(target_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    return str(target_path)


class TrafficAnalyzerApp(tk.Tk):
    def __init__(self, demo_mode: bool = False):
        super().__init__()
        self.title("Network Traffic Observatory")
        self.geometry("1100x720")
        self.configure(bg="#0b1020")
        self.minsize(980, 620)

        self.packets: List[Dict[str, Any]] = []
        self.sniffer = None
        self.demo_mode = demo_mode
        self.wifi_mode_var = tk.StringVar(value="WPA2")

        self._build_ui()

        if self.demo_mode:
            self.after(250, self.run_demo)

    def _build_ui(self):
        title = tk.Label(
            self,
            text="Network Traffic Observatory",
            font=("Segoe UI", 24, "bold"),
            fg="#edf3ff",
            bg="#0b1020",
            pady=18,
        )
        title.pack(fill="x")

        top_bar = tk.Frame(self, bg="#121a2d", padx=18, pady=14)
        top_bar.pack(fill="x")

        tk.Label(top_bar, text="Interface:", fg="#c0d6ff", bg="#121a2d", font=("Segoe UI", 11, "bold")).pack(side="left")
        interfaces = get_if_list() or ["eth0", "wlan0", "lo", "ens33"]
        self.interface_var = tk.StringVar(value=interfaces[0])
        interface_menu = ttk.Combobox(top_bar, textvariable=self.interface_var, values=interfaces, state="readonly", width=18)
        interface_menu.pack(side="left", padx=(8, 14))

        tk.Label(top_bar, text="Capture count:", fg="#c0d6ff", bg="#121a2d", font=("Segoe UI", 11, "bold")).pack(side="left")
        self.capture_count_var = tk.IntVar(value=80)
        count_entry = ttk.Entry(top_bar, textvariable=self.capture_count_var, width=10)
        count_entry.pack(side="left", padx=(8, 14))

        tk.Label(top_bar, text="Wi‑Fi mode:", fg="#c0d6ff", bg="#121a2d", font=("Segoe UI", 11, "bold")).pack(side="left")
        wifi_options = ["WPA2", "WPA3", "WPA", "WEP", "Open Network"]
        wifi_combo = ttk.Combobox(top_bar, textvariable=self.wifi_mode_var, values=wifi_options, state="readonly", width=14)
        wifi_combo.pack(side="left", padx=(8, 14))

        ttk.Button(top_bar, text="Start Capture", command=self.start_capture).pack(side="left", padx=4)
        ttk.Button(top_bar, text="Stop Capture", command=self.stop_capture).pack(side="left", padx=4)
        ttk.Button(top_bar, text="Run Demo", command=self.run_demo).pack(side="left", padx=4)
        ttk.Button(top_bar, text="Save Session", command=self.save_session).pack(side="left", padx=4)
        ttk.Button(top_bar, text="Load Session", command=self.load_session).pack(side="left", padx=4)
        ttk.Button(top_bar, text="Export Summary", command=self.export_summary).pack(side="left", padx=4)
        ttk.Button(top_bar, text="Save Report", command=self.save_report).pack(side="left", padx=4)
        ttk.Button(top_bar, text="Choose Folder", command=self.choose_report_folder).pack(side="left", padx=4)

        content = tk.Frame(self, bg="#0b1020")
        content.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        left = tk.Frame(content, bg="#0f172a", bd=1, relief="flat")
        left.pack(side="left", fill="y", padx=(0, 12))

        right = tk.Frame(content, bg="#0f172a", bd=1, relief="flat")
        right.pack(side="left", fill="both", expand=True)

        self.summary_cards = {}
        for index, label in enumerate([("Packets", "total_packets"), ("Risky hits", "risky_port_hits"), ("Unique IPs", "unique_ips"), ("Scan alert", "scan_alert")]):
            card = tk.Frame(left, bg="#111827", padx=14, pady=12, bd=1, relief="solid")
            card.pack(fill="x", pady=8)
            tk.Label(card, text=label[0], fg="#a8b6d9", bg="#111827", font=("Segoe UI", 10, "bold")).pack(anchor="w")
            value = tk.Label(card, text="0", fg="#61dafb", bg="#111827", font=("Segoe UI", 20, "bold"))
            value.pack(anchor="w")
            self.summary_cards[label[1]] = value

        wifi_card = tk.Frame(left, bg="#111827", padx=14, pady=12, bd=1, relief="solid")
        wifi_card.pack(fill="x", pady=8)
        tk.Label(wifi_card, text="Wi‑Fi posture", fg="#a8b6d9", bg="#111827", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.wifi_status_label = tk.Label(wifi_card, text="unknown", fg="#f8d66d", bg="#111827", font=("Segoe UI", 16, "bold"))
        self.wifi_status_label.pack(anchor="w", pady=(6, 0))
        tk.Label(wifi_card, text="Status will update based on the chosen mode.", fg="#dbe5ff", bg="#111827", font=("Segoe UI", 9), wraplength=180, justify="left").pack(anchor="w", pady=(6, 0))

        host_card = tk.Frame(left, bg="#111827", padx=14, pady=12, bd=1, relief="solid")
        host_card.pack(fill="x", pady=8)
        tk.Label(host_card, text="Top talkers", fg="#a8b6d9", bg="#111827", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.top_talkers_var = tk.StringVar(value="No traffic yet")
        tk.Label(host_card, textvariable=self.top_talkers_var, fg="#dfe7ff", bg="#111827", font=("Segoe UI", 9), wraplength=180, justify="left").pack(anchor="w", pady=(6, 0))

        device_card = tk.Frame(left, bg="#111827", padx=14, pady=12, bd=1, relief="solid")
        device_card.pack(fill="x", pady=8)
        tk.Label(device_card, text="Detected devices", fg="#a8b6d9", bg="#111827", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.device_activity_var = tk.StringVar(value="No activity")
        tk.Label(device_card, textvariable=self.device_activity_var, fg="#dfe7ff", bg="#111827", font=("Segoe UI", 9), wraplength=180, justify="left").pack(anchor="w", pady=(6, 0))

        alert_card = tk.Frame(left, bg="#111827", padx=14, pady=12, bd=1, relief="solid")
        alert_card.pack(fill="x", pady=8)
        tk.Label(alert_card, text="Recent alerts", fg="#a8b6d9", bg="#111827", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.alerts_var = tk.StringVar(value="No alerts")
        tk.Label(alert_card, textvariable=self.alerts_var, fg="#dfe7ff", bg="#111827", font=("Segoe UI", 9), wraplength=180, justify="left").pack(anchor="w", pady=(6, 0))

        trend_frame = tk.Frame(left, bg="#111827", padx=14, pady=12, bd=1, relief="solid")
        trend_frame.pack(fill="x", pady=8)
        tk.Label(trend_frame, text="Traffic trend", fg="#a8b6d9", bg="#111827", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.trend_var = tk.StringVar(value="No data")
        tk.Label(trend_frame, textvariable=self.trend_var, fg="#dfe7ff", bg="#111827", font=("Segoe UI", 9), wraplength=180, justify="left").pack(anchor="w", pady=(6, 0))

        status_frame = tk.Frame(right, bg="#101827")
        status_frame.pack(fill="x", padx=14, pady=(14, 8))
        tk.Label(status_frame, text="Status", fg="#f8f9ff", bg="#101827", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.status_var = tk.StringVar(value="Idle — ready to start a new capture.")
        tk.Label(status_frame, textvariable=self.status_var, fg="#cfe1ff", bg="#101827", font=("Segoe UI", 10), wraplength=700, justify="left").pack(anchor="w", pady=6)

        self.log_text = tk.Text(right, bg="#0a1220", fg="#d9e8ff", insertbackground="#d9e8ff", wrap="word", height=12, font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        self.log_text.tag_configure("alert", foreground="#ff8a80")
        self.log_text.tag_configure("info", foreground="#79d6ff")
        self.log_text.tag_configure("ok", foreground="#7ef2b4")

        detail_frame = tk.Frame(right, bg="#101827", padx=12, pady=10)
        detail_frame.pack(fill="x", padx=14, pady=(0, 12))
        tk.Label(detail_frame, text="Packet details", fg="#f8f9ff", bg="#101827", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.packet_detail_text = tk.Text(detail_frame, bg="#0a1220", fg="#d9e8ff", insertbackground="#d9e8ff", wrap="word", height=7, font=("Consolas", 10))
        self.packet_detail_text.pack(fill="both", expand=True)

        self._write_log("Initialising security scanner...", "info")
        self._write_log("Press Start Capture to inspect traffic or run the built-in demo for a sample analysis.", "ok")
        self.refresh_dashboard()

    def _write_log(self, message: str, tag: str = "info"):
        self.log_text.insert("end", message + "\n", tag)
        self.log_text.see("end")

    def _update_packet_details(self, packet: Dict[str, Any] | None = None):
        if packet is None and self.packets:
            packet = self.packets[-1]

        self.packet_detail_text.delete("1.0", "end")
        if packet is None:
            self.packet_detail_text.insert("end", "No packet data available yet.\n")
            return

        details = describe_packet(packet)
        port_label = details["port"] if details["port"] is not None else "N/A"
        ttl_label = details["ttl"] if details["ttl"] is not None else "N/A"
        payload = (
            f"Timestamp: {packet.get('timestamp', 'N/A')}\n"
            f"Protocol: {details['protocol']}\n"
            f"Source: {details['source']}\n"
            f"Destination: {details['destination']}\n"
            f"Port: {port_label}\n"
            f"Service: {details['service']}\n"
            f"TTL: {ttl_label}\n"
            f"Risk level: {details['risk_level'].upper()}"
        )
        self.packet_detail_text.insert("end", payload)

    def _packet_to_log(self, packet: Dict[str, Any]) -> str:
        port = packet.get("dst_port")
        port_text = f":{port}" if port is not None else ""
        return f"[{packet.get('timestamp', 'N/A')}] {packet.get('protocol', 'UNKNOWN')} | {packet.get('src', 'unknown')} -> {packet.get('dst', 'unknown')}{port_text}"

    def start_capture(self):
        count = max(1, self.capture_count_var.get())
        iface = self.interface_var.get()
        if self.sniffer is not None and self.sniffer.running:
            self._write_log("A capture is already running.", "alert")
            return

        self.packets = []
        self.status_var.set(f"Capturing up to {count} packets on {iface}...")
        self._write_log(f"Starting live analysis on {iface}.", "info")

        try:
            self.sniffer = AsyncSniffer(iface=iface, prn=self._handle_packet, count=count)
            self.sniffer.start()
        except Exception as exc:  # pragma: no cover - GUI safety net
            self._write_log(f"Capture failed: {exc}", "alert")
            self.status_var.set("Capture failed. Please ensure the interface is available and you have permissions.")

    def stop_capture(self):
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
                self._write_log("Capture stopped by user.", "ok")
                self.status_var.set("Capture stopped. The current packet window is still visible in the dashboard.")
            except Exception as exc:  # pragma: no cover - GUI safety net
                self._write_log(f"Stop request failed: {exc}", "alert")
        else:
            self._write_log("No active capture to stop.", "info")

        self.refresh_dashboard()

    def _handle_packet(self, packet):
        if IP not in packet:
            return

        parsed = classify_packet(packet)
        self.packets.append(parsed)
        self._update_packet_details(parsed)
        self._write_log(self._packet_to_log(parsed), "info")

        if parsed.get("dst_port") in RISKY_PORTS:
            self._write_log(f"ALERT: Risky destination port {parsed['dst_port']} ({RISKY_PORTS[parsed['dst_port']]}) reached from {parsed['src']}", "alert")

        self.after(0, self.refresh_dashboard)

    def run_demo(self):
        demo_packets = [
            {"timestamp": "2026-08-29 12:00:01", "protocol": "TCP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 445, "ttl": 64},
            {"timestamp": "2026-08-29 12:00:02", "protocol": "TCP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 3389, "ttl": 64},
            {"timestamp": "2026-08-29 12:00:03", "protocol": "UDP", "src": "192.168.1.23", "dst": "192.168.1.1", "dst_port": 53, "ttl": 64},
            {"timestamp": "2026-08-29 12:00:04", "protocol": "TCP", "src": "198.51.100.8", "dst": "192.168.1.45", "dst_port": 22, "ttl": 62},
            {"timestamp": "2026-08-29 12:00:05", "protocol": "TCP", "src": "198.51.100.8", "dst": "192.168.1.45", "dst_port": 80, "ttl": 62},
            {"timestamp": "2026-08-29 12:00:06", "protocol": "TCP", "src": "198.51.100.8", "dst": "192.168.1.45", "dst_port": 443, "ttl": 62},
            {"timestamp": "2026-08-29 12:00:07", "protocol": "TCP", "src": "198.51.100.8", "dst": "192.168.1.45", "dst_port": 8443, "ttl": 62},
            {"timestamp": "2026-08-29 12:00:08", "protocol": "ICMP", "src": "10.0.0.6", "dst": "10.0.0.1", "dst_port": None, "ttl": 128},
        ]
        self.packets = demo_packets
        self.status_var.set("Demo run complete — a sample dataset is being analysed for risk patterns and Wi‑Fi posture.")
        self._write_log("Demo packets loaded. Evaluating suspicious behaviour against common network heuristics.", "info")
        self.refresh_dashboard()

    def choose_report_folder(self):
        directory = filedialog.askdirectory(title="Choose report folder")
        if not directory:
            return
        self.report_folder = directory
        self.status_var.set(f"Report folder set to {directory}.")
        self._write_log(f"Report folder set to {directory}", "ok")

    def save_session(self):
        session_path = save_capture_session(self.packets)
        self.status_var.set(f"Session saved to {session_path}.")
        self._write_log(f"Session saved to {session_path}", "ok")

    def load_session(self):
        file_path = filedialog.askopenfilename(title="Select capture session", filetypes=[("JSON files", "*.json")])
        if not file_path:
            return
        try:
            packets = load_capture_session(file_path)
            self.packets = packets
            self.status_var.set(f"Loaded session from {file_path}.")
            self._write_log(f"Loaded session from {file_path}", "ok")
            self.refresh_dashboard()
        except Exception as exc:  # pragma: no cover - GUI safety net
            self.status_var.set("Could not load session file.")
            self._write_log(f"Session load failed: {exc}", "alert")

    def export_summary(self):
        summary = summarise_traffic(self.packets)
        export_paths = export_summary(summary, f"traffic_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.status_var.set(f"Exports saved to {list(export_paths.values())}.")
        self._write_log(f"JSON export: {export_paths['json']}", "ok")
        self._write_log(f"CSV export: {export_paths['csv']}", "ok")

    def save_report(self):
        wifi_status = assess_wifi_security(self.wifi_mode_var.get())
        summary = summarise_traffic(self.packets)
        report_dir = getattr(self, "report_folder", str(get_default_report_path().parent))
        report_file = build_report(summary, self.packets, wifi_status, Path(report_dir) / "network_report.txt")
        self.status_var.set(f"Report saved to {report_file}.")
        self._write_log(f"Report saved to {report_file}", "ok")

    def refresh_dashboard(self):
        summary = summarise_traffic(self.packets)
        self.summary_cards["total_packets"].config(text=str(summary["total_packets"]))
        self.summary_cards["risky_port_hits"].config(text=str(summary["risky_port_hits"]))
        self.summary_cards["unique_ips"].config(text=str(summary["unique_ips"]))
        self.summary_cards["scan_alert"].config(text="YES" if summary["port_scan_alert"]["alert"] else "NO")

        wifi_status = assess_wifi_security(self.wifi_mode_var.get())
        self.wifi_status_label.config(text=wifi_status["status"].upper(), fg={
            "secure": "#7ef2b4",
            "moderate": "#f8d66d",
            "at_risk": "#ff9b8d",
            "unsafe": "#ff6b6b",
            "unknown": "#dfe7ff",
        }[wifi_status["status"]])

        if self.packets:
            self._update_packet_details(self.packets[-1])

        top_talkers = summary.get("top_talkers", [])
        if top_talkers:
            top_talkers_text = "\n".join(f"{entry['ip']}: {entry['packets']} packets" for entry in top_talkers[:3])
            self.top_talkers_var.set(top_talkers_text)
        else:
            self.top_talkers_var.set("No traffic yet")

        device_activity = summary.get("device_activity", [])
        if device_activity:
            devices_text = "\n".join(f"{entry['ip']}: {entry['packets']} pkts" for entry in device_activity[:3])
            self.device_activity_var.set(devices_text)
        else:
            self.device_activity_var.set("No activity")

        alerts = summary.get("alert_history", summary.get("alerts", []))
        if alerts:
            alert_text = "\n".join(f"{alert['severity'].upper()}: {alert['title']}" for alert in alerts[:3])
            self.alerts_var.set(alert_text)
        else:
            self.alerts_var.set("No alerts")

        trend = calculate_trend_snapshot(self.packets)
        if self.packets:
            self.trend_var.set(f"{trend['packet_count']} packets | {trend['average_packet_rate']} pkts/s")
        else:
            self.trend_var.set("No data")

        risk_label = summary.get("risk_level", "low").upper()
        if summary["port_scan_alert"]["alert"]:
            self.status_var.set(f"Possible scan: {summary['port_scan_alert']['src_ip']} probed {summary['port_scan_alert']['ports_probed']} ports. Risk level {risk_label}.")
            self._write_log(summary["port_scan_alert"]["explanation"], "alert")
        elif self.packets:
            self.status_var.set(f"Analysis complete — {summary['total_packets']} packets reviewed, {summary['risky_port_hits']} risky destinations touched, risk level {risk_label}.")


def main(argv: List[str] | None = None):
    parser = argparse.ArgumentParser(description="Modern network traffic observatory and Wi‑Fi safety analyzer.")
    parser.add_argument("--demo", action="store_true", help="Launch the GUI with a built-in sample traffic pattern.")
    parser.add_argument("--headless", action="store_true", help="Print a quick summary without opening the GUI.")
    parser.add_argument("--count", type=int, default=80, help="Number of packets to capture in live mode.")
    args = parser.parse_args(argv)

    if args.headless:
        packets = []
        if args.demo:
            packets = [
                {"timestamp": "demo", "protocol": "TCP", "src": "10.0.0.5", "dst": "10.0.0.1", "dst_port": 445},
                {"timestamp": "demo", "protocol": "UDP", "src": "192.168.1.9", "dst": "192.168.1.1", "dst_port": 53},
                {"timestamp": "demo", "protocol": "ICMP", "src": "10.0.0.7", "dst": "10.0.0.1", "dst_port": None},
            ]
        summary = summarise_traffic(packets)
        print(json.dumps({"summary": summary, "wifi": assess_wifi_security("WPA2")}, indent=2))
        return 0

    app = TrafficAnalyzerApp(demo_mode=args.demo)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
