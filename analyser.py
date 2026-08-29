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

    return {
        "total_packets": len(packet_list),
        "protocol_counts": dict(protocol_counts),
        "risky_port_hits": risky_port_hits,
        "unique_ips": len(unique_ips),
        "port_scan_alert": port_scan_alert,
    }


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


def build_report(summary: Dict[str, Any], packets: List[Dict[str, Any]], wifi_status: Dict[str, Any], report_path: str | Path | None = None) -> str:
    protocol_summary = " | ".join(f"{name}: {count}" for name, count in sorted(summary["protocol_counts"].items())) or "No traffic captured"
    scan_alert = summary["port_scan_alert"]
    target_path = Path(report_path) if report_path is not None else get_default_report_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "=" * 70,
        "Network Traffic Observatory Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 70,
        "",
        "Security posture:",
        f"- Wi‑Fi assessment: {wifi_status['status'].upper()} ({wifi_status['score']}/100)",
        f"- Reason: {wifi_status['reason']}",
        "",
        "Traffic summary:",
        f"- Total packets: {summary['total_packets']}",
        f"- Risky port hits: {summary['risky_port_hits']}",
        f"- Unique IPs seen: {summary['unique_ips']}",
        f"- Protocol mix: {protocol_summary}",
        f"- Port scan alert: {'YES' if scan_alert['alert'] else 'NO'}",
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

        status_frame = tk.Frame(right, bg="#101827")
        status_frame.pack(fill="x", padx=14, pady=(14, 8))
        tk.Label(status_frame, text="Status", fg="#f8f9ff", bg="#101827", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.status_var = tk.StringVar(value="Idle — ready to start a new capture.")
        tk.Label(status_frame, textvariable=self.status_var, fg="#cfe1ff", bg="#101827", font=("Segoe UI", 10), wraplength=700, justify="left").pack(anchor="w", pady=6)

        self.log_text = tk.Text(right, bg="#0a1220", fg="#d9e8ff", insertbackground="#d9e8ff", wrap="word", height=18, font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        self.log_text.tag_configure("alert", foreground="#ff8a80")
        self.log_text.tag_configure("info", foreground="#79d6ff")
        self.log_text.tag_configure("ok", foreground="#7ef2b4")

        self._write_log("Initialising security scanner...", "info")
        self._write_log("Press Start Capture to inspect traffic or run the built-in demo for a sample analysis.", "ok")
        self.refresh_dashboard()

    def _write_log(self, message: str, tag: str = "info"):
        self.log_text.insert("end", message + "\n", tag)
        self.log_text.see("end")

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

        if summary["port_scan_alert"]["alert"]:
            self.status_var.set(f"Possible scan: {summary['port_scan_alert']['src_ip']} probed {summary['port_scan_alert']['ports_probed']} ports.")
            self._write_log(summary["port_scan_alert"]["explanation"], "alert")
        elif self.packets:
            self.status_var.set(f"Analysis complete — {summary['total_packets']} packets reviewed and {summary['risky_port_hits']} risky destinations touched.")


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
