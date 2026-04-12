# pulling in everything we need to sniff packets and work with them
from scapy.all import sniff, IP, TCP, UDP, ICMP

# handy tools for tracking behaviour and timestamps
from collections import defaultdict
from datetime import datetime

# this is just for nice coloured terminal output 
from colorama import Fore, Style, init

# makes sure colours reset after each print so things don’t get messy
init(autoreset=True)


#  Config
PACKET_COUNT = 100       # how many packets we want to capture before stopping
SCAN_THRESHOLD = 5       # if an IP hits this many different ports, we flag it
REPORT_FILE = "report.txt"  # where we’ll save the final report


# Tracking 
# keeps track of which ports each IP has tried to access
port_tracker = defaultdict(set)

# stores any alerts we generate like  suspicious behaviour
alerts = []

# stores every packet we log so we can write it later
packet_log = []


# Helpers 
def get_protocol(packet):
    # figure out what type of packet we’re dealing with
    if TCP in packet:
        return "TCP", packet[TCP].dport  # return protocol + destination port
    elif UDP in packet:
        return "UDP", packet[UDP].dport
    elif ICMP in packet:
        return "ICMP", None  # ICMP doesn’t use ports
    return "OTHER", None  # fallback if it’s something else


def flag_suspicious(src_ip, dst_port, proto):
    flags = []

    # these are ports attackers often probe first
    risky_ports = {
        22: "SSH", 23: "Telnet", 3389: "RDP",
        445: "SMB", 1433: "MSSQL", 3306: "MySQL"
    }

    # if someone is hitting one of these ports, we raise an eyebrow
    if dst_port in risky_ports:
        flags.append(
            f"Sensitive port targeted: {risky_ports[dst_port]} ({dst_port})"
        )

    # simple port scan detection logic
    if dst_port:
        port_tracker[src_ip].add(dst_port)  # track the port this IP touched

        # once they hit enough different ports, we flag it
        if len(port_tracker[src_ip]) == SCAN_THRESHOLD:
            flags.append(
                f"Possible port scan from {src_ip} "
                f"({len(port_tracker[src_ip])} ports probed)"
            )

    return flags


#  Main Callback
def packet_callback(packet):
    # ignore anything that isn’t an IP packet (keeps things clean)
    if not IP in packet:
        return

    # grab basic info from the packet
    src = packet[IP].src
    dst = packet[IP].dst

    # figure out protocol + port
    proto, dst_port = get_protocol(packet)

    # timestamp so we know when it happened
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # build a readable log line
    port_str = f":{dst_port}" if dst_port else ""
    entry = f"[{timestamp}] {proto} | {src} → {dst}{port_str}"

    # store it and print it in cyan
    packet_log.append(entry)
    print(Fore.CYAN + entry)

    # check if anything about this packet looks suspicious
    flags = flag_suspicious(src, dst_port, proto)

    # if we found anything weird, log it as an alert
    for flag in flags:
        alert = f"[ALERT] {timestamp} | {flag} | Source: {src}"
        alerts.append(alert)
        print(Fore.RED + alert)


#  Report Writer
def write_report():
    # write everything we captured into a neat report file
    with open(REPORT_FILE, "w") as f:

        # header section
        f.write("=" * 60 + "\n")
        f.write("   NETWORK TRAFFIC ANALYSIS REPORT\n")
        f.write(f"   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        # quick summary 
        f.write("SUMMARY\n")
        f.write(f"  Total packets captured : {len(packet_log)}\n")
        f.write(f"  Alerts raised          : {len(alerts)}\n")
        f.write(f"  Unique source IPs      : {len(port_tracker)}\n\n")

        # list out any alerts we found
        if alerts:
            f.write("SECURITY ALERTS\n")
            f.write("-" * 40 + "\n")
            for alert in alerts:
                f.write(alert + "\n")
            f.write("\n")

        # full raw packet log
        f.write("FULL PACKET LOG\n")
        f.write("-" * 40 + "\n")
        for entry in packet_log:
            f.write(entry + "\n")

    print(Fore.GREEN + f"\n[✓] Report saved to {REPORT_FILE}")


 # running the program
if __name__ == "__main__":
    # let the user know that we’re starting
    print(Fore.YELLOW + f"[*] Starting capture — {PACKET_COUNT} packets...\n")

    # start sniffing packets and process each one with our callback
    sniff(prn=packet_callback, count=PACKET_COUNT, store=False)

    # once done we will generate the report
    write_report()