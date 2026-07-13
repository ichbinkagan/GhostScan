# 🛠️ GhostScan - Advanced Network Analysis & Security Tool

GhostScan is a modular, high-performance command-line (CLI) network security and analysis suite developed in Python. Designed for network administrators and penetration testers, it bundles essential network reconnaissance, packet analysis, and live monitoring tools into a single cohesive interface.

---

## 🚀 Features

GhostScan is highly modularized, with each capability cleanly split into dedicated components:

* **[1] Network Scan:** Discovers live hosts on the local network mapping active IP and MAC addresses.
* **[2] Packet Capture:** Sniffs real-time network traffic and prepares data for local analysis.
* **[3] WiFi Analyzer:** Audits local wireless interfaces and details connection states.
* **[4] DNS Analyzer:** Extracts and parses DNS queries and responses from network data.
* **[5] HTTP/HTTPS Analyzer:** Captures standard unencrypted HTTP data (Methods, Paths, Status) and extracts domain destinations from encrypted HTTPS traffic using **TLS SNI handshake parsing**.
* **[6] Port Scanner:** High-speed parallel TCP port scanner powered by multi-threading (`Queue` architecture).
* **[7] Read PCAP:** Parses and displays captured `.pcap` files into a readable, formatted packet summary table.
* **[8] Save Capture:** Commits captured packet streams cleanly to disk as standard `.pcap` files.
* **[9] Live Statistics:** A dynamic, full-terminal dashboard displaying real-time protocol distribution and Top-Talking IP addresses.
* **[10] IP Geolocation:** Leverages the IPInfo API to instantly query country, region, ISP, and coordinates for any given public IP.

---

## 📂 Project Architecture

The repository is cleanly architected following modular programming best practices:

```text
GHOSTSCAN/
│
├── banner.py            # Terminal branding and custom ASCII art layout
├── main.py              # Main terminal CLI loop, screen controller, and menu interface
│
├── scanner.py           # Network host discovery engine
├── capture.py           # Real-time packet sniffer core logic
├── live_stats.py        # Rich-powered dashboard for real-time packet statistics
├── pcap.py              # Packet reader and tabular summary parser for .pcap files
├── ports.py             # Multi-threaded TCP port scanning logic
├── dns.py               # DNS protocol transaction parser
├── http_analyzer.py     # Deep packet inspector for HTTP and raw TLS SNI extractions
├── geopy.py             # IPInfo API wrapper for location mapping
├── wifi.py / network.py # Wireless interfaces configuration and hardware analytics
│
├── requirements.txt     # Python dependency configuration file
└── README.md            # Repository documentation
