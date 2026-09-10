# Network Packet Sniffer

This is my Task 1 project for the CodeAlpha Cybersecurity Internship. It's a Python tool with a simple GUI that captures live network traffic and shows what's actually happening on the network in real time - source/destination IPs, protocols, ports, and a payload preview for each packet.

## 🎯 Objectives

This project was built to meet the goals of Task 1 (Basic Network Sniffer):

- Build a Python program to capture live network traffic packets
- Analyze captured packets to understand their structure and content
- Learn how data actually flows through a network and get familiar with the basics of common protocols
- Use a packet-capture library (Scapy) instead of building raw socket handling from scratch
- Display useful information for each packet - source/destination IPs, protocols, ports, and payload

## ✨ Features

- Captures live packets in real time, up to 100 per session
- Simple dark-themed GUI (Tkinter) instead of a plain scrolling terminal
- Table view showing packet number, timestamp, protocol, source/destination IP and port, length, and a short payload preview
- Double-click any row to open a full packet breakdown, including a hex dump and ASCII preview of the payload
- Save a full capture session to a `.pcap` file, which can also be opened in Wireshark
- Start / Stop / Clear controls so you can manage a capture session without restarting the script
- Checks for admin/root privileges on startup (cross-platform: works on both Windows and Linux/Mac) since raw packet capture needs elevated permissions

## 🛠️ Technologies & Libraries Used

- **Python 3** - the language the whole project is written in
- **Scapy** - handles the actual packet capture and lets me read each protocol layer (Ethernet, IP, TCP, UDP, ICMP) without building that from scratch
- **Tkinter / ttk** - Python's built-in GUI toolkit, used for the window, buttons, and the Treeview table
- **threading** - runs the packet capture in the background so the GUI doesn't freeze while sniffing
- **datetime** - used for timestamps and naming the saved capture file
- **os / sys / ctypes** - used for the cross-platform admin/root permission check

## Why I built it this way

I originally had a plain terminal version, but I wanted something a bit easier to actually read through while it's running, so I built a small Tkinter GUI around it. The table view means you can watch packets stream in and still go back and inspect any specific one afterward instead of it just scrolling past in a terminal.

Scapy does all the actual packet capture and parsing (`sniff()`, and reading the IP/TCP/UDP/ICMP layers) - my code is mainly about deciding what to pull out of each packet and how to display it.

## Setup

Install Scapy:

```bash
sudo apt install python3-scapy python3-tk -y
```

or:

```bash
pip install scapy --break-system-packages
```

## Running it

```bash
sudo python3 network_sniffer.py
```

![Sniffer running](Screenshot%202026-09-10%20at%208.34.27%20PM.png)

It needs to run with sudo/admin rights, or it will exit immediately with an error - raw socket access for packet capture isn't allowed for normal user accounts.

While it's running, click **Start**, then generate some traffic in another window (browse a site, `ping google.com`, `curl` something) so there's actually something to capture. Double-click any row once packets start coming in to see the full details.

## Packet Information Displayed

For each captured packet, the table and detail view show:

| Field | Description |
|---|---|
| # | Packet number in the current session |
| Time | Timestamp the packet was captured |
| Protocol | TCP, UDP, ICMP, DNS, HTTP, HTTPS, or Unknown |
| Src IP / Dst IP | Source and destination IP addresses |
| Src Port / Dst Port | Source and destination ports (TCP/UDP only) |
| Length | Total packet size in bytes |
| Payload Preview | DNS query name, HTTP method/host/path, "Encrypted (TLS)" for HTTPS, TCP flags, or a short ASCII preview for other payloads |

Double-clicking a row also shows a full hex dump and ASCII preview of the raw payload where available.

## Screenshots

![Packet details view](Screenshot%202026-09-10%20at%208.46.44%20PM.png)

## A note on the traffic you'll see

Port 443 (HTTPS) traffic is automatically detected and labeled `Encrypted (TLS)` instead of trying to decode it, since TLS-encrypted data can't be read as plain text anyway - it would just show up as random-looking symbols. That's a normal part of how HTTPS works, not something wrong with the capture.

Plain HTTP (port 80) and DNS (port 53) traffic, on the other hand, are not encrypted, so you'll see the actual domain being looked up for DNS queries, and the method/host/path for HTTP requests.

![Capture summary](Screenshot%202026-09-10%20at%208.47.17%20PM.png)

## Files in this repo

- `network_sniffer.py` - the main script
- `requirements.txt` - just `scapy`
- `.gitignore` - keeps raw capture files out of the repo
- `screenshot.png` - a screenshot of it running
- `sample_capture.pcap` - one example capture session

## Ethical note

Only run this on a network you own or have permission to monitor. This was built for learning purposes as part of the internship, not for use on networks you don't control.

## What I learned

This was my first real hands-on experience with packet-level networking. Working through this taught me how TCP/UDP/ICMP actually look different at the packet level, how a normal TCP handshake shows up (SYN, SYN-ACK, ACK), and why encrypted traffic looks the way it does when you try to inspect it. It also gave me a much better idea of how tools like Wireshark work under the hood, since Scapy is doing a lot of the same core work, just in a scriptable way.

## Conclusion

This project gave me hands-on experience with real network traffic instead of just reading about how protocols work. Building the GUI around Scapy helped me understand not just how to capture packets, but how to actually make sense of what's happening on a network in real time, identifying protocols, tracking connections, and recognizing what encrypted traffic looks like versus plain data. It's a small project, but it covers the fundamentals that a lot of cybersecurity work builds on.
