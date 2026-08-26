# 🔒 Network Packet Sniffer & Traffic Analyzer

A lightweight, zero-dependency network packet sniffer written in **Python 3** using **Linux raw sockets**. This tool captures live link-layer network traffic, unpacks binary protocol headers, and logs packet metadata in real time.

---

## 🌟 Key Features

- **Raw Socket Capture:** Uses Linux `AF_PACKET` raw sockets to intercept network frames directly at Layer 2.
- **Binary Unpacking:** Manually unpacks and decodes protocol headers using Python's native `struct` library.
- **Multi-Protocol Support:**
  - **Data Link Layer:** Ethernet Frames (MAC Address extraction)
  - **Network Layer:** IPv4 (Source & Destination IP extraction)
  - **Transport Layer:** TCP, UDP, ICMP (Port parsing & protocol identification)
- **Automated Logging:** Saves captured traffic metadata with timestamps to `capture_log.txt`.
- **Zero External Dependencies:** Built using strictly Python standard library modules (`socket`, `struct`, `time`).

---

## ⚙️ How It Works
