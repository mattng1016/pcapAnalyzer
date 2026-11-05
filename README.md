<div align="center">

# pcapAnalyzer

**Live traffic. Saved captures. A closer look at the packets.**

A C++ terminal packet analyzer built with libpcap on macOS.

![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat-square)
![libpcap](https://img.shields.io/badge/capture-libpcap-22c55e?style=flat-square)
![macOS](https://img.shields.io/badge/platform-macOS-111827?style=flat-square)
![Learning project](https://img.shields.io/badge/status-learning%20project-f59e0b?style=flat-square)

[Demo](#demo) · [Quick start](#quick-start) · [Usage](#usage) · [Known limitations](#known-limitations)

</div>

## Demo

<p align="center">
  <img src="https://github.com/user-attachments/assets/58a9d98c-e584-4b57-899a-ce747763ef0b" alt="Animated demonstration of pcapAnalyzer in the terminal" width="850">
</p>

Inspect individual packets, follow source and destination addresses, and see which protocols and hosts account for the traffic.

<details>
<summary><strong>View terminal screenshots</strong></summary>

<p align="center">
  <img src="https://github.com/user-attachments/assets/4d9535a1-6a93-45c5-a52d-39127ec770c0" alt="pcapAnalyzer terminal output, wide view" width="1100">
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/bac998c2-395c-4264-9f61-59c60799c9e1" alt="pcapAnalyzer terminal output, second view" width="950">
</p>

</details>

## What it does

| Mode | Output |
| :--- | :--- |
| **Live capture** | Select an interface, watch packet rows, then stop to see traffic statistics. |
| **Offline inspection** | Open a PCAP and choose individual packet details or a compact summary. |

- **Packet details** — IPv4/IPv6 addresses, protocol names, and TCP/UDP ports for supported packets.
- **IPv6 formatting** — hexadecimal addresses with zero-run compression.
- **Live statistics** — packet counts, captured bytes, unique IP addresses, and protocols seen.
- **Protocol distribution** — packet and byte totals with percentages.
- **Top 10 talkers** — hosts ranked by packets sent, including sent/received bytes and packets.
- **Terminal tables** — source/destination arrows, aligned columns, and colored summaries.

## Quick start

### Requirements

macOS, Xcode Command Line Tools, a C++17 compiler, and libpcap headers/library. Use a terminal with ANSI color support for the formatted summaries.

### Clone and build

```bash
git clone https://github.com/mattng1016/pcapAnalyzer.git
cd pcapAnalyzer

clang++ -std=c++17 -Wall -Wextra \
  main.cpp offlineCapture.cpp liveCapture.cpp \
  -lpcap -o pcapAnalyzer
```

The `-lpcap` flag links the packet-capture library.

## Usage

### Inspect a PCAP

```bash
./pcapAnalyzer --offline sample.pcap
```

At the prompt, choose:

| Option | Display |
| :---: | :--- |
| `1` | Total packets, captured bytes, TCP count, and UDP count |
| `2` | Individual packet details and supported parsing/truncation messages |

### Capture live traffic

```bash
./pcapAnalyzer --live
```

1. Select a network interface from the numbered list.
2. Generate traffic on that interface, such as by opening a webpage.
3. Press **Ctrl+C** to request a stop and print the summary.

Interface names vary between machines. Current live parsing targets plain Ethernet-format frames, which a Wi-Fi interface may also supply in normal capture mode.

If macOS denies access to capture devices, use appropriate capture permissions. For a local test:

```bash
sudo ./pcapAnalyzer --live
```

> **Stopping:** capture reads are blocking, so Ctrl+C may not take effect immediately when there is no traffic.

## Inside the project

```text
main.cpp                 Command-line mode selection
├── offlineCapture.cpp   Saved captures, offline parsing, and output
└── liveCapture.cpp      Interface selection, live parsing, and statistics
```

```text
Read packet → Parse headers → Update counters and maps → Print packet
                                      ↓
                                Final summary
```

Statistics accumulate in protocol and host maps. Individual packets are processed as they arrive rather than stored for later browsing.

<details>
<summary><strong>Packet length: captured bytes vs original bytes</strong></summary>

- `caplen` is the number of bytes actually saved or delivered by the capture.
- `len` is the packet's original length.
- Offline detail rows show original lengths.
- Captured-byte totals and live rows use captured lengths.

A truncated capture can therefore have `caplen < len`.

</details>

## Known limitations

**This is a learning project and is still experimental.** The offline and live paths currently have different levels of validation.

| Area | Current scope |
| :--- | :--- |
| Link layer | Plain Ethernet; VLAN tags, raw Wi-Fi, and loopback formats are unsupported. Offline inspection assumes Ethernet. |
| Live parsing | Complete bounds checking is still needed. Truncated or malformed packets can produce incorrect results or crashes. |
| Transport parsing | Live parsing does not yet correctly exclude non-TCP/UDP traffic, non-first IPv4 fragments, or IPv6 extension headers. |
| Controls | Interface/input validation needs improvement; capture stopping can be delayed. |

<details>
<summary><strong>Additional implementation notes</strong></summary>

- Unsupported live packets can appear as protocol `0` with zero-valued ports.
- Invalid interface selections can fail or crash.
- Live and offline code contain different definitions of identically named structs. These need consolidation or distinct names to satisfy C++ definition rules.
- The capture-buffer timeout controls batching; it is not a guaranteed stop timer.
- Protocol percentages use the total packet count as the denominator. Unidentified traffic may mean protocol rows do not sum to 100%.
- Duration, average bandwidth, capture-file writing, and protocol reassembly are not implemented.

</details>

## About

Built to learn C++, compilation and linking, libpcap, and how network headers are represented as bytes.

Capture files may contain private traffic. Use synthetic or sanitized captures when sharing examples, and only capture traffic you are authorized to inspect.
