# pcapAnalyzer

A terminal packet analyzer written in C++ using libpcap, developed and tested on macOS. This is a learning project exploring packet capture, network headers, and traffic statistics.

It supports inspecting saved PCAP files and capturing live traffic from a selected network interface.

<img width="770" height="500" alt="ScreenRecording2026-11-04at9 37 34PM-ezgif com-video-to-gif-converter(1)" src="https://github.com/user-attachments/assets/58a9d98c-e584-4b57-899a-ce747763ef0b" />

## Features

- IPv4 and IPv6 address display, including IPv6 zero compression.
- TCP/UDP protocol identification and port display for supported packets.
- Offline inspection with detailed and summary modes.
- Live packet rows with source/destination arrows.
- Live capture summary with captured bytes and unique IP addresses.
- Protocol distribution showing packet counts, byte totals, and percentages.
- Top 10 hosts ranked by packets sent, with sent/received packet and byte counts.
- Colored summary headings and terminal tables.

## Requirements

- macOS with Xcode Command Line Tools installed.
- A C++17 compiler and libpcap headers/library.
- A UTF-8 terminal with ANSI color support for the formatted output.

## Build

From the project directory:

```bash
clang++ -std=c++17 -Wall -Wextra \
  main.cpp offlineCapture.cpp liveCapture.cpp \
  -lpcap -o pcapAnalyzer
```

The `-lpcap` flag links the libpcap implementation used by the program.

## Usage

### Inspect a saved capture

```bash
./pcapAnalyzer --offline sample.pcap
```

Choose `1` for summary output or `2` for individual packet details.

Offline summaries currently show total packets, captured bytes, TCP packets, and UDP packets. Detailed output also reports supported truncation and parsing conditions.

### Capture live traffic

```bash
./pcapAnalyzer --live
```

Select an interface from the numbered list. Choose the interface carrying the traffic you want to inspect; interface names vary between machines. Captured link-layer support is currently limited to plain Ethernet-format frames, which may also be supplied by a Wi-Fi interface in normal capture mode.

Live capture may require permission to access macOS capture devices. If access is denied, run with appropriate capture permissions; for a local test, that may mean:

```bash
sudo ./pcapAnalyzer --live
```

Press **Ctrl+C** to request a stop and display the summary. Because reads are blocking, stopping can be delayed while waiting for traffic.

## How it works

```text
Select source → Read packet → Parse headers → Update statistics → Print output
```

- `main.cpp` selects offline or live mode from the command-line arguments.
- `offlineCapture.cpp` reads saved captures and handles offline parsing and output.
- `liveCapture.cpp` selects an interface, captures packets, and builds live statistics.
- Protocol and host statistics are accumulated in maps; individual packets are not retained for later browsing.

`caplen` is the number of bytes actually captured; `len` is the original packet length. Offline rows display original lengths, while captured-byte totals and live rows use captured lengths.

## Current limitations

This is an experimental learning project, not a production packet analyzer.

- Live parsing still needs complete bounds checks for truncated or malformed packets. Such packets can cause incorrect output or a crash.
- Live port parsing does not yet properly exclude non-TCP/UDP protocols, non-first IPv4 fragments, or IPv6 extension headers.
- VLAN-tagged Ethernet, raw Wi-Fi frames, and loopback link-layer formats are unsupported. Offline mode currently assumes Ethernet.
- Unsupported live packets can appear as protocol `0` with zero-valued ports.
- Input validation needs improvement; invalid interface selections can fail or crash.
- Live and offline code currently contain different definitions of identically named structs. These need consolidation or distinct names to avoid violating C++ definition rules.
- The capture-buffer timeout is a batching setting, not a guaranteed stop timer.
- Protocol percentages use the total packet count as the denominator; unidentified traffic may mean displayed protocol rows do not sum to 100%.
- Duration, average bandwidth, capture-file writing, and protocol reassembly are not implemented.
