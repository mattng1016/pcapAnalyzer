#include <cstdio>
#include <iomanip>
#include <iostream>

#include <pcap/pcap.h>
#include <sstream>

#define IP_WIDTH 41

struct PacketInfo {
  std::string sourceIP;
  std::string destIP;
  int protocol = -1;
  int sourcePort = -1;
  int destPort = -1;
  std::string status;
};

struct pcapInfo {
  int totalPackets = 0;
  uint64_t capturedBytes = 0;
  int tcpPackets = 0;
  int udpPackets = 0;
};

void parseIPv4(const u_char *dataIPv4, PacketInfo *p) {
  const u_char *sourceIP = dataIPv4 + 12;
  const u_char *destIP = sourceIP + 4;
  std::string source =
      std::to_string(sourceIP[0]) + "." + std::to_string(sourceIP[1]) + "." +
      std::to_string(sourceIP[2]) + "." + std::to_string(sourceIP[3]);
  std::string dest =
      std::to_string(destIP[0]) + "." + std::to_string(destIP[1]) + "." +
      std::to_string(destIP[2]) + "." + std::to_string(destIP[3]);
  p->sourceIP = source;
  p->destIP = dest;
}

std::string shrinkZero(u_int16_t (&group)[8]) {
  int currentStart = 0;
  int currentLength = 0;
  int bestStart = -1;
  int bestLength = -1;

  for (int i = 0; i < 8; i++) {
    if (group[i] == 0) {
      if (currentLength == 0) {
        currentStart = i;
      }
      currentLength++;
      if (currentLength > bestLength) {
        bestStart = currentStart;
        bestLength = currentLength;
      }
    } else {
      currentLength = 0;
    }
  }
  std::ostringstream s;
  s << std::hex;
  if (bestLength < 2) {
    std::ostringstream s;
    s << std::hex;

    for (int i = 0; i < 8; i++) {
      s << group[i];
      if (i < 7) {
        s << ":";
      }
    }
    return s.str();
  }
  for (int i = 0; i < 8; i++) {
    if (i < bestStart || i > (bestLength + bestStart) - 1) {
      s << group[i];
      if (i < 7 && i + 1 != bestStart) {
        s << ":";
      }
    } else if (i == (bestLength + bestStart) - 1) {
      s << "::";
    }
  }
  return s.str();
}

void parseIPv6(const u_char *dataIPv6, PacketInfo *p) {
  const u_char *sourceIP = dataIPv6 + 8;
  const u_char *destIP = sourceIP + 16;

  u_int16_t sourceGroup[8]{};
  const u_char *tempaddr = sourceIP;
  for (int i = 0; i < 8; i++) {
    u_int16_t temp = (tempaddr[0] << 8) | tempaddr[1];
    sourceGroup[i] = temp;
    tempaddr = tempaddr + 2;
  }

  u_int16_t destGroup[8]{};
  tempaddr = destIP;
  for (int i = 0; i < 8; i++) {
    u_int16_t temp = (tempaddr[0] << 8) | tempaddr[1];
    destGroup[i] = temp;
    tempaddr = tempaddr + 2;
  }

  p->sourceIP = shrinkZero(sourceGroup);
  p->destIP = shrinkZero(destGroup);
}

void parsePort(const u_char *dataTransport, PacketInfo *p) {
  const u_char *sourcePort = dataTransport;
  u_int16_t sourcePortValue = 0;
  sourcePortValue = (sourcePort[0] << 8) | sourcePort[1];
  const u_char *destPort = sourcePort + 2;
  u_int16_t destPortValue = 0;
  destPortValue = (destPort[0] << 8) | destPort[1];
  p->sourcePort = sourcePortValue;
  p->destPort = destPortValue;
}

void parseProtocol(const u_char *protocol, PacketInfo *p) {
  p->protocol = protocol[0];
}

PacketInfo parsePacket(const pcap_pkthdr *header, const u_char *data) {
  PacketInfo packet;

  if (header->caplen < 14) {
    packet.status = "Truncated Ethernet";
    return packet;
  }

  int etherType = (data[12] << 8) | data[13];
  const u_char *ip = data + 14;
  unsigned int ipLength;

  if (etherType == 0x0800) {
    if (header->caplen < 34) {
      packet.status = "Truncated IPv4";
      return packet;
    }

    ipLength = (ip[0] & 0x0F) * 4;

    if ((ip[0] >> 4) != 4 || ipLength < 20) {
      packet.status = "Invalid IPv4 header";
      return packet;
    }

    if (header->caplen < 14 + ipLength) {
      packet.status = "Truncated IPv4 header";
      return packet;
    }

    parseIPv4(ip, &packet);
    parseProtocol(ip + 9, &packet);

    int fragmentOffset = ((ip[6] << 8) | ip[7]) & 0x1FFF;
    if (fragmentOffset != 0) {
      packet.status = "Non-first IPv4 fragment";
      return packet;
    }
  } else if (etherType == 0x86DD) {
    if (header->caplen < 54) {
      packet.status = "Truncated IPv6";
      return packet;
    }

    if ((ip[0] >> 4) != 6) {
      packet.status = "Invalid IPv6 header";
      return packet;
    }

    ipLength = 40;
    parseIPv6(ip, &packet);
    parseProtocol(ip + 6, &packet);
  } else {
    packet.status = "Unsupported EtherType";
    return packet;
  }

  if (packet.protocol != 6 && packet.protocol != 17) {
    packet.status = "Ports unavailable for this protocol";
    return packet;
  }

  unsigned int ipPacketLength;
  if (etherType == 0x0800) {
    ipPacketLength = (ip[2] << 8) | ip[3];
  } else {
    ipPacketLength = 40 + ((ip[4] << 8) | ip[5]);
  }

  if (ipPacketLength < ipLength + 4) {
    packet.status = "IP packet too short for ports";
    return packet;
  }

  if (header->caplen < 14 + ipLength + 4) {
    packet.status = "Truncated ports";
    return packet;
  }

  parsePort(ip + ipLength, &packet);
  return packet;
}

void printPacket(PacketInfo *p) {
  std::string protocol = "Other";
  if (p->protocol == -1)
    protocol = "-";
  else if (p->protocol == 6)
    protocol = "TCP";
  else if (p->protocol == 17)
    protocol = "UDP";
  else if (p->protocol == 1)
    protocol = "ICMP";
  else if (p->protocol == 58)
    protocol = "ICMPv6";

  std::cout << std::left << std::setw(IP_WIDTH)
            << (p->sourceIP.empty() ? "-" : p->sourceIP) << std::setw(IP_WIDTH)
            << (p->destIP.empty() ? "-" : p->destIP) << std::setw(10)
            << protocol << std::setw(10)
            << (p->sourcePort < 0 ? "-" : std::to_string(p->sourcePort))
            << std::setw(10)
            << (p->destPort < 0 ? "-" : std::to_string(p->destPort));

  if (!p->status.empty()) {
    std::cout << "  " << p->status;
  }

  std::cout << '\n';
}

void loopPcap(pcap_t *pcap, bool detailed) {
  pcap_pkthdr *header;
  const u_char *data;
  pcapInfo pcapp{};
  if (detailed) {
    std::cout << std::left << std::setw(8) << "No." << std::setw(8) << "Bytes"
              << std::setw(IP_WIDTH) << "SourceIP" << std::setw(IP_WIDTH)
              << "DestinationIP" << std::setw(10) << "Protocol" << std::setw(10)
              << "SrcPort" << std::setw(10) << "DestPort" << "\n";
  }
  while (1) {
    int t = pcap_next_ex(pcap, &header, &data);
    if (t == PCAP_ERROR) {
      std::cout << pcap_geterr(pcap);
      exit(1);
    } else if (t == PCAP_ERROR_BREAK) {
      break;
    } else if (t == 1) {
      pcapp.totalPackets++;
      pcapp.capturedBytes += header->caplen;

      PacketInfo p = parsePacket(header, data);
      if (p.protocol == 6) {
        pcapp.tcpPackets++;
      } else if (p.protocol == 17) {
        pcapp.udpPackets++;
      }
      if (detailed) {
        std::cout << std::left << std::setw(8) << pcapp.totalPackets
                  << std::setw(8) << header->len;
        printPacket(&p);
      }
    }
  }
  if (!detailed) {
    std::cout << "\nTotal packets: " << pcapp.totalPackets << "\n";
    std::cout << "Total captured bytes: " << pcapp.capturedBytes << "\n";
    std::cout << "TCP packets: " << pcapp.tcpPackets << "\n";
    std::cout << "UDP packets: " << pcapp.udpPackets << "\n\n";
  }
}

void openpcap(pcap_t *&pcap, const char *path) {
  char errbuf[PCAP_ERRBUF_SIZE];
  if (!(pcap = pcap_open_offline(path, errbuf))) {
    std::cout << errbuf;
    exit(1);
  }

  int input;
  std::cout << "Valid pcap, press 1 to see summary or 2 to see details: ";
  bool valid = false;
  while (!valid) {
    std::cin >> input;
    if (input == 1) {
      loopPcap(pcap, false);
      valid = true;
    } else if (input == 2) {
      loopPcap(pcap, true);
      valid = true;
    } else {
      valid = false;
      std::cout
          << "Invalid input, press 1 to see summary or 2 to see details: ";
      input = 0;
    }
  }
}

int main(int argc, char *argv[]) {
  pcap_t *handle = nullptr;

  if (argc != 2) {
    std::cout << "Error: Usage: <./pcapAnalyzer <filename.pcap>\n";
    exit(1);
  }

  openpcap(handle, argv[1]);
  pcap_close(handle);
  return 0;
}
