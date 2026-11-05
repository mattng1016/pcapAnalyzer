#include <algorithm>
#include <vector>
#include <utility>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <pcap.h>
#include <csignal>
#include <string>
#include <sys/types.h>
#include <thread>

#include "offlineCapture.h"
#include "liveCapture.h"

std::string protocolName(int protocol){
  switch(protocol) {
    case 6: return "TCP";
    case 17: return "UDP";
    case 1: return "ICMP";
    case 58: return "ICMPv6";
    case -1: return "Unknown";
    default: return "Other";
  }
}

int listDevice(pcap_if_t* alldevs) {
  int i = 1;
  for (pcap_if_t* device = alldevs; device != nullptr; device = device->next) {
    std::cout << i << "." << device->name << " ";
    i++;
  }
  return i;
}

std::string chooseDevice() {
  pcap_if_t* alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];
  int choice;

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    std::cout << errbuf;
    exit(1);
  }

  int num = listDevice(alldevs);
  std::cout << "\nChoose a device bewteen (1-" << num << "): "; 
  std::cin >> choice; 

  pcap_if_t* temp = alldevs;
  for (int i = 0; i < choice-1; i++) {
    temp = temp->next; 
  } 
  std::string name = temp->name;
  return name;
}

volatile std::sig_atomic_t stopReq = 0;
void handleStop(int) {
  stopReq = 1;
}

void printPacket(const PacketInfo* packet) {
  std::cout << std::left << std::setw(10) << protocolName(packet->protocol)
              << std::setw(41) << packet->srcAddress
              << " -> "
              << std::setw(41) << packet->destAddress
              << " :"
              << std::setw(10) << packet->srcPort
              << " -> :"
              << std::setw(10) << packet->destPort
              << " " << packet->bytes << '\n'; 
}

void parseIPv4Packet(const u_char* data, PacketInfo* Info) {
  // Protocol
  const u_char* protocol = data + 9;
  Info->protocol = protocol[0];    
  
  // IP address
  const u_char* srcIP = data + 12;
  Info->srcAddress = std::to_string(srcIP[0]) + "." + std::to_string(srcIP[1]) + "." + std::to_string(srcIP[2]) + "." + std::to_string(srcIP[3]);
  srcIP += 4;
  Info->destAddress = std::to_string(srcIP[0]) + "." + std::to_string(srcIP[1]) + "." + std::to_string(srcIP[2]) + "." + std::to_string(srcIP[3]);

  // Port
  int networkHeaderLength = (data[0] & 0x0F) * 4; 
  const u_char* transportLayer = data + networkHeaderLength;
  Info->srcPort = (transportLayer[0] << 8) | transportLayer[1];
  transportLayer += 2;
  Info->destPort = (transportLayer[0] << 8) | transportLayer[1];
}

void parseIPv6Packet(const u_char* data, PacketInfo* Info) {
  // Protocol
  const u_char* protocol = data + 6;
  Info->protocol = protocol[0];
  
  const u_char* srcAddress = data + 8;
  const u_char* destAddress = data + 24;
  u_int16_t srcGroup[8]{};
  u_int16_t destGroup[8]{};
  const u_char* tempaddr = srcAddress;
   
  // IP Address
  for (int i = 0; i < 8; i++) {
    srcGroup[i] = (tempaddr[0] << 8) | tempaddr[1];
    tempaddr += 2;
  }
  tempaddr = destAddress;
  for (int i = 0; i < 8; i++) {
    destGroup[i] = (tempaddr[0] << 8) | tempaddr[1];
    tempaddr += 2;
  }
  Info->srcAddress = shrinkZero(srcGroup);
  Info->destAddress = shrinkZero(destGroup);

  // Port
  const u_char* transportLayer = data + 40;
  Info->srcPort = (transportLayer[0] << 8) | transportLayer[1];
  transportLayer += 2;
  Info->destPort = (transportLayer[0] << 8) | transportLayer[1]; 
}

void updatePcap(pcapInfo* pcap, PacketInfo* packet) {
  pcap->capturedBytes += packet->bytes; 
  pcap->totalPackets++; 
  if (packet->protocol != -1) {
    pcap->protocols[packet->protocol].packets++;
    pcap->protocols[packet->protocol].bytes += packet->bytes;
  }
  if (!packet->srcAddress.empty()) {
    pcap->hosts[packet->srcAddress].packetsSent++;
    pcap->hosts[packet->srcAddress].bytesSent += packet->bytes;
  }
  if (!packet->destAddress.empty()) {
    pcap->hosts[packet->destAddress].packetsReceived++;
    pcap->hosts[packet->destAddress].bytesReceived += packet->bytes;
  }
}

void printHeader() {
  std::cout << std::left
            << std::setw(10) << "Protocol"
            << std::setw(41) << "Source IP"
            << "    "
            << std::setw(41) << "Destination IP"
            << "  "
            << std::setw(10) << "Src Port"
            << "     "
            << std::setw(10) << "Dst Port"
            << " Captured Bytes\n";
}

void printPcapSummary(pcapInfo* info) {
  const int width = 48;
  const std::string border = "+" + std::string(width, '-') + "+";
  auto row = [](const std::string& text) {
    std::cout << "\033[32m|\033[0m " << std::left
              << std::setw(47) << text << "\033[32m|\033[0m\n";
  };
  std::cout << "\n\033[32m" << border << "\033[0m\n";
  row("Capture Summary");
  std::cout << "\033[32m" << border << "\033[0m\n";
  row("Total packets: " + std::to_string(info->totalPackets));
  row("Captured bytes: " + std::to_string(info->capturedBytes));
  row("Unique IP addresses: " + std::to_string(info->hosts.size()));
  row("Protocols seen: " + std::to_string(info->protocols.size()));
  std::cout << "\033[32m" << border << "\033[0m\n";
}

void printProtocolSummary(pcapInfo* info) {
  const std::string border = "+--------------------+--------------+------------------+------------+";
  std::cout << "\n\033[32mProtocol Distribution\033[0m\n"
            << border << '\n'
            << "| " << std::left << std::setw(18) << "Protocol"
            << " | " << std::setw(12) << "Packets"
            << " | " << std::setw(16) << "Captured bytes"
            << " | " << std::setw(10) << "Percent" << " |\n"
            << border << '\n';
  for (const auto& entry : info->protocols) {
    const auto& stats = entry.second;
    double percent = info->totalPackets > 0
        ? 100.0 * stats.packets / info->totalPackets : 0.0;
    std::ostringstream percentage;
    percentage << std::fixed << std::setprecision(1) << percent << '%';
    std::string label = protocolName(entry.first);
    if (label == "Other") label += " (" + std::to_string(entry.first) + ")";
    std::cout << "| " << std::left << std::setw(18) << label
              << " | " << std::setw(12) << stats.packets
              << " | " << std::setw(16) << stats.bytes
              << " | " << std::setw(10) << percentage.str() << " |\n";
  }
  std::cout << border << '\n';
}

void printAddressSummary(pcapInfo* info) {
  std::vector<std::pair<std::string, HostStats>> hosts(
      info->hosts.begin(), info->hosts.end());
  std::sort(hosts.begin(), hosts.end(),
      [](const std::pair<std::string, HostStats>& a,
         const std::pair<std::string, HostStats>& b) {
        if (a.second.packetsSent != b.second.packetsSent)
          return a.second.packetsSent > b.second.packetsSent;
        return a.first < b.first;
      });
  const std::string border = "+-----------------------------------------+--------------+--------------+------------------+------------------+";
  std::cout << "\n\033[32mTop 10 Talkers (by packets sent)\033[0m\n"
            << border << '\n'
            << "| " << std::left << std::setw(39) << "IP address"
            << " | " << std::setw(12) << "Packets sent"
            << " | " << std::setw(12) << "Packets recv"
            << " | " << std::setw(16) << "Bytes sent"
            << " | " << std::setw(16) << "Bytes recv" << " |\n"
            << border << '\n';
  for (std::size_t i = 0; i < hosts.size() && i < 10; ++i) {
    const auto& host = hosts[i];
    std::cout << "| " << std::left << std::setw(39) << host.first
              << " | " << std::setw(12) << host.second.packetsSent
              << " | " << std::setw(12) << host.second.packetsReceived
              << " | " << std::setw(16) << host.second.bytesSent
              << " | " << std::setw(16) << host.second.bytesReceived << " |\n";
  }
  std::cout << border << '\n';
}

void liveCapture() {
  char errbuf[PCAP_ERRBUF_SIZE];
  std::string name = chooseDevice();

  std::signal(SIGINT, handleStop);

  pcap_t* pcap = pcap_create(name.c_str(), errbuf);
  if (!pcap) {
    std::cout << "pcap_t creation error";
    exit(0);
  }
  // Returns packet buffer every 100ms (if not it just waits until buffer full)
  if (pcap_set_timeout(pcap, 100) != 0) { 
    std::cerr << pcap_geterr(pcap) << "\n";
    pcap_close(pcap);
    return;
  }
  if (pcap_activate(pcap) != 0) {
    std::cout << "pcap_activate error";
    exit(0);
  }

  std::cout << "\n Starting capture on " << name << "...\n";
  std::cout << "Press CTRL+C to stop\n"; 

  pcap_pkthdr* header;
  const u_char* data;
  pcapInfo Info{};  

  printHeader();

  while (!stopReq) {
    int result = pcap_next_ex(pcap, &header, &data);
    switch(result) {
      case 1: {
        //std::cout << "Captured" << header->caplen << "bytes" << std::endl;
        PacketInfo Packet{};
        Packet.bytes = header->caplen;
        if (header->caplen < 14) {
          break;
        }
        if (pcap_datalink(pcap) == DLT_EN10MB) {
          u_int16_t typeIP = (data[12] << 8) | data[13];
          if (typeIP == 0x0800) {
            //IPv4
            parseIPv4Packet(data+14, &Packet);             
          } else if (typeIP == 0x86DD) {
            //IPv6
            parseIPv6Packet(data+14, &Packet);
          } else {
            //Skip parsing
          }
        }
        updatePcap(&Info, &Packet);
        printPacket(&Packet );
        break;
      }
      case 0:
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        break;
      case PCAP_ERROR:
        std::cerr << pcap_geterr(pcap) << "\n";
        stopReq = -1;
        break;
      case PCAP_ERROR_BREAK:
        stopReq = -1;
        break;
    }
 }
  printPcapSummary(&Info);
  printProtocolSummary(&Info);
  printAddressSummary(&Info);

  pcap_close(pcap);
}




