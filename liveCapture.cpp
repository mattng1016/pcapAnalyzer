#include <cstdint>
#include <iostream>
#include <pcap.h>
#include <csignal>
#include <map>
#include <sys/types.h>
#include <thread>

struct ProtocolStats {
  uint64_t packets = 0;
  uint64_t bytes = 0;
};

struct HostStats {
  uint64_t packetsSent = 0;
  uint64_t packetsReceived = 0;
  uint64_t bytesSent = 0;
  uint64_t bytesReceived = 0;
};

struct pcapInfo {
  int totalPackets = 0;
  uint64_t capturedBytes = 0;

  std::map<int, ProtocolStats> protocols;
  std::map<std::string, HostStats> hosts;
};

struct PacketInfo {
  std::string srcAddress;
  std::string destAddress;
  int protocol;
  int srcPort;
  int destPort;
};

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

void printPacket() {

}

void parseProtocol() {

}

void parsePacket(const u_char* data, PacketInfo* Info) {
  //Protocol
  const u_char* protocol = data + 9;
  Info->protocol = protocol[0];    
  std::cout << "Protocol: " << protocolName(Info->protocol);
  
}

void updatePcap(pcapInfo* pcap, PacketInfo* packet) {

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

  while (!stopReq) {
    int result = pcap_next_ex(pcap, &header, &data);

    switch(result) {
      case 1: {
        std::cout << "Captured" << header->caplen << "bytes" << std::endl;
        PacketInfo Packet{};
        if (header->caplen < 14) {
          break;
        }
        if (pcap_datalink(pcap) == DLT_EN10MB) {
          u_int16_t typeIP = (data[12] << 8) | data[13];
          if (typeIP == 0x0800) {
            //IPv4
            parsePacket(data+14, &Packet);             
          } else if (typeIP == 0x86DD) {
            //IPv6
          } else {
            //Skip parsing
          }
        }
        updatePcap(&Info, &Packet);
        printPacket();
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
  pcap_close(pcap);
}

int main (int argc, char *argv[]) {
  liveCapture();
  return 0;
}






