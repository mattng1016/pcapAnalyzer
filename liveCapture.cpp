#include <cstdint>
#include <iostream>
#include <pcap.h>
#include <csignal>
#include <map>
#include <sys/types.h>

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

void parseIP() {

}

void liveCapture() {
  char errbuf[PCAP_ERRBUF_SIZE];
  std::string name = chooseDevice();

  std::signal(SIGINT, handleStop);

  pcap_t* pcap = pcap_create(name.c_str(), errbuf);
  pcap_activate(pcap);

  std::cout << "\n Starting capture on " << name << "...\n";
  std::cout << "Press C to stop\n"; 

  pcap_pkthdr* header;
  const u_char* data;
  pcapInfo Info{};  

  while (!stopReq) {
    if (pcap_next_ex(pcap, &header, &data) == 1) {
                   
    } else {

    }
  }
}

int main (int argc, char *argv[]) {
  liveCapture();
  return 0;
}






