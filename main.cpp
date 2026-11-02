#include <iomanip>
#include <iostream>

#include <pcap/pcap.h>
#include <set>

void printIP(const u_char* dataIPv4) {
  const u_char* sourceIP = dataIPv4 + 12;      
  const u_char* destIP = sourceIP + 4;

  std::string source = 
    std::to_string(sourceIP[0]) + "." +  
    std::to_string(sourceIP[1]) + "." +  
    std::to_string(sourceIP[2]) + "." +  
    std::to_string(sourceIP[3]); 

  std::string dest = 
    std::to_string(destIP[0]) + "." +  
    std::to_string(destIP[1]) + "." +  
    std::to_string(destIP[2]) + "." +  
    std::to_string(destIP[3]); 


  std::cout << std::setw(18) << source;
  std::cout << std::setw(18) << dest;
}

// Prints the port numebr
void printPort(const u_char* dataTransport) {
  const u_char* sourcePort = dataTransport;
  u_int16_t sourcePortValue = 0;
  sourcePortValue = (sourcePort[0] << 8) | sourcePort[1];
  const u_char* destPort = sourcePort + 2;
  u_int16_t destPortValue = 0;
  destPortValue = (destPort[0] << 8) | destPort[1];
  std::cout << std::setw(10) << sourcePortValue;
  std::cout << std::setw(10) << destPortValue;
}

void printProtocol(const u_char* dataIPv4) {
  const u_char* protocol = dataIPv4 + 9;
  if (protocol[0] == 6) {
    std::cout << std::setw(10) << "TCP";
  } else if (protocol[0] == 17) {
    std::cout << std::setw(10) << "UDP";
  }
}

void printPacket(pcap_pkthdr* header, const u_char* data) {
  std::cout << std::left
            << std::setw(8) << "Bytes"
            << std::setw(18) << "Source IP"
            << std::setw(18) << "Destination IP"
            << std::setw(10) << "Protocol"
            << std::setw(10) << "Src Port"
            << std::setw(10) << "Dest Port" << "\n";

  const u_char* ipheader = data+14;
  int headerLength = ipheader[0] & 0xF; 
  const u_char* transportHeader = ipheader + (headerLength * 4);
 

  std::cout << std::left << std::setw(8) << header->len;
  printIP(ipheader); 
  printProtocol(ipheader);  
  printPort(transportHeader);
}

void loopPcap(pcap_t* pcap) {
  pcap_pkthdr* header;
  const u_char* data;
  int packetNum = 1;
    while (1) {
    int t = pcap_next_ex(pcap, &header, &data);
    if (t == PCAP_ERROR) {
      std::cout << pcap_geterr(pcap); 
      exit(1);
    } else if (t == PCAP_ERROR_BREAK) {
      break;
    } else if (t == 1){
      std::cout << "Packet " << packetNum << ":\n";
      printPacket(header, data);
      packetNum++;
      std::cout << "\n";
    }
  } 
}

void openpcap(pcap_t*& pcap, const char* path) {
  char errbuf[PCAP_ERRBUF_SIZE];
  if (!(pcap = pcap_open_offline(path, errbuf))) {
    std::cout << errbuf;
    exit(1);
  }
}

int main (int argc, char *argv[]) {
  pcap_t* handle = nullptr;

  if (argc != 2) {
    std::cout << "Error: Usage: <./pcapAnalyzer <filename.pcap>\n";
    exit(1);
  }  

  openpcap(handle, argv[1]);
  loopPcap(handle);

  return 0;
}
