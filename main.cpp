#include <iostream>
#include <bitset>

#include <pcap/pcap.h>

//print packet size and source/destination IPv4 address
int numpcap(pcap_t* pcap) {
  int packets = 0;
  pcap_pkthdr* header = nullptr;
  const u_char* data = nullptr;

  while (1) {
    int t = pcap_next_ex(pcap, &header, &data);
    
    if (t == PCAP_ERROR) {
      std::cout << pcap_geterr(pcap); 
      exit(1);
    } else if (t == PCAP_ERROR_BREAK) {
      break;
    } else if (t == 1){
      packets++;
      const u_char* ipheader = data+14; 
      const u_char* sourceIP = ipheader + 12;      
      const u_char* destIP = sourceIP + 4;

      std::cout << "Packet " << packets;
      std::cout << " Source IP: " << int(sourceIP[0]) << "." << int(sourceIP[1]) << "." << int(sourceIP[2]) << "." << int(sourceIP[3]);
      std::cout << " Destiantion IP: " << int(destIP[0]) << "." << int(destIP[1]) << "." << int(destIP[2]) << "." << int(destIP[3]);
      std::cout << " Size: " << header->len << "\n";  
    }
  }
  return packets;
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
  int numpackets = numpcap(handle);

  std::cout << "Amount of packets in " << argv[1] << ": " << numpackets << "\n";

  return 0;
}
