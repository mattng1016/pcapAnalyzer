#include <iostream>

#include <pcap/pcap.h>

int openpcap(pcap_t* pcap, const char* path) {
  int packets = 0;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_pkthdr* header = nullptr;
  const u_char* data = nullptr;

  if (!(pcap = pcap_open_offline(path, errbuf))) {
    std::cout << errbuf;
    exit(1);
  }

  while (1) {
    int t = pcap_next_ex(pcap, &header, &data);
    
    if (t == 0) {
      std::cout << "packet error"; 
      exit(1);
    } else if (t == PCAP_ERROR_BREAK) {
      break;
    } 

    packets++;
  } 
  return packets; 
}

int main (int argc, char *argv[]) {
  pcap_t* handle = nullptr;

  if (argc != 2) {
    std::cout << "Error: Usage: <./pcapAnalyzer <filename.pcap>\n";
    exit(1);
  }  
  int packets = openpcap(handle, argv[1]);

  std::cout << "Amount of packets in " << argv[1] << ": " << packets << "\n";

  return 0;
}
