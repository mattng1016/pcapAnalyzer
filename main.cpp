#include <iomanip>
#include <iostream>

#include <pcap/pcap.h>
#include <sstream>

void printIPv4(const u_char* dataIPv4) {
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
    if (i < bestStart || i > (bestLength+bestStart)-1) {
      s << group[i];
      if (i < 7 && i+1 != bestStart) {
        s << ":";
      }
    }
    else if (i == (bestLength+bestStart)-1) {
      s << "::";
    }
  } 

  return s.str();
}

void printIPv6(const u_char* dataIPv6) {
  const u_char* sourceIP = dataIPv6 + 8;      
  const u_char* destIP = sourceIP + 16;

  u_int16_t sourceGroup[8]{};
  const u_char* tempaddr = sourceIP;
  for (int i = 0; i < 8; i++) {
    u_int16_t temp = (tempaddr[0] << 8) | tempaddr[1];
    sourceGroup[i] = temp;
    tempaddr = tempaddr + 2;
  }

  std::cout << std::hex << "\n";
  for (auto i : sourceGroup) {
    std::cout << i << ".";
  }
  std::cout << "\n" << std::dec;

  u_int16_t destGroup[8]{};
  for (int i = 0; i < 8; i++) {
    tempaddr = destIP;
    u_int16_t temp = (tempaddr[0] << 8) | tempaddr[1];
    destGroup[i] = temp;
    tempaddr = tempaddr + 2;
  }

  shrinkZero(sourceGroup);

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

bool checkIPVersion(const u_char* data) {
  const u_char* type = data + 12;
  u_int16_t typeValue = (type[0] << 8) | type[1];

  if (typeValue == 0x0800) {
    return true; 
  } else if (typeValue == 0x86DD) {
    return false;
  }
  return false;
}

void printPacket(pcap_pkthdr* header, const u_char* data) {
  const u_char* ipheader;
  int headerLength;
  const u_char* transportHeader;
  int version;
  if (header->caplen < 14) {
    std::cout << "Error reading this packet \n";
    return;
  }
  ipheader = data + 14;

  if (checkIPVersion(data)) { 
    //IPV4
    headerLength = ipheader[0] & 0xF; 
    transportHeader = ipheader + (headerLength * 4);
    version = 4;
  } else { 
    // IPV6
    version = 6;
  }

  std::cout << std::left
            << std::setw(8) << "Bytes"
            << std::setw(18) << "Source IP"
            << std::setw(18) << "Destination IP"
            << std::setw(10) << "Protocol"
            << std::setw(10) << "Src Port"
            << std::setw(10) << "Dest Port" << "\n";
 
  std::cout << std::left << std::setw(8) << header->len;
  if (version == 4) {
    printIPv4(ipheader);
  } else if (version == 6) {
    printIPv6(ipheader);
  }
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
