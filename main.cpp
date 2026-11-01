#include <iostream>

int main (int argc, char *argv[]) {
  if (argc != 2) {
    std::cout << "Error: Usage: <./pcapAnalyzer <filename.pcap>";
    exit(1);
  }  
  
  return 0;
}
