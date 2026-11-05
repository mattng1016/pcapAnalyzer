#include <iostream>
#include "offlineCapture.h"
#include "liveCapture.h"

int main (int argc, char *argv[]) {
  if (argc == 2 && std::string(argv[1]) == "--live") {
    liveCapture();
  } else if (argc == 3 && std::string(argv[1]) == "--offline") {
    offlineCapture(argv[2]); 
  } else {
    std::cerr << "Usage:\n"
                  << "  ./pcapAnalyzer --live\n"
                  << "  ./pcapAnalyzer --offline <file.pcap>\n";
        return 1; 
  }
  return 0;
}
