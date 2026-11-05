#include <cstdint>
#include <map>

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
  int bytes;
};

void liveCapture();
