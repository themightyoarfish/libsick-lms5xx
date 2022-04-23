#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>

namespace sick {

static uint32_t ip_addr_to_int(const std::string &ip_str) {

  uint32_t ip_network;
  // store this IP address in sa:
  inet_pton(AF_INET, ip_str.c_str(), &ip_network);

  return ip_network;
}

static std::string ip_addr_to_hex_str(const std::string &ip_str) {
  uint32_t ip_as_int = ntohl(ip_addr_to_int(ip_str));
  char out[2 * 4 + 3 + 1]{0};
  int sprintf_result =
      sprintf(out, "%02X %02X %02X %02X",
              // clang-format off
               (ip_as_int >> 24) & 0xFF,
               (ip_as_int >> 16) & 0xFF,
               (ip_as_int >> 8)  & 0xFF,
               ip_as_int         & 0xFF
              // clang-format on
      );
  if (sprintf_result < 0) {
    throw std::runtime_error("sprintf failed");
  }
  return out;
}
} // namespace sick
