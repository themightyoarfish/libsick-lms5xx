#pragma once
#include <chrono>
#include <string>
#include <netinet/in.h>
#include <sys/socket.h>

namespace sick {

uint32_t ip_addr_to_int(const std::string &ip_str);

std::string ip_addr_to_hex_str(const std::string &ip_str);

/**
 * @brief Wrapper around connect() which supports timeout. Adapted from
 * https://stackoverflow.com/a/61960339/2397253 There is no way to do this
 * without polling the file descriptor.
 * @return 0 On success, -1 on error. errno get set.
 */
int connect_with_timeout(int sockfd, const struct sockaddr *addr,
                         socklen_t addrlen,
                         const std::chrono::system_clock::duration &timeout);
} // namespace sick
