#pragma once
#include <chrono>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>

namespace sick {

/**
 * @brief   Convert an IP address in dotted notation to an integer **in network
 * byte order**
 *
 * @param ip_str    Input, e.g. `192.168.1.0`
 *
 * @return  32 bit integer in network byte order
 */
uint32_t ip_addr_to_int(const std::string &ip_str);

std::string ip_addr_to_hex_str(const std::string &ip_str);

/**
 * @brief Wrapper around connect() which supports timeout. Same API as
 * `connect()` Adapted from https://stackoverflow.com/a/61960339/2397253 There
 * is no way to do this without polling the file descriptor.
 * @param   sockfd    File descriptor of the socket
 * @param   addr    address struct as passed to `connect()`
 * @param   addrlen   address struct size as passed to `connect()`
 * @param   timeout Timeout to wait on connection until fail
 * @return 0 On success, -1 on error. errno gets set.
 */
int connect_with_timeout(int sockfd, const struct sockaddr *addr,
                         socklen_t addrlen,
                         const std::chrono::system_clock::duration &timeout);
} // namespace sick
