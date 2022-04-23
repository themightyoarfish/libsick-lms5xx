#pragma once
#include <arpa/inet.h>
#include <chrono>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
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

/**
 * @brief Wrapper around connect() which supports timeout. Adapted from
 * https://stackoverflow.com/a/61960339/2397253 There is no way to do this
 * without polling the file descriptor.
 * @return 0 On success, -1 on error. errno get set.
 */
static int
connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen,
                     const std::chrono::system_clock::duration &timeout) {
  int rc = 0;
  // Set O_NONBLOCK
  int sockfd_flags_before;
  if ((sockfd_flags_before = fcntl(sockfd, F_GETFL, 0) < 0))
    return -1;
  if (fcntl(sockfd, F_SETFL, sockfd_flags_before | O_NONBLOCK) < 0)
    return -1;
  // Start connecting (asynchronously)
  do {
    if (connect(sockfd, addr, addrlen) < 0) {
      // Did connect return an error? If so, we'll fail.
      if ((errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
        rc = -1;
      }
      // Otherwise, we'll wait for it to complete.
      else {
        const auto poll_begin = std::chrono::system_clock::now();
        const auto poll_end = poll_begin + timeout;
        do {
          const auto now = std::chrono::system_clock::now();
          if (now > poll_end) {
            return -1;
          }
          const int remaining_ms =
              std::chrono::duration_cast<std::chrono::milliseconds>(poll_end -
                                                                    now)
                  .count();
          // Wait for connect to complete (or for the timeout deadline)
          struct pollfd pfds[] = {{.fd = sockfd, .events = POLLOUT}};
          rc = poll(pfds, 1, remaining_ms);
          // If poll 'succeeded', make sure it *really* succeeded
          if (rc > 0) {
            int error = 0;
            socklen_t len = sizeof(error);
            int retval = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
            if (retval == 0)
              errno = error;
            if (error != 0)
              rc = -1;
          }
        }
        // If poll was interrupted, try again.
        while (rc == -1 && errno == EINTR);
        // Did poll timeout? If so, fail.
        if (rc == 0) {
          errno = ETIMEDOUT;
          rc = -1;
        }
      }
    }
  } while (0);
  // Restore original O_NONBLOCK state
  if (fcntl(sockfd, F_SETFL, sockfd_flags_before) < 0)
    return -1;
  // Success
  return rc;
}
} // namespace sick
