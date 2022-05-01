#include <sick-lms5xx/sopas.hpp>

namespace sick {

static int uninterrupted_recv(int fd, char *data, int len) {
  int ret;
  while ((ret = recv(fd, data, len, 0)) == -1 && errno == EINTR) {
    continue;
  }
  return ret;
}

static int uninterrupted_send(int fd, const char *data, int len) {
  int ret;
  while ((ret = send(fd, data, len, 0)) == -1 && errno == EINTR) {
    continue;
  }
  return ret;
}

SOPASProtocol::SOPASProtocol(const std::string &sensor_ip, const uint32_t port,
                             const ScanCallback &fn)
    : sensor_ip_(sensor_ip), port_(port), callback_(fn) {
  stop_.store(false);

  sock_fd_ = socket(PF_INET, SOCK_STREAM, 0);
  if (sock_fd_ < 0) {
    throw std::runtime_error("Unable to create socket.");
  }
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = ip_addr_to_int(sensor_ip);

  // TODO: some commands might cause the scanner to take a while to respond
  // (when config changes or something). so there might not be a universal
  // timeout, but we should set a long one to not deadlock during config, and
  // a shorter one during scan parsing to know that we have lost connection.
  struct timeval timeout {
    .tv_sec = 2, .tv_usec = 0
  };

  setsockopt(sock_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sock_fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  constexpr auto connect_timeout = std::chrono::seconds(1);
  int connect_result =
      connect_with_timeout(sock_fd_, reinterpret_cast<struct sockaddr *>(&addr),
                           sizeof(addr), connect_timeout);
  if (connect_result < 0) {
    throw std::runtime_error("Unable to connect to scanner.");
  }
}

sick_err_t SOPASProtocol::start_scan() {
  poller_ = std::thread([&] {
    std::vector<char> buffer(2 * 4096);
    while (!stop_.load()) {
      int read_bytes =
          uninterrupted_recv(sock_fd_, buffer.data(), buffer.size());
      if (read_bytes < 0) {
      } else {
        simple_optional<Scan> maybe_s =
            batcher_.add_data(buffer.data(), read_bytes);
        if (maybe_s.has_value()) {
          callback_(maybe_s);
        }
      }
    }
  });

  return sick_err_t::Ok;
}

void SOPASProtocol::stop() {
  stop_.store(true);
  poller_.join();
}

int receive_sopas_reply(int sock_fd, char *data_out, size_t len) {
  if (len < 1) {
    throw std::runtime_error("No data passed to receive_sopas_reply()");
  }
  return uninterrupted_recv(sock_fd, data_out, len);
}

int send_sopas_command(int sock_fd, const char *data, size_t len) {
  if (len < 1) {
    throw std::runtime_error("No data passed to send_sopas_command()");
  }
  return uninterrupted_send(sock_fd, data, len);
}

sick_err_t send_sopas_command_and_check_answer(int sock_fd, const char *data,
                                               size_t len) {
  int send_result = send_sopas_command(sock_fd, data, len);
  if (send_result < 0) {
    return sick_err_t::CustomErrorSocketSend;
  } else if (send_result == 0) {
    return sick_err_t::CustomErrorConnectionClosed;
  }
  std::array<char, 4096> recvbuf;
  // fill with 0s so we have a null-terminated string
  recvbuf.fill(0x00);
  int recv_result = receive_sopas_reply(sock_fd, recvbuf.data(), 4096);
  if (recv_result < 0) {
    return sick_err_t::CustomErrorSocketRecv;
  } else if (recv_result == 0) {
    return sick_err_t::CustomErrorConnectionClosed;
  }
  sick_err_t status = status_from_bytes_ascii(recvbuf.data(), recv_result);
  return status;
}

sick_err_t SOPASProtocolASCII::set_access_mode(const uint8_t mode,
                                               const uint32_t pw_hash) {
  std::array<char, 128> buffer;
  // authorized client mode with pw hash from telegram listing
  int bytes_written = std::sprintf(
      buffer.data(), command_masks_[SETACCESSMODE].c_str(), mode, pw_hash);
  if (bytes_written < 0) {
    return sick_err_t::CustomError;
  }
  sick_err_t result = send_sopas_command_and_check_answer(
      sock_fd_, buffer.data(), bytes_written);
  return result;
}

sick_err_t SOPASProtocolASCII::configure_ntp_client(const std::string &ip) {
  const sick_err_t role_res = send_command(TSCROLE, 1);
  if (role_res != sick_err_t::Ok) {
    return role_res;
  }
  const sick_err_t iface_res = send_command(TSCTCINTERFACE, 0);
  if (iface_res != sick_err_t::Ok) {
    return iface_res;
  }
  const sick_err_t srvaddr_res = send_command(
      TSCTCSRVADDR,
      ip_addr_to_hex_str(ip.c_str())
          .c_str() /* convert to c str to pass to variadic std::sprintf */);
  return srvaddr_res;
}

sick_err_t
SOPASProtocolASCII::set_scan_config(const lms5xx::LMSConfigParams &params) {

  const hz frequency = params.frequency;
  const unsigned int hz_Lms = static_cast<unsigned int>(frequency * 100);
  const rad ang_increment = params.resolution;
  const unsigned int ang_increment_lms =
      static_cast<unsigned int>(round(ang_increment * 10000));
  const int start_angle_lms =
      static_cast<int>(angle_to_lms(params.start_angle) * 10000);
  const int end_angle_lms =
      static_cast<unsigned int>(angle_to_lms(params.end_angle) * 10000);

  sick_err_t status = send_command(MLMPSETSCANCFG, hz_Lms, ang_increment_lms,
                                   start_angle_lms, end_angle_lms);
  if (status != sick_err_t::Ok) {
    return status;
  }
  status = send_command(LMDSCANDATACFG);
  if (status != sick_err_t::Ok) {
    return status;
  }
  status = send_command(FRECHOFILTER, 2);
  if (status != sick_err_t::Ok) {
    return status;
  }
  status = send_command(LMPOUTPUTRANGE, ang_increment_lms, start_angle_lms,
                        end_angle_lms);
  status = send_command(LMCSTARTMEAS);
  return status;
}

sick_err_t SOPASProtocolASCII::save_params() {
  return send_command(MEEWRITEALL);
}

sick_err_t SOPASProtocolASCII::run() {
  sick_err_t status = send_command(RUN);
  if (status != sick_err_t::Ok) {
    return status;
  }
  return send_command(LMDSCANDATA, 1);
}

void SOPASProtocolASCII::stop() {
  SOPASProtocol::stop();
  // thread should now be joined
  std::array<char, 4096> buffer;
  int len = make_command_msg(buffer.data(), LMDSCANDATA, 0);
  int bytes_sent = send_sopas_command(sock_fd_, buffer.data(), len);
  if (bytes_sent < 0) {
    throw std::runtime_error("Failed to send.");
  }
  while (true) {
    int bytes_received = receive_sopas_reply(sock_fd_, &buffer[0], 4096);
    std::string answer(&buffer[0], bytes_received);
    if (answer.find("LMDscandata") != std::string::npos) {
      sick_err_t status =
          status_from_bytes_ascii(buffer.data(), bytes_received);
      if (status == sick_err_t::Ok) {
        sick_err_t login_result = set_access_mode(3);
        if (login_result == sick_err_t::Ok) {
          sick_err_t stop_meas_result = send_command(LMCSTOPMEAS);
          if (stop_meas_result == sick_err_t::Ok) {
            /* std::cout << "Stopped measurements." << std::endl; */
          } else {
            /* std::cout << "Failed to stop measurements." << std::endl; */
          }
        } else {
          /* std::cout << "Login failed." << std::endl; */
        }
      } else {
        /* std::cout << "Scan stop cmd failed: " << sick_err_t_to_string(status)
         */
        /*           << std::endl; */
      }
      return;
    } else {
      /* std::cout << "Skipping trailing data ..." << std::endl; */
    }
  }
}

} // namespace sick
