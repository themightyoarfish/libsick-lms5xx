#include <errno.h>

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
                             const ScanCallback &fn, unsigned int timeout_s)
    : sensor_ip_(sensor_ip), port_(port), callback_(fn) {
  stop_.store(false);

  sock_fd_ = socket(PF_INET, SOCK_STREAM, 0);
  if (sock_fd_ < 0) {
    throw std::runtime_error(std::string("Unable to create socket: ") +
                             strerror(errno));
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
    .tv_sec = timeout_s, .tv_usec = 0
  };

  setsockopt(sock_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sock_fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  const auto connect_timeout = std::chrono::seconds(timeout_s);
  int connect_result =
      connect_with_timeout(sock_fd_, reinterpret_cast<struct sockaddr *>(&addr),
                           sizeof(addr), connect_timeout);
  if (connect_result < 0) {
    throw std::runtime_error(std::string("Unable to connect to scanner: ") +
                             strerror(errno));
  }
}

SickErr SOPASProtocol::start_scan() {
  poller_ = std::thread([&] {
    std::vector<char> buffer(2 * 4096);
    while (!stop_.load()) {
      int read_bytes =
          uninterrupted_recv(sock_fd_, buffer.data(), buffer.size());
      if (read_bytes < 0) {
        // do nothing for now. TODO: is this an error?
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

void SOPASProtocol::stop(bool stop_laser) {
  stop_.store(true);
  // for mysterious reasons, sometimes the poller is not joinable even though
  // it is not join()ed anywhere else
  if (poller_.joinable()) {
    poller_.join();
  }
}

SOPASProtocol::~SOPASProtocol() {
  this->stop();
  close(sock_fd_);
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

SickErr send_sopas_command_and_check_answer(int sock_fd, const char *data,
                                            size_t len) {
  int send_result = send_sopas_command(sock_fd, data, len);
  if (send_result < 0) {
    return SickErr(errno);
  } else if (send_result == 0) {
    return sick_err_t::CustomErrorConnectionClosed;
  }
  std::array<char, 4096> recvbuf;
  // fill with 0s so we have a null-terminated string
  recvbuf.fill(0x00);
  int recv_result = receive_sopas_reply(sock_fd, recvbuf.data(), 4096);
  if (recv_result < 0) {
    return SickErr(errno);
  } else if (recv_result == 0) {
    return sick_err_t::CustomErrorConnectionClosed;
  }
  return status_from_bytes_ascii(recvbuf.data(), recv_result);
}

std::string SOPASProtocolASCII::send_raw_command(SOPASCommand cmd) {
  std::cout << "buffer" << std::endl;
  std::array<char, 4096> buffer_w;
  std::cout << "buffer created" << std::endl;
  std::string out_str = "\x02sRN LMPscancfg\x03";
  int bytes_written = std::sprintf(buffer_w.data(), out_str.c_str(), 0);
  // int bytes_written = make_command_msg(buffer_w.data(), cmd, 0);
  std::cout << "bytes written " << std::endl;

  // int send_result =
  //     send_sopas_command(this->sock_fd_, buffer_w.data(), bytes_written);

  int send_result;
  while ((send_result =
              send(this->sock_fd_, buffer_w.data(), bytes_written, 0)) == -1 &&
         errno == EINTR) {
    continue;
  }
  std::cout << "send result " << std::endl;
  if (send_result < 0) {
    return "SEND RESULT < 0";
  } else if (send_result == 0) {
    return "SEND RESULT = 0";
  }

  std::cout << "create rcv buffer " << std::endl;
  int len = 4096;
  std::array<char, 4096> recvbuf;
  recvbuf.fill(0x00);

  std::cout << "rcv result " << std::endl;

  int recv_result;
  while ((recv_result = recv(this->sock_fd_, recvbuf.data(), len, 0)) == -1 &&
         errno == EINTR) {
    continue;
  }
  if (recv_result < 0) {
    return "RCV RESULT < 0";
  } else if (recv_result == 0) {
    return "RCV RESULT = 0";
  }
  auto data = recvbuf.data();
  std::array<char, 4096>::value_type *ptr = data;
  std::cout << "rcv result finished printing .... :  " << std::endl;

  for (int i = 0; i < buffer_w.size(); ++i) {
    std::cout << ptr[i];
  }
  if (!validate_response(data, len)) {
    return "No valid response";
  }
  std::string answer_method = method(data, len);

  return data;
}

SickErr SOPASProtocolASCII::set_access_mode(const uint8_t mode,
                                            const uint32_t pw_hash) {
  std::array<char, 128> buffer;
  // authorized client mode with pw hash from telegram listing
  int bytes_written = std::sprintf(
      buffer.data(), command_masks_[SETACCESSMODE].c_str(), mode, pw_hash);
  if (bytes_written < 0) {
    return SickErr(errno);
  }
  return send_sopas_command_and_check_answer(sock_fd_, buffer.data(),
                                             bytes_written);
}

SickErr SOPASProtocolASCII::configure_ntp_client(const std::string &ip) {
  const SickErr role_res = send_command(TSCROLE, 1);
  if (!role_res.ok()) {
    return role_res;
  }
  const SickErr iface_res = send_command(TSCTCINTERFACE, 0);
  if (!iface_res.ok()) {
    return iface_res;
  }
  const SickErr srvaddr_res = send_command(
      TSCTCSRVADDR,
      ip_addr_to_hex_str(ip.c_str())
          .c_str() /* convert to c str to pass to variadic std::sprintf */);
  return srvaddr_res;
}

SickErr
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

  SickErr status = send_command(MLMPSETSCANCFG, hz_Lms, ang_increment_lms,
                                start_angle_lms, end_angle_lms);
  if (!status.ok()) {
    return status;
  }
  status = send_command(LMDSCANDATACFG);
  if (!status.ok()) {
    return status;
  }
  status = send_command(FRECHOFILTER, 2);
  if (!status.ok()) {
    return status;
  }
  status = send_command(LMPOUTPUTRANGE_WRITE, ang_increment_lms,
                        start_angle_lms, end_angle_lms);
  if (!status.ok()) {
    return status;
  }
  status = send_command(LMCSTARTMEAS);
  return status;
}

SickErr SOPASProtocolASCII::save_params() { return send_command(MEEWRITEALL); }

SickErr SOPASProtocolASCII::reboot() { return send_command(REBOOT); }

SickErr SOPASProtocolASCII::run() {
  SickErr status = send_command(RUN);
  if (!status.ok()) {
    return status;
  }
  return send_command(LMDSCANDATA, 1);
}

void SOPASProtocolASCII::stop(bool stop_laser) {
  SOPASProtocol::stop();

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
      SickErr status = status_from_bytes_ascii(buffer.data(), bytes_received);
      if (status.ok() && stop_laser) {
        SickErr login_result = set_access_mode(3);
        if (login_result.ok()) {
          SickErr stop_meas_result = send_command(LMCSTOPMEAS);
          if (stop_meas_result.ok()) {
            /* std::cout << "Stopped measurements." << std::endl; */
          } else {
            // TODO: return an error here?
            /* std::cout << "Failed to stop measurements." <<
             * std::endl; */
          }
        } else {
          // TODO: return an error here?
          /* std::cout << "Login failed." << std::endl; */
        }
      } else {
        // TODO: return an error here?
        /* std::cout << "Scan stop cmd failed: " <<
         * sick_err_t_to_string(status)
         */
        /*           << std::endl; */
      }
      return;
    } else {
      // trailing lidar data should be skipped
      /* std::cout << "Skipping trailing data ..." << std::endl; */
    }
  }
}

} // namespace sick
