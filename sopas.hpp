#pragma once
#include "network.hpp"
#include "parsing.hpp"
#include <atomic>
#include <iostream>
#include <map>
#include <memory>
#include <thread>

namespace sick {

using ScanCallback = std::function<void(const Scan &)>;

class SOPASProtocol {

protected:
  const std::string sensor_ip_;
  const uint32_t port_;
  ScanCallback callback_;
  std::atomic<bool> stop_;
  std::thread poller_;
  ScanBatcher batcher_;

  int sock_fd_;

public:
  using SOPASProtocolPtr = std::shared_ptr<const SOPASProtocol>;

  SOPASProtocol(const std::string &sensor_ip, const uint32_t port,
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
    int connect_result = connect_with_timeout(
        sock_fd_, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr),
        connect_timeout);
    if (connect_result < 0) {
      throw std::runtime_error("Unable to connect to scanner.");
    }
  }

  virtual sick_err_t run() = 0;

  virtual sick_err_t set_access_mode(const uint8_t mode,
                                     const uint32_t pw_hash) = 0;

  virtual sick_err_t configure_ntp_client(const std::string &ip) = 0;

  virtual sick_err_t set_scan_config(const lms5xx::LMSConfigParams &params) = 0;

  virtual sick_err_t save_params() = 0;

  sick_err_t start_scan() {
    poller_ = std::thread([&] {
      std::vector<char> buffer(2 * 4096);
      while (!stop_.load()) {
        int read_bytes = recv(sock_fd_, buffer.data(), buffer.size(), 0);
        if (read_bytes < 0) {
          std::cout << "Scan recv: " << strerror(errno) << std::endl;
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

  virtual void stop() {
    stop_.store(true);
    poller_.join();
  }
};

static int receive_sopas_reply(int sock_fd, char *data_out, size_t len) {
  return recv(sock_fd, data_out, len, 0);
}

static int send_sopas_command(int sock_fd, const char *data, size_t len) {
  return send(sock_fd, data, len, 0);
}

static sick_err_t
send_sopas_command_and_check_answer(int sock_fd, const char *data, size_t len) {
  std::cout << "Command: " << std::string(data, len) << std::endl;
  int send_result = send_sopas_command(sock_fd, data, len);
  if (send_result < 0) {
    std::cout << "Could not send sopas command" << std::endl;
    return sick_err_t::CustomErrorSocketSend;
  }
  std::array<char, 4096> recvbuf;
  // fill with 0s so we have a null-terminated string
  recvbuf.fill(0x00);
  int recv_result = receive_sopas_reply(sock_fd, recvbuf.data(), 4096);
  if (recv_result < 0) {
    std::cout << "Send sopas error: " << strerror(recv_result) << std::endl;
    return sick_err_t::CustomErrorSocketRecv;
  }
  sick_err_t status = status_from_bytes_ascii(recvbuf.data(), recv_result);
  std::cout << "Command answer: " << std::string(recvbuf.data())
            << ". Status: " << sick_err_t_to_string(status) << std::endl;
  return status;
}

class SOPASProtocolASCII : public SOPASProtocol {

  using SOPASProtocol::SOPASProtocol;

  std::map<SOPASCommand, std::string> command_masks_ = {
      {SETACCESSMODE, "\x02sMN SetAccessMode %02d %08X\x03"},
      {TSCROLE, "\x02sWN TSCRole %02d\x03"},
      {TSCTCINTERFACE, "\x02sWN TSCTCInterface %02d\x03"},
      {TSCTCSRVADDR, "\x02sWN TSCTCSrvAddr %s\x03"},
      // retardation: the signs in sopas ascci are usually optional, but not for
      // the start and end angles
      {MLMPSETSCANCFG, "\x02sMN mLMPsetscancfg +%4u +1 +%4u %+d %+d\x03"},
      // the telegram listing has fewer values than are actually needed, so this
      // is guesswork. this is hardcoded to make remission show up in the scan
      // telegrams. looks like the second 00 is an unknown mystery value that is
      // not documented
      {LMDSCANDATACFG, "\x02sWN LMDscandatacfg 00 00 1 0 0 0 00 0 0 0 1 1\x03"},
      {FRECHOFILTER, "\x02sWN FREchoFilter %u\x03"},
      {LMPOUTPUTRANGE, "\x02sWN LMPoutputRange 1 +%4u %+d %+d\x03"},
      {MEEWRITEALL, "\x02sMN mEEwriteall\x03"},
      {RUN, "\x02sMN Run\x03"},
      {LMDSCANDATA, "\x02sEN LMDscandata %u\x03"},
      {LMCSTOPMEAS, "\x02sMN LMCstopmeas\x03"},
      {LMCSTARTMEAS, "\x02sMN LMCstartmeas\x03"}};

public:
  sick_err_t set_access_mode(const uint8_t mode = 3,
                             const uint32_t pw_hash = 0xF4724744) override {
    std::array<char, 128> buffer;
    // authorized client mode with pw hash from telegram listing
    int bytes_written = std::sprintf(
        buffer.data(), command_masks_[SETACCESSMODE].c_str(), mode, pw_hash);
    if (bytes_written < 0) {
      /* error */
    }
    sick_err_t result = send_sopas_command_and_check_answer(
        sock_fd_, buffer.data(), bytes_written);
    return result;
  }

  template <typename... Args>
  int make_command_msg(char *data_out, SOPASCommand cmd, Args... args) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
    int bytes_written =
        std::sprintf(data_out, command_masks_[cmd].c_str(), args...);
#pragma GCC diagnostic pop
    if (bytes_written < 0) {
      throw std::runtime_error("sprintf fail");
    }
    return bytes_written;
  }

  template <typename... Args>
  sick_err_t send_command(SOPASCommand cmd, Args... args) {
    std::array<char, 4096> buffer;
    int bytes_written = make_command_msg(buffer.data(), cmd, args...);

    sick_err_t result = send_sopas_command_and_check_answer(
        sock_fd_, buffer.data(), bytes_written);
    return result;
  }

  sick_err_t configure_ntp_client(const std::string &ip) override {
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

  sick_err_t set_scan_config(const lms5xx::LMSConfigParams &params) override {

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

  sick_err_t save_params() override { return send_command(MEEWRITEALL); }

  sick_err_t run() override {
    sick_err_t status = send_command(RUN);
    if (status != sick_err_t::Ok) {
      return status;
    }
    return send_command(LMDSCANDATA, 1);
  }

  void stop() override {
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
              std::cout << "Stopped measurements." << std::endl;
            } else {
              std::cout << "Failed to stop measurements." << std::endl;
            }
          } else {
            std::cout << "Login failed." << std::endl;
          }
        } else {
          std::cout << "Scan stop cmd failed: " << sick_err_t_to_string(status)
                    << std::endl;
        }
        return;
      } else {
        std::cout << "Skipping trailing data ..." << std::endl;
      }
    }
  }
};

} // namespace sick
