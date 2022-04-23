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
                const ScanCallback &fn);

  virtual sick_err_t run() = 0;

  virtual sick_err_t set_access_mode(const uint8_t mode,
                                     const uint32_t pw_hash) = 0;

  virtual sick_err_t configure_ntp_client(const std::string &ip) = 0;

  virtual sick_err_t set_scan_config(const lms5xx::LMSConfigParams &params) = 0;

  virtual sick_err_t save_params() = 0;

  sick_err_t start_scan();

  virtual void stop();
};

int receive_sopas_reply(int sock_fd, char *data_out, size_t len);

int send_sopas_command(int sock_fd, const char *data, size_t len);

sick_err_t send_sopas_command_and_check_answer(int sock_fd, const char *data,
                                               size_t len);

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
                             const uint32_t pw_hash = 0xF4724744) override;

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

  sick_err_t configure_ntp_client(const std::string &ip) override;

  sick_err_t set_scan_config(const lms5xx::LMSConfigParams &params) override;

  sick_err_t save_params() override;

  sick_err_t run() override;

  void stop() override;
};

} // namespace sick
