#pragma once
#include <atomic>
#include <iostream>
#include <map>
#include <memory>
#include <sick-lms5xx/network.hpp>
#include <sick-lms5xx/parsing.hpp>
#include <thread>
#include <unistd.h>

namespace sick {

using ScanCallback =
    std::function<void(const Scan &)>; ///< Callback type for complete scans
constexpr size_t CMD_BUFLEN = 4096;

/**
 * @brief   Class implementing SOPAS protocol abstractions on sockets.
 */
class SOPASProtocol {

protected:
  const std::string sensor_ip_; ///< ip address of the sensor
  const uint32_t
      port_; ///< SOPAS port. 2111 for ascii, 2112 for binary, usually
  ScanCallback callback_;  ///< callback for complete scans
  std::atomic<bool> stop_; ///< stop flag for thread
  std::thread poller_;     ///< scanner polling thread
  ScanBatcher batcher_;    ///< batcher for partial telegrams

  int sock_fd_; ///< socket file descriptor

public:
  using SOPASProtocolPtr = std::shared_ptr<SOPASProtocol>;

  /**
   * @brief Constructor
   *
   * @param sensor_ip   IP address of the scanner (host name will not work)
   * @param port    SOPAS port
   * @param fn  Callback function
   * @param timeout_s  Socket timeout in s for both connect and receive
   */
  SOPASProtocol(const std::string &sensor_ip, const uint32_t port,
                const ScanCallback &fn, unsigned int timeout_s = 5);

  /**
   * @brief Log out from scanner and request scan data stream. After this, the
   * next data from the scanner will be the data.
   *
   * @return Error or success
   */
  virtual SickErr run() = 0;

  /**
   * @brief Log in to the scanner
   *
   * @param mode    2 for Maintenance, 3 for authorized client, 4 for service
   * @param pw_hash Hash of the appropriate password
   *
   * @return    Error or success
   */
  virtual SickErr set_access_mode(const uint8_t mode,
                                  const uint32_t pw_hash) = 0;

  /**
   * @brief Configure the scanner as NTP client
   *
   * @param ip  NTP server IP
   *
   * @return    Error or success
   */
  virtual SickErr configure_ntp_client(const std::string &ip) = 0;

  /**
   * @brief Set new scan configuration
   *
   * @param params  Parameters for scanner
   *
   * @return Error or success
   */
  virtual SickErr set_scan_config(const lms5xx::LMSConfigParams &params) = 0;

  /**
   * @brief Save the scan configuration on the device
   *
   * @return    Error or success
   */
  virtual SickErr save_params() = 0;

  /**
   * @brief send reboot command. Takes a while to return.
   * @return Error or success
   */
  virtual SickErr reboot() = 0;

  /**
   * @brief Start the thread to receive scan data and get the callback invoked
   *
   * @return    Error or success
   */
  SickErr start_scan();

  /**
   * @brief Stop receiving
   * @param stop_laser attempt to shut down the laser.
   */
  virtual void stop(bool stop_laser = false);

  virtual ~SOPASProtocol();
};

/**
 * @brief   Get reply from socket. Basically `read()`
 *
 * @param sock_fd   Socket file descroptor
 * @param data_out  Output data buffer allocated by the user
 * @param len   Max number of bytes to read
 *
 * @return  Number of bytes actually read
 */
int receive_sopas_reply(int sock_fd, char *data_out, size_t len);

/**
 * @brief   Send data to socket. Basically `write()`
 *
 * @param sock_fd   Socket file descroptor
 * @param data  data buffer to send
 * @param len   number of bytes to write
 *
 * @return  Number of bytes actually written
 */
int send_sopas_command(int sock_fd, const char *data, size_t len);

/**
 * @brief   Send a command and parse the answer for success
 *
 * @param sock_fd   Socket file descroptor
 * @param data       data buffer to send
 * @param len   number of bytes to write
 *
 * @return  Error code or success
 */
SickErr send_sopas_command_and_check_answer(int sock_fd, const char *data,
                                            size_t len);

/**
 * @brief   Implementation of the ASCII sopas protocol. This protocol is
 * wasteful in terms of bandwidth, but easier to parse. For the LMS scanner this
 * is fine since the data rate is quite low.
 */
class SOPASProtocolASCII : public SOPASProtocol {

  using SOPASProtocol::SOPASProtocol;

  std::map<SOPASCommand, std::string> command_masks_ = {
      {REBOOT, "\x02sMN mSCreboot\x03"},
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
      {LMPOUTPUTRANGE_WRITE, "\x02sWN LMPoutputRange 1 +%4u %+d %+d\x03"},
      {LMPOUTPUTRANGE_READ, "\x02sRN LMPoutputRange\x03"},
      {MEEWRITEALL, "\x02sMN mEEwriteall\x03"},
      {RUN, "\x02sMN Run\x03"},
      {LMDSCANDATA, "\x02sEN LMDscandata %u\x03"},
      {LMCSTOPMEAS, "\x02sMN LMCstopmeas\x03"},
      {LMCSTARTMEAS,
       "\x02sMN LMCstartmeas\x03"}}; ///<    map from commands to format strings
                                     ///<    to fill arguments into

public:
  SickErr set_access_mode(const uint8_t mode = 3,
                          const uint32_t pw_hash = 0xF4724744) override;

  /**
   * @brief Function to assemble a command message with the use of `sprintf()`
   *
   * @tparam Args   Argument types
   * @param data_out    Output argument with the command
   * @param cmd SOPAS Command
   * @param args    Argument values
   *
   * @return    Sprintf return value (number of chars printed)
   */
  template <typename... Args>
  int make_command_msg(char *data_out, SOPASCommand cmd, Args... args) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
    int bytes_written = std::snprintf(data_out, CMD_BUFLEN,
                                      command_masks_[cmd].c_str(), args...);
#pragma GCC diagnostic pop
    if (bytes_written < 0) {
      throw std::runtime_error("sprintf fail");
    }
    return bytes_written;
  }

  /**
   * @brief Send a SOPAS command to the socket
   *
   * @tparam Args   Command parameter types
   * @param cmd     Command to send
   * @param args    Command parameter values
   *
   * @return    Error result from `send_sopas_command_and_check_answer()`
   */
  template <typename... Args>
  SickErr send_command(SOPASCommand cmd, Args... args) {
    std::array<char, CMD_BUFLEN> buffer;
    int bytes_written = make_command_msg(buffer.data(), cmd, args...);

    SickErr result = send_sopas_command_and_check_answer(
        sock_fd_, buffer.data(), bytes_written);
    return result;
  }

  SickErr configure_ntp_client(const std::string &ip) override;

  SickErr set_scan_config(const lms5xx::LMSConfigParams &params) override;

  SickErr save_params() override;

  SickErr run() override;

  SickErr reboot() override;

  void stop(bool stop_laser = false) override;

  ~SOPASProtocolASCII() {}
};

} // namespace sick
