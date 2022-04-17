#include <Eigen/Core>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <errno.h>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <netinet/in.h>
#include <pcl/io/pcd_io.h>
#include <pcl/point_cloud.h>
#include <pcl/point_types.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace std;
using namespace Eigen;

using days = chrono::duration<long, std::ratio<86400>>;
using months = chrono::duration<long, std::ratio<2629746>>;
using years = chrono::duration<long, std::ratio<31556952>>;

using rad = double;
using deg = double;
using hz = double;

struct LMSConfigParams {
  hz frequency;
  rad resolution;
  // from -95° to 95°
  rad start_angle;
  rad end_angle;

  // echo config?
  //
};

class TokenBuffer {
  vector<char> tokens_copy_;
  char *cur_tok_;
  string delim_;

public:
  TokenBuffer(const char *tokens, size_t len, const string &delim = " ") {
    delim_ = delim;
    tokens_copy_.resize(len + 1, '\0');
    memcpy(&tokens_copy_[0], tokens, len);
    cur_tok_ = strtok(&tokens_copy_[0], delim.c_str());
  }

  bool has_next() const { return cur_tok_ != nullptr; }

  const char *next() {
    const char *ret = cur_tok_;
    cur_tok_ = strtok(nullptr, delim_.c_str());
    return ret;
  }
};

constexpr char ETX = '\x03';
constexpr char STX = '\x02';

constexpr double RAD2DEG = 180.0 / M_PI;
constexpr double DEG2RAD = 1 / RAD2DEG;
//
// convert to degrees and add offset so 0 is straight ahead
static deg angle_to_lms(rad angle_in) { return angle_in * RAD2DEG + 90; }
static rad angle_from_lms(deg angle_in) { return (angle_in - 90) * DEG2RAD; }

enum class sick_err_t : uint8_t {
  Ok = 0,
  Sopas_Error_METHODIN_ACCESSDENIED,
  Sopas_Error_METHODIN_UNKNOWNINDEX,
  Sopas_Error_VARIABLE_UNKNOWNINDEX,
  Sopas_Error_LOCALCONDITIONFAILED,
  Sopas_Error_INVALID_DATA,
  Sopas_Error_UNKNOWN_ERROR,
  Sopas_Error_BUFFER_OVERFLOW,
  Sopas_Error_BUFFER_UNDERFLOW,
  Sopas_Error_ERROR_UNKNOWN_TYPE,
  Sopas_Error_VARIABLE_WRITE_ACCESSDENIED,
  Sopas_Error_UNKNOWN_CMD_FOR_NAMESERVER,
  Sopas_Error_UNKNOWN_COLA_COMMAND,
  Sopas_Error_METHODIN_SERVER_BUSY,
  Sopas_Error_FLEX_OUT_OF_BOUNDS,
  Sopas_Error_EVENTREG_UNKNOWNINDEX,
  Sopas_Error_COLA_A_VALUE_OVERFLOW,
  Sopas_Error_COLA_A_INVALID_CHARACTER,
  Sopas_Error_OSAI_NO_MESSAGE,
  Sopas_Error_OSAI_NO_ANSWER_MESSAGE,
  Sopas_Error_INTERNAL,
  Sopas_Error_HubAddressCorrupted,
  Sopas_Error_HubAddressDecoding,
  Sopas_Error_HubAddressAddressExceeded,
  Sopas_Error_HubAddressBlankExpected,
  Sopas_Error_AsyncMethodsAreSuppressed,
  Sopas_Error_ComplexArraysNotSupported,
  CustomError,
  CustomErrorInvalidDatagram,
  CustomErrorCommandFailure,
  CustomErrorSocketSend,
  CustomErrorSocketRecv,
  _LAST
};

const string sick_err_t_to_string(const sick_err_t &err) {
  const size_t idx = static_cast<size_t>(err);
  constexpr size_t last_idx = static_cast<size_t>(sick_err_t::_LAST);
  const array<string, last_idx> strerrors{
      "Ok",
      "Sopas_Error_METHODIN_ACCESSDENIED",
      "Sopas_Error_METHODIN_UNKNOWNINDEX",
      "Sopas_Error_VARIABLE_UNKNOWNINDEX",
      "Sopas_Error_LOCALCONDITIONFAILED",
      "Sopas_Error_INVALID_DATA",
      "Sopas_Error_UNKNOWN_ERROR",
      "Sopas_Error_BUFFER_OVERFLOW",
      "Sopas_Error_BUFFER_UNDERFLOW",
      "Sopas_Error_ERROR_UNKNOWN_TYPE",
      "Sopas_Error_VARIABLE_WRITE_ACCESSDENIED",
      "Sopas_Error_UNKNOWN_CMD_FOR_NAMESERVER",
      "Sopas_Error_UNKNOWN_COLA_COMMAND",
      "Sopas_Error_METHODIN_SERVER_BUSY",
      "Sopas_Error_FLEX_OUT_OF_BOUNDS",
      "Sopas_Error_EVENTREG_UNKNOWNINDEX",
      "Sopas_Error_COLA_A_VALUE_OVERFLOW",
      "Sopas_Error_COLA_A_INVALID_CHARACTER",
      "Sopas_Error_OSAI_NO_MESSAGE",
      "Sopas_Error_OSAI_NO_ANSWER_MESSAGE",
      "Sopas_Error_INTERNAL",
      "Sopas_Error_HubAddressCorrupted",
      "Sopas_Error_HubAddressDecoding",
      "Sopas_Error_HubAddressAddressExceeded",
      "Sopas_Error_HubAddressBlankExpected",
      "Sopas_Error_AsyncMethodsAreSuppressed",
      "Sopas_Error_ComplexArraysNotSupported",
      "CustomError",
      "CustomErrorInvalidDatagram",
      "CustomErrorCommandFailure",
      "CustomErrorSocketSend",
      "CustomErrorSocketRecv"};
  return strerrors[static_cast<size_t>(err)];
}

static uint32_t ip_addr_to_int(const string &ip_str) {

  uint32_t ip_network;
  // store this IP address in sa:
  inet_pton(AF_INET, ip_str.c_str(), &ip_network);

  return ip_network;
}

static string ip_addr_to_hex_str(const string &ip_str) {
  uint32_t ip_as_int = ntohl(ip_addr_to_int(ip_str));
  char out[2 * 4 + 3 + 1]{0};
  int sprintf_result =
      sprintf(out, "%02X %02X %02X %02X",
              // clang-format off
                               (ip_as_int & 0xFF000000) >> 24,
                               (ip_as_int & 0x00FF0000) >> 16,
                               (ip_as_int & 0x0000FF00) >> 8,
                               (ip_as_int & 0x000000FF) >> 0
              // clang-format on
      );
  if (sprintf_result < 0) {
    throw runtime_error("sprintf failed");
  }
  return out;
}

struct Scan {
  unsigned int size;
  VectorXf ranges;
  VectorXf intensities;
  rad start_angle;
  rad end_angle;
  rad ang_increment;
  VectorXf sin_map;
  VectorXf cos_map;

  chrono::system_clock::time_point time;

  Scan() { size = 0; }

  Scan(const Scan &other) = default;
};

template <typename T> class simple_optional {
  T t_;
  bool has_value_;

public:
  simple_optional(const T &t) : t_(t), has_value_(true){};
  simple_optional() : has_value_(false){};

  bool has_value() const { return has_value_; }

  operator T() const {
    if (!has_value()) {
      throw invalid_argument("optional has no content.");
    }
    return t_;
  }
};

using ScanCallback = function<void(const Scan &)>;

struct Channel {
  double ang_incr;
  vector<float> angles;
  vector<float> values;
  string description;

  Channel() { ang_incr = 0; }

  Channel(const string &description, size_t n_values, double ang_incr) {
    this->description = description;
    this->ang_incr = ang_incr;
    angles.reserve(n_values);
    values.reserve(n_values);
  }

  bool valid() { return angles.size() == values.size(); }
};

class ScanBatcher {
  vector<char> buffer;
  size_t num_bytes_buffered;
  Scan s;

public:
  ScanBatcher() { num_bytes_buffered = 0; }

  static Channel parse_channel(TokenBuffer &buf) {
    string content(buf.next());

    string scale_factor_s(buf.next());
    unsigned int scale_factor = scale_factor_s == "3F800000" ? 1 : 2;

    char *p;
    const long offset = strtol(buf.next(), &p, 16);

    unsigned int start_angle_u;
    double start_angle;
    sscanf(buf.next(), "%X  ", &start_angle_u);
    start_angle = static_cast<int>(start_angle_u) / 10000.0;

    const double ang_incr = strtol(buf.next(), &p, 16) / 10000.0;

    const long n_values = strtol(buf.next(), &p, 16);

    Channel cn(content, ang_incr, n_values);
    for (int i = 0; i < n_values; ++i) {
      const long value = strtol(buf.next(), &p, 16);
      cn.values.emplace_back(offset + scale_factor * value);
    }

    for (int i = 0; i < n_values; ++i) {
      cn.angles.emplace_back(angle_from_lms(start_angle + i * ang_incr));
    }
    return cn;
  }

  static bool parse_scan_telegram(const vector<char> &buffer,
                                  size_t last_valid_idx, Scan &scan) {
    TokenBuffer buf(&buffer[0], last_valid_idx + 1);

    string method(buf.next());
    string command(buf.next());
    string proto_version(buf.next());
    string device_num(buf.next());
    char *p;
    const int serial_num = strtol(buf.next(), &p, 16);
    string device_status1(buf.next());
    string device_status2(buf.next());
    string num_telegrams(buf.next());
    string num_scans(buf.next());
    const long time_since_boot_us = strtol(buf.next(), &p, 16);
    const long time_of_transmission_us = strtol(buf.next(), &p, 16);
    string status_digital_input_pins1(buf.next());
    string status_digital_input_pins2(buf.next());
    string status_digital_output_pins1(buf.next());
    string status_digital_output_pins2(buf.next());
    string layer_angle(buf.next());
    // if layer_angle != 0: error
    const double scan_freq = strtol(buf.next(), &p, 16) / 100.0;
    const long measurement_freq = strtol(buf.next(), &p, 16);
    const long encoder = strtol(buf.next(), &p, 16);
    if (encoder != 0) {
      // pos
      buf.next();
      // speed
      buf.next();
    }
    const long num_16bit_channels = strtol(buf.next(), &p, 16);
    if (num_16bit_channels != 1) {
      throw std::runtime_error("num_16bit_channels != 1");
    }

    vector<Channel> channels_16bit(num_16bit_channels);
    for (int i = 0; i < num_16bit_channels; ++i) {
      channels_16bit[i] = parse_channel(buf);
    }

    const long num_8bit_channels = strtol(buf.next(), &p, 16);
    if (num_8bit_channels != 1) {
      throw std::runtime_error("num_8bit_channels = " +
                               to_string(num_8bit_channels));
    }

    vector<Channel> channels_8bit(num_8bit_channels);
    for (int i = 0; i < num_8bit_channels; ++i) {
      channels_8bit[i] = parse_channel(buf);
    }

    const long position = strtol(buf.next(), &p, 16);
    const long name_exists = strtol(buf.next(), &p, 16);
    if (name_exists == 1) {
      buf.next();
      buf.next();
    }
    // always 0
    const long comment_exists = strtol(buf.next(), &p, 16);

    const long time_exists = strtol(buf.next(), &p, 16);
    if (time_exists == 1) {
      const long y = strtol(buf.next(), &p, 16);
      const long mo = strtol(buf.next(), &p, 16);
      const long d = strtol(buf.next(), &p, 16);
      const long h = strtol(buf.next(), &p, 16);
      const long mi = strtol(buf.next(), &p, 16);
      const long s = strtol(buf.next(), &p, 16);
      const long us = strtol(buf.next(), &p, 16);
      chrono::system_clock::time_point stamp;
      stamp += years(y) + months(mo) + days(d) + chrono::hours(h) +
               chrono::minutes(mi) + chrono::seconds(s) +
               chrono::microseconds(us);

      if (channels_16bit.size() < 1) {
        throw runtime_error("parse_scan_telegram() got no 16bit channels");
      } else {
        const Channel &range_cn = channels_16bit.front();
        if (range_cn.description.find("DIST") == string::npos) {
          throw runtime_error("First 16bit channel was not range but " +
                              range_cn.description);
        } else {
          const Channel &intensity_cn = channels_8bit.front();
          if (intensity_cn.description.find("RSSI") == string::npos) {
            throw runtime_error("First 8bit channel was not intensity but " +
                                range_cn.description);
          } else {
            if (range_cn.values.size() != intensity_cn.values.size()) {
              throw runtime_error(
                  "Ranges and intensities not matched in size.");
            } else {

              if (scan.ranges.size() == 0) {
                // first time -> fill nonchanging fields
                scan.size = range_cn.values.size();
                scan.ranges = VectorXf::Zero(scan.size, 1);
                scan.intensities = VectorXf::Zero(scan.size, 1);
                scan.ang_increment = range_cn.ang_incr;
                scan.start_angle = angle_to_lms(range_cn.angles.front());
                scan.end_angle = angle_to_lms(range_cn.angles.back());
                VectorXf angles(scan.size, 1);
                memcpy(angles.data(), &range_cn.angles[0],
                       scan.size * sizeof(float));
                scan.cos_map = Eigen::cos(angles.array());
                scan.sin_map = Eigen::sin(angles.array());
              }

              memcpy(scan.ranges.data(), &range_cn.values[0],
                     scan.size * sizeof(float));
              scan.ranges /= 1000;
              memcpy(scan.intensities.data(), &intensity_cn.values[0],
                     scan.size * sizeof(float));
              scan.time = stamp;
              return true;
            }
          }
        }
      }
    } else {
      // no time stamp, use system time?
    }
    return false;
  }

  simple_optional<Scan> add_data(const char *data_new, size_t length) {
    // check if etx found
    int etx_idx = -1;
    for (size_t i = 0; i < length; ++i) {
      if (data_new[i] == ETX) {
        etx_idx = i;
        break;
      }
    }

    bool got_scan = false;

    // 1. if etx found -> append data up until etx to current buffer, parse
    // scan, then replace by everything after etx
    // 2. no etx found -> append all data
    if (etx_idx < 0) {
      buffer.reserve(num_bytes_buffered + length + 1);
      char *buf_begin = buffer.data();
      memcpy(buf_begin + num_bytes_buffered, data_new, length);
      num_bytes_buffered += length;
    } else {
      // etx found
      buffer.reserve(num_bytes_buffered + etx_idx + 1);
      char *buf_begin = buffer.data();
      memcpy(buf_begin + num_bytes_buffered, data_new, etx_idx + 1);
      num_bytes_buffered += etx_idx + 1;
      if (buffer[0] == STX && buffer[num_bytes_buffered - 1] == ETX) {
        // try to parse scan telegram
        if (parse_scan_telegram(buffer, num_bytes_buffered - 1, s)) {
          // return the scan
          got_scan = true;
        } else {
          std::cout << "Error: scan did not parse" << std::endl;
        }
      } else {
        std::cout << "Error: invalid data." << std::endl;
      }
      num_bytes_buffered = 0;

      if (length > etx_idx + 1) {
        // trailing data must be kept
        // You'd think to check that the start token of the trailing data is
        // STX, but the partial datagrams don't seem to have it
        const size_t new_data_length = length - (etx_idx + 1);
        char *buf_begin = buffer.data();
        memcpy(buf_begin, data_new + etx_idx + 1, new_data_length);
        num_bytes_buffered = new_data_length;
      }
    }

    if (got_scan) {
      return simple_optional<Scan>(s);
    } else {
      return simple_optional<Scan>();
    }
  }
};

class SOPASProtocol {

protected:
  const string sensor_ip_;
  const uint32_t port_;
  ScanCallback callback_;
  atomic<bool> stop_;
  thread poller_;
  ScanBatcher batcher_;

  int sock_fd_;

public:
  using SOPASProtocolPtr = shared_ptr<const SOPASProtocol>;

  SOPASProtocol(const string &sensor_ip, const uint32_t port,
                const ScanCallback &fn)
      : sensor_ip_(sensor_ip), port_(port), callback_(fn) {
    stop_.store(false);

    sock_fd_ = socket(PF_INET, SOCK_STREAM, 0);
    if (sock_fd_ < 0) {
      throw runtime_error("Unable to create socket.");
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

    // TODO: connect timeout
    int connect_result = connect(
        sock_fd_, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
    if (connect_result < 0) {
      throw runtime_error("Unable to connect to scanner.");
    }
  }

  virtual sick_err_t run() = 0;

  virtual sick_err_t set_access_mode(const uint8_t mode,
                                     const uint32_t pw_hash) = 0;

  virtual sick_err_t configure_ntp_client(const string &ip) = 0;

  virtual sick_err_t set_scan_config(const LMSConfigParams &params) = 0;

  virtual sick_err_t save_params() = 0;

  sick_err_t start_scan() {
    poller_ = thread([&] {
      vector<char> buffer(2 * 4096);
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

enum SOPASCommand {
  SETACCESSMODE,
  TSCROLE,
  TSCTCINTERFACE,
  TSCTCSRVADDR,
  MLMPSETSCANCFG,
  LMDSCANDATACFG,
  FRECHOFILTER,
  LMPOUTPUTRANGE,
  MEEWRITEALL,
  RUN,
  LMDSCANDATA,
  LMCSTOPMEAS,
  LMCSTARTMEAS

};

static string method(const char *sopas_reply, size_t len) {
  if (len < sizeof("\x02...")) {
    throw runtime_error("wat");
  } else
    return string(sopas_reply + 1, 3);
}

static bool status_ok(const string &cmd_name, int status_code) {
  if (cmd_name == "mLMPsetscancfg") {
    return status_code == 0;
  }
  if (cmd_name == "mEEwriteall") {
    return status_code == 1;
  }
  if (cmd_name == "Run") {
    return status_code == 1;
  }
  if (cmd_name == "LMCstopmeas" || cmd_name == "LMCstartmeas") {
    return status_code == 0;
  }
  if (cmd_name == "LMDscandata") {
    // 0 means stop, 1 means start, there is no error
    return true;
  }
  return status_code == 1;
}

static bool validate_response(const char *data, size_t len) {
  if (len <= 6) {
    return false;
  }
  // check that there is exactly one STX and one ETX byte, otherwise we somehow
  // read multiple messages, which can happen in some cases if you time out your
  // recv, but the data then comes with your next call (should you try one)
  size_t n_stx = 0, n_etx = 0;
  for (int i = 0; i < len; ++i) {
    if (data[i] == STX) {
      ++n_stx;
    }
    if (data[i] == ETX) {
      ++n_etx;
    }
  }
  return n_stx == 1 && n_etx == 1;
}

sick_err_t status_from_bytes_ascii(const char *data, size_t len) {
  if (!validate_response(data, len)) {
    return sick_err_t::CustomErrorInvalidDatagram;
  }
  const string answer_method = method(data, len);
  if (answer_method == "sFA") {
    // generic errors
    static const char pattern[]{"\x02sFA %2X\x03"};
    unsigned int status = 0;
    int scanf_result = sscanf(data, pattern, &status);
    if (scanf_result != 1) {
      // parse error
    }
    return static_cast<sick_err_t>(status);
  } else {
    TokenBuffer buf(data, len);
    string method(buf.next());
    string cmd_name(buf.next());
    if (buf.has_next()) {
      int status_code = atoi(buf.next());
      if (status_ok(cmd_name, status_code)) {
        std::cout << "Command success" << std::endl;
        return sick_err_t::Ok;
      } else {
        return sick_err_t::CustomErrorCommandFailure;
      }
    } else
      return sick_err_t::Ok;
  }
}

static int receive_sopas_reply(int sock_fd, char *data_out, size_t len) {
  return recv(sock_fd, data_out, len, 0);
}

static int send_sopas_command(int sock_fd, const char *data, size_t len) {
  return send(sock_fd, data, len, 0);
}

static sick_err_t
send_sopas_command_and_check_answer(int sock_fd, const char *data, size_t len) {
  std::cout << "Command: " << string(data, len) << std::endl;
  int send_result = send_sopas_command(sock_fd, data, len);
  if (send_result < 0) {
    std::cout << "Could not send sopas command" << std::endl;
    return sick_err_t::CustomErrorSocketSend;
  }
  array<char, 4096> recvbuf;
  // fill with 0s so we have a null-terminated string
  recvbuf.fill(0x00);
  int recv_result = receive_sopas_reply(sock_fd, recvbuf.data(), 4096);
  if (recv_result < 0) {
    std::cout << "Send sopas error: " << strerror(recv_result) << std::endl;
    return sick_err_t::CustomErrorSocketRecv;
  }
  sick_err_t status = status_from_bytes_ascii(recvbuf.data(), recv_result);
  std::cout << "Command answer: " << string(recvbuf.data())
            << ". Status: " << sick_err_t_to_string(status) << std::endl;
  return status;
}

class SOPASProtocolASCII : public SOPASProtocol {

  using SOPASProtocol::SOPASProtocol;

  map<SOPASCommand, string> command_masks_ = {
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
    array<char, 128> buffer;
    // authorized client mode with pw hash from telegram listing
    int bytes_written = sprintf(
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
    int bytes_written = sprintf(data_out, command_masks_[cmd].c_str(), args...);
#pragma GCC diagnostic pop
    if (bytes_written < 0) {
      throw runtime_error("sprintf fail");
    }
    return bytes_written;
  }

  template <typename... Args>
  sick_err_t send_command(SOPASCommand cmd, Args... args) {
    array<char, 4096> buffer;
    int bytes_written = make_command_msg(buffer.data(), cmd, args...);

    sick_err_t result = send_sopas_command_and_check_answer(
        sock_fd_, buffer.data(), bytes_written);
    return result;
  }

  sick_err_t configure_ntp_client(const string &ip) override {
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
            .c_str() /* convert to c str to pass to variadic sprintf */);
    return srvaddr_res;
  }

  sick_err_t set_scan_config(const LMSConfigParams &params) override {

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
    array<char, 4096> buffer;
    int len = make_command_msg(buffer.data(), LMDSCANDATA, 0);
    int bytes_sent = send_sopas_command(sock_fd_, buffer.data(), len);
    while (true) {
      int bytes_received = receive_sopas_reply(sock_fd_, &buffer[0], 4096);
      string answer(&buffer[0], bytes_received);
      if (answer.find("LMDscandata") != string::npos) {
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

static atomic<int> n_scans;
using namespace pcl;

static void cbk(const Scan &scan) {
  PointCloud<PointXYZI> cloud_out;
  cloud_out.width = scan.ranges.size();
  cloud_out.height = 1;
  const VectorXf x = scan.ranges.array() * scan.cos_map.array();
  const VectorXf y = scan.ranges.array() * scan.sin_map.array();
  for (int i = 0; i < x.size(); ++i) {
    cloud_out.points.emplace_back(
        PointXYZI(x(i), y(i), 0, scan.intensities[i]));
  }
  io::savePCDFileASCII(string("clouds/cloud-") + to_string(n_scans) + ".pcd",
                       cloud_out);
  std::cout << "Got scan with " << cloud_out.size() << " points." << std::endl;
  ++n_scans;
}

int main() {
  n_scans = 0;
  SOPASProtocolASCII proto("192.168.95.194", 2111, cbk);
  sick_err_t status = proto.set_access_mode();
  if (status != sick_err_t::Ok) {
    std::cout << "Could not set access mode." << std::endl;
    return 1;
  }
  status = proto.configure_ntp_client("192.168.95.44");
  if (status != sick_err_t::Ok) {
    std::cout << "Could not configure ntp client" << std::endl;
    return 2;
  }
  status = proto.set_scan_config(LMSConfigParams{.frequency = 25,
                                                 .resolution = 0.1667,
                                                 .start_angle = -95 * DEG2RAD,
                                                 .end_angle = 95 * DEG2RAD});
  if (status != sick_err_t::Ok) {
    std::cout << "Could not configure scan" << std::endl;
    return 3;
  }
  status = proto.save_params();
  if (status != sick_err_t::Ok) {
    std::cout << "Could not save params" << std::endl;
    return 4;
  }
  status = proto.run();
  if (status != sick_err_t::Ok) {
    std::cout << "Could not run scanner" << std::endl;
    return 5;
  }
  proto.start_scan();
  std::cout << "Wait a bit for scanner..." << std::endl;
  std::this_thread::sleep_for(std::chrono::seconds(2));
  const auto tic = chrono::system_clock::now();
  n_scans = 0;
  std::this_thread::sleep_for(std::chrono::seconds(4));
  const auto toc = chrono::system_clock::now();
  const double s_elapsed =
      chrono::duration_cast<chrono::milliseconds>(toc - tic).count() / 1000.0;
  std::cout << "got " << n_scans << " in " << s_elapsed << "s ("
            << n_scans.load() / s_elapsed << "hz)" << std::endl;
  proto.stop();
}
