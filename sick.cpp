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
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace std;
using namespace Eigen;

using days = chrono::duration<long, std::ratio<86400>>;
using months = chrono::duration<long, std::ratio<2629746>>;
using years = chrono::duration<long, std::ratio<31556952>>;

constexpr double DEG2RAD = 180.0 / M_PI;
constexpr double RAD2DEG = 1 / DEG2RAD;

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
  CustomError
};

const string sick_err_t_to_string(const sick_err_t &err) {
  const size_t idx = static_cast<size_t>(err);
  constexpr size_t last_idx = static_cast<size_t>(sick_err_t::CustomError);
  const array<string, last_idx + 1> strerrors{
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
      "CustomError"};
  return strerrors[static_cast<size_t>(err)];
}

using rad = double;
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
  /* EIGEN_MAKE_ALIGNED_OPERTOR_NEW; */

  unsigned int n_vals;
  VectorXf ranges;
  VectorXf intensities;
  rad start_angle;
  rad end_angle;
  rad ang_increment;
  VectorXf sin_map;
  VectorXf cos_map;
};

/* using ScanCallback = function<void(const Scan<1141> &)>; */
using ScanCallback = function<void(int read_bytes, char *data)>;

class ScanBatcher {
  vector<char> buffer;
  size_t first_junk_idx;

public:
  ScanBatcher() {
    first_junk_idx = 0;
    buffer.reserve(4096);
  }
  struct Channel {
    double ang_incr;
    vector<float> angles;
    vector<float> values;

    Channel() { ang_incr = 0; }

    Channel(size_t n_values, double ang_incr) {
      this->ang_incr = ang_incr;
      angles.reserve(n_values);
      values.reserve(n_values);
    }
  };

  static Channel parse_channel(char *token) {
    string content(token);
    token = strtok(NULL, " ");

    string scale_factor_s(token);
    unsigned int scale_factor = scale_factor_s == "3F800000" ? 1 : 2;
    token = strtok(NULL, " ");

    char *p;
    const long offset = strtol(token, &p, 16);
    token = strtok(NULL, " ");

    unsigned int start_angle_u;
    double start_angle;
    sscanf(token, "%X  ", &start_angle_u);
    start_angle = static_cast<int>(start_angle_u) / 10000.0;
    token = strtok(NULL, " ");

    const double ang_incr = strtol(token, &p, 16) / 10000.0;
    token = strtok(NULL, " ");

    const long n_values = strtol(token, &p, 16);
    token = strtok(NULL, " ");

    std::cout << "n_values=" << n_values << ", start_angle=" << start_angle
              << std::endl;

    Channel cn(ang_incr, n_values);
    for (int i = 0; i < n_values; ++i) {
      const long value = strtol(token, &p, 16);
      cn.values.emplace_back(offset + scale_factor * value / 1000.0);
      token = strtok(NULL, " ");
    }

    for (int i = 0; i < n_values; ++i) {
      cn.angles.emplace_back(start_angle + i * ang_incr);
    }
    return cn;
  }
  /*     def parse_channel(generator): */
  /*         content = next(tokens) */
  /*         scale_factor = int(next(tokens), 16) */
  /*         if scale_factor == int("3F800000", 16): */
  /*             scale_factor = 1 */
  /*         elif scale_factor == int("40000000", 16): */
  /*             scale_factor = 2 */
  /*         else: */
  /*             raise ValueError(f"Unexpected scale factor {scale_factor}")
   */

  /*         offset = int(next(tokens), 16) */
  /*         start_angle_hex = next(tokens) */
  /*         start_angle = parse_int32(start_angle_hex) / 10000 */

  /*         ang_incr_hex = next(tokens) */
  /*         ang_incr = parse_int16(ang_incr_hex) / 10000 */
  /*         n_data = int(next(tokens), 16) */
  /*         values = [offset + scale_factor * int(next(tokens), 16) for i in
   * range(n_data)] */
  /*         angles = [start_angle + i * ang_incr for i in range(n_data)] */
  /*         values = np.array(values) */
  /*         angles = np.array(angles) */
  /*         return ang_incr, angles, values */

  static void parse_scan_telegram(const vector<char> &buffer,
                                  size_t last_valid_idx) {
    const char *begin = &buffer[0];
    const char *end = begin + last_valid_idx + 1;
    vector<char> copy(std::distance(begin, end) + 1, '\0');
    std::copy(begin, end, copy.begin());
    char *token = strtok(&copy[0], " ");

    string method(token);
    token = strtok(NULL, " ");
    string command(token);
    token = strtok(NULL, " ");
    string proto_version(token);
    token = strtok(NULL, " ");
    string device_num(token);
    token = strtok(NULL, " ");
    char *p;
    const int serial_num = strtol(token, &p, 16);
    token = strtok(NULL, " ");
    string device_status1(token);
    token = strtok(NULL, " ");
    string device_status2(token);
    token = strtok(NULL, " ");
    string num_telegrams(token);
    token = strtok(NULL, " ");
    string num_scans(token);
    token = strtok(NULL, " ");
    const long time_since_boot_us = strtol(token, &p, 16);
    token = strtok(NULL, " ");
    const long time_of_transmission_us = strtol(token, &p, 16);
    token = strtok(NULL, " ");
    string status_digital_input_pins1(token);
    token = strtok(NULL, " ");
    string status_digital_input_pins2(token);
    token = strtok(NULL, " ");
    string status_digital_output_pins1(token);
    token = strtok(NULL, " ");
    string status_digital_output_pins2(token);
    token = strtok(NULL, " ");
    string layer_angle(token);
    // if layer_angle != 0: error
    token = strtok(NULL, " ");
    const double scan_freq = strtol(token, &p, 16) / 100.0;
    token = strtok(NULL, " ");
    const long measurement_freq = strtol(token, &p, 16);
    token = strtok(NULL, " ");
    const long encoder = strtol(token, &p, 16);
    token = strtok(NULL, " ");
    if (encoder != 0) {
      // pos
      token = strtok(NULL, " ");
      // speed
      token = strtok(NULL, " ");
    }
    const long num_16bit_channels = strtol(token, &p, 16);
    token = strtok(NULL, " ");
    std::cout << "num_16bit_channels = " << num_16bit_channels << std::endl;
    if (num_16bit_channels != 1) {
      throw std::runtime_error("num_16bit_channels != 1");
    }

    vector<Channel> channels_16bit(num_16bit_channels);
    for (int i = 0; i < num_16bit_channels; ++i) {
      Channel cn = parse_channel(token);
    }

    const long num_8bit_channels = strtol(token, &p, 16);
    token = strtok(NULL, " ");
    if (num_8bit_channels != 1) {
      throw std::runtime_error("num_8bit_channels = " +
                               to_string(num_8bit_channels));
    }

    vector<Channel> channels_8bit(num_8bit_channels);
    for (int i = 0; i < num_8bit_channels; ++i) {
      Channel cn = parse_channel(token);
    }

    const long position = strtol(token, &p, 16);
    token = strtok(NULL, " ");
    const long name_exists = strtol(token, &p, 16);
    token = strtok(NULL, " ");
    if (name_exists == 1) {
      token = strtok(NULL, " ");
      token = strtok(NULL, " ");
    }
    // always 0
    const long comment_exists = strtol(token, &p, 16);
    token = strtok(NULL, " ");

    const long time_exists = strtol(token, &p, 16);
    token = strtok(NULL, " ");
    if (time_exists == 1) {
      const long y = strtol(token, &p, 16);
      token = strtok(NULL, " ");
      const long mo = strtol(token, &p, 16);
      token = strtok(NULL, " ");
      const long d = strtol(token, &p, 16);
      token = strtok(NULL, " ");
      const long h = strtol(token, &p, 16);
      token = strtok(NULL, " ");
      const long mi = strtol(token, &p, 16);
      token = strtok(NULL, " ");
      const long s = strtol(token, &p, 16);
      token = strtok(NULL, " ");
      const long us = strtol(token, &p, 16);
      token = strtok(NULL, " ");
      chrono::system_clock::time_point stamp;
      stamp += years(y) + months(mo) + days(d) + chrono::hours(h) +
               chrono::minutes(mi) + chrono::seconds(s) +
               chrono::microseconds(us);
      std::cout << "h m s " << h << ", " << mi << ", " << s << std::endl;
    } else {
      // no time stamp, use system time?
    }

    /*     name = int(next(tokens), 16) */
    /*     if name == 1: */
    /*         next(tokens) */
    /*         next(tokens) */

    /*     comment = int(next(tokens), 16) */
    /*     time = int(next(tokens), 16) */
    /*     if time == 1: */
    /*         y = int(next(tokens), 16) */
    /*         mo = int(next(tokens), 16) */
    /*         d = int(next(tokens), 16) */
    /*         h = int(next(tokens), 16) */
    /*         mi = int(next(tokens), 16) */
    /*         s = int(next(tokens), 16) */
    /*         us = int(next(tokens), 16) */
    /*         date = datetime(y, mo, d, hour=h, minute=mi, second=s,
     * microsecond=us) */
    /*         print(date) */
    /*     else: */
    /*         print("there is no time") */

    /* def parse_scan_telegram(telegram: bytes): */
    /*     """Expects STX and ETX bytes to be stripped off""" */
    /*     tokens = (t for t in telegram.split(b" ")) */
    /*     method = next(tokens) */
    /*     command = next(tokens) */
    /*     proto_version = next(tokens) */
    /*     device_num = next(tokens) */
    /*     serial_num = int(next(tokens), 16) */
    /*     device_status = (next(tokens), next(tokens)) */
    /*     num_telegrams = next(tokens) */
    /*     num_scans = next(tokens) */
    /*     time_since_boot_us = int(next(tokens), 16) */
    /*     time_of_transmission_us = int(next(tokens), 16) */
    /*     status_digital_input_pins = (next(tokens), next(tokens)) */
    /*     status_digital_output_pins = (next(tokens), next(tokens)) */
    /*     layer_angle = next(tokens)  # should be 0 */
    /*     scan_freq = int(next(tokens), 16) / 100 */
    /*     measurement_freq = int(next(tokens), 16)  # should be 1141 * 25 */
    /*     encoder = int(next(tokens), 16) */
    /*     if encoder != 0: */
    /*         encoder_pos = next(tokens) */
    /*         encoder_speed = next(tokens) */
    /*     num_16bit_channels = int(next(tokens), 16) */

    /*     channels_16bit = [parse_channel(tokens) for i in
     * range(num_16bit_channels)] */

    /*     num_8bit_channels = int(next(tokens), 16) */
    /*     channels_8bit = [parse_channel(tokens) for i in
     * range(num_8bit_channels)] */
    /*     _, _, ranges = channels_16bit[0] */
    /*     ang_incr, angles, intensities = channels_8bit[0] */

    /*     position = int(next(tokens), 16) */
    /*     name = int(next(tokens), 16) */
    /*     if name == 1: */
    /*         next(tokens) */
    /*         next(tokens) */

    /*     comment = int(next(tokens), 16) */
    /*     time = int(next(tokens), 16) */
    /*     if time == 1: */
    /*         y = int(next(tokens), 16) */
    /*         mo = int(next(tokens), 16) */
    /*         d = int(next(tokens), 16) */
    /*         h = int(next(tokens), 16) */
    /*         mi = int(next(tokens), 16) */
    /*         s = int(next(tokens), 16) */
    /*         us = int(next(tokens), 16) */
    /*         date = datetime(y, mo, d, hour=h, minute=mi, second=s,
     * microsecond=us) */
    /*         print(date) */
    /*     else: */
    /*         print("there is no time") */

    /*     return PointCloudLMS(ranges, intensities, angles[0], angles[-1],
     * ang_incr) */
  }

  void add_data(const char *data, size_t length) {

    // check if etx found
    int etx_idx = -1;
    for (size_t i = 0; i < length; ++i) {
      if (data[i] == '\x03') {
        etx_idx = i;
        break;
      }
    }

    if (etx_idx >= 0) {
      buffer.reserve(first_junk_idx - 1 + etx_idx + 1);
      buffer.insert(buffer.begin() + first_junk_idx, data, data + etx_idx + 1);
      first_junk_idx += etx_idx + 1;
      if (buffer[0] == '\x02' && buffer[first_junk_idx - 1] == '\x03') {
        parse_scan_telegram(buffer, first_junk_idx - 1);
      } else {
        // this happens sometimes, how possible?
        std::cout << "Invalid data: " << string(&buffer[0], first_junk_idx - 1)
                  << std::endl;
      }
      first_junk_idx = 0;

      // its possible that etx is not the end of the telegram, but there is new
      // data thereafter. we cannot discard this.
      if (etx_idx + 1 < length) {
        buffer.insert(buffer.begin(), data + etx_idx + 1, data + length);
        first_junk_idx += (length - (etx_idx + 1));
      }
    } else {
      buffer.insert(buffer.begin() + first_junk_idx, data, data + length);
      first_junk_idx += length;
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
          std::cout << sock_fd_ << std::endl;
          std::cout << strerror(errno) << std::endl;
        }
        batcher_.add_data(buffer.data(), read_bytes);
        // optional<Scan> maybe_s = scan_assembler.add_telegram();
        callback_(read_bytes, buffer.data());
      }

      // read socket until entire message
    });

    return sick_err_t::Ok;
  }

  void stop() {
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

};
/* def status_from_bytes(response: bytes): */
/*     pattern = bytes("\x02sFA (.+)\03", "ascii") */
/*     match = re.search(pattern, response) */
/*     if match: */
/*         return int(match.group(1), 16) */
/*     else: */
/*         return 0 */

static string method(const char *sopas_cmd, size_t len) {
  if (len < sizeof("\x02...")) {
    throw runtime_error("wat");
  } else
    return string(sopas_cmd + 1, 3);
}

sick_err_t status_from_bytes_ascii(const char *data, size_t len) {
  // todo, regex search for the different answer starts, match the command name
  // and check if there's at least one more number. If yes, is usually success
  // or error, if no, is success.
  if (len <= 6) {
    // error, msg cant contain a status code
    throw runtime_error("data too short");
  }
  const string answer_method = method(data, len);
  if (answer_method == "sFA") {
    // generic errors
    static const char pattern[]{"\x02sFA %u\x03"};
    unsigned int status = 0;
    int scanf_result = sscanf(data, pattern, &status);
    if (scanf_result != 1) {
      // parse error
    }
    return static_cast<sick_err_t>(status);
  } else {
    // proper response, but might have to get parsed specifically for
    // success/fail
    // skip STX and method, then identify response name, then check if there is
    // a space after it, in which case any error code is always* following. If
    // 0, ok, otherwise not ok
    // * retardedly, the Run command inverts this pattern. 1 = success, 0 =
    // fail. i cant believe how stupid this is.
    return sick_err_t::Ok;
  }
}

static sick_err_t send_sopas_command(int sock_fd, const char *data,
                                     size_t len) {
  std::cout << "Command: " << string(data, len) << std::endl;
  int send_result = send(sock_fd, data, len, 0);
  if (send_result < 0) {
    // error
  }
  array<char, 4096> recvbuf;
  recvbuf.fill(0x00);
  int recv_result = recv(sock_fd, recvbuf.data(), 4096, 0);
  if (recv_result < 0) {
    // error
  }
  std::cout << "Command answer: " << string(recvbuf.data()) << std::endl;
  return status_from_bytes_ascii(recvbuf.data(), recv_result);
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
      {LMDSCANDATA, "\x02sEN LMDscandata 1\x03"}};

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
    sick_err_t result =
        send_sopas_command(sock_fd_, buffer.data(), bytes_written);
    return result;
  }

  template <typename... Args>
  sick_err_t send_command(SOPASCommand cmd, Args... args) {
    array<char, 4096> buffer;
    // authorized client mode with pw hash from telegram listing
    int bytes_written =
        sprintf(buffer.data(), command_masks_[cmd].c_str(), args...);
    if (bytes_written < 0) {
      throw runtime_error("sprintf fail");
    }

    sick_err_t result =
        send_sopas_command(sock_fd_, buffer.data(), bytes_written);
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
    // convert to degrees and add offset so 0 is straight ahead
    auto angle_to_lms = [](rad angle_in) { return angle_in * RAD2DEG + 90; };

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
    return status;
  }

  sick_err_t save_params() override { return send_command(MEEWRITEALL); }

  sick_err_t run() override {
    sick_err_t status = send_command(RUN);
    if (status != sick_err_t::Ok) {
      return status;
    }
    return send_command(LMDSCANDATA);
  }
};

static void cbk(int read_bytes, char *data) {}

int main() {
  SOPASProtocolASCII proto("192.168.95.194", 2111, cbk);
  sick_err_t status = proto.set_access_mode();
  status = proto.configure_ntp_client("192.168.95.44");
  status = proto.set_scan_config(LMSConfigParams{.frequency = 50,
                                                 .resolution = 0.25,
                                                 .start_angle = -95 * DEG2RAD,
                                                 .end_angle = 95 * DEG2RAD});
  status = proto.save_params();
  status = proto.run();
  std::cout << sick_err_t_to_string(status) << std::endl;
  proto.start_scan();
  std::this_thread::sleep_for(std::chrono::seconds(10));
  proto.stop();
}
