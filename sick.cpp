#include <Eigen/Core>
#include <arpa/inet.h>
#include <atomic>
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

template <size_t NumPts = 1141> struct Scan {
  /* EIGEN_MAKE_ALIGNED_OPERTOR_NEW; */

  Vector<float, NumPts> ranges;
  Vector<float, NumPts> intensities;
  rad start_angle;
  rad end_angle;
  rad ang_increment;
  Vector<float, NumPts> sin_map;
  Vector<float, NumPts> cos_map;
};

using ScanCallback = function<void(const Scan<1141> &)>;

class SOPASProtocol {

protected:
  const string sensor_ip_;
  const uint32_t port_;
  ScanCallback callback_;
  atomic<bool> stop_;
  thread poller_;

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
    vector<char> buffer(4096);
    poller_ = thread([&] {
      while (!stop_.load()) {
        int read_bytes = read(sock_fd_, &buffer[0], 4096);
        if (read_bytes < 0) {
          // error
        }
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
      {MLMPSETSCANCFG, "\x02sMN mLMPsetscancfg %+4u +1 +%4u %+d %+d\x03"},
  };

public:
  sick_err_t run() override { return sick_err_t::Ok; }

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

    return send_command(MLMPSETSCANCFG, hz_Lms, ang_increment_lms,
                        start_angle_lms, end_angle_lms);
    /* set_scancfg_cmd = "\x02sMN mLMPsetscancfg +2500 +1 +1667 -50000
     * +1850000\x03" */
    /*   hz freuency; */
    /*   rad resolution; */
    /*   // from -95° to 95° */
    /*   rad start_angle; */
    /*   rad end_angle; */
  }

  sick_err_t save_params() override { return sick_err_t::Ok; }
};

static void cbk(const Scan<1141> &scan) {}

int main() {
  SOPASProtocolASCII proto("192.168.95.194", 2111, cbk);
  sick_err_t status = proto.set_access_mode();
  status = proto.configure_ntp_client("192.168.95.44");
  status = proto.set_scan_config(LMSConfigParams{.frequency = 25,
                                                 .resolution = 0.1667,
                                                 .start_angle = -95 * DEG2RAD,
                                                 .end_angle = 95 * DEG2RAD});
  std::cout << sick_err_t_to_string(status) << std::endl;
}
