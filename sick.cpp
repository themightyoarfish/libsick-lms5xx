#include <Eigen/Core>
#include <arpa/inet.h>
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace std;
using namespace Eigen;

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
  Sopas_Error_ComplexArraysNotSupported
};

using rad = double;
using hz = double;

struct LMSConfigParams {
  hz freuency;
  rad resolution;
  // from -95° to 95°
  rad start_angle;
  rad end_angle;

  // echo config?
  //
};

static uint32_t ip_addr_to_int(const string &ip_str) {
  struct sockaddr_in sa;
  static constexpr int LEN = 3 + 4 * 3 + 1;
  char str[LEN];

  // store this IP address in sa:
  inet_pton(AF_INET, ip_str.c_str(), &(sa.sin_addr));

  return sa.sin_addr.s_addr;
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

using ScanCallback = function<void(Scan<1141>)>;

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

    sock_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd_ < 0) {
      throw std::runtime_error("Unable to create socket.");
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = port;
    addr.sin_addr.s_addr = ip_addr_to_int(sensor_ip);

    int connect_result = connect(
        sock_fd_, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
    if (connect_result < 0) {
      throw std::runtime_error("Unable to connect to scanner.");
    }
  }

  virtual sick_err_t run() = 0;

  virtual sick_err_t set_access_mode(const uint8_t mode,
                                     const uint32_t pw_hash) = 0;

  virtual sick_err_t configure_ntp_client(const string &ip) = 0;

  virtual sick_err_t set_scan_config(const LMSConfigParams &params) = 0;

  virtual sick_err_t save_params() = 0;

  sick_err_t start_scan() {
    std::vector<char> buffer(4096);
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

sick_err_t status_from_bytes(const char *data, size_t len) {
  if (len <= 6) {
    // error, msg cant contain a status code
  }
  static const string pattern = "\x02 %2X \x03";
  uint8_t status;
  int scanf_result = sscanf(data, pattern.c_str(), status);
  if (scanf_result != 1) {
    // parse error
  }
  return static_cast<sick_err_t>(status);
}

static sick_err_t send_sopas_command(int sock_fd, const char *data,
                                     size_t len) {
  int send_result = send(sock_fd, data, len, 0);
  if (send_result < 0) {
    // error
  }
  array<char, 4096> recvbuf;
  int recv_result = recv(sock_fd, recvbuf.data(), 4096, 0);
  if (recv_result < 0) {
    // error
  }
  return status_from_bytes(recvbuf.data(), recv_result);
}

class SOPASProtocolASCII : public SOPASProtocol {

  using SOPASProtocol::SOPASProtocol;

  map<SOPASCommand, string> command_masks_ = {
      {SETACCESSMODE, "\x02sMN SetAccessMode %02d %08X\x03"}};

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

  sick_err_t configure_ntp_client(const string &ip) override {
    return sick_err_t::Ok;
  }

  sick_err_t set_scan_config(const LMSConfigParams &params) override {
    return sick_err_t::Ok;
  }

  sick_err_t save_params() override { return sick_err_t::Ok; }
};

int main() {
  // wat
}
