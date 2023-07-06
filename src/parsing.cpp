#include <iostream>
#include <sick-lms5xx/parsing.hpp>

using namespace std;

namespace sick {
TokenBuffer::TokenBuffer(const char *tokens, size_t len, char delim) {
  tokens_copy_.reserve(len / 2);
  size_t begin_tok = 0;
  size_t end_tok = 0;
  for (size_t idx = 0; idx < len; ++idx) {
    if (tokens[idx] == delim) {
      end_tok = idx - 1;
      string token(tokens + begin_tok, end_tok - begin_tok + 1);
      tokens_copy_.push_back(token);
      begin_tok = idx + 1;
    }
  }
  if (begin_tok < len) {
    string final_token(tokens + begin_tok, len - begin_tok);
    tokens_copy_.push_back(final_token);
  }
  iter_ = tokens_copy_.begin();
}

bool TokenBuffer::has_next() const { return iter_ != tokens_copy_.end(); }

const char *TokenBuffer::next() {
  if (!has_next()) {
    throw std::out_of_range("TokenBuffer has no more tokens.");
  }
  return (iter_++)->c_str();
}

Channel::Channel() { ang_incr = 0; }

Channel::Channel(const std::string &description, size_t n_values,
                 double ang_incr) {
  this->description = description;
  this->ang_incr = ang_incr;
  angles.reserve(n_values);
  values.reserve(n_values);
}

bool Channel::valid() const { return angles.size() == values.size(); }

ScanBatcher::ScanBatcher() { num_bytes_buffered = 0; }

simple_optional<Scan> ScanBatcher::add_data(const char *data_new,
                                            size_t length) {
  if (length < 1) {
    return simple_optional<Scan>();
  }

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
    std::memcpy(buffer.data() + num_bytes_buffered, data_new, length);
    num_bytes_buffered += length;
  } else {
    // etx found
    buffer.reserve(num_bytes_buffered + etx_idx + 1);
    std::memcpy(buffer.data() + num_bytes_buffered, data_new, etx_idx + 1);
    num_bytes_buffered += etx_idx + 1;
    if (buffer[0] == STX && buffer[num_bytes_buffered - 1] == ETX) {
      // try to parse scan telegram
      if (parse_scan_telegram(buffer, num_bytes_buffered - 1, s)) {
        // return the scan
        got_scan = true;
      } else {
        /* std::cout << "Error: scan did not parse" << std::endl; */
      }
    } else {
      /* std::cout << "Error: invalid data." << std::endl; */
    }
    num_bytes_buffered = 0;

    if (length > etx_idx + 1) {
      // trailing data must be kept
      // You'd think to check that the start token of the trailing data is
      // STX, but the partial datagrams don't seem to have it
      const size_t new_data_length = length - (etx_idx + 1);
      buffer.reserve(new_data_length);
      if (new_data_length > 0) {
        std::memcpy(buffer.data(), data_new + etx_idx + 1, new_data_length);
      }
      num_bytes_buffered = new_data_length;
    }
  }

  if (got_scan) {
    return simple_optional<Scan>(s);
  } else {
    return simple_optional<Scan>();
  }
}

Channel ScanBatcher::parse_channel(TokenBuffer &buf) {
  std::string content(buf.next());

  std::string scale_factor_s(buf.next());
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

bool ScanBatcher::parse_scan_telegram(const std::vector<char> &buffer,
                                      size_t last_valid_idx, Scan &scan) {
  using std::string;
  // remove STX and ETX bytes
  TokenBuffer buf(&buffer[1], last_valid_idx);

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
    return false;
    /* throw std::runtime_error(__fun__+ ": num_16bit_channels != 1"); */
  }

  std::vector<Channel> channels_16bit(num_16bit_channels);
  for (int i = 0; i < num_16bit_channels; ++i) {
    channels_16bit[i] = parse_channel(buf);
  }

  const long num_8bit_channels = strtol(buf.next(), &p, 16);
  if (num_8bit_channels != 1) {
    return false;
    /* throw std::runtime_error(__func__ + ": num_8bit_channels = " + */
    /*                          std::to_string(num_8bit_channels)); */
  }

  std::vector<Channel> channels_8bit(num_8bit_channels);
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
    std::tm tm;
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = s;
    tm.tm_isdst = -1;
    std::time_t tmt = std::mktime(&tm);
    std::chrono::system_clock::time_point stamp =
        std::chrono::system_clock::from_time_t(tmt) +
        std::chrono::microseconds(us);

    if (channels_16bit.size() < 1) {
      return false;
      /* throw std::runtime_error(__func__ + */
      /*                          ": parse_scan_telegram() got no 16bit channels"); */
    } else {
      const Channel &range_cn = channels_16bit.front();
      if (range_cn.description.find("DIST") == std::string::npos) {
        return false;
        /* throw std::runtime_error( */
        /*     __func__ + ": First 16bit channel was not range but " + */
        /*     range_cn.description); */
      } else {
        const Channel &intensity_cn = channels_8bit.front();
        if (intensity_cn.description.find("RSSI") == std::string::npos) {
          return false;
          /* throw std::runtime_error( */
          /*     __func__ + ": First 8bit channel was not intensity but " + */
          /*     range_cn.description); */
        } else {
          if (range_cn.values.size() != intensity_cn.values.size()) {
            throw std::runtime_error(
                "Ranges and intensities not matched in size.");
          } else {
            if (scan.ranges.size() == 0) {
              // first time -> fill nonchanging fields
              scan.size = range_cn.values.size();
              scan.ranges = Eigen::VectorXf::Zero(scan.size, 1);
              scan.intensities = Eigen::VectorXf::Zero(scan.size, 1);
              scan.ang_increment = range_cn.ang_incr;
              scan.start_angle = angle_to_lms(range_cn.angles.front());
              scan.end_angle = angle_to_lms(range_cn.angles.back());
              Eigen::VectorXf angles(scan.size, 1);
              std::memcpy(angles.data(), &range_cn.angles[0],
                          scan.size * sizeof(float));
              scan.cos_map = Eigen::cos(angles.array());
              scan.sin_map = Eigen::sin(angles.array());
            }

            std::memcpy(scan.ranges.data(), &range_cn.values[0],
                        scan.size * sizeof(float));
            scan.ranges /= 1000;
            std::memcpy(scan.intensities.data(), &intensity_cn.values[0],
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

std::string method(const char *sopas_reply, size_t len) {
  if (len < sizeof("\x02...")) {
    throw std::runtime_error("Sopas reply string too short to have a method.");
  } else
    return std::string(sopas_reply + 1, 3);
}

bool status_ok(const std::string &cmd_name, int status_code) {
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

bool validate_response(const char *data, size_t len) {
  if (len <= 6) {
    return false;
  }
  // check that there is exactly one STX and one ETX byte, otherwise we
  // somehow read multiple messages, which can happen in some cases if you
  // time out your recv, but the data then comes with your next call (should
  // you try one)
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

SickErr parse_generic_error(const char *data, size_t len) {
  // generic errors
  static const char pattern[]{"\x02sFA %2X\x03"};
  unsigned int status = 0;
  int scanf_result = sscanf(data, pattern, &status);
  if (scanf_result != 1) {
    return sick_err_t::CustomError;
  }
  return static_cast<sick_err_t>(status);
}

SickErr parse_generic_return(const char *data, size_t len) {
  TokenBuffer buf(data, len);
  std::string method(buf.next());
  std::string cmd_name(buf.next());
  if (buf.has_next()) {
    int status_code = atoi(buf.next());
    if (status_ok(cmd_name, status_code)) {
      return sick_err_t::Ok;
    } else {
      return sick_err_t::CustomErrorCommandFailure;
    }
  } else {
    return sick_err_t::Ok;
  }
}

SickErr status_from_bytes_ascii(const char *data, size_t len) {
  if (!validate_response(data, len)) {
    return sick_err_t::CustomErrorInvalidDatagram;
  }
  const std::string answer_method = method(data, len);
  if (answer_method == "sFA") {
    return parse_generic_error(data, len);
  } else {
    return parse_generic_return(data, len);
  }
}

SickErr get_response_ascii(const char *data, size_t len, TokenBuffer &buf) {
  if (!validate_response(data, len)) {
    return sick_err_t::CustomErrorInvalidDatagram;
  }
  const std::string answer_method = method(data, len);
  if (answer_method == "sFA") {
    return parse_generic_error(data, len);
  } else {
    buf = TokenBuffer(data, len);
    return SickErr();
  }
}

} // namespace sick
