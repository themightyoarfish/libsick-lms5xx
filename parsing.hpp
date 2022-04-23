#pragma once
#include "config.hpp"
#include "util.hpp"
#include <Eigen/Core>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>

namespace sick {

class TokenBuffer {
  std::vector<char> tokens_copy_;
  char *cur_tok_;
  std::string delim_;

public:
  TokenBuffer(const char *tokens, size_t len, const std::string &delim = " ");

  bool has_next() const;

  const char *next();
};

struct Scan {
  unsigned int size;
  Eigen::VectorXf ranges;
  Eigen::VectorXf intensities;
  rad start_angle;
  rad end_angle;
  rad ang_increment;
  Eigen::VectorXf sin_map;
  Eigen::VectorXf cos_map;

  std::chrono::system_clock::time_point time;

  Scan() { size = 0; }

  Scan(const Scan &other) = default;
};

template <typename T> class simple_optional {
  T t_;
  bool has_value_;

public:
  simple_optional(const T &t) : t_(t), has_value_(true){};
  simple_optional() : has_value_(false){};

  static simple_optional none() { return simple_optional<T>(); }

  bool has_value() const { return has_value_; }

  operator T() const {
    if (!has_value()) {
      throw std::invalid_argument("optional has no content.");
    }
    return t_;
  }
};

struct Channel {
  double ang_incr;
  std::vector<float> angles;
  std::vector<float> values;
  std::string description;

  Channel();

  Channel(const std::string &description, size_t n_values, double ang_incr);

  bool valid() const;
};

class ScanBatcher {
  std::vector<char> buffer;
  size_t num_bytes_buffered;
  Scan s;

public:
  ScanBatcher();

  simple_optional<Scan> add_data(const char *data_new, size_t length);

  static Channel parse_channel(TokenBuffer &buf);

  static bool parse_scan_telegram(const std::vector<char> &buffer,
                                  size_t last_valid_idx, Scan &scan);
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

std::string method(const char *sopas_reply, size_t len);

bool status_ok(const std::string &cmd_name, int status_code);

bool validate_response(const char *data, size_t len);

sick_err_t status_from_bytes_ascii(const char *data, size_t len);

} // namespace sick
