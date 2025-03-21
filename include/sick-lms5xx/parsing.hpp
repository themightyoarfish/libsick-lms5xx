#pragma once
#include <Eigen/Core>
#include <chrono>
#include <sick-lms5xx/config.hpp>
#include <sick-lms5xx/util.hpp>
#include <string>
#include <vector>

namespace sick {

/**
 * @brief   Class to emulate Python iterator. Tokenizes string by use of a
 * delimiter.
 */
class TokenBuffer {

  std::vector<std::string>
      tokens_copy_; ///< we need to copy tokens to not destroy the input string
  decltype(tokens_copy_)::iterator iter_;

public:
  /**
   * @param tokens  Null-terminated input string of tokens delimited by \p delim
   * @param len len Length of the \p tokens input string **not number of
   * tokens**
   * @param delim   Delimiter between the tokens
   */
  TokenBuffer(const char *tokens, size_t len, char delim = ' ');

  /**
   * @return    Whether there are more tokens
   */
  bool has_next() const;

  /**
   * @return    Pointer to next token
   */
  const char *next();
};

/**
 * @brief   Struct for scan data
 */
struct Scan {
  unsigned int size;           ///< Number of points
  Eigen::VectorXf ranges;      ///< vector of distances in meters
  Eigen::VectorXf intensities; ///< vector of reflectivities
  rad start_angle;             ///< begin angle of the scan plane
  rad end_angle;               ///< end angle of the scan plane
  rad ang_increment;           ///< angular increment between rays
  Eigen::VectorXf
      sin_map; ///< reuseable map of sine coefficients for each angle
  Eigen::VectorXf
      cos_map; ///< reuseable map of cosine coefficients for each angle

  std::chrono::system_clock::time_point time; ///< timestamp of scan acquisition

  /**
   * @brief Default init the scan with 0 points
   */
  Scan() { size = 0; }

  Scan(const Scan &other) = default;
};

/**
 * @brief   Trivial optional type
 *
 * @tparam T
 */
template <typename T> class simple_optional {
  T t_;
  bool has_value_;

public:
  /**
   * @param t   Value to wrap
   */
  simple_optional(const T &t) : t_(t), has_value_(true){};

  /**
   * @brief Default ctor with no value
   */
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

/**
 * @brief   Structure for holding parse results for one channel
 */
struct Channel {
  double ang_incr;           ///< angular step between points
  std::vector<float> angles; ///< angles of each ray
  std::vector<float>
      values; ///< channel values (meters for distance, 0-255 for intensities)
  std::string description; ///< name of the channel, e.g. RSSI1, DIST1

  /**
   * @brief Empty default ctor for collections. Undefined values.
   */
  Channel();

  /**
   * @param description Name for the channel
   * @param n_values    Number of measurements in the channel
   * @param ang_incr    Angular increment between measuremend
   */
  Channel(const std::string &description, size_t n_values, double ang_incr);

  /**
   * @return    True if the \ref angles and \ref values have the same size,
   * false otherwise
   */
  bool valid() const;
};

/**
 * @brief   Helper class to feed data telegrams to and assemble them to scans
 */
class ScanBatcher {
  std::vector<char> buffer;  ///< temporary data store
  size_t num_bytes_buffered; ///< number of bytes currently buffered
  Scan s;                    ///< scan to return

public:
  /**
   * @brief Default ctor with undefined values
   */
  ScanBatcher();

  /**
   * @brief Add data, and get a scan if the data is complete. Function will
   * ingest new data and check if it completes currently buffered data to parse
   * an entire scan.
   *
   * @param data_new    Data to append
   * @param length  Number of bytes in \p data_new
   *
   * @return    Maybe, a parsed scan.
   */
  simple_optional<Scan> add_data(const char *data_new, size_t length);

  /**
   * @brief Helper function to parse a channel from a token buffer pointing to
   * the beginning of the channel's SOPA data
   *
   * @param buf mutable buffer that delivers the subsequent tokens
   *
   * @return    A parsed channel
   */
  static Channel parse_channel(TokenBuffer &buf);

  /**
   * @brief Parse a complete scan telegram. Into a scan
   *
   * @param buffer  Complete telegram with all channels and metadata. Vector may
   * have trailing data or junk at the end
   * @param last_valid_idx  Index of last valid byte in \p buffer
   * @param scan    Parse scan
   *
   * @return    Whether the parse was successful and \p scan can be used
   */
  static bool parse_scan_telegram(const std::vector<char> &buffer,
                                  size_t last_valid_idx, Scan &scan);
};

/**
 * @brief   Enum for known scanner commands.
 */
enum SOPASCommand {
  SETACCESSMODE,
  TSCROLE,
  TSCTCINTERFACE,
  TSCTCSRVADDR,
  MLMPSETSCANCFG,
  LMDSCANDATACFG,
  FRECHOFILTER,
  LMPOUTPUTRANGE_READ,
  LMPOUTPUTRANGE_WRITE,
  MEEWRITEALL,
  RUN,
  LMDSCANDATA,
  LMCSTOPMEAS,
  LMCSTARTMEAS,
  REBOOT
};

/**
 * @brief   Badly named function to determine the SOPAS method (e.g. `sMN`) from
 * a reply
 *
 * @param sopas_reply   Response from the scanner
 * @param len   Lenght of \p sopas_reply
 *
 * @return  The method string from the reply
 */
std::string method(const char *sopas_reply, size_t len);

/**
 * @brief   Check command status code for validity for a fixed list of commands.
 * Some SOPAS methods need special handling, as a status of 1 usually means
 * success, but for some it's 0. This applies to e.g. `mEEwriteall` and `Run`.
 * That's pretty insane, but i guess it's legacy interest.
 *
 * @param cmd_name  SOPAS command name
 * @param status_code   Status code parsed from telegram
 *
 * @return  Whether the status code signals an error for the given command
 */
bool status_ok(const std::string &cmd_name, int status_code);

/**
 * @brief   Check if a string can constitute a valid SOPAS response. It must
 * have a minimum length and contain the start and end bytes
 *
 * @param data  Data from scanner
 * @param len   Length of \p data
 *
 * @return  Whether this looks like a properly formed SOPAS reply
 */
bool validate_response(const char *data, size_t len);

/**
 * @brief   Parse status from ascii SOPAS response
 *
 * @param data  Data from scanner
 * @param len   Length of \p data
 *
 * @return  Error or success code for this telegram
 */
SickErr status_from_bytes_ascii(const char *data, size_t len);

} // namespace sick
