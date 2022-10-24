#pragma once

#include <array>
#include <chrono>
#include <cmath>
#include <string.h>
#include <string>

static constexpr char STX = '\x02'; ///< telegram start marker
static constexpr char ETX = '\x03'; ///< telegram end marker

static constexpr double RAD2DEG = 180.0 / M_PI;
static constexpr double DEG2RAD = 1 / RAD2DEG;

namespace sick {

/**
 * @brief   Error type for errors returned by the scanner, and errors from this
 * library
 */
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
  CustomErrorConnectionClosed,
  _LAST
};

/**
 * @brief   Convert error type to string
 *
 * @param   err Error
 *
 * @return  Name of the error for display
 */
static std::string sick_err_t_to_string(const sick_err_t &err) {
  constexpr size_t last_idx = static_cast<size_t>(sick_err_t::_LAST);
  const std::array<std::string, last_idx> strerrors{
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
      "CustomErrorSocketRecv",
      "CustomErrorConnectionClosed",
  };
  return strerrors[static_cast<size_t>(err)];
}
class SickErr {
private:
  int code_;
  bool is_posix_err_;

public:
  SickErr(int error_num) : code_(error_num), is_posix_err_(true) {}
  SickErr(sick_err_t err)
      : code_(static_cast<int>(err)), is_posix_err_(false) {}
  bool ok() const {
    return is_posix_err_ ? code_ == 0
                         : code_ == static_cast<int>(sick_err_t::Ok);
  }
  int code() const { return code_; }
  std::string what() const {
    if (!is_posix_err_) {
      return sick_err_t_to_string(static_cast<sick_err_t>(code_));
    } else {
      return strerror(code_);
    }
  }
};

} // namespace sick
