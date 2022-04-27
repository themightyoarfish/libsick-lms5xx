#pragma once

// Marker types
// TODO: use boost::unit
using rad = double;
using deg = double;
using hz = double;

namespace sick {
namespace lms5xx {

/**
 * @brief   Struct to hold parameters for LMS scanner
 */
struct LMSConfigParams {
  hz frequency;    ///< scan frequency (25, 50, 75)
  rad resolution;  ///< scan resolution (0.1667, 0.25, 0.5, 1)
  rad start_angle; ///< begin scan angle, from -95° to 95°
  rad end_angle;   ///< end scan angle, from -95° to 95°

  // echo config?
};
} // namespace lms5xx

} // namespace sick
