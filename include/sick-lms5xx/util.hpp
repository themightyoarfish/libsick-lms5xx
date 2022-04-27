#pragma once
#include <sick-lms5xx/config.hpp>
#include <sick-lms5xx/types.hpp>

namespace sick {

/**
 * @brief convert to degrees and add offset so 0 is straight ahead
 *
 * @param angle_in  Input angle
 *
 * @return Angle in LMS coordinate system
 */
deg angle_to_lms(rad angle_in);

/**
 * @brief convert from LMS coordinate system to standard coordinate system with
 * X straigh ahead
 *
 * @param angle_in  Input angle in deg
 *
 * @return Angle in standard right-handed coordinate system
 */
rad angle_from_lms(deg angle_in);

} // namespace sick
