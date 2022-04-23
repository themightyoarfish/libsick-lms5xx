#pragma once
#include "types.hpp"
#include "config.hpp"

namespace sick {

// convert to degrees and add offset so 0 is straight ahead
static deg angle_to_lms(rad angle_in) { return angle_in * RAD2DEG + 90; }
static rad angle_from_lms(deg angle_in) { return (angle_in - 90) * DEG2RAD; }

} // namespace sick
