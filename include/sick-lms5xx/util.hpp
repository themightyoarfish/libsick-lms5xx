#pragma once
#include <sick-lms5xx/config.hpp>
#include <sick-lms5xx/types.hpp>

namespace sick {

// convert to degrees and add offset so 0 is straight ahead
deg angle_to_lms(rad angle_in);
rad angle_from_lms(deg angle_in);

} // namespace sick
