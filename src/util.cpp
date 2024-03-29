#include <sick-lms5xx/util.hpp>
namespace sick {
deg angle_to_lms(rad angle_in) { return angle_in * RAD2DEG + 90; }
rad angle_from_lms(deg angle_in) { return (angle_in - 90) * DEG2RAD; }

} // namespace sick
