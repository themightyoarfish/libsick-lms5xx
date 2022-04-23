#include "parsing.hpp"
#include "pcl.hpp"

namespace sick {
namespace pcl {
::pcl::PointCloud<::pcl::PointXYZI> cloud_from_scan(const sick::Scan &scan) {
  ::pcl::PointCloud<::pcl::PointXYZI> cloud_out;
  cloud_out.width = scan.ranges.size();
  cloud_out.height = 1;
  const Eigen::VectorXf x = scan.ranges.array() * scan.cos_map.array();
  const Eigen::VectorXf y = scan.ranges.array() * scan.sin_map.array();
  for (int i = 0; i < x.size(); ++i) {
    cloud_out.points.emplace_back(
        ::pcl::PointXYZI(x(i), y(i), 0, scan.intensities[i]));
  }
  return cloud_out;
}
} // namespace pcl

} // namespace sick
