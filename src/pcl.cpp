#include <sick-lms5xx/parsing.hpp>
#include <sick-lms5xx/pcl.hpp>

namespace sick {
namespace pcl {

::pcl::PointCloud<::pcl::PointXYZI>::Ptr
cloud_ptr_from_scan(const sick::Scan &scan) {
  ::pcl::PointCloud<::pcl::PointXYZI>::Ptr cloud_out =
      ::pcl::make_shared<::pcl::PointCloud<::pcl::PointXYZI>>();
  cloud_out->resize(scan.ranges.size(), 1);
  for (int i = 0; i < scan.ranges.size(); ++i) {
    cloud_out->points[i].x = scan.ranges(i) * scan.cos_map(i);
    cloud_out->points[i].y = scan.ranges(i) * scan.sin_map(i);
    cloud_out->points[i].z = 0;
    cloud_out->points[i].intensity = scan.intensities[i];
  }
  return cloud_out;
}

::pcl::PointCloud<::pcl::PointXYZI> cloud_from_scan(const sick::Scan &scan) {
  ::pcl::PointCloud<::pcl::PointXYZI> cloud_out;
  cloud_out.resize(scan.ranges.size());
  const Eigen::VectorXf x = scan.ranges.array() * scan.cos_map.array();
  const Eigen::VectorXf y = scan.ranges.array() * scan.sin_map.array();
  for (int i = 0; i < x.size(); ++i) {
    cloud_out.points[i].x = x(i);
    cloud_out.points[i].y = y(i);
    cloud_out.points[i].z = 0;
    cloud_out.points[i].intensity = scan.intensities[i];
  }
  return cloud_out;
}
} // namespace pcl

} // namespace sick
