#pragma once
#include <pcl/point_cloud.h>
#include <pcl/point_types.h>
namespace sick {
namespace pcl {

::pcl::PointCloud<::pcl::PointXYZI> cloud_from_scan(const sick::Scan &scan);

} // namespace pcl

} // namespace sick
