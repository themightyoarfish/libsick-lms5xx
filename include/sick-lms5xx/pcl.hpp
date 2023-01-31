#pragma once
#include <pcl/point_cloud.h>
#include <pcl/point_types.h>

namespace sick {

class Scan;

namespace pcl {

/**
 * @brief   Convert Scan struct into PCL point cloud
 *
 * @param scan  Scan structure
 *
 * @return  Point cloud
 */
::pcl::PointCloud<::pcl::PointXYZI>::Ptr
cloud_ptr_from_scan(const sick::Scan &scan);

::pcl::PointCloud<::pcl::PointXYZI> cloud_from_scan(const sick::Scan &scan);

} // namespace pcl

} // namespace sick
