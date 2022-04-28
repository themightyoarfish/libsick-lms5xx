#include <atomic>
#include <chrono>
#include <errno.h>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <thread>
#include <unistd.h>
#include <vector>

#include <sick-lms5xx/config.hpp>
#include <sick-lms5xx/network.hpp>
#include <sick-lms5xx/parsing.hpp>
#include <sick-lms5xx/sopas.hpp>
#include <sick-lms5xx/types.hpp>

#ifdef WITH_PCL
#include <pcl/io/pcd_io.h>
#include <pcl/point_cloud.h>
#include <pcl/point_types.h>
#include <sick-lms5xx/pcl.hpp>
#endif

using namespace std;
using namespace sick;

static atomic<int> n_scans;

#ifdef WITH_PCL
static void cbk(const Scan &scan) {
  const auto cloud = sick::pcl::cloud_from_scan(scan);
  ::pcl::io::savePCDFileASCII(string("cloud-") + to_string(n_scans) + ".pcd",
                              cloud);
  std::cout << "Got scan with " << cloud.size() << " points." << std::endl;
  ++n_scans;
}
#else
static void cbk(const Scan &scan) {
  std::cout << "Got scan with " << scan.size << " points." << std::endl;
  ++n_scans;
}
#endif

int main() {
  n_scans = 0;
  SOPASProtocolASCII proto("192.168.95.194", 2111, cbk);

  // log into the scanner as authorized client.
  sick_err_t status = proto.set_access_mode();
  if (status != sick_err_t::Ok) {
    std::cout << "Could not set access mode." << std::endl;
    return 1;
  }

  // Sync scanner clock to ntp server
  status = proto.configure_ntp_client("192.168.95.44");
  if (status != sick_err_t::Ok) {
    std::cout << "Could not configure ntp client" << std::endl;
    return 2;
  }

  // Set scan config. Only some combinations of values are supported by a given
  // model
  status = proto.set_scan_config(
      lms5xx::LMSConfigParams{.frequency = 25,
                              .resolution = 0.1667,
                              .start_angle = -95 * DEG2RAD,
                              .end_angle = 95 * DEG2RAD});

  if (status != sick_err_t::Ok) {
    std::cout << "Could not configure scan" << std::endl;
    return 3;
  }

  // save the parameters to eeprom, optional
  status = proto.save_params();
  if (status != sick_err_t::Ok) {
    std::cout << "Could not save params" << std::endl;
    return 4;
  }

  // request the scan data
  status = proto.run();
  if (status != sick_err_t::Ok) {
    std::cout << "Could not run scanner" << std::endl;
    return 5;
  }

  // start socket poller for receive. wait for a few seconds to warm up and then
  // start counting scans. Print resulting hz.
  proto.start_scan();
  std::cout << "Wait a bit for scanner..." << std::endl;
  std::this_thread::sleep_for(std::chrono::seconds(2));
  const auto tic = chrono::system_clock::now();
  n_scans = 0;
  std::this_thread::sleep_for(std::chrono::seconds(4));
  const auto toc = chrono::system_clock::now();
  const double s_elapsed =
      chrono::duration_cast<chrono::milliseconds>(toc - tic).count() / 1000.0;
  std::cout << "got " << n_scans << " in " << s_elapsed << "s ("
            << n_scans.load() / s_elapsed << "hz)" << std::endl;
  proto.stop();
}
