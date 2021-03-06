[![Build project](https://github.com/themightyoarfish/libsick-lms5xx/actions/workflows/build.yml/badge.svg)](https://github.com/themightyoarfish/libsick-lms5xx/actions/workflows/build.yml)

---

<p align="center">
<img src="gfx/image.png" alt="accidental art" width="200"/>
<p>

# C++ library to talk to Sick LMS511 sensors

This library implements ASCII SOPAS subsets to talk to LMS511 scanners. It should work
with all LMS5xx scanners, though this has not been tested.

# Usage

You can install this CMake project in the usual way, but inclusion via
`add_subdirectory()` should also work. Linking to the library can be done like this

```
find_package(SickLMS5xx REQUIRED)
target_link_libraries(<target> PUBLIC SickLMS5xx::SickLMS5xx)
```

See `src/example.cpp` for how to interact with a scanner.

# Requirements

Uses BSD sockets and should therefore run on Linux and MacOS.

The dependencies are

- PCL >= 1.10, which is available in the package repos only from ubuntu 20.04. for older
  OS versions, you'll have to install form source
- Eigen3, which is a PCL dependency anyway
- Doxygen if you want to generate HTML doc

# Disclaimer

Not affiliated with [Sick AG](https://www.sick.com/de/en/)
