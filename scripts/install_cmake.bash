#!/bin/env bash
set -o errexit

wget https://github.com/Kitware/CMake/releases/download/v3.23.1/cmake-3.23.1.tar.gz
tar -xzf cmake-3.23.1.tar.gz
cd cmake-3.23.1
./configure
make j$(getconf _NPROCESSORS_ONLN) install
