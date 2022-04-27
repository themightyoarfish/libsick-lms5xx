#!/bin/env bash
set -o errexit

function version { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }

os="$(uname)"

if [ $os == "Darwin" ]; then
    brew update
    brew install cmake
fi
if [ $os == "Linux" ]; then
    curl -L https://github.com/Kitware/CMake/releases/download/v3.23.1/cmake-3.23.1-linux-x86_64.sh -o cmake.sh
    sh cmake.sh --skip-license --prefix=/usr/local
fi
