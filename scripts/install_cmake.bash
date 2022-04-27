#!/bin/env bash
set -o errexit

function version { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }

os="$(uname)"

if [ $os == "Darwin" ]; then
    os_version = $(sw_vers -productVersion)
    if [ $(version $os_version) -ge $(version "10.13") ]; then
        curl -L https://github.com/Kitware/CMake/releases/download/v3.23.1/cmake-3.23.1-macos-universal.dmg -o cmake.dmg
    elif [ $(version $os_version) -ge $(version "10.10") ]; then
        curl -L https://github.com/Kitware/CMake/releases/download/v3.23.1/cmake-3.23.1-macos10.10-universal.dmg -o cmake.dmg
    fi
    hdiutil attach cmake.dmg
    installer -package /Volumes//<image>.pkg -target /
fi
if [ $os == "Linux" ]; then
    curl -L https://github.com/Kitware/CMake/releases/download/v3.23.1/cmake-3.23.1-linux-x86_64.sh -o cmake.sh
    sh cmake.sh --skip-license --prefix=/usr/local
fi
