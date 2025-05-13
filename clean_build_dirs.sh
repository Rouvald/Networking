#! /bin/bash

declare -a dirs=(
    "build_linux_Release"
    "build_linux_Debug"
    "build_win_Release"
    "build_win_Debug"
    "cmake-build-debug"
    "cmake-build-release"
)

for dir in "${dirs[@]}";
do
  if [ -d "${dir}" ];
  then
    rm -vrf "${dir}"
  fi

done