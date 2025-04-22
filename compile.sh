#!/bin/bash

build_type="Debug"
build_dir="build"
cmake_generator="Unix Makefiles" # @todo: Ninja?

case $1 in
    -b )
    build_type="Debug"
    ;;
    -r )
    build_type="Release"
    ;;
esac

if [[ "${OSTYPE}" == "linux-gnu" ]];
then
    build_dir="build_${build_type}"
    cmake_generator="Unix Makefiles"
elif [[ "${OSTYPE}" == "msys" ]]; 
then
    build_dir="build_win_${build_type}"
    cmake_generator="MinGW Makefiles"
fi

rm -rf "${build_dir}"
mkdir "${build_dir}"

cmake -DCMAKE_BUILD_TYPE:STRING=${build_type} -DCMAKE_CXX_COMPILER=g++ -S "." -B "${build_dir}" -G "${cmake_generator}"
cmake --build "${build_dir}" --config ${build_type} --target clean -j 18 --
cmake --build "${build_dir}" --config ${build_type} --target all -j 18 --
