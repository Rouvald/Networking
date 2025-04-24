#!/bin/bash

build_type="Release"
build_dir="build"
cmake_generator="Ninja"
conan_profile="conanProfileRelease"

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
    cmake_generator="Ninja"
fi

rm -rf "${build_dir}"
mkdir "${build_dir}"

conan install . --profile=${conan_profile} --output-folder=""${build_dir}"" --build=missing

cmake -DCMAKE_BUILD_TYPE:STRING=${build_type} -DCMAKE_CXX_COMPILER=g++ -S "." -B "${build_dir}" -G "${cmake_generator}"
cmake --build "${build_dir}" --config ${build_type} --target clean -j 18 --
cmake --build "${build_dir}" --config ${build_type} --target all -j 18 --
