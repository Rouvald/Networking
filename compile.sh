#!/bin/bash

build_type="Release"
build_dir="build"
cmake_generator="Ninja"
conan_profile_dir="conanProfiles"
conan_profile="conanProfileRelease"

case $1 in
    -d )
    build_type="Debug"
    ;;
    -r )
    build_type="Release"
    ;;
esac

os_name="$(uname -s)"

if [[ "$os_name" == "Linux" ]]; 
then
    build_dir="build_linux_${build_type}"
    cmake_generator="Ninja"
    conan_profile="conanProfile${build_type}_Linux"
elif [[ "$os_name" == "MINGW64_NT"* || "$os_name" == "MSYS_NT"* ]]; 
then
    build_dir="build_win_${build_type}"
    cmake_generator="Ninja"
    conan_profile="conanProfile${build_type}_Win"
fi

rm -rf "${build_dir}"
mkdir "${build_dir}"

conan install . --profile="${conan_profile_dir}/${conan_profile}" --profile:b="${conan_profile_dir}/${conan_profile}" --output-folder="${build_dir}" --build=missing

cmake -DCMAKE_BUILD_TYPE:STRING=${build_type} -DCMAKE_CXX_COMPILER=g++ -S "." -B "${build_dir}" -G "${cmake_generator}"
cmake --build "${build_dir}" --config ${build_type} --target clean -j 18 --
cmake --build "${build_dir}" --config ${build_type} --target all -j 18 --
