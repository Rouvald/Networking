#! /bin/bash

# вызов конфигурационного скрипта для дополнительных переменных
# "./config.sh" @todo:
src_root=$PWD

# ========== НАЧАЛО ==========
declare -a paths=(
    "networkLib"
    "client"
    "server"
)

for path in "${paths[@]}";
do
    for file in $(find "${src_root}/${path}" -type f \( -name "*.cpp" -o -name "*.c" -o -name "*.h" -o -name "*.hpp" \));
    do
        echo "${file}"
        clang-format -i -style=file "${file}"
    done
done

# @todo
main_file="${src_root}/main.cpp"
echo "${main_file}"
clang-format -i -style=file "${main_file}"