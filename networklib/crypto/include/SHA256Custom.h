// Author: https://github.com/kibonga/sha256-cpp

#ifndef SHA256CUSTOM_H
#define SHA256CUSTOM_H

#include <cstdint>
#include <vector>

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

#endif // SHA256CUSTOM_H