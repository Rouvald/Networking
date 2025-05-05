// Author: https://github.com/kibonga/sha256-cpp

#ifndef SHA256CUSTOM_H
#define SHA256CUSTOM_H

#include <cstdint>
#include <iomanip>
#include <string>
#include <vector>

std::string sha256(std::string m);
std::vector<uint8_t> hexStringToBytes(const std::string& hex);

#endif // SHA256CUSTOM_H