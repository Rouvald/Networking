// Author: https://github.com/kibonga/sha256-cpp

#include <SHA256Custom.h>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <sstream>
#include <string>

constexpr int32_t a = 0;
constexpr int32_t b = 1;
constexpr int32_t c = 2;
constexpr int32_t d = 3;
constexpr int32_t e = 4;
constexpr int32_t f = 5;
constexpr int32_t g = 6;
constexpr int32_t h = 7;
constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,  //
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,  //
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,  //
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,  //
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,  //
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,  //
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,  //
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,  //
};

static uint32_t right_rotate(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t little_sigma_0(uint32_t x)
{
    return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3);
}

static uint32_t little_sigma_1(uint32_t x)
{
    return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10);
}

static uint32_t big_sigma_0(uint32_t x)
{
    return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22);
}

static uint32_t big_sigma_1(uint32_t x)
{
    return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25);
}

static void message_schedule(uint32_t (&W)[64], const uint8_t (&block)[64])
{
    for (int32_t i = 0; i < 16; i++)
    {
        W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
    }

    for (int32_t i = 16; i < 64; i++)
    {
        W[i] = little_sigma_1(W[i - 2]) + W[i - 7] + little_sigma_0(W[i - 15]) + W[i - 16];
    }
}

static uint32_t choice(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

static uint32_t majority(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

static void round(uint32_t (&H)[8], uint32_t round_constant, uint32_t schedule_word)
{
    uint32_t const T1 = H[h] + big_sigma_1(H[e]) + choice(H[e], H[f], H[g]) + round_constant + schedule_word;

    uint32_t T2 = big_sigma_0(H[a]) + majority(H[a], H[b], H[c]);

    for (int32_t i = 7; i > 0; i--)
    {
        H[i] = H[i - 1];
    }

    H[a] = T1 + T2;
    H[e] += T1;
}

void compress_block(uint32_t (&H)[8], const uint8_t (&block)[64])
{
    uint32_t W[64];
    uint32_t h[8];

    message_schedule(W, block);

    for (int32_t i = 0; i < 8; i++)
    {
        h[i] = H[i];
    }
    for (int32_t i = 0; i < 64; i++)
    {
        round(h, W[i], K[i]);
    }
    for (int32_t i = 0; i < 8; i++)
    {
        H[i] += h[i];
    }
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data)
{
    uint32_t H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    const int32_t size{static_cast<int32_t>(data.size())};
    const uint64_t l = static_cast<uint64_t>(size) * 8;
    std::vector<uint8_t> message;

    int32_t N = 1;
    if ((l + 64) > 512)
    {
        N += ((l + 64) / 512);
    }

    int32_t k = 0;
    for (int32_t i = l; i < (N * 512 - 8 - 64); i += 8)
    {
        ++k;
    }
    message.reserve(size + k + 1 + 8);
    message.insert(message.end(), data.begin(), data.end());
    message.push_back(0x80);
    message.insert(message.end(), k, 0x00);

    for (int i = 7; i >= 0; --i)
    {
        message.push_back((l >> (i * 8)) & 0xFF);
    }

    for (int i = 0; i < static_cast<int>(message.size() / 64); ++i)
    {
        uint8_t block[64];
        std::memcpy(block, &message[i * 64], 64);
        compress_block(H, block);
    }

    std::vector<uint8_t> hashBytes;
    hashBytes.reserve(32);
    for (uint32_t h : H)
    {
        for (int i = 3; i >= 0; --i)
        {
            hashBytes.push_back((h >> (i * 8)) & 0xFF);
        }
    }
    return hashBytes;
}