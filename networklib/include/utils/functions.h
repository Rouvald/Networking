#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <openssl/evp.h>
#include "utils/types.h"
#include <boost/asio.hpp>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

namespace functions
{
    namespace crypto
    {
        inline std::vector<uint8_t> sha256(const std::vector<uint8_t>& input)
        {
            std::vector<uint8_t> output(types::vars::SHA256_KEY_SIZE);
            SHA256(input.data(), input.size(), output.data());
            return output;
        }
        inline EVP_PKEY* d2iPubKeyFromVector(const std::vector<uint8_t>& data)
        {
            const uint8_t* ptr{data.data()};
            return d2i_PUBKEY(nullptr, &ptr, static_cast<long>(data.size()));
        }
        inline std::vector<uint8_t> hmacSha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data)
        {
            unsigned int len = EVP_MAX_MD_SIZE;
            std::vector<uint8_t> result(len);

            HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), result.data(), &len);

            result.resize(len);
            return result;
        }
    }  // namespace crypto

    namespace network
    {
        inline uint32_t readUint32(btcp::socket& socket)
        {
            uint32_t val{0};
            boost::asio::read(socket, boost::asio::buffer(&val, sizeof(val)));
            return ntohl(val);
        }
        inline void writeUint32(btcp::socket& socket, uint32_t value)
        {
            uint32_t netValue{static_cast<uint32_t>(htonl(value))};
            boost::asio::write(socket, boost::asio::buffer(&netValue, sizeof(netValue)));
        }
        inline void writeVector(boost::asio::ip::tcp::socket& socket, const std::vector<uint8_t>& data)
        {
            const auto payloadSize = static_cast<uint32_t>(data.size());
            uint32_t size{htonl(payloadSize)};
            boost::asio::write(socket, boost::asio::buffer(&size, sizeof(size)));
            if (!data.empty())
            {
                boost::asio::write(socket, boost::asio::buffer(data));
            }
        }
        inline std::vector<uint8_t> readVector(boost::asio::ip::tcp::socket& socket)
        {
            uint32_t size{0};
            boost::asio::read(socket, boost::asio::buffer(&size, sizeof(size)));
            size = ntohl(size);

            std::vector<uint8_t> data(size);
            if (size > 0)
            {
                boost::asio::read(socket, boost::asio::buffer(data));
            }
            return data;
        }
    }  // namespace network
};  // namespace functions

#endif  // UTILS_H
