#ifndef SHACRYPTO_H
#define SHACRYPTO_H

#include <cstdint>
#include <vector>
#include <boost/asio.hpp>

typedef boost::asio::ip::tcp btcp;

namespace UtilsNetwork
{
    inline uint32_t read_uint32(btcp::socket& socket)
    {
        uint32_t val{0};
        boost::asio::read(socket, boost::asio::buffer(&val, sizeof(val)));
        return ntohl(val);
    }

    inline void write_uint32(btcp::socket& socket, uint32_t val)
    {
        uint32_t net_val{htonl(val)};
        boost::asio::write(socket, boost::asio::buffer(&net_val, sizeof(net_val)));
    }
}  // namespace UtilsNetwork

#endif  // SHACRYPTO_H
