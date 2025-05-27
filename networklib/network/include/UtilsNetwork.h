#ifndef SHACRYPTO_H
#define SHACRYPTO_H

#include <cstdint>
#include <vector>
#include <boost/asio.hpp>
#include <chrono>
#include <iostream>

typedef boost::asio::ip::tcp btcp;

namespace Timer
{
    class Timer {
    public:
        void start() {
            _start = std::chrono::high_resolution_clock::now();
        }

        void stop() {
            _end = std::chrono::high_resolution_clock::now();
        }

        double elapsed_ms() const {
            return std::chrono::duration<double, std::milli>(_end - _start).count();
        }

        void print(const std::string& label = "Elapsed") const {
            std::cout << label << ": " << elapsed_ms() << " ms\n";
        }

    private:
        std::chrono::high_resolution_clock::time_point _start, _end;
    };
};


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
        uint32_t net_val{static_cast<uint32_t>(htonl(val))};
        boost::asio::write(socket, boost::asio::buffer(&net_val, sizeof(net_val)));
    }
    inline void write_vector(boost::asio::ip::tcp::socket& socket, const std::vector<uint8_t>& data)
    {
        uint32_t size{static_cast<uint32_t>(htonl(data.size()))};
        boost::asio::write(socket, boost::asio::buffer(&size, sizeof(size)));
        if (!data.empty())
        {
            boost::asio::write(socket, boost::asio::buffer(data));
        }
    }
    inline std::vector<uint8_t> read_vector(boost::asio::ip::tcp::socket& socket)
    {
        uint32_t size;
        boost::asio::read(socket, boost::asio::buffer(&size, sizeof(size)));
        size = ntohl(size);

        std::vector<uint8_t> data(size);
        if (size > 0)
        {
            boost::asio::read(socket, boost::asio::buffer(data));
        }
        return data;
    }
} // namespace UtilsNetwork

#endif  // SHACRYPTO_H