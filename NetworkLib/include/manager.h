//
// Created by rouvald on 8/04/25.
//

#ifndef MANAGER_H
#define MANAGER_H

#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/json.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>

namespace basio = boost::asio;
namespace bbeast = boost::beast;
namespace bjson = boost::json;

class Manager
{
public:
    Manager() = default;
    Manager(basio::any_io_executor executor, const std::string& url);
    ~Manager() = default;

    void connect();
    void disconnect();
    std::string getKey_boost(const std::string& user);

    std::string request(const std::string& target, const std::string& objectKey,
        const std::string& hash = "");

    const bool& isConnected() const { return _isConnected; }

private:
    basio::any_io_executor _executor;
    basio::ssl::context _ssl_ctx;
    basio::ip::tcp::resolver _resolver;
    bbeast::ssl_stream<basio::ip::tcp::socket> _stream;
    bbeast::flat_buffer _buffer;
    std::string _host;
    std::string _port;
    bool _isConnected{false};
};

#endif  // MANAGER_H
