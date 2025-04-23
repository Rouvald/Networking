//
// Created by rouvald on 8/04/25.
//

#include "manager.h"

#include <iostream>

#include <boost/url.hpp>

Manager::Manager(basio::any_io_executor executor, const std::string& url)
    : _executor(executor), _ssl_ctx(basio::ssl::context::tls_client),
      _resolver(executor), _stream(executor, _ssl_ctx)
{
    boost::urls::url_view urlV(url);

    _host = urlV.host();
    _port = urlV.port();

    _ssl_ctx.set_verify_mode(basio::ssl::verify_none);
}

void Manager::connect()
{
    if (_isConnected)
    {
        return;
    }
    try
    {
        auto results = _resolver.resolve(_host, _port);

        _stream =
            bbeast::ssl_stream<basio::ip::tcp::socket>(_executor, _ssl_ctx);

        basio::connect(_stream.next_layer(), results);
        _stream.handshake(basio::ssl::stream_base::client);

        _isConnected = true;
    }
    catch (const std::exception& e)
    {
        std::cerr << "(" << __FUNCTION__ << "):" << __LINE__
                  << ": Exception: " << e.what() << std::endl;
    }
}

void Manager::disconnect()
{
    if (!_isConnected)
    {
        return;
    }
    try
    {
        _stream.shutdown();
        _isConnected = false;
    }
    catch (const std::exception& e)
    {
        std::cerr << "(" << __FUNCTION__ << "):" << __LINE__
                  << ": Exception: " << e.what() << std::endl;
    }
}

std::string Manager::request(const std::string& target,
    const std::string& objectKey, const std::string& hash)
{
    try
    {
        bbeast::http::request<bbeast::http::empty_body> req{
            bbeast::http::verb::get, target, 11};
        req.set(bbeast::http::field::host, this->_host);
        req.set(bbeast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.set(bbeast::http::field::connection, "keep-alive");

        if (!hash.empty())
        {
            req.set(bbeast::http::field::authorization, hash);
        }

        // @todo: idk for what
        // req.prepare_payload();
        // this->_buffer.consume(this->_buffer.size());

        bbeast::http::write(this->_stream, req);

        bbeast::http::response<bbeast::http::string_body> res;
        bbeast::http::read(this->_stream, this->_buffer, res);

        bjson::value json{bjson::parse(res.body())};
        std::string value{""};
        if (json.as_object().contains(objectKey))
        {
            value = json.as_object()[objectKey].as_string().c_str();
        }
        return value;
    }
    catch (const std::exception& e)
    {
        std::cerr << "(" << __FUNCTION__ << "):" << __LINE__
                  << ": Exception: " << e.what() << std::endl;
        return "";
    }
}
