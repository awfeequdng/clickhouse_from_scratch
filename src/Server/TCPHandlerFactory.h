#pragma once

#include <Poco/Net/TCPServerConnectionFactory.h>
#include <Poco/Net/NetException.h>
#include <base/logger_useful.h>
#include <Server/IServer.h>
#include <Server/TCPHandler.h>
#include <Common/CurrentThread.h>

namespace Poco { class Logger; }

namespace DB
{

class TCPHandlerFactory : public Poco::Net::TCPServerConnectionFactory
{
private:
    IServer & server;
    Poco::Logger * log;
    std::string server_display_name;

    class DummyTCPHandler : public Poco::Net::TCPServerConnection
    {
    public:
        using Poco::Net::TCPServerConnection::TCPServerConnection;
        void run() override {}
    };

public:
    /** parse_proxy_protocol_ - if true, expect and parse the header of PROXY protocol in every connection
      * and set the information about forwarded address accordingly.
      * See https://github.com/wolfeidau/proxyv2/blob/master/docs/proxy-protocol.txt
      */
    TCPHandlerFactory(IServer & server_, bool secure_)
        : server(server_)
        , log(&Poco::Logger::get(std::string("TCP") + (secure_ ? "S" : "") + "HandlerFactory"))
    {
        server_display_name = "my clickhouse server";
    }

    Poco::Net::TCPServerConnection * createConnection(const Poco::Net::StreamSocket & socket) override
    {
        try
        {
            LOG_TRACE(log, "TCP Request. Address: {}", socket.peerAddress().toString());

            return new TCPHandler(server, socket, server_display_name);
        }
        catch (const Poco::Net::NetException &)
        {
            LOG_TRACE(log, "TCP Request. Client is not connected (most likely RST packet was sent).");
            return new DummyTCPHandler(socket);
        }
    }
};

}
