#pragma once

#include <Poco/Net/TCPServerConnection.h>
#include "IO/ReadBuffer.h"
#include "IO/WriteBuffer.h"

#include "IServer.h"

namespace Poco { class Logger; }

namespace DB
{

class TCPHandler : public Poco::Net::TCPServerConnection
{
public:
    /** parse_proxy_protocol_ - if true, expect and parse the header of PROXY protocol in every connection
      * and set the information about forwarded address accordingly.
      * See https://github.com/wolfeidau/proxyv2/blob/master/docs/proxy-protocol.txt
      *
      * Note: immediate IP address is always used for access control (accept-list of IP networks),
      *  because it allows to check the IP ranges of the trusted proxy.
      * Proxy-forwarded (original client) IP address is used for quota accounting if quota is keyed by forwarded IP.
      */
    TCPHandler(IServer & server_, const Poco::Net::StreamSocket & socket_);
    ~TCPHandler() override;

    void run() override;

private:
    IServer & server;

    Poco::Logger * log;
    /// Streams for reading/writing from/to client connection socket.
    std::shared_ptr<ReadBuffer> in;
    std::shared_ptr<WriteBuffer> out;

    void runImpl();
    bool receivePacket();

};

}
