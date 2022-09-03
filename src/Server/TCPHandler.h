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

    String client_name;
    UInt64 client_version_major = 0;
    UInt64 client_version_minor = 0;
    UInt64 client_version_patch = 0;
    UInt64 client_tcp_protocol_version = 0;

    /// Connection settings, which are extracted from a context.
    bool send_exception_with_stack_trace = true;
    Poco::Timespan send_timeout = DBMS_DEFAULT_SEND_TIMEOUT_SEC;
    Poco::Timespan receive_timeout = 10000000;
    // Poco::Timespan receive_timeout = DBMS_DEFAULT_RECEIVE_TIMEOUT_SEC;
    UInt64 poll_interval = DBMS_DEFAULT_POLL_INTERVAL;
    UInt64 idle_connection_timeout = 3600;
    UInt64 interactive_delay = 100000;
    Poco::Timespan sleep_in_send_tables_status;
    UInt64 unknown_packet_in_send_data = 0;
    Poco::Timespan sleep_in_receive_cancel;

    /// Streams for reading/writing from/to client connection socket.
    std::shared_ptr<ReadBuffer> in;
    std::shared_ptr<WriteBuffer> out;

    void runImpl();
    bool receivePacket();

};

}
