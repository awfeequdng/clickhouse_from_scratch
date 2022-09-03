#include <algorithm>
#include <iomanip>
#include <iterator>
#include <memory>
#include <mutex>
#include <vector>
#include <string_view>
#include <string.h>
#include <Poco/Net/NetException.h>
#include <Poco/Util/LayeredConfiguration.h>
#include <Poco/Timestamp.h>
#include <Poco/DateTimeFormatter.h>
#include <iostream>
#include <base/logger_useful.h>
#include <IO/ReadHelpers.h>
#include <IO/ReadBufferFromPocoSocket.h>
// #include <IO/WriteBufferFromPocoSocket.h>
#include <Common/CurrentThread.h>

#include "TCPHandler.h"


using namespace std::literals;

namespace DB
{
namespace ErrorCodes
{
    extern const int LOGICAL_ERROR;
    extern const int ATTEMPT_TO_READ_AFTER_EOF;
    extern const int CLIENT_HAS_CONNECTED_TO_WRONG_PORT;
    extern const int UNKNOWN_EXCEPTION;
    extern const int UNKNOWN_PACKET_FROM_CLIENT;
    extern const int POCO_EXCEPTION;
    extern const int SOCKET_TIMEOUT;
    extern const int UNEXPECTED_PACKET_FROM_CLIENT;
    extern const int SUPPORT_IS_DISABLED;
    extern const int UNKNOWN_PROTOCOL;
}

TCPHandler::TCPHandler(IServer & server_, const Poco::Net::StreamSocket & socket_)
    : Poco::Net::TCPServerConnection(socket_)
    , server(server_)
{
}

TCPHandler::~TCPHandler()
{

}

void TCPHandler::runImpl()
{
    std::cout << "runImpl" << std::endl;
    // std::cout << "runImpl, receive_timeout: " << receive_timeout << std::endl;

    socket().setReceiveTimeout(receive_timeout);
    socket().setSendTimeout(send_timeout);
    socket().setNoDelay(true);

    std::cout << "runImpl 1" << std::endl;

    in = std::make_shared<ReadBufferFromPocoSocket>(socket());
    // out = std::make_shared<WriteBufferFromPocoSocket>(socket());
    std::cout << "runImpl 2" << std::endl;

    if (in->eof())
    {
        std::cout << "runImpl 3" << std::endl;
        LOG_INFO(log, "Client has not sent any data.");
        return;
    }
    std::cout << "runImpl 4" << std::endl;

    while (true)
    {
    std::cout << "runImpl 5" << std::endl;
        /// If we need to shut down, or client disconnects.
        if (server.isCancelled())
            break;


        try
        {
    std::cout << "runImpl 6" << std::endl;
            if (!receivePacket())
                continue;
            std::cout << "receivePacket success." << std::endl;
        }
        catch (const Poco::Net::NetException & e)
        {
        }
        catch (const Poco::Exception & e)
        {
        }

        catch (const std::exception & e)
        {
        }
        catch (...)
        {
        }
    }
}


bool TCPHandler::receivePacket()
{
    String str;
    std::cout << "receive1: " << str << std::endl;
    readString(str, *in);
    std::cout << "receive2: " << str << std::endl;
    static int cnt = 0;
    cnt ++;
    if (cnt > 3) {
        exit(0);
    }
    // UInt64 packet_type = 0;
    // readVarUInt(packet_type, *in);

    // switch (packet_type)
    // {
    //     case Protocol::Client::IgnoredPartUUIDs:
    //         /// Part uuids packet if any comes before query.
    //         if (!state.empty() || state.part_uuids_to_ignore)
    //             receiveUnexpectedIgnoredPartUUIDs();
    //         receiveIgnoredPartUUIDs();
    //         return true;

    //     case Protocol::Client::Query:
    //         if (!state.empty())
    //             receiveUnexpectedQuery();
    //         receiveQuery();
    //         return true;

    //     case Protocol::Client::Data:
    //     case Protocol::Client::Scalar:
    //         if (state.skipping_data)
    //             return receiveUnexpectedData(false);
    //         if (state.empty())
    //             receiveUnexpectedData(true);
    //         return receiveData(packet_type == Protocol::Client::Scalar);

    //     case Protocol::Client::Ping:
    //         writeVarUInt(Protocol::Server::Pong, *out);
    //         out->next();
    //         return false;

    //     case Protocol::Client::Cancel:
    //     {
    //         /// For testing connection collector.
    //         if (sleep_in_receive_cancel.totalMilliseconds())
    //         {
    //             std::chrono::milliseconds ms(sleep_in_receive_cancel.totalMilliseconds());
    //             std::this_thread::sleep_for(ms);
    //         }

    //         return false;
    //     }

    //     case Protocol::Client::Hello:
    //         receiveUnexpectedHello();

    //     case Protocol::Client::TablesStatusRequest:
    //         if (!state.empty())
    //             receiveUnexpectedTablesStatusRequest();
    //         processTablesStatusRequest();
    //         out->next();
    //         return false;

    //     default:
    //         throw Exception("Unknown packet " + toString(packet_type) + " from client", ErrorCodes::UNKNOWN_PACKET_FROM_CLIENT);
    // }
    return true;
}


void TCPHandler::run()
{
    try
    {
        runImpl();

        std::cout << "Done processing connection." << std::endl;;
        LOG_DEBUG(log, "Done processing connection.");
    }
    catch (Poco::Exception & e)
    {
        /// Timeout - not an error.
        if (e.what() == "Timeout"sv)
        {
            std::cout << fmt::format("Poco::Exception. Code: {}, e.code() = {}, e.displayText() = {}, e.what() = {}", ErrorCodes::POCO_EXCEPTION, e.code(), e.displayText(), e.what());
            LOG_DEBUG(log, "Poco::Exception. Code: {}, e.code() = {}, e.displayText() = {}, e.what() = {}", ErrorCodes::POCO_EXCEPTION, e.code(), e.displayText(), e.what());
        }
        else
            throw;
    }
}
// void TCPHandler::run()
// {
//     try
//     {
//         runImpl();
//         std::cout << "Done processing connection." << std::endl;
//     }
//     catch (Poco::Exception & e)
//     {
//         /// Timeout - not an error.
//         if (e.what() == "Timeout"sv)
//         {
//             std::cout << "Poco::Exception. Code: {}, e.code() = {}, e.displayText() = {}, e.what() = {}" << std::endl;
//         }
//         else
//             throw;
//     }
// }

}
