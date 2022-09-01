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

#include "TCPHandler.h"


using namespace std::literals;

namespace DB
{

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
    socket().setReceiveTimeout(/*receive_timeout*/ 10);
    socket().setSendTimeout(/*send_timeout*/ 10);
    socket().setNoDelay(true);

    while (true)
    {
        /// If we need to shut down, or client disconnects.
        if (server.isCancelled())
            break;


        try
        {
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
    return true;
}

void TCPHandler::run()
{
    try
    {
        runImpl();
        std::cout << "Done processing connection." << std::endl;
    }
    catch (Poco::Exception & e)
    {
        /// Timeout - not an error.
        if (e.what() == "Timeout"sv)
        {
            std::cout << "Poco::Exception. Code: {}, e.code() = {}, e.displayText() = {}, e.what() = {}" << std::endl;
        }
        else
            throw;
    }
}

}
