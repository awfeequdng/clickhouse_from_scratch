#include <Poco/Net/NetException.h>

#include <IO/ReadBufferFromPocoSocket.h>
#include <Common/Exception.h>
#include <Common/NetException.h>

namespace DB
{
namespace ErrorCodes
{
    extern const int NETWORK_ERROR;
    extern const int SOCKET_TIMEOUT;
    extern const int CANNOT_READ_FROM_SOCKET;
}


bool ReadBufferFromPocoSocket::nextImpl()
{
    ssize_t bytes_read = 0;
    std::cout << "ReadBufferFromPocoSocket::nextImpl" << std::endl;
    /// Add more details to exceptions.
    try
    {
    std::cout << "ReadBufferFromPocoSocket::nextImpl2" << std::endl;
        /// If async_callback is specified, and read will block, run async_callback and try again later.
        /// It is expected that file descriptor may be polled externally.
        /// Note that receive timeout is not checked here. External code should check it while polling.
        while (async_callback && !socket.poll(0, Poco::Net::Socket::SELECT_READ))
            async_callback(socket.impl()->sockfd(), socket.getReceiveTimeout(), socket_description);
    std::cout << "ReadBufferFromPocoSocket::nextImpl3" << std::endl;
        bytes_read = socket.impl()->receiveBytes(internal_buffer.begin(), internal_buffer.size());
        static int cnt = 0;
        cnt ++;
        if (cnt >3) {
            exit(0);
        }
        std::cout << "receive: " << std::string(internal_buffer.begin());
    std::cout << "ReadBufferFromPocoSocket::nextImpl4" << std::endl;
    }
    catch (const Poco::Net::NetException & e)
    {
    std::cout << "ReadBufferFromPocoSocket::nextImpl5" << std::endl;
        throw NetException(e.displayText() + ", while reading from socket (" + peer_address.toString() + ")", ErrorCodes::NETWORK_ERROR);
    }
    catch (const Poco::TimeoutException &)
    {
        std::cout << fmt::format("Timeout exceeded while reading from socket ({}, {} ms)\n",
            peer_address.toString(),
            socket.impl()->getReceiveTimeout().totalMilliseconds(), ErrorCodes::SOCKET_TIMEOUT);
        throw NetException(fmt::format("Timeout exceeded while reading from socket ({}, {} ms)",
            peer_address.toString(),
            socket.impl()->getReceiveTimeout().totalMilliseconds()), ErrorCodes::SOCKET_TIMEOUT);
    }
    catch (const Poco::IOException & e)
    {
        std::cout << "ReadBufferFromPocoSocket::nextImpl7" << std::endl;
        throw NetException(e.displayText() + ", while reading from socket (" + peer_address.toString() + ")", ErrorCodes::NETWORK_ERROR);
    }

    std::cout << "ReadBufferFromPocoSocket::nextImpl8" << std::endl;
    if (bytes_read < 0)
        throw NetException("Cannot read from socket (" + peer_address.toString() + ")", ErrorCodes::CANNOT_READ_FROM_SOCKET);

    std::cout << "ReadBufferFromPocoSocket::nextImpl9" << std::endl;
    /// NOTE: it is quite inaccurate on high loads since the thread could be replaced by another one

    if (bytes_read)
        working_buffer.resize(bytes_read);
    else
        return false;
    std::cout << "ReadBufferFromPocoSocket::nextImpl10" << std::endl;

    return true;
}

ReadBufferFromPocoSocket::ReadBufferFromPocoSocket(Poco::Net::Socket & socket_, size_t buf_size)
    : BufferWithOwnMemory<ReadBuffer>(buf_size)
    , socket(socket_)
    , peer_address(socket.peerAddress())
    , socket_description("socket (" + peer_address.toString() + ")")
{
}

bool ReadBufferFromPocoSocket::poll(size_t timeout_microseconds) const
{
    std::cout << "ReadBufferFromPocoSocket::poll\n";
    if (available())
        return true;
    std::cout << "ReadBufferFromPocoSocket::poll2\n";

    bool res = socket.poll(timeout_microseconds, Poco::Net::Socket::SELECT_READ | Poco::Net::Socket::SELECT_ERROR);
    std::cout << "ReadBufferFromPocoSocket::poll3\n";
    return res;
}

}
