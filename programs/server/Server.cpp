#include "Server.h"
#include "Server/ProtocolServerAdapter.h"
#include "Server/TCPHandlerFactory.h"

#include <memory>
#include <iostream>

#include <errno.h>
#include <pwd.h>
#include <string>
#include <unistd.h>
#include <Poco/Version.h>
#include <Poco/DirectoryIterator.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/NetException.h>
#include <Poco/Util/HelpFormatter.h>
#include <Poco/Environment.h>
#include <base/errnoToString.h>
#include "Common/Exception.h"
#include "Common/ThreadStatus.h"


#if defined(OS_LINUX)
#    include <sys/mman.h>
#    include <Common/hasLinuxCapability.h>
#    include <unistd.h>
#endif

namespace DB {

namespace ErrorCodes
{
    extern const int POCO_EXCEPTION;
    extern const int STD_EXCEPTION;
    extern const int UNKNOWN_EXCEPTION;
    extern const int LOGICAL_ERROR;
    extern const int CANNOT_ALLOCATE_MEMORY;
    extern const int CANNOT_MREMAP;
    extern const int NETWORK_ERROR;
}

Poco::Net::SocketAddress makeSocketAddress(const std::string & host, UInt16 port)
{
    Poco::Net::SocketAddress socket_address;
    try
    {
        socket_address = Poco::Net::SocketAddress(host, port);
    }
    catch (const Poco::Net::DNSException & e)
    {
        const auto code = e.code();
        if (code == EAI_FAMILY
#if defined(EAI_ADDRFAMILY)
                    || code == EAI_ADDRFAMILY
#endif
           )
        {
            // LOG_ERROR(log, "Cannot resolve listen_host ({}), error {}: {}. "
            //     "If it is an IPv6 address and your host has disabled IPv6, then consider to "
            //     "specify IPv4 address to listen in <listen_host> element of configuration "
            //     "file. Example: <listen_host>0.0.0.0</listen_host>",
            //     host, e.code(), e.message());
        }

        throw;
    }
    return socket_address;
}

Poco::Net::SocketAddress Server::socketBindListen(Poco::Net::ServerSocket & socket, const std::string & host, UInt16 port, [[maybe_unused]] bool secure) const
{
    auto address = makeSocketAddress(host, port);
#if !defined(POCO_CLICKHOUSE_PATCH) || POCO_VERSION < 0x01090100
    if (secure)
        /// Bug in old (<1.9.1) poco, listen() after bind() with reusePort param will fail because have no implementation in SecureServerSocketImpl
        /// https://github.com/pocoproject/poco/pull/2257
        socket.bind(address, /* reuseAddress = */ true);
    else
#endif
#if POCO_VERSION < 0x01080000
    socket.bind(address, /* reuseAddress = */ true);
#else
    socket.bind(address, /* reuseAddress = */ true, /* reusePort = */false);
#endif

    /// If caller requests any available port from the OS, discover it after binding.
    if (port == 0)
    {
        address = socket.address();
        // LOG_DEBUG(&logger(), "Requested any available port (port == 0), actual port is {:d}", address.port());
    }

    socket.listen(/* backlog = */ 4096);

    return address;
}

std::map<std::string, int> port_name_map = {
    {"http_port", 19000},
    {"tcp_port", 19003},
    {"mysql_port", 19004},
};

void Server::createServer(const std::string & listen_host, std::string port_name, bool listen_try, CreateServerFunc && func) const
{
    auto port = port_name_map[port_name];
    try
    {
        func(port);
    }
    catch (const Poco::Exception &)
    {
        std::string message = "Listen [" + listen_host + "]:" + std::to_string(port) + " failed " ;

        if (listen_try)
        {
            std::cout << "{}. If it is an IPv6 or IPv4 address and your host has disabled IPv6 or IPv4, then consider to "
                "specify not disabled IPv4 or IPv6 address to listen in <listen_host> element of configuration "
                "file. Example for disabled IPv6: <listen_host>0.0.0.0</listen_host> ."
                " Example for disabled IPv4: <listen_host>::</listen_host>" <<
                message;
        }
        else
        {
            throw Exception{message, ErrorCodes::NETWORK_ERROR};
        }
    }
}

void Server::uninitialize()
{
    std::cout << "shutting down" << std::endl;
    BaseDaemon::uninitialize();
}

int Server::run()
{
    return Application::run(); // NOLINT
}

void Server::initialize(Poco::Util::Application & self)
{
    BaseDaemon::initialize(self);
    std::cout << "starting up" << std::endl;

    // LOG_INFO(&logger(), "OS name: {}, version: {}, architecture: {}",
        // Poco::Environment::osName(),
        // Poco::Environment::osVersion(),
        // Poco::Environment::osArchitecture());
    std::cout << Poco::Environment::osName() << " " << Poco::Environment::osVersion() << " " << Poco::Environment::osArchitecture() << std::endl;
}

void Server::defineOptions(Poco::Util::OptionSet & options)
{
    options.addOption(
        Poco::Util::Option("help", "h", "show help and exit")
            .required(false)
            .repeatable(false)
            .binding("help"));
    options.addOption(
        Poco::Util::Option("version", "V", "show version and exit")
            .required(false)
            .repeatable(false)
            .binding("version"));
    BaseDaemon::defineOptions(options);
}

int Server::main(const std::vector<std::string> & /*args*/)
{
    Poco::Logger * log = &logger();
    MainThreadStatus::getInstance();

    Poco::Timespan keep_alive_timeout(10, 0);

    Poco::ThreadPool server_pool(3, /*max_connections*/ 1024);

    // auto servers_to_start_before_tables = std::make_shared<std::vector<ProtocolServerAdapter>>();

    std::vector<std::string> listen_hosts = {"127.0.0.1"};

    bool listen_try = false;
    if (listen_hosts.empty())
    {
        listen_hosts.emplace_back("::1");
        listen_hosts.emplace_back("127.0.0.1");
        listen_try = true;
    }


#if defined(OS_LINUX)
    if (!hasLinuxCapability(CAP_SYS_NICE))
    {
        std::cout << "It looks like the process has no CAP_SYS_NICE capability, the setting 'os_thread_priority' will have no effect."
            " It could happen due to incorrect ClickHouse package installation."
            " You could resolve the problem manually with 'sudo setcap cap_sys_nice=+ep {}'."
            " Note that it will not work on 'nosuid' mounted filesystems." << std::endl;
    }
#endif

    auto servers = std::make_shared<std::vector<ProtocolServerAdapter>>();
    {
        for (const auto & listen_host : listen_hosts)
        {
            /// HTTP
            std::string port_name = "http_port";
            // createServer(listen_host, port_name, listen_try, [&](UInt16 port)
            // {
            //     Poco::Net::ServerSocket socket;
            //     auto address = socketBindListen(socket, listen_host, port);
            //     socket.setReceiveTimeout(/*http_receive_timeout*/ 10);
            //     socket.setSendTimeout(/*http_send_timeout*/ 10);

            //     servers->emplace_back(
            //         port_name,
            //         std::make_unique<HTTPServer>(
            //             context(), createHandlerFactory(*this, async_metrics, "HTTPHandler-factory"), server_pool, socket, http_params));

            //     std::cout << "Listening for http://" << address.toString() std::endl;;
            // });

            /// TCP
            port_name = "tcp_port";
            createServer(listen_host, port_name, listen_try, [&](UInt16 port)
            {
                Poco::Net::ServerSocket socket;
                auto address = socketBindListen(socket, listen_host, port);
                socket.setReceiveTimeout(/*receive_timeout*/ 10000000);
                socket.setSendTimeout(/*send_timeout*/ 10000000);
                servers->emplace_back(port_name, std::make_unique<Poco::Net::TCPServer>(
                    new TCPHandlerFactory(*this),
                    server_pool,
                    socket,
                    new Poco::Net::TCPServerParams));

                std::cout << "Listening for connections with native protocol (tcp): " << address.toString() << std::endl;
            });

        }

        if (servers->empty()) {
            std::cout << "No servers started (add valid listen_host and 'tcp_port' or 'http_port' to configuration file.)" << std::endl;
            exit(-1);
        }

        for (auto & server : *servers)
            server.start();

        std::cout << "Ready for connections." << std::endl;

        waitForTerminationRequest();

        is_cancelled = true;

        int current_connections = 0;
        for (auto & server : *servers)
        {
            server.stop();
            current_connections += server.currentConnections();
        }

        if (current_connections)
            std::cout << "Closed all listening sockets. Waiting for {} outstanding connections." << current_connections << std::endl;
        else
            std::cout << "Closed all listening sockets." << std::endl;
    }

    return Application::EXIT_OK;
}

} // namespace DB

int mainEntryClickHouseServer(int argc, char ** argv)
{
    DB::Server app;

    try
    {
        return app.run(argc, argv);
    }
    catch (...)
    {
        std::cerr << "app run error" << "\n";
    }
    return 0;
}
