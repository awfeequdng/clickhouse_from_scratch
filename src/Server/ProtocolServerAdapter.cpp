#include <Server/ProtocolServerAdapter.h>
#include <Poco/Net/TCPServer.h>

namespace DB
{
class ProtocolServerAdapter::TCPServerAdapterImpl : public Impl
{
public:
    explicit TCPServerAdapterImpl(std::unique_ptr<Poco::Net::TCPServer> tcp_server_) : tcp_server(std::move(tcp_server_)) {}
    ~TCPServerAdapterImpl() override = default;

    void start() override { tcp_server->start(); }
    void stop() override { tcp_server->stop(); }
    size_t currentConnections() const override { return tcp_server->currentConnections(); }
    size_t currentThreads() const override { return tcp_server->currentThreads(); }

private:
    std::unique_ptr<Poco::Net::TCPServer> tcp_server;
};

ProtocolServerAdapter::ProtocolServerAdapter(std::string port_name_, std::unique_ptr<Poco::Net::TCPServer> tcp_server_)
    : port_name(port_name_), impl(std::make_unique<TCPServerAdapterImpl>(std::move(tcp_server_)))
{
}

}