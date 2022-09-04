#pragma once

#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <memory>
#include <functional>
#include <optional>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <Poco/Process.h>
#include <Poco/ThreadPool.h>
#include <Poco/Util/Application.h>
#include <Poco/Util/ServerApplication.h>
#include <Poco/Net/SocketAddress.h>
#include <Poco/Version.h>

#include <loggers/Loggers.h>
#include <base/types.h>

class BaseDaemon : public Poco::Util::ServerApplication, Loggers
{

public:
    BaseDaemon();
    ~BaseDaemon() override;

    /// Load configuration, prepare loggers, etc.
    void initialize(Poco::Util::Application &) override;
    // void uninitialize() override;

    /// Process command line parameters
    void defineOptions(Poco::Util::OptionSet & new_options) override;

    /// Graceful shutdown
    static void terminate();

    /// Forceful shutdown
    [[noreturn]] void kill();

    /// Cancellation request has been received.
    bool isCancelled() const
    {
        return is_cancelled;
    }

    static BaseDaemon & instance()
    {
        return dynamic_cast<BaseDaemon &>(Poco::Util::Application::instance());
    }

    /// return none if daemon doesn't exist, reference to the daemon otherwise
    static std::optional<std::reference_wrapper<BaseDaemon>> tryGetInstance() { return tryGetInstance<BaseDaemon>(); }

protected:
    void waitForTerminationRequest()
#if POCO_VERSION >= 0x02000000 // in old upstream poco not vitrual
    override
#endif
    ;

    template <class Daemon>
    static std::optional<std::reference_wrapper<Daemon>> tryGetInstance();

    std::atomic_bool is_cancelled{false};

    Poco::Util::AbstractConfiguration * last_configuration = nullptr;

    std::mutex signal_handler_mutex;
    std::condition_variable signal_event;
    std::atomic_size_t terminate_signals_counter{0};
    // std::atomic_size_t sigint_signals_counter{0};
};


template <class Daemon>
std::optional<std::reference_wrapper<Daemon>> BaseDaemon::tryGetInstance()
{
    Daemon * ptr = nullptr;
    try
    {
        ptr = dynamic_cast<Daemon *>(&Poco::Util::Application::instance());
    }
    catch (const Poco::NullPointerException &)
    {
        /// if daemon doesn't exist than instance() throw NullPointerException
    }

    if (ptr)
        return std::optional<std::reference_wrapper<Daemon>>(*ptr);
    else
        return {};
}
