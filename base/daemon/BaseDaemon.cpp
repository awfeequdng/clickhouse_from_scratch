#include <daemon/BaseDaemon.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#if defined(__linux__)
    #include <sys/prctl.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <cxxabi.h>
#include <unistd.h>

#include <typeinfo>
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>

#include <Poco/Observer.h>
#include <Poco/AutoPtr.h>
#include <Poco/PatternFormatter.h>
#include <Poco/Message.h>
#include <Poco/Util/Application.h>
#include <Poco/Exception.h>
#include <Poco/ErrorHandler.h>
#include <Poco/Condition.h>
#include <Poco/SyslogChannel.h>
#include <Poco/DirectoryIterator.h>

#include <ucontext.h>

// // namespace fs = std::filesystem;
// namespace fs = std::experimental::filesystem;

// static std::string createDirectory(const std::string & file)
// {
//     fs::path path = fs::path(file).parent_path();
//     if (path.empty())
//         return "";
//     fs::create_directories(path);
//     return path;
// };

BaseDaemon::BaseDaemon() = default;


BaseDaemon::~BaseDaemon()
{

}

void BaseDaemon::terminate()
{
    if (::raise(SIGTERM) != 0)
        throw Poco::SystemException("cannot terminate process");
}

void BaseDaemon::kill()
{
    /// Exit with the same code as it is usually set by shell when process is terminated by SIGKILL.
    /// It's better than doing 'raise' or 'kill', because they have no effect for 'init' process (with pid = 0, usually in Docker).
    _exit(128 + SIGKILL);
}

void BaseDaemon::initialize(Application & self)
{

    ServerApplication::initialize(self);

    bool is_daemon = false;

    /// Write core dump on crash.
    {
        struct rlimit rlim;
        if (getrlimit(RLIMIT_CORE, &rlim))
            throw Poco::Exception("Cannot getrlimit");
        /// 1 GiB by default. If more - it writes to disk too long.
        rlim.rlim_cur = 1024 * 1024 * 1024;

        if (rlim.rlim_cur && setrlimit(RLIMIT_CORE, &rlim))
        {
            /// It doesn't work under address/thread sanitizer. http://lists.llvm.org/pipermail/llvm-bugs/2013-April/027880.html
            std::cerr << "Cannot set max size of core file to " + std::to_string(rlim.rlim_cur) << std::endl;
        }
    }

}

void BaseDaemon::defineOptions(Poco::Util::OptionSet & new_options)
{
    new_options.addOption(
        Poco::Util::Option("config-file", "C", "load configuration from a given file")
            .required(false)
            .repeatable(false)
            .argument("<file>")
            .binding("config-file"));

    new_options.addOption(
        Poco::Util::Option("log-file", "L", "use given log file")
            .required(false)
            .repeatable(false)
            .argument("<file>")
            .binding("logger.log"));

    new_options.addOption(
        Poco::Util::Option("errorlog-file", "E", "use given log file for errors only")
            .required(false)
            .repeatable(false)
            .argument("<file>")
            .binding("logger.errorlog"));

    new_options.addOption(
        Poco::Util::Option("pid-file", "P", "use given pidfile")
            .required(false)
            .repeatable(false)
            .argument("<file>")
            .binding("pid"));

    Poco::Util::ServerApplication::defineOptions(new_options);
}

void BaseDaemon::waitForTerminationRequest()
{
    /// NOTE: as we already process signals via pipe, we don't have to block them with sigprocmask in threads
    std::unique_lock<std::mutex> lock(signal_handler_mutex);
    signal_event.wait(lock, [this](){ return terminate_signals_counter > 0; });
}


// void BaseDaemon::uninitialize()
// {
//     ServerApplication::uninitialize();
// }