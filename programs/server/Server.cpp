#include "Server.h"

#include <memory>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <Poco/Version.h>
#include <Poco/DirectoryIterator.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/NetException.h>
#include <Poco/Util/HelpFormatter.h>
#include <Poco/Environment.h>
#include <Poco/String.h>
#include <base/scope_guard_safe.h>
#include <base/defines.h>
#include <base/logger_useful.h>
#include <base/phdr_cache.h>
#include <base/ErrorHandlers.h>
#include <base/getMemoryAmount.h>
#include <base/errnoToString.h>
#include <base/coverage.h>
#include <Common/MemoryTracker.h>
#include <Common/ClickHouseRevision.h>
#include <Common/DNSResolver.h>
#include <Common/CurrentMetrics.h>
#include <Common/Macros.h>
#include <Common/ShellCommand.h>
#include <Common/StringUtils/StringUtils.h>
#include <base/getFQDNOrHostName.h>
#include <Common/getMultipleKeysFromConfig.h>
#include <Common/getNumberOfPhysicalCPUCores.h>
#include <Common/getExecutablePath.h>
#include <Common/ProfileEvents.h>
#include <Common/ThreadProfileEvents.h>
#include <Common/ThreadStatus.h>
#include <Common/getMappedArea.h>
#include <Common/remapExecutable.h>
#include <Common/TLDListsHolder.h>
#include <Core/ServerUUID.h>
#include <IO/ReadHelpers.h>
#include <IO/UseSSL.h>
// #include <Formats/registerFormats.h>
#include <Disks/registerDisks.h>
#include <Common/StatusFile.h>
#include <Server/TCPHandlerFactory.h>
#include <Server/TCPServer.h>
#include <Common/SensitiveDataMasker.h>
#include <Common/ThreadFuzzer.h>
#include <Common/getHashOfLoadedBinary.h>
#include <Common/Elf.h>
#include <Server/ProtocolServerAdapter.h>
#include <Compression/CompressionCodecEncrypted.h>
#include <filesystem>
#include <Interpreters/DNSCacheUpdater.h>
#include "config_core.h"
#include "Common/config_version.h"

#if defined(OS_LINUX)
#    include <sys/mman.h>
#    include <sys/ptrace.h>
#    include <Common/hasLinuxCapability.h>
#    include <unistd.h>
#    include <sys/syscall.h>
#endif

#if USE_SSL
#    include <Compression/CompressionCodecEncrypted.h>
#    include <Poco/Net/Context.h>
#    include <Poco/Net/SecureServerSocket.h>
#endif

#if USE_GRPC
#   include <Server/GRPCServer.h>
#endif

#if USE_NURAFT
#    include <Coordination/FourLetterCommand.h>
#    include <Server/KeeperTCPHandlerFactory.h>
#endif

#if USE_JEMALLOC
#    include <jemalloc/jemalloc.h>
#endif

namespace CurrentMetrics
{
    extern const Metric Revision;
    extern const Metric VersionInteger;
    extern const Metric MemoryTracking;
    extern const Metric MaxDDLEntryID;
    extern const Metric MaxPushedDDLEntryID;
}

namespace ProfileEvents
{
    extern const Event MainConfigLoads;
}

namespace fs = std::filesystem;

#if USE_JEMALLOC
static bool jemallocOptionEnabled(const char *name)
{
    bool value;
    size_t size = sizeof(value);

    if (mallctl(name, reinterpret_cast<void *>(&value), &size, /* newp= */ nullptr, /* newlen= */ 0))
        throw Poco::SystemException("mallctl() failed");

    return value;
}
#else
static bool jemallocOptionEnabled(const char *) { return 0; }
#endif

int mainEntryClickHouseServer(int argc, char ** argv)
{
    DB::Server app;

    if (jemallocOptionEnabled("opt.background_thread"))
    {
        LOG_ERROR(&app.logger(),
            "jemalloc.background_thread was requested, "
            "however ClickHouse uses percpu_arena and background_thread most likely will not give any benefits, "
            "and also background_thread is not compatible with ClickHouse watchdog "
            "(that can be disabled with CLICKHOUSE_WATCHDOG_ENABLE=0)");
    }

    /// Do not fork separate process from watchdog if we attached to terminal.
    /// Otherwise it breaks gdb usage.
    /// Can be overridden by environment variable (cannot use server config at this moment).
    if (argc > 0)
    {
        const char * env_watchdog = getenv("CLICKHOUSE_WATCHDOG_ENABLE");
        if (env_watchdog)
        {
            if (0 == strcmp(env_watchdog, "1"))
                app.shouldSetupWatchdog(argv[0]);

            /// Other values disable watchdog explicitly.
        }
        else if (!isatty(STDIN_FILENO) && !isatty(STDOUT_FILENO) && !isatty(STDERR_FILENO))
            app.shouldSetupWatchdog(argv[0]);
    }

    try
    {
        return app.run(argc, argv);
    }
    catch (...)
    {
        std::cerr << DB::getCurrentExceptionMessage(true) << "\n";
        auto code = DB::getCurrentExceptionCode();
        return code ? code : 1;
    }
}


namespace
{

void setupTmpPath(Poco::Logger * log, const std::string & path)
try
{
    LOG_DEBUG(log, "Setting up {} to store temporary data in it", path);

    fs::create_directories(path);

    /// Clearing old temporary files.
    fs::directory_iterator dir_end;
    for (fs::directory_iterator it(path); it != dir_end; ++it)
    {
        if (it->is_regular_file() && startsWith(it->path().filename(), "tmp"))
        {
            LOG_DEBUG(log, "Removing old temporary file {}", it->path().string());
            fs::remove(it->path());
        }
        else
            LOG_DEBUG(log, "Skipped file in temporary path {}", it->path().string());
    }
}
catch (...)
{
    DB::tryLogCurrentException(
        log,
        fmt::format(
            "Caught exception while setup temporary path: {}. It is ok to skip this exception as cleaning old temporary files is not "
            "necessary",
            path));
}

int waitServersToFinish(std::vector<DB::ProtocolServerAdapter> & servers, size_t seconds_to_wait)
{
    const int sleep_max_ms = 1000 * seconds_to_wait;
    const int sleep_one_ms = 100;
    int sleep_current_ms = 0;
    int current_connections = 0;
    for (;;)
    {
        current_connections = 0;

        for (auto & server : servers)
        {
            server.stop();
            current_connections += server.currentConnections();
        }

        if (!current_connections)
            break;

        sleep_current_ms += sleep_one_ms;
        if (sleep_current_ms < sleep_max_ms)
            std::this_thread::sleep_for(std::chrono::milliseconds(sleep_one_ms));
        else
            break;
    }
    return current_connections;
}

}

namespace DB
{

namespace ErrorCodes
{
    extern const int NO_ELEMENTS_IN_CONFIG;
    extern const int SUPPORT_IS_DISABLED;
    extern const int ARGUMENT_OUT_OF_BOUND;
    extern const int EXCESSIVE_ELEMENT_IN_CONFIG;
    extern const int INVALID_CONFIG_PARAMETER;
    extern const int SYSTEM_ERROR;
    extern const int FAILED_TO_GETPWUID;
    extern const int MISMATCHING_USERS_FOR_PROCESS_AND_DATA;
    extern const int NETWORK_ERROR;
    extern const int CORRUPTED_DATA;
}


static std::string getCanonicalPath(std::string && path)
{
    Poco::trimInPlace(path);
    if (path.empty())
        throw Exception("path configuration parameter is empty", ErrorCodes::INVALID_CONFIG_PARAMETER);
    if (path.back() != '/')
        path += '/';
    return std::move(path);
}

static std::string getUserName(uid_t user_id)
{
    /// Try to convert user id into user name.
    auto buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buffer_size <= 0)
        buffer_size = 1024;
    std::string buffer;
    buffer.reserve(buffer_size);

    struct passwd passwd_entry;
    struct passwd * result = nullptr;
    const auto error = getpwuid_r(user_id, &passwd_entry, buffer.data(), buffer_size, &result);

    if (error)
        throwFromErrno("Failed to find user name for " + toString(user_id), ErrorCodes::FAILED_TO_GETPWUID, error);
    else if (result)
        return result->pw_name;
    return toString(user_id);
}

Poco::Net::SocketAddress makeSocketAddress(const std::string & host, UInt16 port, Poco::Logger * log)
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
            LOG_ERROR(log, "Cannot resolve listen_host ({}), error {}: {}. "
                "If it is an IPv6 address and your host has disabled IPv6, then consider to "
                "specify IPv4 address to listen in <listen_host> element of configuration "
                "file. Example: <listen_host>0.0.0.0</listen_host>",
                host, e.code(), e.message());
        }

        throw;
    }
    return socket_address;
}

Poco::Net::SocketAddress Server::socketBindListen(Poco::Net::ServerSocket & socket, const std::string & host, UInt16 port, [[maybe_unused]] bool secure) const
{
    auto address = makeSocketAddress(host, port, &logger());
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
    socket.bind(address, /* reuseAddress = */ true, /* reusePort = */ config().getBool("listen_reuse_port", false));
#endif

    /// If caller requests any available port from the OS, discover it after binding.
    if (port == 0)
    {
        address = socket.address();
        LOG_DEBUG(&logger(), "Requested any available port (port == 0), actual port is {:d}", address.port());
    }

    socket.listen(/* backlog = */ config().getUInt("listen_backlog", 4096));

    return address;
}

std::vector<std::string> getListenHosts(const Poco::Util::AbstractConfiguration & config)
{
    auto listen_hosts = DB::getMultipleValuesFromConfig(config, "", "listen_host");
    if (listen_hosts.empty())
    {
        // listen_hosts.emplace_back("::1");
        listen_hosts.emplace_back("127.0.0.1");
    }
    return listen_hosts;
}

bool getListenTry(const Poco::Util::AbstractConfiguration & config)
{
    bool listen_try = config.getBool("listen_try", false);
    if (!listen_try)
        listen_try = DB::getMultipleValuesFromConfig(config, "", "listen_host").empty();
    return listen_try;
}


void Server::createServer(
    Poco::Util::AbstractConfiguration & config,
    const std::string & listen_host,
    const char * port_name,
    bool listen_try,
    bool start_server,
    std::vector<ProtocolServerAdapter> & servers,
    CreateServerFunc && func) const
{
    /// For testing purposes, user may omit tcp_port or http_port or https_port in configuration file.
    if (config.getString(port_name, "").empty())
        return;
    // static std::map<std::string, int>port_name_map = {
    //     {"tcp_port", 19000},
    //     {"keeper_server.tcp_port", 19001},
    // };
    // if (port_name_map.find(port_name) == port_name_map.end()) {
    //     std::cout << "not register port name: " << port_name << std::endl;
    //     return;
    // }

    /// If we already have an active server for this listen_host/port_name, don't create it again
    for (const auto & server : servers)
        if (!server.isStopping() && server.getListenHost() == listen_host && server.getPortName() == port_name)
            return;

    auto port = config.getInt(port_name);
    // auto port = port_name_map[port_name];
    try
    {
        servers.push_back(func(port));
        if (start_server)
        {
            servers.back().start();
            LOG_INFO(&logger(), "Listening for {}", servers.back().getDescription());
        }
        global_context->registerServerPort(port_name, port);
    }
    catch (const Poco::Exception &)
    {
        std::string message = "Listen [" + listen_host + "]:" + std::to_string(port) + " failed: " + getCurrentExceptionMessage(false);

        if (listen_try)
        {
            LOG_WARNING(&logger(), "{}. If it is an IPv6 or IPv4 address and your host has disabled IPv6 or IPv4, then consider to "
                "specify not disabled IPv4 or IPv6 address to listen in <listen_host> element of configuration "
                "file. Example for disabled IPv6: <listen_host>0.0.0.0</listen_host> ."
                " Example for disabled IPv4: <listen_host>::</listen_host>",
                message);
        }
        else
        {
            throw Exception{message, ErrorCodes::NETWORK_ERROR};
        }
    }
}

void Server::uninitialize()
{
    logger().information("shutting down");
    BaseDaemon::uninitialize();
}

int Server::run()
{
    if (config().hasOption("help"))
    {
        Poco::Util::HelpFormatter help_formatter(Server::options());
        auto header_str = fmt::format("{} [OPTION] [-- [ARG]...]\n"
                                      "positional arguments can be used to rewrite config.xml properties, for example, --http_port=8010",
                                      commandName());
        help_formatter.setHeader(header_str);
        help_formatter.format(std::cout);
        return 0;
    }
    if (config().hasOption("version"))
    {
        std::cout << DBMS_NAME << " server version " << VERSION_STRING << VERSION_OFFICIAL << "." << std::endl;
        return 0;
    }
    return Application::run(); // NOLINT
}

void Server::initialize(Poco::Util::Application & self)
{
    BaseDaemon::initialize(self);
    logger().information("starting up");

    LOG_INFO(&logger(), "OS name: {}, version: {}, architecture: {}",
        Poco::Environment::osName(),
        Poco::Environment::osVersion(),
        Poco::Environment::osArchitecture());
}

std::string Server::getDefaultCorePath() const
{
    return getCanonicalPath(config().getString("path", DBMS_DEFAULT_PATH)) + "cores";
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


void checkForUsersNotInMainConfig(
    const Poco::Util::AbstractConfiguration & config,
    const std::string & config_path,
    const std::string & users_config_path,
    Poco::Logger * log)
{
    if (config.getBool("skip_check_for_incorrect_settings", false))
        return;

    if (config.has("users") || config.has("profiles") || config.has("quotas"))
    {
        /// We cannot throw exception here, because we have support for obsolete 'conf.d' directory
        /// (that does not correspond to config.d or users.d) but substitute configuration to both of them.

        LOG_ERROR(log, "The <users>, <profiles> and <quotas> elements should be located in users config file: {} not in main config {}."
            " Also note that you should place configuration changes to the appropriate *.d directory like 'users.d'.",
            users_config_path, config_path);
    }
}

[[noreturn]] void forceShutdown()
{
#if defined(THREAD_SANITIZER) && defined(OS_LINUX)
    /// Thread sanitizer tries to do something on exit that we don't need if we want to exit immediately,
    /// while connection handling threads are still run.
    (void)syscall(SYS_exit_group, 0);
    __builtin_unreachable();
#else
    _exit(0);
#endif
}


int Server::main(const std::vector<std::string> & /*args*/)
{
    Poco::Logger * log = &logger();

    UseSSL use_ssl;

    MainThreadStatus::getInstance();

    registerDisks();
    // registerFormats();

    CurrentMetrics::set(CurrentMetrics::Revision, ClickHouseRevision::getVersionRevision());
    CurrentMetrics::set(CurrentMetrics::VersionInteger, ClickHouseRevision::getVersionInteger());

    /** Context contains all that query execution is dependent:
      *  settings, available functions, data types, aggregate functions, databases, ...
      */
    auto shared_context = Context::createShared();
    global_context = Context::createGlobal(shared_context.get());

    global_context->makeGlobalContext();
    global_context->setApplicationType(Context::ApplicationType::SERVER);

#if !defined(NDEBUG) || !defined(__OPTIMIZE__)
    global_context->addWarningMessage("Server was built in debug mode. It will work slowly.");
#endif

if (ThreadFuzzer::instance().isEffective())
    global_context->addWarningMessage("ThreadFuzzer is enabled. Application will run slowly and unstable.");

#if defined(SANITIZER)
    global_context->addWarningMessage("Server was built with sanitizer. It will work slowly.");
#endif


    // Initialize global thread pool. Do it before we fetch configs from zookeeper
    // nodes (`from_zk`), because ZooKeeper interface uses the pool. We will
    // ignore `max_thread_pool_size` in configs we fetch from ZK, but oh well.
    GlobalThreadPool::initialize(
        config().getUInt("max_thread_pool_size", 10000),
        config().getUInt("max_thread_pool_free_size", 1000),
        config().getUInt("thread_pool_queue_size", 10000)
    );

    Poco::ThreadPool server_pool(3, config().getUInt("max_connections", 1024));
    std::mutex servers_lock;
    std::vector<ProtocolServerAdapter> servers;
    std::vector<ProtocolServerAdapter> servers_to_start_before_tables;

    bool has_zookeeper = config().has("zookeeper");

    // Settings::checkNoSettingNamesAtTopLevel(config(), config_path);

    const auto memory_amount = getMemoryAmount();

#if defined(OS_LINUX)
    std::string executable_path = getExecutablePath();

    if (!executable_path.empty())
    {
        /// Integrity check based on checksum of the executable code.
        /// Note: it is not intended to protect from malicious party,
        /// because the reference checksum can be easily modified as well.
        /// And we don't involve asymmetric encryption with PKI yet.
        /// It's only intended to protect from faulty hardware.
        /// Note: it is only based on machine code.
        /// But there are other sections of the binary (e.g. exception handling tables)
        /// that are interpreted (not executed) but can alter the behaviour of the program as well.

        String calculated_binary_hash = getHashOfLoadedBinaryHex();

        if (stored_binary_hash.empty())
        {
            LOG_WARNING(log, "Calculated checksum of the binary: {}."
                " There is no information about the reference checksum.", calculated_binary_hash);
        }
        else if (calculated_binary_hash == stored_binary_hash)
        {
            LOG_INFO(log, "Calculated checksum of the binary: {}, integrity check passed.", calculated_binary_hash);
        }
        else
        {
            /// If program is run under debugger, ptrace will fail.
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
            {
                /// Program is run under debugger. Modification of it's binary image is ok for breakpoints.
                global_context->addWarningMessage(
                    fmt::format("Server is run under debugger and its binary image is modified (most likely with breakpoints).",
                    calculated_binary_hash)
                );
            }
            else
            {
                throw Exception(ErrorCodes::CORRUPTED_DATA,
                    "Calculated checksum of the ClickHouse binary ({0}) does not correspond"
                    " to the reference checksum stored in the binary ({1})."
                    " It may indicate one of the following:"
                    " - the file {2} was changed just after startup;"
                    " - the file {2} is damaged on disk due to faulty hardware;"
                    " - the loaded executable is damaged in memory due to faulty hardware;"
                    " - the file {2} was intentionally modified;"
                    " - logical error in code."
                    , calculated_binary_hash, stored_binary_hash, executable_path);
            }
        }
    }
    else
        executable_path = "/usr/bin/clickhouse";    /// It is used for information messages.

    /// After full config loaded
    {
        if (config().getBool("remap_executable", false))
        {
            LOG_DEBUG(log, "Will remap executable in memory.");
            size_t size = remapExecutable();
            LOG_DEBUG(log, "The code ({}) in memory has been successfully remapped.", ReadableSize(size));
        }

        if (config().getBool("mlock_executable", false))
        {
            if (hasLinuxCapability(CAP_IPC_LOCK))
            {
                try
                {
                    /// Get the memory area with (current) code segment.
                    /// It's better to lock only the code segment instead of calling "mlockall",
                    /// because otherwise debug info will be also locked in memory, and it can be huge.
                    auto [addr, len] = getMappedArea(reinterpret_cast<void *>(mainEntryClickHouseServer));

                    LOG_TRACE(log, "Will do mlock to prevent executable memory from being paged out. It may take a few seconds.");
                    if (0 != mlock(addr, len))
                        LOG_WARNING(log, "Failed mlock: {}", errnoToString(ErrorCodes::SYSTEM_ERROR));
                    else
                        LOG_TRACE(log, "The memory map of clickhouse executable has been mlock'ed, total {}", ReadableSize(len));
                }
                catch (...)
                {
                    LOG_WARNING(log, "Cannot mlock: {}", getCurrentExceptionMessage(false));
                }
            }
            else
            {
                LOG_INFO(log, "It looks like the process has no CAP_IPC_LOCK capability, binary mlock will be disabled."
                    " It could happen due to incorrect ClickHouse package installation."
                    " You could resolve the problem manually with 'sudo setcap cap_ipc_lock=+ep {}'."
                    " Note that it will not work on 'nosuid' mounted filesystems.", executable_path);
            }
        }
    }
#endif

    // global_context->setRemoteHostFilter(config());

    std::string path_str = getCanonicalPath(config().getString("path", DBMS_DEFAULT_PATH));
    fs::path path = path_str;
    std::string default_database = config().getString("default_database", "default");

    /// Check that the process user id matches the owner of the data.
    const auto effective_user_id = geteuid();
    struct stat statbuf;
    if (stat(path_str.c_str(), &statbuf) == 0 && effective_user_id != statbuf.st_uid)
    {
        const auto effective_user = getUserName(effective_user_id);
        const auto data_owner = getUserName(statbuf.st_uid);
        std::string message = "Effective user of the process (" + effective_user +
            ") does not match the owner of the data (" + data_owner + ").";
        if (effective_user_id == 0)
        {
            message += " Run under 'sudo -u " + data_owner + "'.";
            throw Exception(message, ErrorCodes::MISMATCHING_USERS_FOR_PROCESS_AND_DATA);
        }
        else
        {
            global_context->addWarningMessage(message);
        }
    }

    global_context->setPath(path_str);

    StatusFile status{path / "status", StatusFile::write_full_info};

    DB::ServerUUID::load(path / "uuid", log);

    /// Try to increase limit on number of open files.
    {
        rlimit rlim;
        if (getrlimit(RLIMIT_NOFILE, &rlim))
            throw Poco::Exception("Cannot getrlimit");

        if (rlim.rlim_cur == rlim.rlim_max)
        {
            LOG_DEBUG(log, "rlimit on number of file descriptors is {}", rlim.rlim_cur);
        }
        else
        {
            rlim_t old = rlim.rlim_cur;
            rlim.rlim_cur = config().getUInt("max_open_files", rlim.rlim_max);
            int rc = setrlimit(RLIMIT_NOFILE, &rlim);
            if (rc != 0)
                LOG_WARNING(log, "Cannot set max number of file descriptors to {}. Try to specify max_open_files according to your system limits. error: {}", rlim.rlim_cur, strerror(errno));
            else
                LOG_DEBUG(log, "Set max number of file descriptors to {} (was {}).", rlim.rlim_cur, old);
        }
    }

    static ServerErrorHandler error_handler;
    Poco::ErrorHandler::set(&error_handler);

    /// Initialize DateLUT early, to not interfere with running time of first query.
    LOG_DEBUG(log, "Initializing DateLUT.");
    DateLUT::instance();
    LOG_TRACE(log, "Initialized DateLUT with time zone '{}'.", DateLUT::instance().getTimeZone());

    /// Storage with temporary data for processing of heavy queries.
    // {
    //     std::string tmp_path = config().getString("tmp_path", path / "tmp/");
    //     std::string tmp_policy = config().getString("tmp_policy", "");
    //     const VolumePtr & volume = global_context->setTemporaryStorage(tmp_path, tmp_policy);
    //     for (const DiskPtr & disk : volume->getDisks())
    //         setupTmpPath(log, disk->getPath());
    // }

    /** Directory with 'flags': files indicating temporary settings for the server set by system administrator.
      * Flags may be cleared automatically after being applied by the server.
      * Examples: do repair of local data; clone all replicated tables from replica.
      */
    {
        auto flags_path = path / "flags/";
        fs::create_directories(flags_path);
        global_context->setFlagsPath(flags_path);
    }

    /** Directory with user provided files that are usable by 'file' table function.
      */
    {

        std::string user_files_path = config().getString("user_files_path", path / "user_files/");
        global_context->setUserFilesPath(user_files_path);
        fs::create_directories(user_files_path);
    }

    {
        std::string dictionaries_lib_path = config().getString("dictionaries_lib_path", path / "dictionaries_lib/");
        global_context->setDictionariesLibPath(dictionaries_lib_path);
        fs::create_directories(dictionaries_lib_path);
    }

    {
        std::string user_scripts_path = config().getString("user_scripts_path", path / "user_scripts/");
        global_context->setUserScriptsPath(user_scripts_path);
        fs::create_directories(user_scripts_path);
    }

    /// top_level_domains_lists
    {
        const std::string & top_level_domains_path = config().getString("top_level_domains_path", path / "top_level_domains/");
        TLDListsHolder::getInstance().parseConfig(fs::path(top_level_domains_path) / "", config());
    }

    {
        fs::create_directories(path / "data/");
        fs::create_directories(path / "metadata/");
        fs::create_directories(path / "user_defined/");

        /// Directory with metadata of tables, which was marked as dropped by Atomic database
        fs::create_directories(path / "metadata_dropped/");
    }

    if (config().has("interserver_http_port") && config().has("interserver_https_port"))
        throw Exception("Both http and https interserver ports are specified", ErrorCodes::EXCESSIVE_ELEMENT_IN_CONFIG);

    static const auto interserver_tags =
    {
        std::make_tuple("interserver_http_host", "interserver_http_port", "http"),
        std::make_tuple("interserver_https_host", "interserver_https_port", "https")
    };

    /// Initialize main config reloader.
    std::string include_from_path = config().getString("include_from", "/etc/metrika.xml");

    if (config().has("query_masking_rules"))
    {
        SensitiveDataMasker::setInstance(std::make_unique<SensitiveDataMasker>(config(), "query_masking_rules"));
    }

    const auto listen_hosts = getListenHosts(config());
    const auto listen_try = getListenTry(config());

    if (config().has("keeper_server"))
    {
#if USE_NURAFT
        //// If we don't have configured connection probably someone trying to use clickhouse-server instead
        //// of clickhouse-keeper, so start synchronously.
        bool can_initialize_keeper_async = false;

        // if (has_zookeeper) /// We have configured connection to some zookeeper cluster
        // {
        //     /// If we cannot connect to some other node from our cluster then we have to wait our Keeper start
        //     /// synchronously.
        //     can_initialize_keeper_async = global_context->tryCheckClientConnectionToMyKeeperCluster();
        // }
        /// Initialize keeper RAFT.
        global_context->initializeKeeperDispatcher(can_initialize_keeper_async);
        FourLetterCommandFactory::registerCommands(*global_context->getKeeperDispatcher());

        for (const auto & listen_host : listen_hosts)
        {
            /// TCP Keeper
            const char * port_name = "keeper_server.tcp_port";
            createServer(
                config(), listen_host, port_name, listen_try, /* start_server: */ false,
                servers_to_start_before_tables,
                [&](UInt16 port) -> ProtocolServerAdapter
                {
                    Poco::Net::ServerSocket socket;
                    auto address = socketBindListen(socket, listen_host, port);
                    socket.setReceiveTimeout(config().getUInt64("keeper_server.socket_receive_timeout_sec", DBMS_DEFAULT_RECEIVE_TIMEOUT_SEC));
                    socket.setSendTimeout(config().getUInt64("keeper_server.socket_send_timeout_sec", DBMS_DEFAULT_SEND_TIMEOUT_SEC));
                    return ProtocolServerAdapter(
                        listen_host,
                        port_name,
                        "Keeper (tcp): " + address.toString(),
                        std::make_unique<TCPServer>(
                            new KeeperTCPHandlerFactory(*this, false), server_pool, socket));
                });

            const char * secure_port_name = "keeper_server.tcp_port_secure";
            createServer(
                config(), listen_host, secure_port_name, listen_try, /* start_server: */ false,
                servers_to_start_before_tables,
                [&](UInt16 port) -> ProtocolServerAdapter
                {
#if USE_SSL
                    Poco::Net::SecureServerSocket socket;
                    auto address = socketBindListen(socket, listen_host, port, /* secure = */ true);
                    socket.setReceiveTimeout(config().getUInt64("keeper_server.socket_receive_timeout_sec", DBMS_DEFAULT_RECEIVE_TIMEOUT_SEC));
                    socket.setSendTimeout(config().getUInt64("keeper_server.socket_send_timeout_sec", DBMS_DEFAULT_SEND_TIMEOUT_SEC));
                    return ProtocolServerAdapter(
                        listen_host,
                        secure_port_name,
                        "Keeper with secure protocol (tcp_secure): " + address.toString(),
                        std::make_unique<TCPServer>(
                            new KeeperTCPHandlerFactory(*this, true), server_pool, socket));
#else
                    UNUSED(port);
                    throw Exception{"SSL support for TCP protocol is disabled because Poco library was built without NetSSL support.",
                        ErrorCodes::SUPPORT_IS_DISABLED};
#endif
                });
        }
#else
        throw Exception(ErrorCodes::SUPPORT_IS_DISABLED, "ClickHouse server built without NuRaft library. Cannot use internal coordination.");
#endif

    }

    for (auto & server : servers_to_start_before_tables)
    {
        server.start();
        LOG_INFO(log, "Listening for {}", server.getDescription());
    }


    /// Set up caches.

    /// Lower cache size on low-memory systems.
    double cache_size_to_ram_max_ratio = config().getDouble("cache_size_to_ram_max_ratio", 0.5);
    size_t max_cache_size = memory_amount * cache_size_to_ram_max_ratio;

    /// Size of cache for uncompressed blocks. Zero means disabled.
    size_t uncompressed_cache_size = config().getUInt64("uncompressed_cache_size", 0);
    if (uncompressed_cache_size > max_cache_size)
    {
        uncompressed_cache_size = max_cache_size;
        LOG_INFO(log, "Uncompressed cache size was lowered to {} because the system has low amount of memory",
            formatReadableSizeWithBinarySuffix(uncompressed_cache_size));
    }
    // global_context->setUncompressedCache(uncompressed_cache_size);

    /// Load global settings from default_profile and system_profile.
    // global_context->setDefaultProfiles(config());
    // const Settings & settings = global_context->getSettingsRef();

    /// Initialize background executors after we load default_profile config.
    /// This is needed to load proper values of background_pool_size etc.
    // global_context->initializeBackgroundExecutorsIfNeeded();

    /// Size of cache for marks (index of MergeTree family of tables). It is mandatory.
    // size_t mark_cache_size = config().getUInt64("mark_cache_size");
    // if (!mark_cache_size)
    //     LOG_ERROR(log, "Too low mark cache size will lead to severe performance degradation.");
    // if (mark_cache_size > max_cache_size)
    // {
    //     mark_cache_size = max_cache_size;
    //     LOG_INFO(log, "Mark cache size was lowered to {} because the system has low amount of memory",
    //         formatReadableSizeWithBinarySuffix(mark_cache_size));
    // }
    // global_context->setMarkCache(mark_cache_size);

    /// Size of cache for uncompressed blocks of MergeTree indices. Zero means disabled.
    // size_t index_uncompressed_cache_size = config().getUInt64("index_uncompressed_cache_size", 0);
    // if (index_uncompressed_cache_size)
    //     global_context->setIndexUncompressedCache(index_uncompressed_cache_size);

    /// Size of cache for index marks (index of MergeTree skip indices). It is necessary.
    /// Specify default value for index_mark_cache_size explicitly!
    // size_t index_mark_cache_size = config().getUInt64("index_mark_cache_size", 0);
    // if (index_mark_cache_size)
    //     global_context->setIndexMarkCache(index_mark_cache_size);

    /// A cache for mmapped files.
    // size_t mmap_cache_size = config().getUInt64("mmap_cache_size", 1000);   /// The choice of default is arbitrary.
    // if (mmap_cache_size)
    //     global_context->setMMappedFileCache(mmap_cache_size);

    /// Set path for format schema files
    // fs::path format_schema_path(config().getString("format_schema_path", path / "format_schemas/"));
    // global_context->setFormatSchemaPath(format_schema_path);
    // fs::create_directories(format_schema_path);

    /// Check sanity of MergeTreeSettings on server startup
    // global_context->getMergeTreeSettings().sanityCheck(settings);
    // global_context->getReplicatedMergeTreeSettings().sanityCheck(settings);


    /// try set up encryption. There are some errors in config, error will be printed and server wouldn't start.
    CompressionCodecEncrypted::Configuration::instance().load(config(), "encryption_codecs");

    SCOPE_EXIT({
        /// Stop reloading of the main config. This must be done before `global_context->shutdown()` because
        /// otherwise the reloading may pass a changed config to some destroyed parts of ContextSharedPart.

        /** Ask to cancel background jobs all table engines,
          *  and also query_log.
          * It is important to do early, not in destructor of Context, because
          *  table engines could use Context on destroy.
          */
        LOG_INFO(log, "Shutting down storages.");

        global_context->shutdown();

        LOG_DEBUG(log, "Shut down storages.");

        if (!servers_to_start_before_tables.empty())
        {
            LOG_DEBUG(log, "Waiting for current connections to servers for tables to finish.");
            int current_connections = 0;
            for (auto & server : servers_to_start_before_tables)
            {
                server.stop();
                current_connections += server.currentConnections();
            }

            if (current_connections)
                LOG_INFO(log, "Closed all listening sockets. Waiting for {} outstanding connections.", current_connections);
            else
                LOG_INFO(log, "Closed all listening sockets.");

            if (current_connections > 0)
                current_connections = waitServersToFinish(servers_to_start_before_tables, config().getInt("shutdown_wait_unfinished", 5));

            if (current_connections)
                LOG_INFO(log, "Closed connections to servers for tables. But {} remain. Probably some tables of other users cannot finish their connections after context shutdown.", current_connections);
            else
                LOG_INFO(log, "Closed connections to servers for tables.");

            global_context->shutdownKeeperDispatcher();
        }

        /// Wait server pool to avoid use-after-free of destroyed context in the handlers
        server_pool.joinAll();

        /** Explicitly destroy Context. It is more convenient than in destructor of Server, because logger is still available.
          * At this moment, no one could own shared part of Context.
          */
        global_context.reset();
        shared_context.reset();
        LOG_DEBUG(log, "Destroyed global context.");
    });

    /// Set current database name before loading tables and databases because
    /// system logs may copy global context.
    // global_context->setCurrentDatabaseNameInGlobalContext(default_database);


    /// Init trace collector only after trace_log system table was created
    /// Disable it if we collect test coverage information, because it will work extremely slow.
#if USE_UNWIND && !WITH_COVERAGE && defined(__x86_64__)
    /// Profilers cannot work reliably with any other libunwind or without PHDR cache.
    if (hasPHDRCache())
    {
        global_context->initializeTraceCollector();

        /// Set up server-wide memory profiler (for total memory tracker).
        UInt64 total_memory_profiler_step = config().getUInt64("total_memory_profiler_step", 0);
        if (total_memory_profiler_step)
        {
            total_memory_tracker.setProfilerStep(total_memory_profiler_step);
        }

        double total_memory_tracker_sample_probability = config().getDouble("total_memory_tracker_sample_probability", 0);
        if (total_memory_tracker_sample_probability)
        {
            total_memory_tracker.setSampleProbability(total_memory_tracker_sample_probability);
        }
    }
#endif

    /// Describe multiple reasons when query profiler cannot work.

#if !USE_UNWIND
    LOG_INFO(log, "Query Profiler and TraceCollector are disabled because they cannot work without bundled unwind (stack unwinding) library.");
#endif

#if WITH_COVERAGE
    LOG_INFO(log, "Query Profiler and TraceCollector are disabled because they work extremely slow with test coverage.");
#endif

#if defined(SANITIZER)
    LOG_INFO(log, "Query Profiler disabled because they cannot work under sanitizers"
        " when two different stack unwinding methods will interfere with each other.");
#endif

#if !defined(__x86_64__)
    LOG_INFO(log, "Query Profiler is only tested on x86_64. It also known to not work under qemu-user.");
#endif

    if (!hasPHDRCache())
        LOG_INFO(log, "Query Profiler and TraceCollector are disabled because they require PHDR cache to be created"
            " (otherwise the function 'dl_iterate_phdr' is not lock free and not async-signal safe).");

    std::unique_ptr<DNSCacheUpdater> dns_cache_updater;
    if (config().has("disable_internal_dns_cache") && config().getInt("disable_internal_dns_cache"))
    {
        /// Disable DNS caching at all
        DNSResolver::instance().setDisableCacheFlag();
        LOG_DEBUG(log, "DNS caching disabled");
    }
    else
    {
        /// Initialize a watcher periodically updating DNS cache
        dns_cache_updater = std::make_unique<DNSCacheUpdater>(global_context, config().getInt("dns_cache_update_period", 15));
    }

#if defined(OS_LINUX)
    if (!TasksStatsCounters::checkIfAvailable())
    {
        LOG_INFO(log, "It looks like this system does not have procfs mounted at /proc location,"
            " neither clickhouse-server process has CAP_NET_ADMIN capability."
            " 'taskstats' performance statistics will be disabled."
            " It could happen due to incorrect ClickHouse package installation."
            " You can try to resolve the problem manually with 'sudo setcap cap_net_admin=+ep {}'."
            " Note that it will not work on 'nosuid' mounted filesystems."
            " It also doesn't work if you run clickhouse-server inside network namespace as it happens in some containers.",
            executable_path);
    }

    if (!hasLinuxCapability(CAP_SYS_NICE))
    {
        LOG_INFO(log, "It looks like the process has no CAP_SYS_NICE capability, the setting 'os_thread_priority' will have no effect."
            " It could happen due to incorrect ClickHouse package installation."
            " You could resolve the problem manually with 'sudo setcap cap_sys_nice=+ep {}'."
            " Note that it will not work on 'nosuid' mounted filesystems.",
            executable_path);
    }
#else
    LOG_INFO(log, "TaskStats is not implemented for this OS. IO accounting will be disabled.");
#endif

    {

        {
            std::lock_guard lock(servers_lock);
            createServers(config(), listen_hosts, listen_try, server_pool, servers);
            if (servers.empty())
                throw Exception(
                    "No servers started (add valid listen_host and 'tcp_port' or 'http_port' to configuration file.)",
                    ErrorCodes::NO_ELEMENTS_IN_CONFIG);
        }

        if (servers.empty())
             throw Exception("No servers started (add valid listen_host and 'tcp_port' or 'http_port' to configuration file.)",
                ErrorCodes::NO_ELEMENTS_IN_CONFIG);


        /// Must be done after initialization of `servers`, because async_metrics will access `servers` variable from its thread.

        buildLoggers(config(), logger());

        if (dns_cache_updater)
            dns_cache_updater->start();

        {
            LOG_INFO(log, "Available RAM: {}; physical cores: {}; logical cores: {}.",
                formatReadableSizeWithBinarySuffix(memory_amount),
                getNumberOfPhysicalCPUCores(),  // on ARM processors it can show only enabled at current moment cores
                std::thread::hardware_concurrency());
        }

        {
            std::lock_guard lock(servers_lock);
            for (auto & server : servers)
            {
                server.start();
                LOG_INFO(log, "Listening for {}", server.getDescription());
            }
            LOG_INFO(log, "Ready for connections.");
        }


        SCOPE_EXIT_SAFE({
            LOG_DEBUG(log, "Received termination signal.");
            LOG_DEBUG(log, "Waiting for current connections to close.");

            is_cancelled = true;

            int current_connections = 0;
            {
                std::lock_guard lock(servers_lock);
                for (auto & server : servers)
                {
                    server.stop();
                    current_connections += server.currentConnections();
                }
            }

            if (current_connections)
                LOG_INFO(log, "Closed all listening sockets. Waiting for {} outstanding connections.", current_connections);
            else
                LOG_INFO(log, "Closed all listening sockets.");

            /// Killing remaining queries.
            // if (!config().getBool("shutdown_wait_unfinished_queries", false))
            //     global_context->getProcessList().killAllQueries();

            if (current_connections)
                current_connections = waitServersToFinish(servers, config().getInt("shutdown_wait_unfinished", 5));

            if (current_connections)
                LOG_INFO(log, "Closed connections. But {} remain."
                    " Tip: To increase wait time add to config: <shutdown_wait_unfinished>60</shutdown_wait_unfinished>", current_connections);
            else
                LOG_INFO(log, "Closed connections.");

            dns_cache_updater.reset();

            if (current_connections)
            {
                /// There is no better way to force connections to close in Poco.
                /// Otherwise connection handlers will continue to live
                /// (they are effectively dangling objects, but they use global thread pool
                ///  and global thread pool destructor will wait for threads, preventing server shutdown).

                /// Dump coverage here, because std::atexit callback would not be called.
                dumpCoverageReportIfPossible();
                LOG_INFO(log, "Will shutdown forcefully.");
                forceShutdown();
            }
        });

        waitForTerminationRequest();
    }

    return Application::EXIT_OK;
}

void Server::createServers(
    Poco::Util::AbstractConfiguration & config,
    const std::vector<std::string> & listen_hosts,
    bool listen_try,
    Poco::ThreadPool & server_pool,
    std::vector<ProtocolServerAdapter> & servers,
    bool start_servers)
{
    const Settings & settings = global_context->getSettingsRef();

    for (const auto & listen_host : listen_hosts)
    {
        const char * port_name = nullptr;

        /// TCP
        port_name = "tcp_port";
        createServer(config, listen_host, port_name, listen_try, start_servers, servers, [&](UInt16 port) -> ProtocolServerAdapter
        {
            Poco::Net::ServerSocket socket;
            auto address = socketBindListen(socket, listen_host, port);
            socket.setReceiveTimeout(settings.receive_timeout);
            socket.setSendTimeout(settings.send_timeout);
            return ProtocolServerAdapter(
                listen_host,
                port_name,
                "native protocol (tcp): " + address.toString(),
                std::make_unique<TCPServer>(
                    new TCPHandlerFactory(*this, /* secure */ false, /* proxy protocol */ false),
                    server_pool,
                    socket,
                    new Poco::Net::TCPServerParams));
        });
    }

}


}
