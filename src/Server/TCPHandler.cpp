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
#include <IO/WriteHelpers.h>
#include <IO/ReadBufferFromPocoSocket.h>
#include <IO/WriteBufferFromPocoSocket.h>
#include <Compression/CompressedReadBuffer.h>
#include <Compression/CompressedWriteBuffer.h>
#include <Common/CurrentThread.h>
#include <Common/setThreadName.h>
#include <Common/Stopwatch.h>
#include <Common/NetException.h>
#include "TCPHandler.h"
#include <base/scope_guard.h>
#include <Interpreters/Session.h>
#include <Interpreters/StorageID.h>

#include "Interpreters/Context.h"
#include "Interpreters/ClientInfo.h"

#include <Common/config_version.h>
#include <Server/TCPServer.h>
#include <Interpreters/executeQuery.h>

#include <thread>

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

TCPHandler::TCPHandler(IServer & server_, TCPServer & tcp_server_, const Poco::Net::StreamSocket & socket_, std::string server_display_name_)
    : Poco::Net::TCPServerConnection(socket_)
    , server(server_)
    , tcp_server(tcp_server_)
    , log(&Poco::Logger::get("TCPHandler"))
    , server_display_name(std::move(server_display_name_))
{
}

TCPHandler::~TCPHandler()
{

}

void TCPHandler::sendHello()
{
    writeVarUInt(Protocol::Server::Hello, *out);
    writeStringBinary(DBMS_NAME, *out);
    writeVarUInt(DBMS_VERSION_MAJOR, *out);
    writeVarUInt(DBMS_VERSION_MINOR, *out);
    writeVarUInt(DBMS_TCP_PROTOCOL_VERSION, *out);
    if (client_tcp_protocol_version >= DBMS_MIN_REVISION_WITH_SERVER_TIMEZONE)
        writeStringBinary(DateLUT::instance().getTimeZone(), *out);
    if (client_tcp_protocol_version >= DBMS_MIN_REVISION_WITH_SERVER_DISPLAY_NAME)
        writeStringBinary(server_display_name, *out);
    if (client_tcp_protocol_version >= DBMS_MIN_REVISION_WITH_VERSION_PATCH)
        writeVarUInt(DBMS_VERSION_PATCH, *out);
    out->next();
}

void TCPHandler::receiveHello()
{
    /// Receive `hello` packet.
    UInt64 packet_type = 0;
    String user;
    String password;

    readVarUInt(packet_type, *in);
    if (packet_type != Protocol::Client::Hello)
    {
        /** If you accidentally accessed the HTTP protocol for a port destined for an internal TCP protocol,
          * Then instead of the packet type, there will be G (GET) or P (POST), in most cases.
          */
        if (packet_type == 'G' || packet_type == 'P')
        {
            // writeString(formatHTTPErrorResponseWhenUserIsConnectedToWrongPort(server.config()), *out);
            writeString(String("Client has connected to wrong port, packet_type is G or P"), *out);
            throw Exception("Client has connected to wrong port", ErrorCodes::CLIENT_HAS_CONNECTED_TO_WRONG_PORT);
        }
        else
            throw NetException("Unexpected packet from client", ErrorCodes::UNEXPECTED_PACKET_FROM_CLIENT);
    }

    readStringBinary(client_name, *in);
    readVarUInt(client_version_major, *in);
    readVarUInt(client_version_minor, *in);
    // NOTE For backward compatibility of the protocol, client cannot send its version_patch.
    readVarUInt(client_tcp_protocol_version, *in);
    readStringBinary(default_database, *in);
    readStringBinary(user, *in);
    readStringBinary(password, *in);

    if (user.empty()) {
        // std::cout << "Unexpected packet from client (no user in Hello package)\n";
        throw NetException("Unexpected packet from client (no user in Hello package)", ErrorCodes::UNEXPECTED_PACKET_FROM_CLIENT);
    }

    // std::cout <<fmt::format("Connected {} version {}.{}.{}, revision: {}{}{}.",
    //     client_name,
    //     client_version_major, client_version_minor, client_version_patch,
    //     client_tcp_protocol_version,
    //     (!default_database.empty() ? ", database: " + default_database : ""),
    //     (!user.empty() ? ", user: " + user : "")
    // );
    LOG_DEBUG(log, "Connected {} version {}.{}.{}, revision: {}{}{}.",
        client_name,
        client_version_major, client_version_minor, client_version_patch,
        client_tcp_protocol_version,
        (!default_database.empty() ? ", database: " + default_database : ""),
        (!user.empty() ? ", user: " + user : "")
    );

    is_interserver_mode = (user == USER_INTERSERVER_MARKER);
    if (is_interserver_mode)
    {
        std::cout << "is_interserver_mode\n";
        return;
    }
}


void TCPHandler::extractConnectionSettingsFromContext(const ContextPtr & context)
{
    const auto & settings = context->getSettingsRef();
    send_exception_with_stack_trace = settings.calculate_text_stack_trace;
    send_timeout = settings.send_timeout;
    receive_timeout = settings.receive_timeout;
    poll_interval = settings.poll_interval;
    idle_connection_timeout = settings.idle_connection_timeout;
    interactive_delay = settings.interactive_delay;
    sleep_in_send_tables_status = settings.sleep_in_send_tables_status_ms;
    unknown_packet_in_send_data = settings.unknown_packet_in_send_data;
    sleep_in_receive_cancel = settings.sleep_in_receive_cancel_ms;
}

void TCPHandler::sendException(const Exception & e, bool with_stack_trace)
{
    writeVarUInt(Protocol::Server::Exception, *out);
    writeException(e, *out, with_stack_trace);
    out->next();
}

void TCPHandler::sendLogs()
{

}

void TCPHandler::runImpl()
{
    setThreadName("TCPHandler");
    ThreadStatus thread_status;

    session = std::make_unique<Session>(server.context(), ClientInfo::Interface::TCP);
    extractConnectionSettingsFromContext(server.context());

    // std::cout << "runImpl, receive_timeout: " << receive_timeout << std::endl;

    socket().setReceiveTimeout(receive_timeout);
    socket().setSendTimeout(send_timeout);
    socket().setNoDelay(true);


    in = std::make_shared<ReadBufferFromPocoSocket>(socket());
    out = std::make_shared<WriteBufferFromPocoSocket>(socket());

    if (in->eof())
    {
        LOG_INFO(log, "Client has not sent any data.");
        return;
    }

    /// User will be authenticated here. It will also set settings from user profile into connection_context.
    try
    {
        receiveHello();
        sendHello();

        if (!is_interserver_mode) /// In interserver mode queries are executed without a session context.
        {
            session->makeSessionContext();

            /// If session created, then settings in session context has been updated.
            /// So it's better to update the connection settings for flexibility.
            extractConnectionSettingsFromContext(session->sessionContext());

            /// When connecting, the default database could be specified.
            if (!default_database.empty())
                session->sessionContext()->setCurrentDatabase(default_database);
        }
    }
    catch (const Exception & e) /// Typical for an incorrect username, password, or address.
    {
        if (e.code() == ErrorCodes::CLIENT_HAS_CONNECTED_TO_WRONG_PORT)
        {
            std::cout <<  "Client has connected to wrong port." << std::endl;
            LOG_DEBUG(log, "Client has connected to wrong port.");
            return;
        }

        if (e.code() == ErrorCodes::ATTEMPT_TO_READ_AFTER_EOF)
        {
            LOG_INFO(log, "Client has gone away.");
            return;
        }

        try
        {
            /// We try to send error information to the client.
            sendException(e, send_exception_with_stack_trace);
        }
        catch (...) {}

        throw;
    }

    while (tcp_server.isOpen())
    {
        /// We are waiting for a packet from the client. Thus, every `poll_interval` seconds check whether we need to shut down.
        {
            std::cout << "main loop 1" << std::endl;
            Stopwatch idle_time;
            UInt64 timeout_ms = std::min(poll_interval, idle_connection_timeout) * 1000000;
            while (tcp_server.isOpen() && !server.isCancelled() && !static_cast<ReadBufferFromPocoSocket &>(*in).poll(timeout_ms))
            {
                std::cout << "main loop 2" << std::endl;
                if (idle_time.elapsedSeconds() > idle_connection_timeout)
                {
                    std::cout << "main loop 3" << std::endl;
                    LOG_TRACE(log, "Closing idle connection");
                    return;
                }
            }
        }
        std::cout << "main loop 4" << std::endl;

        /// If we need to shut down, or client disconnects.
        if (!tcp_server.isOpen() || server.isCancelled() || in->eof()) {
            std::cout << "!tcp_server.isOpen or server.isCancelled  or in->eof" << std::endl;
            break;
        }

        std::cout << "main loop 5" << std::endl;
        Stopwatch watch;
        state.reset();

        // /// Initialized later.
        // std::optional<CurrentThread::QueryScope> query_scope;
        std::cout << "main loop 6" << std::endl;
        /** An exception during the execution of request (it must be sent over the network to the client).
         *  The client will be able to accept it, if it did not happen while sending another packet and the client has not disconnected yet.
         */
        std::optional<DB::Exception> exception;
        bool network_error = false;

        try
        {
            std::cout << "main loop 7" << std::endl;
            /// If a user passed query-local timeouts, reset socket to initial state at the end of the query
            SCOPE_EXIT({state.timeout_setter.reset();});

            /** If Query - process it. If Ping or Cancel - go back to the beginning.
             *  There may come settings for a separate query that modify `query_context`.
             *  It's possible to receive part uuids packet before the query, so then receivePacket has to be called twice.
             */
            if (!receivePacket()) {
                LOG_DEBUG(log, "receive packet failed.");
                std::cout << "main loop 8" << std::endl;
                continue;
            }
            LOG_INFO(log, "receive packet success. query: {}", state.query);


            /** If part_uuids got received in previous packet, trying to read again.
              */
            // if (state.empty() && state.part_uuids_to_ignore && !receivePacket())
            //     continue;
            // if (state.empty() && !receivePacket())
            //     continue;

            std::cout << "main loop 9" << std::endl;
            /// Sync timeouts on client and server during current query to avoid dangling queries on server
            /// NOTE: We use send_timeout for the receive timeout and vice versa (change arguments ordering in TimeoutSetter),
            ///  because send_timeout is client-side setting which has opposite meaning on the server side.
            /// NOTE: these settings are applied only for current connection (not for distributed tables' connections)
            // state.timeout_setter = std::make_unique<TimeoutSetter>(socket(), receive_timeout, send_timeout);
            std::cout << "main loop 10" << std::endl;


                        /// Processing Query
            auto res = executeQuery(state.query, query_context, false, state.stage);

            std::cout << "executeQuery result: " << res << std::endl;


            if (state.is_connection_closed)
                break;

            sendLogs();
            sendEndOfStream();

            /// QueryState should be cleared before QueryScope, since otherwise
            /// the MemoryTracker will be wrong for possible deallocations.
            /// (i.e. deallocations from the Aggregator with two-level aggregation)
            state.reset();
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

void TCPHandler::sendEndOfStream()
{
    state.sent_all_data = true;
    writeVarUInt(Protocol::Server::EndOfStream, *out);
    out->next();
}

void TCPHandler::receiveQuery()
{
    std::cout << "recieve query -----------------xxxxxxxxxxxxx" << std::endl;
    UInt64 stage = 0;
    UInt64 compression = 0;

    state.is_empty = false;
    std::cout << "state.is_empyt: " << state.is_empty << std::endl;
    readStringBinary(state.query_id, *in);
    std::cout << "receive query_id: " << state.query_id << std::endl;

    /// In interserer mode,
    /// initial_user can be empty in case of Distributed INSERT via Buffer/Kafka,
    /// (i.e. when the INSERT is done with the global context w/o user),
    /// so it is better to reset session to avoid using old user.
    // if (is_interserver_mode)
    // {
    //     ClientInfo original_session_client_info = session->getClientInfo();
    //     session = std::make_unique<Session>(server.context(), ClientInfo::Interface::TCP_INTERSERVER);
    //     session->getClientInfo() = original_session_client_info;
    // }

    /// Read client info.
    ClientInfo client_info = session->getClientInfo();
    if (client_tcp_protocol_version >= DBMS_MIN_REVISION_WITH_CLIENT_INFO)
        client_info.read(*in, client_tcp_protocol_version);

    /// Per query settings are also passed via TCP.
    /// We need to check them before applying due to they can violate the settings constraints.
    auto settings_format = (client_tcp_protocol_version >= DBMS_MIN_REVISION_WITH_SETTINGS_SERIALIZED_AS_STRINGS)
        ? SettingsWriteFormat::STRINGS_WITH_FLAGS
        : SettingsWriteFormat::BINARY;
    Settings passed_settings;
    passed_settings.read(*in, settings_format);

    /// Interserver secret.
    std::string received_hash;
    if (client_tcp_protocol_version >= DBMS_MIN_REVISION_WITH_INTERSERVER_SECRET)
    {
        readStringBinary(received_hash, *in, 32);
        std::cout << "receive hash: " << received_hash << std::endl;
    }

    readVarUInt(stage, *in);
    state.stage = QueryProcessingStage::Enum(stage);

    readVarUInt(compression, *in);
    state.compression = static_cast<Protocol::Compression>(compression);
    last_block_in.compression = state.compression;

    readStringBinary(state.query, *in);

    LOG_INFO(log, "receive query: {}", state.query);

    query_context = session->makeQueryContext(std::move(client_info));

    /// Sets the default database if it wasn't set earlier for the session context.
    if (!default_database.empty() && !session->sessionContext())
        query_context->setCurrentDatabase(default_database);

    // if (state.part_uuids_to_ignore)
    //     query_context->getIgnoredPartUUIDs()->add(*state.part_uuids_to_ignore);

    // query_context->setProgressCallback([this] (const Progress & value) { return this->updateProgress(value); });

    ///
    /// Settings
    ///
    auto settings_changes = passed_settings.changes();
    auto query_kind = query_context->getClientInfo().query_kind;
    // if (query_kind == ClientInfo::QueryKind::INITIAL_QUERY)
    // {
    //     /// Throw an exception if the passed settings violate the constraints.
    //     query_context->checkSettingsConstraints(settings_changes);
    // }
    // else
    // {
    //     /// Quietly clamp to the constraints if it's not an initial query.
    //     query_context->clampToSettingsConstraints(settings_changes);
    // }
    query_context->applySettingsChanges(settings_changes);

    /// Use the received query id, or generate a random default. It is convenient
    /// to also generate the default OpenTelemetry trace id at the same time, and
    /// set the trace parent.
    /// Notes:
    /// 1) ClientInfo might contain upstream trace id, so we decide whether to use
    /// the default ids after we have received the ClientInfo.
    /// 2) There is the opentelemetry_start_trace_probability setting that
    /// controls when we start a new trace. It can be changed via Native protocol,
    /// so we have to apply the changes first.
    query_context->setCurrentQueryId(state.query_id);

    /// Disable function name normalization when it's a secondary query, because queries are either
    /// already normalized on initiator node, or not normalized and should remain unnormalized for
    /// compatibility.
    if (query_kind == ClientInfo::QueryKind::SECONDARY_QUERY)
    {
        query_context->setSetting("normalize_function_names", false);
    }
}

void TCPHandler::receiveUnexpectedQuery()
{
    std::cout << "receiveUnexpectedQuery 1" << std::endl;
    UInt64 skip_uint_64;
    String skip_string;

    readStringBinary(skip_string, *in);

    ClientInfo skip_client_info;
    if (client_tcp_protocol_version >= DBMS_MIN_REVISION_WITH_CLIENT_INFO)
        skip_client_info.read(*in, client_tcp_protocol_version);

    Settings skip_settings;
    auto settings_format = (client_tcp_protocol_version >= DBMS_MIN_REVISION_WITH_SETTINGS_SERIALIZED_AS_STRINGS) ? SettingsWriteFormat::STRINGS_WITH_FLAGS
                                                                                                      : SettingsWriteFormat::BINARY;
    skip_settings.read(*in, settings_format);

    std::string skip_hash;
    bool interserver_secret = client_tcp_protocol_version >= DBMS_MIN_REVISION_WITH_INTERSERVER_SECRET;
    if (interserver_secret)
        readStringBinary(skip_hash, *in, 32);

    readVarUInt(skip_uint_64, *in);

    readVarUInt(skip_uint_64, *in);
    last_block_in.compression = static_cast<Protocol::Compression>(skip_uint_64);

    readStringBinary(skip_string, *in);

    throw NetException("Unexpected packet Query received from client", ErrorCodes::UNEXPECTED_PACKET_FROM_CLIENT);
}

void TCPHandler::initBlockInput()
{
    std::cout << "initBlockInput 1" << std::endl;
    if (!state.block_in)
    {
        std::cout << "initBlockInput 2" << std::endl;
        /// 'allow_different_codecs' is set to true, because some parts of compressed data can be precompressed in advance
        /// with another codec that the rest of the data. Example: data sent by Distributed tables.

        if (state.compression == Protocol::Compression::Enable) {
            std::cout << "CompressedReadBuffer implemented.\n";
            state.maybe_compressed_in = in;
            state.maybe_compressed_in = std::make_shared<CompressedReadBuffer>(*in, /* allow_different_codecs */ true);
        }
        else
            state.maybe_compressed_in = in;

        std::cout << "initBlockInput 3" << std::endl;

        // todo: changed
        state.block_in = std::make_unique<NativeReader>(
            *state.maybe_compressed_in,
            client_tcp_protocol_version);
    }
        std::cout << "initBlockInput 4" << std::endl;
}

bool TCPHandler::receiveData(bool scalar)
{
    std::cout << "receive DATA -----------------------12 " << std::endl;
    initBlockInput();
    std::cout << "receive DATA -----------------------31 " << std::endl;
    LOG_DEBUG(log,  "receiveData");
    std::cout << "receive DATA ----------------------- " << std::endl;
    /// The name of the temporary table for writing data, default to empty string
    auto temporary_id = StorageID::createEmpty();
    readStringBinary(temporary_id.table_name, *in);
    std::cout << "receive DATA -----------------------1 " << std::endl;

    /// Read one block from the network and write it down
    Block block = state.block_in->read();

    if (!block)
    {
        state.read_all_data = true;
    std::cout << "receive DATA -----------------------2 " << std::endl;
        return false;
    }

    if (scalar)
    {
    std::cout << "receive DATA -----------------------3 " << std::endl;
        /// Scalar value
        // query_context->addScalar(temporary_id.table_name, block);
        LOG_DEBUG(log, "query_context->addScalar( not implemented");
    }
    else if (!state.need_receive_data_for_insert && !state.need_receive_data_for_input)
    {
    std::cout << "receive DATA -----------------------4 " << std::endl;
        /// Data for external tables
        LOG_DEBUG(log, "Data for external tables not implemented");
        // auto resolved = query_context->tryResolveStorageID(temporary_id, Context::ResolveExternal);
        // StoragePtr storage;
        // /// If such a table does not exist, create it.
        // if (resolved)
        // {
        //     storage = DatabaseCatalog::instance().getTable(resolved, query_context);
        // }
        // else
        // {
        //     NamesAndTypesList columns = block.getNamesAndTypesList();
        //     auto temporary_table = TemporaryTableHolder(query_context, ColumnsDescription{columns}, {});
        //     storage = temporary_table.getTable();
        //     query_context->addExternalTable(temporary_id.table_name, std::move(temporary_table));
        // }
        // auto metadata_snapshot = storage->getInMemoryMetadataPtr();
        // /// The data will be written directly to the table.
        // QueryPipeline temporary_table_out(storage->write(ASTPtr(), metadata_snapshot, query_context));
        // PushingPipelineExecutor executor(temporary_table_out);
        // executor.start();
        // executor.push(block);
        // executor.finish();
    }
    else if (state.need_receive_data_for_input)
    {
    std::cout << "receive DATA -----------------------5 " << std::endl;
        /// 'input' table function.
        state.block_for_input = block;
    }
    else
    {
    std::cout << "receive DATA -----------------------6 " << std::endl;
        /// INSERT query.
        state.block_for_insert = block;
    }
    std::cout << "receive DATA -----------------------7 " << std::endl;
    return true;
}


void TCPHandler::receiveUnexpectedHello()
{
    UInt64 skip_uint_64;
    String skip_string;

    readStringBinary(skip_string, *in);
    readVarUInt(skip_uint_64, *in);
    readVarUInt(skip_uint_64, *in);
    readVarUInt(skip_uint_64, *in);
    readStringBinary(skip_string, *in);
    readStringBinary(skip_string, *in);
    readStringBinary(skip_string, *in);

    throw NetException("Unexpected packet Hello received from client", ErrorCodes::UNEXPECTED_PACKET_FROM_CLIENT);
}


void TCPHandler::receiveIgnoredPartUUIDs()
{
    readVectorBinary(state.part_uuids_to_ignore.emplace(), *in);
}


void TCPHandler::receiveUnexpectedIgnoredPartUUIDs()
{
    std::vector<UUID> skip_part_uuids;
    readVectorBinary(skip_part_uuids, *in);
    throw NetException("Unexpected packet IgnoredPartUUIDs received from client", ErrorCodes::UNEXPECTED_PACKET_FROM_CLIENT);
}

bool TCPHandler::receiveUnexpectedData(bool throw_exception)
{
    std::cout << "receiveUnexpectedData : " << throw_exception << std::endl;
    String skip_external_table_name;
    readStringBinary(skip_external_table_name, *in);
    std::cout << "receiveUnexpectedData : 1" << throw_exception << std::endl;

    std::shared_ptr<ReadBuffer> maybe_compressed_in;
    if (last_block_in.compression == Protocol::Compression::Enable) {

    std::cout << "receiveUnexpectedData : 3" << throw_exception << std::endl;
        maybe_compressed_in = std::make_shared<CompressedReadBuffer>(*in, /* allow_different_codecs */ true);
    }
    else
        maybe_compressed_in = in;
    std::cout << "receiveUnexpectedData : 2" << throw_exception << std::endl;

    auto skip_block_in = std::make_shared<NativeReader>(*maybe_compressed_in, client_tcp_protocol_version);
    bool read_ok = skip_block_in->read();

    if (!read_ok)
        state.read_all_data = true;

    std::cout << "receiveUnexpectedData : 4" << throw_exception << std::endl;
    if (throw_exception)
        throw NetException("Unexpected packet Data received from client", ErrorCodes::UNEXPECTED_PACKET_FROM_CLIENT);
    std::cout << "receiveUnexpectedData : 5" << throw_exception << std::endl;

    return read_ok;
}

bool TCPHandler::receivePacket()
{
    UInt64 packet_type = 0;
    readVarUInt(packet_type, *in);

    switch (packet_type)
    {
        case Protocol::Client::IgnoredPartUUIDs:
            // Part uuids packet if any comes before query.
            if (!state.empty() || state.part_uuids_to_ignore)
                receiveUnexpectedIgnoredPartUUIDs();
            receiveIgnoredPartUUIDs();
            return true;
        case Protocol::Client::Query:
            if (!state.empty()) {
                receiveUnexpectedQuery();
            }
            receiveQuery();
            return true;

        case Protocol::Client::Data:
        case Protocol::Client::Scalar:
            if (state.skipping_data)
                return receiveUnexpectedData(false);
            std::cout << "state.empty: " << state.empty() << std::endl;
            if (state.empty()) {
                // receiveUnexpectedData(false);
                receiveUnexpectedData(true);
                return true;
            }
            return receiveData(packet_type == Protocol::Client::Scalar);
        case Protocol::Client::Ping:
            writeVarUInt(Protocol::Server::Pong, *out);
            out->next();
            std::cout << "receive Ping and send Pong" << std::endl;
            return false;

        case Protocol::Client::Cancel:
        {
            /// For testing connection collector.
            if (sleep_in_receive_cancel.totalMilliseconds())
            {
                std::chrono::milliseconds ms(sleep_in_receive_cancel.totalMilliseconds());
                std::this_thread::sleep_for(ms);
            }
            return false;
        }

        case Protocol::Client::Hello:
            receiveUnexpectedHello();
            return false;
        case Protocol::Client::TablesStatusRequest:
            // if (!state.empty())
            //     receiveUnexpectedTablesStatusRequest();
            // processTablesStatusRequest();
            // out->next();
            // return false;
            LOG_DEBUG(log, "Protocol::Client::TablesStatusRequest not implemented.");
            throw Exception("Unknown packet " + toString(packet_type) + " from client", ErrorCodes::UNKNOWN_PACKET_FROM_CLIENT);

        default:
            throw Exception("Unknown packet " + toString(packet_type) + " from client", ErrorCodes::UNKNOWN_PACKET_FROM_CLIENT);
    }
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
