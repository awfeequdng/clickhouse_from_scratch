#pragma once

#include <Poco/Net/TCPServerConnection.h>
#include "IO/ReadBuffer.h"
#include "IO/WriteBuffer.h"
#include <Core/Protocol.h>
#include "IServer.h"
#include <Common/Stopwatch.h>
#include <optional>
#include <base/UUID.h>
#include <Interpreters/Context_fwd.h>
#include <Interpreters/Session.h>
#include <IO/TimeoutSetter.h>
#include <Formats/NativeReader.h>
#include <Formats/NativeWriter.h>

#include <Core/QueryProcessingStage.h>
namespace Poco { class Logger; }

namespace DB
{

/// State of query processing.
struct QueryState
{
    /// Identifier of the query.
    String query_id;

    QueryProcessingStage::Enum stage = QueryProcessingStage::Complete;
    Protocol::Compression compression = Protocol::Compression::Disable;

    /// From where to read data for INSERT.
    std::shared_ptr<ReadBuffer> maybe_compressed_in;
    std::unique_ptr<NativeReader> block_in;

    /// Where to write result data.
    std::shared_ptr<WriteBuffer> maybe_compressed_out;
    std::unique_ptr<NativeWriter> block_out;
    Block block_for_insert;

    /// Query text.
    String query;


    /// Is request cancelled
    bool is_cancelled = false;
    bool is_connection_closed = false;
    /// empty or not
    bool is_empty = true;
    /// Data was sent.
    bool sent_all_data = false;
    /// Request requires data from the client (INSERT, but not INSERT SELECT).
    bool need_receive_data_for_insert = false;
    /// Data was read.
    bool read_all_data = false;

    /// A state got uuids to exclude from a query
    std::optional<std::vector<UUID>> part_uuids_to_ignore;

    /// Request requires data from client for function input()
    bool need_receive_data_for_input = false;
    /// temporary place for incoming data block for input()
    Block block_for_input;
    /// sample block from StorageInput
    Block input_header;

    /// If true, the data packets will be skipped instead of reading. Used to recover after errors.
    bool skipping_data = false;

    /// Timeouts setter for current query
    std::unique_ptr<TimeoutSetter> timeout_setter;

    void reset()
    {
        *this = QueryState();
    }

    bool empty() const
    {
        return is_empty;
    }
};

struct LastBlockInputParameters
{
    Protocol::Compression compression = Protocol::Compression::Disable;
};

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
    TCPHandler(IServer & server_, const Poco::Net::StreamSocket & socket_, std::string server_display_name_);
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
    Poco::Timespan sleep_in_receive_cancel = 100000;

    std::unique_ptr<Session> session;
    ContextMutablePtr query_context;

    /// Streams for reading/writing from/to client connection socket.
    std::shared_ptr<ReadBuffer> in;
    std::shared_ptr<WriteBuffer> out;

    /// Time after the last check to stop the request and send the progress.
    Stopwatch after_check_cancelled;
    Stopwatch after_send_progress;

    String default_database;

    /// For inter-server secret (remote_server.*.secret)
    bool is_interserver_mode = false;
    String salt;
    String cluster;
    String cluster_secret;

    std::mutex task_callback_mutex;

    /// At the moment, only one ongoing query in the connection is supported at a time.
    QueryState state;
    /// Last block input parameters are saved to be able to receive unexpected data packet sent after exception.
    LastBlockInputParameters last_block_in;

    /// It is the name of the server that will be sent to the client.
    String server_display_name;

    void runImpl();
    void extractConnectionSettingsFromContext(const ContextPtr & context);
    // bool receiveProxyHeader();
    void receiveHello();
    bool receivePacket();
    void receiveQuery();
    void receiveIgnoredPartUUIDs();
    String receiveReadTaskResponseAssumeLocked();
    bool receiveData(bool scalar);
    bool readDataNext();
    void readData();
    void skipData();
    void receiveClusterNameAndSalt();

    bool receiveUnexpectedData(bool throw_exception = true);
    [[noreturn]] void receiveUnexpectedQuery();
    [[noreturn]] void receiveUnexpectedIgnoredPartUUIDs();
    [[noreturn]] void receiveUnexpectedHello();
    [[noreturn]] void receiveUnexpectedTablesStatusRequest();

    void sendHello();
    // void sendData(const Block & block);    /// Write a block to the network.
    // void sendLogData(const Block & block);
    // void sendTableColumns(const ColumnsDescription & columns);
    void sendException(const Exception & e, bool with_stack_trace);
    void sendProgress();
    void sendLogs();
    void sendEndOfStream();
    void sendPartUUIDs();
    void sendReadTaskRequestAssumeLocked();
    // void sendTotals(const Block & totals);
    // void sendExtremes(const Block & extremes);

    void initBlockInput();
};

}
