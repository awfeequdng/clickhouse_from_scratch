#include <Common/formatReadable.h>
#include <Common/PODArray.h>
#include <Common/typeid_cast.h>
#include <Common/ThreadProfileEvents.h>

// #include <Interpreters/AsynchronousInsertQueue.h>
#include <IO/WriteBufferFromFile.h>
#include <IO/WriteBufferFromVector.h>
#include <IO/LimitReadBuffer.h>
#include <IO/copyData.h>

// #include <QueryPipeline/BlockIO.h>
// #include <Processors/Transforms/CountingTransform.h>
// #include <Processors/Transforms/getSourceFromASTInsertQuery.h>

// #include <Parsers/ASTIdentifier.h>
// #include <Parsers/ASTInsertQuery.h>
// #include <Parsers/ASTLiteral.h>
// #include <Parsers/ASTSelectQuery.h>
// #include <Parsers/ASTDropQuery.h>
// #include <Parsers/ASTCreateQuery.h>
// #include <Parsers/ASTRenameQuery.h>
// #include <Parsers/ASTAlterQuery.h>
// #include <Parsers/ASTSelectWithUnionQuery.h>
// #include <Parsers/ASTShowProcesslistQuery.h>
// #include <Parsers/ASTWatchQuery.h>
#include <Parsers/Lexer.h>
#include <Parsers/parseQuery.h>
#include <Parsers/ParserQuery.h>
// #include <Parsers/queryNormalization.h>
#include <Parsers/queryToString.h>

// #include <Formats/FormatFactory.h>
// #include <Storages/StorageInput.h>

// #include <Access/EnabledQuota.h>
// #include <Interpreters/ApplyWithGlobalVisitor.h>
#include <Interpreters/Context.h>
// #include <Interpreters/InterpreterFactory.h>
// #include <Interpreters/InterpreterSetQuery.h>
// #include <Interpreters/NormalizeSelectWithUnionQueryVisitor.h>
// #include <Interpreters/OpenTelemetrySpanLog.h>
// #include <Interpreters/ProcessList.h>
// #include <Interpreters/QueryLog.h>
// #include <Interpreters/ReplaceQueryParameterVisitor.h>
// #include <Interpreters/SelectQueryOptions.h>
#include <Interpreters/executeQuery.h>
// #include <Interpreters/SelectIntersectExceptQueryVisitor.h>
#include <Common/ProfileEvents.h>

// #include <Common/SensitiveDataMasker.h>
// #include <IO/CompressionMethod.h>

// #include <Processors/Transforms/LimitsCheckingTransform.h>
// #include <Processors/Transforms/MaterializingTransform.h>
// #include <Processors/Formats/IOutputFormat.h>
// #include <Processors/Executors/CompletedPipelineExecutor.h>
// #include <Processors/Sources/WaitForAsyncInsertSource.h>

#include <random>


namespace ProfileEvents
{
    extern const Event QueryMaskingRulesMatch;
    extern const Event FailedQuery;
    extern const Event FailedInsertQuery;
    extern const Event FailedSelectQuery;
    extern const Event QueryTimeMicroseconds;
    extern const Event SelectQueryTimeMicroseconds;
    extern const Event InsertQueryTimeMicroseconds;
}

namespace DB
{

namespace ErrorCodes
{
    extern const int INTO_OUTFILE_NOT_ALLOWED;
    extern const int QUERY_WAS_CANCELLED;
    extern const int LOGICAL_ERROR;
    extern const int NOT_IMPLEMENTED;
}


static void checkASTSizeLimits(const IAST & ast, const Settings & settings)
{
    if (settings.max_ast_depth)
        ast.checkDepth(settings.max_ast_depth);
    if (settings.max_ast_elements)
        ast.checkSize(settings.max_ast_elements);
}


static String joinLines(const String & query)
{
    /// Care should be taken. We don't join lines inside non-whitespace tokens (e.g. multiline string literals)
    ///  and we don't join line after comment (because it can be single-line comment).
    /// All other whitespaces replaced to a single whitespace.

    String res;
    const char * begin = query.data();
    const char * end = begin + query.size();

    Lexer lexer(begin, end);
    Token token = lexer.nextToken();
    for (; !token.isEnd(); token = lexer.nextToken())
    {
        if (token.type == TokenType::Whitespace)
        {
            res += ' ';
        }
        else if (token.type == TokenType::Comment)
        {
            res.append(token.begin, token.end);
            if (token.end < end && *token.end == '\n')
                res += '\n';
        }
        else
            res.append(token.begin, token.end);
    }

    return res;
}


static String prepareQueryForLogging(const String & query, ContextPtr context)
{
    String res = query;

    // // wiping sensitive data before cropping query by log_queries_cut_to_length,
    // // otherwise something like credit card without last digit can go to log
    // if (auto * masker = SensitiveDataMasker::getInstance())
    // {
    //     auto matches = masker->wipeSensitiveData(res);
    //     if (matches > 0)
    //     {
    //         ProfileEvents::increment(ProfileEvents::QueryMaskingRulesMatch, matches);
    //     }
    // }

    res = res.substr(0, context->getSettingsRef().log_queries_cut_to_length);

    return res;
}


/// Log query into text log (not into system table).
static void logQuery(const String & query, ContextPtr context, bool internal)
{
    if (internal)
    {
        LOG_DEBUG(&Poco::Logger::get("executeQuery"), "(internal) {}", joinLines(query));
    }
    else
    {
        const auto & client_info = context->getClientInfo();

        const auto & current_query_id = client_info.current_query_id;
        const auto & initial_query_id = client_info.initial_query_id;
        const auto & current_user = client_info.current_user;

        String comment = context->getSettingsRef().log_comment;
        size_t max_query_size = context->getSettingsRef().max_query_size;

        if (comment.size() > max_query_size)
            comment.resize(max_query_size);

        if (!comment.empty())
            comment = fmt::format(" (comment: {})", comment);

        LOG_DEBUG(&Poco::Logger::get("executeQuery"), "(from {}{}{}){} {}",
            client_info.current_address.toString(),
            (current_user != "default" ? ", user: " + current_user : ""),
            (!initial_query_id.empty() && current_query_id != initial_query_id ? ", initial_query_id: " + initial_query_id : std::string()),
            comment,
            joinLines(query));

        if (client_info.client_trace_context.trace_id != UUID())
        {
            LOG_TRACE(&Poco::Logger::get("executeQuery"),
                "OpenTelemetry traceparent '{}'",
                client_info.client_trace_context.composeTraceparentHeader());
        }
    }
}


// /// Call this inside catch block.
// static void setExceptionStackTrace(QueryLogElement & elem)
// {
//     /// Disable memory tracker for stack trace.
//     /// Because if exception is "Memory limit (for query) exceed", then we probably can't allocate another one string.
//     MemoryTracker::BlockerInThread temporarily_disable_memory_tracker(VariableContext::Global);

//     try
//     {
//         throw;
//     }
//     catch (const std::exception & e)
//     {
//         elem.stack_trace = getExceptionStackTraceString(e);
//     }
//     catch (...) {}
// }


// /// Log exception (with query info) into text log (not into system table).
// static void logException(ContextPtr context, QueryLogElement & elem)
// {
//     String comment;
//     if (!elem.log_comment.empty())
//         comment = fmt::format(" (comment: {})", elem.log_comment);

//     if (elem.stack_trace.empty())
//         LOG_ERROR(
//             &Poco::Logger::get("executeQuery"),
//             "{} (from {}){} (in query: {})",
//             elem.exception,
//             context->getClientInfo().current_address.toString(),
//             comment,
//             joinLines(elem.query));
//     else
//         LOG_ERROR(
//             &Poco::Logger::get("executeQuery"),
//             "{} (from {}){} (in query: {})"
//             ", Stack trace (when copying this message, always include the lines below):\n\n{}",
//             elem.exception,
//             context->getClientInfo().current_address.toString(),
//             comment,
//             joinLines(elem.query),
//             elem.stack_trace);
// }

inline UInt64 time_in_microseconds(std::chrono::time_point<std::chrono::system_clock> timepoint)
{
    return std::chrono::duration_cast<std::chrono::microseconds>(timepoint.time_since_epoch()).count();
}


inline UInt64 time_in_seconds(std::chrono::time_point<std::chrono::system_clock> timepoint)
{
    return std::chrono::duration_cast<std::chrono::seconds>(timepoint.time_since_epoch()).count();
}

// static void onExceptionBeforeStart(const String & query_for_logging, ContextPtr context, UInt64 current_time_us, ASTPtr ast)
// {
//     /// Exception before the query execution.
//     if (auto quota = context->getQuota())
//         quota->used(Quota::ERRORS, 1, /* check_exceeded = */ false);

//     const Settings & settings = context->getSettingsRef();

//     /// Log the start of query execution into the table if necessary.
//     QueryLogElement elem;

//     elem.type = QueryLogElementType::EXCEPTION_BEFORE_START;

//     // all callers to onExceptionBeforeStart method construct the timespec for event_time and
//     // event_time_microseconds from the same time point. So, it can be assumed that both of these
//     // times are equal up to the precision of a second.
//     elem.event_time = current_time_us / 1000000;
//     elem.event_time_microseconds = current_time_us;
//     elem.query_start_time = current_time_us / 1000000;
//     elem.query_start_time_microseconds = current_time_us;

//     elem.current_database = context->getCurrentDatabase();
//     elem.query = query_for_logging;
//     elem.normalized_query_hash = normalizedQueryHash<false>(query_for_logging);

//     // Try log query_kind if ast is valid
//     if (ast)
//     {
//         elem.query_kind = ast->getQueryKindString();
//         if (settings.log_formatted_queries)
//             elem.formatted_query = queryToString(ast);
//     }

//     // We don't calculate databases, tables and columns when the query isn't able to start

//     elem.exception_code = getCurrentExceptionCode();
//     elem.exception = getCurrentExceptionMessage(false);

//     elem.client_info = context->getClientInfo();

//     elem.log_comment = settings.log_comment;
//     if (elem.log_comment.size() > settings.max_query_size)
//         elem.log_comment.resize(settings.max_query_size);

//     if (settings.calculate_text_stack_trace)
//         setExceptionStackTrace(elem);
//     logException(context, elem);

//     /// Update performance counters before logging to query_log
//     CurrentThread::finalizePerformanceCounters();

//     if (settings.log_queries && elem.type >= settings.log_queries_min_type && !settings.log_queries_min_query_duration_ms.totalMilliseconds())
//         if (auto query_log = context->getQueryLog())
//             query_log->add(elem);

//     if (auto opentelemetry_span_log = context->getOpenTelemetrySpanLog();
//         context->query_trace_context.trace_id != UUID()
//             && opentelemetry_span_log)
//     {
//         OpenTelemetrySpanLogElement span;
//         span.trace_id = context->query_trace_context.trace_id;
//         span.span_id = context->query_trace_context.span_id;
//         span.parent_span_id = context->getClientInfo().client_trace_context.span_id;
//         span.operation_name = "query";
//         span.start_time_us = current_time_us;
//         span.finish_time_us = current_time_us;

//         /// Keep values synchronized to type enum in QueryLogElement::createBlock.
//         span.attribute_names.push_back("clickhouse.query_status");
//         span.attribute_values.push_back("ExceptionBeforeStart");

//         span.attribute_names.push_back("db.statement");
//         span.attribute_values.push_back(elem.query);

//         span.attribute_names.push_back("clickhouse.query_id");
//         span.attribute_values.push_back(elem.client_info.current_query_id);

//         if (!context->query_trace_context.tracestate.empty())
//         {
//             span.attribute_names.push_back("clickhouse.tracestate");
//             span.attribute_values.push_back(
//                 context->query_trace_context.tracestate);
//         }

//         opentelemetry_span_log->add(span);
//     }

//     ProfileEvents::increment(ProfileEvents::FailedQuery);

//     if (ast)
//     {
//         if (ast->as<ASTSelectQuery>() || ast->as<ASTSelectWithUnionQuery>())
//         {
//             ProfileEvents::increment(ProfileEvents::FailedSelectQuery);
//         }
//         else if (ast->as<ASTInsertQuery>())
//         {
//             ProfileEvents::increment(ProfileEvents::FailedInsertQuery);
//         }
//     }
// }

// static void setQuerySpecificSettings(ASTPtr & ast, ContextMutablePtr context)
// {
//     if (auto * ast_insert_into = ast->as<ASTInsertQuery>())
//     {
//         if (ast_insert_into->watch)
//             context->setSetting("output_format_enable_streaming", 1);
//     }
// }

// static void applySettingsFromSelectWithUnion(const ASTSelectWithUnionQuery & select_with_union, ContextMutablePtr context)
// {
//     const ASTs & children = select_with_union.list_of_selects->children;
//     if (children.empty())
//         return;

//     // We might have an arbitrarily complex UNION tree, so just give
//     // up if the last first-order child is not a plain SELECT.
//     // It is flattened later, when we process UNION ALL/DISTINCT.
//     const auto * last_select = children.back()->as<ASTSelectQuery>();
//     if (last_select && last_select->settings())
//     {
//         InterpreterSetQuery(last_select->settings(), context).executeForCurrentContext();
//     }
// }

static ASTPtr executeQueryImpl(
    const char * begin,
    const char * end,
    ContextMutablePtr context,
    bool internal,
    QueryProcessingStage::Enum stage,
    ReadBuffer * istr)
{
    const auto current_time = std::chrono::system_clock::now();

    auto & client_info = context->getClientInfo();

    // If it's not an internal query and we don't see an initial_query_start_time yet, initialize it
    // to current time. Internal queries are those executed without an independent client context,
    // thus should not set initial_query_start_time, because it might introduce data race. It's also
    // possible to have unset initial_query_start_time for non-internal and non-initial queries. For
    // example, the query is from an initiator that is running an old version of clickhouse.
    if (!internal && client_info.initial_query_start_time == 0)
    {
        client_info.initial_query_start_time = time_in_seconds(current_time);
        client_info.initial_query_start_time_microseconds = time_in_microseconds(current_time);
    }

    assert(internal || CurrentThread::get().getQueryContext());
    assert(internal || CurrentThread::get().getQueryContext()->getCurrentQueryId() == CurrentThread::getQueryId());

    const Settings & settings = context->getSettingsRef();

    ASTPtr ast;
    const char * query_end;

    /// Don't limit the size of internal queries.
    size_t max_query_size = 0;
    if (!internal) max_query_size = settings.max_query_size;

    String query_database;
    String query_table;
    try
    {
        ParserQuery parser(end);
        /// TODO: parser should fail early when max_query_size limit is reached.
        std::cout << "before parseQuery: " << begin << std::endl;
        ast = parseQuery(parser, begin, end, "", max_query_size, settings.max_parser_depth);
    }
    catch (...)
    {
        /// Anyway log the query.
        String query = String(begin, begin + std::min(end - begin, static_cast<ptrdiff_t>(max_query_size)));

        auto query_for_logging = prepareQueryForLogging(query, context);
        logQuery(query_for_logging, context, internal);

        if (!internal)
        {
            // onExceptionBeforeStart(query_for_logging, context, time_in_microseconds(current_time), ast);
        }

        throw;
    }


    return ast;
}


// BlockIO executeQuery(
//     const String & query,
//     ContextMutablePtr context,
//     bool internal,
//     QueryProcessingStage::Enum stage)
bool executeQuery(
    const String & query,
    ContextMutablePtr context,
    bool internal,
    QueryProcessingStage::Enum stage)
{
    ASTPtr ast;
    // BlockIO streams;
    // std::tie(ast, streams) = executeQueryImpl(query.data(), query.data() + query.size(), context, internal, stage, nullptr);
    ast = executeQueryImpl(query.data(), query.data() + query.size(), context, internal, stage, nullptr);

    // if (const auto * ast_query_with_output = dynamic_cast<const ASTQueryWithOutput *>(ast.get()))
    // {
    //     String format_name = ast_query_with_output->format
    //             ? getIdentifierName(ast_query_with_output->format)
    //             : context->getDefaultFormat();

    //     if (format_name == "Null")
    //         streams.null_format = true;
    // }


    return true;
}

// bool executeQuery(
//     bool allow_processors,
//     const String & query,
//     ContextMutablePtr context,
//     bool internal,
//     QueryProcessingStage::Enum stage)
// {
//     if (!allow_processors)
//         throw Exception(ErrorCodes::NOT_IMPLEMENTED, "Flag allow_processors is deprecated for executeQuery");

//     return executeQuery(query, context, internal, stage);
// }


// void executeQuery(
//     ReadBuffer & istr,
//     WriteBuffer & ostr,
//     bool allow_into_outfile,
//     ContextMutablePtr context,
//     SetResultDetailsFunc set_result_details,
//     const std::optional<FormatSettings> & output_format_settings)
// {
//     PODArray<char> parse_buf;
//     const char * begin;
//     const char * end;

//     istr.nextIfAtEnd();

//     size_t max_query_size = context->getSettingsRef().max_query_size;

//     if (istr.buffer().end() - istr.position() > static_cast<ssize_t>(max_query_size))
//     {
//         /// If remaining buffer space in 'istr' is enough to parse query up to 'max_query_size' bytes, then parse inplace.
//         begin = istr.position();
//         end = istr.buffer().end();
//         istr.position() += end - begin;
//     }
//     else
//     {
//         /// FIXME: this is an extra copy not required for async insertion.

//         /// If not - copy enough data into 'parse_buf'.
//         WriteBufferFromVector<PODArray<char>> out(parse_buf);
//         LimitReadBuffer limit(istr, max_query_size + 1, false);
//         copyData(limit, out);
//         out.finalize();

//         begin = parse_buf.data();
//         end = begin + parse_buf.size();
//     }

//     ASTPtr ast;
//     BlockIO streams;

//     std::tie(ast, streams) = executeQueryImpl(begin, end, context, false, QueryProcessingStage::Complete, &istr);
//     auto & pipeline = streams.pipeline;

//     std::unique_ptr<WriteBuffer> compressed_buffer;
//     try
//     {
//         if (pipeline.pushing())
//         {
//             auto pipe = getSourceFromASTInsertQuery(ast, true, pipeline.getHeader(), context, nullptr);
//             pipeline.complete(std::move(pipe));
//         }
//         else if (pipeline.pulling())
//         {
//             const ASTQueryWithOutput * ast_query_with_output = dynamic_cast<const ASTQueryWithOutput *>(ast.get());

//             WriteBuffer * out_buf = &ostr;
//             if (ast_query_with_output && ast_query_with_output->out_file)
//             {
//                 if (!allow_into_outfile)
//                     throw Exception("INTO OUTFILE is not allowed", ErrorCodes::INTO_OUTFILE_NOT_ALLOWED);

//                 const auto & out_file = typeid_cast<const ASTLiteral &>(*ast_query_with_output->out_file).value.safeGet<std::string>();

//                 std::string compression_method;
//                 if (ast_query_with_output->compression)
//                 {
//                     const auto & compression_method_node = ast_query_with_output->compression->as<ASTLiteral &>();
//                     compression_method = compression_method_node.value.safeGet<std::string>();
//                 }

//                 compressed_buffer = wrapWriteBufferWithCompressionMethod(
//                     std::make_unique<WriteBufferFromFile>(out_file, DBMS_DEFAULT_BUFFER_SIZE, O_WRONLY | O_EXCL | O_CREAT),
//                     chooseCompressionMethod(out_file, compression_method),
//                     /* compression level = */ 3
//                 );
//             }

//             String format_name = ast_query_with_output && (ast_query_with_output->format != nullptr)
//                                     ? getIdentifierName(ast_query_with_output->format)
//                                     : context->getDefaultFormat();

//             auto out = FormatFactory::instance().getOutputFormatParallelIfPossible(
//                 format_name,
//                 compressed_buffer ? *compressed_buffer : *out_buf,
//                 materializeBlock(pipeline.getHeader()),
//                 context,
//                 {},
//                 output_format_settings);

//             out->setAutoFlush();

//             /// Save previous progress callback if any. TODO Do it more conveniently.
//             auto previous_progress_callback = context->getProgressCallback();

//             /// NOTE Progress callback takes shared ownership of 'out'.
//             pipeline.setProgressCallback([out, previous_progress_callback] (const Progress & progress)
//             {
//                 if (previous_progress_callback)
//                     previous_progress_callback(progress);
//                 out->onProgress(progress);
//             });

//             if (set_result_details)
//                 set_result_details(
//                     context->getClientInfo().current_query_id, out->getContentType(), format_name, DateLUT::instance().getTimeZone());

//             pipeline.complete(std::move(out));
//         }
//         else
//         {
//             pipeline.setProgressCallback(context->getProgressCallback());
//         }

//         if (pipeline.initialized())
//         {
//             CompletedPipelineExecutor executor(pipeline);
//             executor.execute();
//         }
//         else
//         {
//             /// It's possible to have queries without input and output.
//         }
//     }
//     catch (...)
//     {
//         streams.onException();
//         throw;
//     }

//     streams.onFinish();
// }

// void executeTrivialBlockIO(BlockIO & streams, ContextPtr context)
// {
//     try
//     {
//         if (!streams.pipeline.initialized())
//             return;

//         if (!streams.pipeline.completed())
//             throw Exception(ErrorCodes::LOGICAL_ERROR, "Query pipeline requires output, but no output buffer provided, it's a bug");

//         streams.pipeline.setProgressCallback(context->getProgressCallback());
//         CompletedPipelineExecutor executor(streams.pipeline);
//         executor.execute();
//     }
//     catch (...)
//     {
//         streams.onException();
//         throw;
//     }

//     streams.onFinish();
// }

}
