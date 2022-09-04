#pragma once

#include <Common/Allocator.h>
#include <Formats/FormatSettings.h>
#include <Interpreters/Context_fwd.h>
#include <base/types.h>

#include <Core/Settings.h>
#include <functional>
#include <memory>
#include <unordered_map>

namespace DB
{

struct Settings;
struct FormatFactorySettings;

class ReadBuffer;
class WriteBuffer;


template <typename Allocator>
struct Memory;

FormatSettings getFormatSettings(ContextPtr context);

template <typename T>
FormatSettings getFormatSettings(ContextPtr context, const T & settings);

/** Allows to create an IInputFormat or IOutputFormat by the name of the format.
  * Note: format and compression are independent things.
  */
class FormatFactory final
{
public:
    /// This callback allows to perform some additional actions after reading a single row.
    /// It's initial purpose was to extract payload for virtual columns from Kafka Consumer ReadBuffer.
    using ReadCallback = std::function<void()>;

    /** Fast reading data from buffer and save result to memory.
      * Reads at least min_chunk_bytes and some more until the end of the chunk, depends on the format.
      * Used in ParallelParsingBlockInputStream.
      */
    using FileSegmentationEngine = std::function<std::pair<bool, size_t>(
        ReadBuffer & buf,
        DB::Memory<Allocator<false>> & memory,
        size_t min_chunk_bytes)>;

private:
    // using InputCreator = std::function<InputFormatPtr(
    //         ReadBuffer & buf,
    //         const Block & header,
    //         const RowInputFormatParams & params,
    //         const FormatSettings & settings)>;

    // using OutputCreator = std::function<OutputFormatPtr(
    //         WriteBuffer & buf,
    //         const Block & sample,
    //         const RowOutputFormatParams & params,
    //         const FormatSettings & settings)>;
    using InputCreator = std::function<void()>;

    using OutputCreator = std::function<void()>;

    /// Some input formats can have non trivial readPrefix() and readSuffix(),
    /// so in some cases there is no possibility to use parallel parsing.
    /// The checker should return true if parallel parsing should be disabled.
    using NonTrivialPrefixAndSuffixChecker = std::function<bool(ReadBuffer & buf)>;

    struct Creators
    {
        InputCreator input_creator;
        OutputCreator output_creator;
        FileSegmentationEngine file_segmentation_engine;
        bool supports_parallel_formatting{false};
        bool is_column_oriented{false};
        NonTrivialPrefixAndSuffixChecker non_trivial_prefix_and_suffix_checker;
    };

    using FormatsDictionary = std::unordered_map<String, Creators>;

public:
    static FormatFactory & instance();

    /// Register format by its name.
    void registerInputFormat(const String & name, InputCreator input_creator);
    void registerOutputFormat(const String & name, OutputCreator output_creator);

    void registerNonTrivialPrefixAndSuffixChecker(
                const String & name,
                NonTrivialPrefixAndSuffixChecker non);
    void markOutputFormatSupportsParallelFormatting(const String & name);
    void markFormatAsColumnOriented(const String & name);

    bool checkIfFormatIsColumnOriented(const String & name);

    const FormatsDictionary & getAllFormats() const
    {
        return dict;
    }

    bool isInputFormat(const String & name) const;
    bool isOutputFormat(const String & name) const;

private:
    FormatsDictionary dict;

    const Creators & getCreators(const String & name) const;
};

}
