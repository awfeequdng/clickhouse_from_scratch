#include <Formats/FormatFactory.h>

#include <algorithm>
#include <Common/Exception.h>
#include <Interpreters/Context.h>
#include <Core/Settings.h>
#include <Formats/FormatSettings.h>
#include <Poco/URI.h>

#include <IO/BufferWithOwnMemory.h>
#include <IO/ReadHelpers.h>

namespace DB
{

namespace ErrorCodes
{
    extern const int UNKNOWN_FORMAT;
    extern const int LOGICAL_ERROR;
    extern const int FORMAT_IS_NOT_SUITABLE_FOR_INPUT;
    extern const int FORMAT_IS_NOT_SUITABLE_FOR_OUTPUT;
}

const FormatFactory::Creators & FormatFactory::getCreators(const String & name) const
{
    auto it = dict.find(name);
    if (dict.end() != it)
        return it->second;
    throw Exception("Unknown format " + name, ErrorCodes::UNKNOWN_FORMAT);
}

FormatSettings getFormatSettings(ContextPtr context)
{
    const auto & settings = context->getSettingsRef();

    return getFormatSettings(context, settings);
}

template <typename Settings>
FormatSettings getFormatSettings(ContextPtr context, const Settings & settings)
{
    FormatSettings format_settings;

    format_settings.avro.allow_missing_fields = settings.input_format_avro_allow_missing_fields;
    format_settings.avro.output_codec = settings.output_format_avro_codec;
    format_settings.avro.output_sync_interval = settings.output_format_avro_sync_interval;
    format_settings.avro.schema_registry_url = settings.format_avro_schema_registry_url.toString();
    format_settings.avro.string_column_pattern = settings.output_format_avro_string_column_pattern.toString();
    format_settings.avro.output_rows_in_file = settings.output_format_avro_rows_in_file;
    format_settings.csv.allow_double_quotes = settings.format_csv_allow_double_quotes;
    format_settings.csv.allow_single_quotes = settings.format_csv_allow_single_quotes;
    format_settings.csv.crlf_end_of_line = settings.output_format_csv_crlf_end_of_line;
    format_settings.csv.delimiter = settings.format_csv_delimiter;
    format_settings.csv.empty_as_default = settings.input_format_csv_empty_as_default;
    format_settings.csv.input_format_enum_as_number = settings.input_format_csv_enum_as_number;
    format_settings.csv.null_representation = settings.format_csv_null_representation;
    format_settings.csv.input_format_arrays_as_nested_csv = settings.input_format_csv_arrays_as_nested_csv;
    format_settings.custom.escaping_rule = settings.format_custom_escaping_rule;
    format_settings.custom.field_delimiter = settings.format_custom_field_delimiter;
    format_settings.custom.result_after_delimiter = settings.format_custom_result_after_delimiter;
    format_settings.custom.result_before_delimiter = settings.format_custom_result_before_delimiter;
    format_settings.custom.row_after_delimiter = settings.format_custom_row_after_delimiter;
    format_settings.custom.row_before_delimiter = settings.format_custom_row_before_delimiter;
    format_settings.custom.row_between_delimiter = settings.format_custom_row_between_delimiter;
    format_settings.date_time_input_format = settings.date_time_input_format;
    format_settings.date_time_output_format = settings.date_time_output_format;
    format_settings.enable_streaming = settings.output_format_enable_streaming;
    format_settings.import_nested_json = settings.input_format_import_nested_json;
    format_settings.input_allow_errors_num = settings.input_format_allow_errors_num;
    format_settings.input_allow_errors_ratio = settings.input_format_allow_errors_ratio;
    format_settings.json.array_of_rows = settings.output_format_json_array_of_rows;
    format_settings.json.escape_forward_slashes = settings.output_format_json_escape_forward_slashes;
    format_settings.json.named_tuples_as_objects = settings.output_format_json_named_tuples_as_objects;
    format_settings.json.quote_64bit_integers = settings.output_format_json_quote_64bit_integers;
    format_settings.json.quote_denormals = settings.output_format_json_quote_denormals;
    format_settings.null_as_default = settings.input_format_null_as_default;
    format_settings.decimal_trailing_zeros = settings.output_format_decimal_trailing_zeros;
    format_settings.parquet.row_group_size = settings.output_format_parquet_row_group_size;
    format_settings.parquet.import_nested = settings.input_format_parquet_import_nested;
    format_settings.pretty.charset = settings.output_format_pretty_grid_charset.toString() == "ASCII" ? FormatSettings::Pretty::Charset::ASCII : FormatSettings::Pretty::Charset::UTF8;
    format_settings.pretty.color = settings.output_format_pretty_color;
    format_settings.pretty.max_column_pad_width = settings.output_format_pretty_max_column_pad_width;
    format_settings.pretty.max_rows = settings.output_format_pretty_max_rows;
    format_settings.pretty.max_value_width = settings.output_format_pretty_max_value_width;
    format_settings.pretty.output_format_pretty_row_numbers = settings.output_format_pretty_row_numbers;
    format_settings.regexp.escaping_rule = settings.format_regexp_escaping_rule;
    format_settings.regexp.regexp = settings.format_regexp;
    format_settings.regexp.skip_unmatched = settings.format_regexp_skip_unmatched;
    format_settings.schema.format_schema = settings.format_schema;
    format_settings.schema.is_server = context->hasGlobalContext() && (context->getGlobalContext()->getApplicationType() == Context::ApplicationType::SERVER);
    format_settings.skip_unknown_fields = settings.input_format_skip_unknown_fields;
    format_settings.template_settings.resultset_format = settings.format_template_resultset;
    format_settings.template_settings.row_between_delimiter = settings.format_template_rows_between_delimiter;
    format_settings.template_settings.row_format = settings.format_template_row;
    format_settings.tsv.crlf_end_of_line = settings.output_format_tsv_crlf_end_of_line;
    format_settings.tsv.empty_as_default = settings.input_format_tsv_empty_as_default;
    format_settings.tsv.input_format_enum_as_number = settings.input_format_tsv_enum_as_number;
    format_settings.tsv.null_representation = settings.format_tsv_null_representation;
    format_settings.values.accurate_types_of_literals = settings.input_format_values_accurate_types_of_literals;
    format_settings.values.deduce_templates_of_expressions = settings.input_format_values_deduce_templates_of_expressions;
    format_settings.values.interpret_expressions = settings.input_format_values_interpret_expressions;
    format_settings.with_names_use_header = settings.input_format_with_names_use_header;
    format_settings.with_types_use_header = settings.input_format_with_types_use_header;
    format_settings.write_statistics = settings.output_format_write_statistics;
    format_settings.arrow.low_cardinality_as_dictionary = settings.output_format_arrow_low_cardinality_as_dictionary;
    format_settings.arrow.import_nested = settings.input_format_arrow_import_nested;
    format_settings.orc.import_nested = settings.input_format_orc_import_nested;
    format_settings.defaults_for_omitted_fields = settings.input_format_defaults_for_omitted_fields;
    format_settings.capn_proto.enum_comparing_mode = settings.format_capn_proto_enum_comparising_mode;

    return format_settings;
}

template FormatSettings getFormatSettings<FormatFactorySettings>(ContextPtr context, const FormatFactorySettings & settings);

template FormatSettings getFormatSettings<Settings>(ContextPtr context, const Settings & settings);

void FormatFactory::registerInputFormat(const String & name, InputCreator input_creator)
{
    auto & target = dict[name].input_creator;
    if (target)
        throw Exception("FormatFactory: Input format " + name + " is already registered", ErrorCodes::LOGICAL_ERROR);
    target = std::move(input_creator);
}

void FormatFactory::registerNonTrivialPrefixAndSuffixChecker(const String & name, NonTrivialPrefixAndSuffixChecker non_trivial_prefix_and_suffix_checker)
{
    auto & target = dict[name].non_trivial_prefix_and_suffix_checker;
    if (target)
        throw Exception("FormatFactory: Non trivial prefix and suffix checker " + name + " is already registered", ErrorCodes::LOGICAL_ERROR);
    target = std::move(non_trivial_prefix_and_suffix_checker);
}

void FormatFactory::registerOutputFormat(const String & name, OutputCreator output_creator)
{
    auto & target = dict[name].output_creator;
    if (target)
        throw Exception("FormatFactory: Output format " + name + " is already registered", ErrorCodes::LOGICAL_ERROR);
    target = std::move(output_creator);
}

void FormatFactory::markOutputFormatSupportsParallelFormatting(const String & name)
{
    auto & target = dict[name].supports_parallel_formatting;
    if (target)
        throw Exception("FormatFactory: Output format " + name + " is already marked as supporting parallel formatting", ErrorCodes::LOGICAL_ERROR);
    target = true;
}


void FormatFactory::markFormatAsColumnOriented(const String & name)
{
    auto & target = dict[name].is_column_oriented;
    if (target)
        throw Exception("FormatFactory: Format " + name + " is already marked as column oriented", ErrorCodes::LOGICAL_ERROR);
    target = true;
}


bool FormatFactory::checkIfFormatIsColumnOriented(const String & name)
{
    const auto & target = getCreators(name);
    return target.is_column_oriented;
}

bool FormatFactory::isInputFormat(const String & name) const
{
    auto it = dict.find(name);
    return it != dict.end() && it->second.input_creator;
}

bool FormatFactory::isOutputFormat(const String & name) const
{
    auto it = dict.find(name);
    return it != dict.end() && it->second.output_creator;
}

FormatFactory & FormatFactory::instance()
{
    static FormatFactory ret;
    return ret;
}

}
