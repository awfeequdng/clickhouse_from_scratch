
// #include <Parsers/ASTSelectWithUnionQuery.h>

// #include <Parsers/ParserSelectWithUnionQuery.h>
#include <Parsers/ParserShowTablesQuery.h>
#include <Parsers/ParserQueryWithOutput.h>
#include <Parsers/ExpressionElementParsers.h>

#include "Common/Exception.h"


namespace DB
{

bool ParserQueryWithOutput::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{
    ParserShowTablesQuery show_tables_p;
    // ParserSelectWithUnionQuery select_p;

    ASTPtr query;

    bool parsed = show_tables_p.parse(pos, query, expected);
        // select_p.parse(pos, query, expected)
        // || show_tables_p.parse(pos, query, expected);

    if (!parsed)
        return false;

    /// FIXME: try to prettify this cast using `as<>()`
    auto & query_with_output = dynamic_cast<ASTQueryWithOutput &>(*query);

    ParserKeyword s_into_outfile("INTO OUTFILE");
    if (s_into_outfile.ignore(pos, expected))
    {
        ParserStringLiteral out_file_p;
        if (!out_file_p.parse(pos, query_with_output.out_file, expected))
            return false;

        ParserKeyword s_compression_method("COMPRESSION");
        if (s_compression_method.ignore(pos, expected))
        {
            ParserStringLiteral compression;
            if (!compression.parse(pos, query_with_output.compression, expected))
                return false;
        }

        query_with_output.children.push_back(query_with_output.out_file);
    }

    ParserKeyword s_format("FORMAT");

    if (s_format.ignore(pos, expected))
    {
        ParserIdentifier format_p;

        if (!format_p.parse(pos, query_with_output.format, expected))
            return false;
        // setIdentifierSpecial(query_with_output.format);
        std::cout << "setIdentifierSpecial(query_with_output.format); not implemented yet." << std::endl;

        query_with_output.children.push_back(query_with_output.format);
    }

    // SETTINGS key1 = value1, key2 = value2, ...
    ParserKeyword s_settings("SETTINGS");
    if (s_settings.ignore(pos, expected))
    {
        std::cout << "not implemented ParserKeyword s_settings(\"SETTINGS\");" << std::endl;
        return false;
        // ParserSetQuery parser_settings(true);
        // if (!parser_settings.parse(pos, query_with_output.settings_ast, expected))
        //     return false;
        // query_with_output.children.push_back(query_with_output.settings_ast);

        // // SETTINGS after FORMAT is not parsed by the SELECT parser (ParserSelectQuery)
        // // Pass them manually, to apply in InterpreterSelectQuery::initSettings()
        // if (query->as<ASTSelectWithUnionQuery>())
        // {
        //     QueryWithOutputSettingsPushDownVisitor::Data data{query_with_output.settings_ast};
        //     QueryWithOutputSettingsPushDownVisitor(data).visit(query);
        // }
    }

    node = std::move(query);
    return true;
}

}
