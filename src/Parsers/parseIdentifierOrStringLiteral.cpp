#include "parseIdentifierOrStringLiteral.h"

#include "ExpressionElementParsers.h"
#include "ASTLiteral.h"
#include <Parsers/CommonParsers.h>
// #include <Parsers/ExpressionListParsers.h>
#include <Common/typeid_cast.h>

namespace DB
{
bool parseIdentifierOrStringLiteral(IParser::Pos & pos, Expected & expected, String & result)
{
    return IParserBase::wrapParseImpl(pos, [&]
    {
        ASTPtr ast;
        if (ParserIdentifier().parse(pos, ast, expected))
        {
            // result = getIdentifierName(ast);
            std::cout << "result = getIdentifierName(ast); not implemented yet." << std::endl;
            result = "not implement result";
            return true;
        }

        if (ParserStringLiteral().parse(pos, ast, expected))
        {
            result = ast->as<ASTLiteral &>().value.safeGet<String>();
            return true;
        }

        return false;
    });
}


bool parseIdentifiersOrStringLiterals(IParser::Pos & pos, Expected & expected, Strings & result)
{
    Strings res;

    auto parse_single_id_or_literal = [&]
    {
        String str;
        if (!parseIdentifierOrStringLiteral(pos, expected, str))
            return false;

        res.emplace_back(std::move(str));
        return true;
    };

    // if (!ParserList::parseUtil(pos, expected, parse_single_id_or_literal, false))
    //     return false;
    std::cout << "not implemented yet: ParserList::parseUtil(pos, e" << std::endl;
    return false;

    result = std::move(res);
    return true;
}

}
