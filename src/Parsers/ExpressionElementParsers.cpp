#include <errno.h>
#include <cstdlib>

#include <Poco/String.h>

#include <IO/ReadBufferFromMemory.h>
#include <IO/ReadHelpers.h>
#include <Parsers/DumpASTNode.h>
#include <Common/typeid_cast.h>

#include <Parsers/ASTAsterisk.h>
#include <Parsers/ASTLiteral.h>
#include <Parsers/ASTQueryParameter.h>
#include <Parsers/ASTSubquery.h>
#include <Parsers/IAST.h>
#include <Parsers/CommonParsers.h>
#include <Parsers/parseIdentifierOrStringLiteral.h>
#include <Parsers/ExpressionElementParsers.h>

#include <Parsers/queryToString.h>

namespace DB
{

namespace ErrorCodes
{
    extern const int BAD_ARGUMENTS;
    extern const int SYNTAX_ERROR;
    extern const int LOGICAL_ERROR;
}


template <TokenType ...tokens>
static bool isOneOf(TokenType token)
{
    return ((token == tokens) || ...);
}


bool ParserNull::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{
    ParserKeyword nested_parser("NULL");
    if (nested_parser.parse(pos, node, expected))
    {
        node = std::make_shared<ASTLiteral>(Null());
        return true;
    }
    else
        return false;
}

static bool parseNumber(char * buffer, size_t size, bool negative, int base, Field & res)
{
    errno = 0;    /// Functions strto* don't clear errno.

    char * pos_integer = buffer;
    UInt64 uint_value = std::strtoull(buffer, &pos_integer, base);

    if (pos_integer == buffer + size && errno != ERANGE && (!negative || uint_value <= (1ULL << 63)))
    {
        if (negative)
            res = static_cast<Int64>(-uint_value);
        else
            res = uint_value;

        return true;
    }

    return false;
}

bool ParserNumber::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{
    Pos literal_begin = pos;
    bool negative = false;

    if (pos->type == TokenType::Minus)
    {
        ++pos;
        negative = true;
    }
    else if (pos->type == TokenType::Plus)  /// Leading plus is simply ignored.
        ++pos;

    Field res;

    if (!pos.isValid())
        return false;

    /** Maximum length of number. 319 symbols is enough to write maximum double in decimal form.
      * Copy is needed to use strto* functions, which require 0-terminated string.
      */
    static constexpr size_t MAX_LENGTH_OF_NUMBER = 319;

    if (pos->size() > MAX_LENGTH_OF_NUMBER)
    {
        expected.add(pos, "number");
        return false;
    }

    char buf[MAX_LENGTH_OF_NUMBER + 1];

    memcpy(buf, pos->begin, pos->size());
    buf[pos->size()] = 0;

    char * pos_double = buf;
    errno = 0;    /// Functions strto* don't clear errno.
    Float64 float_value = std::strtod(buf, &pos_double);
    if (pos_double != buf + pos->size() || errno == ERANGE)
    {
        /// Try to parse number as binary literal representation. Example: 0b0001.
        if (pos->size() > 2 && buf[0] == '0' && buf[1] == 'b')
        {
            char * buf_skip_prefix = buf + 2;

            if (parseNumber(buf_skip_prefix, pos->size() - 2, negative, 2, res))
            {
                auto literal = std::make_shared<ASTLiteral>(res);
                literal->begin = literal_begin;
                literal->end = ++pos;
                node = literal;

                return true;
            }
        }

        expected.add(pos, "number");
        return false;
    }

    if (float_value < 0)
        throw Exception("Logical error: token number cannot begin with minus, but parsed float number is less than zero.", ErrorCodes::LOGICAL_ERROR);

    if (negative)
        float_value = -float_value;

    res = float_value;

    /// try to use more exact type: UInt64

    parseNumber(buf, pos->size(), negative, 0, res);

    auto literal = std::make_shared<ASTLiteral>(res);
    literal->begin = literal_begin;
    literal->end = ++pos;
    node = literal;

    return true;
}


bool ParserUnsignedInteger::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{
    Field res;

    if (!pos.isValid())
        return false;

    UInt64 x = 0;
    ReadBufferFromMemory in(pos->begin, pos->size());
    if (!tryReadIntText(x, in) || in.count() != pos->size())
    {
        expected.add(pos, "unsigned integer");
        return false;
    }

    res = x;
    auto literal = std::make_shared<ASTLiteral>(res);
    literal->begin = pos;
    literal->end = ++pos;
    node = literal;
    return true;
}


bool ParserStringLiteral::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{
    if (pos->type != TokenType::StringLiteral && pos->type != TokenType::HereDoc)
        return false;

    String s;

    if (pos->type == TokenType::StringLiteral)
    {
        ReadBufferFromMemory in(pos->begin, pos->size());

        try
        {
            readQuotedStringWithSQLStyle(s, in);
        }
        catch (const Exception &)
        {
            expected.add(pos, "string literal");
            return false;
        }

        if (in.count() != pos->size())
        {
            expected.add(pos, "string literal");
            return false;
        }
    }
    else if (pos->type == TokenType::HereDoc)
    {
        std::string_view here_doc(pos->begin, pos->size());
        size_t heredoc_size = here_doc.find('$', 1) + 1;
        assert(heredoc_size != std::string_view::npos);
        s = String(pos->begin + heredoc_size, pos->size() - heredoc_size * 2);
    }

    auto literal = std::make_shared<ASTLiteral>(s);
    literal->begin = pos;
    literal->end = ++pos;
    node = literal;
    return true;
}

template <typename Collection>
bool ParserCollectionOfLiterals<Collection>::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{
    if (pos->type != opening_bracket)
        return false;

    Pos literal_begin = pos;

    Collection arr;
    ParserLiteral literal_p;
    ParserCollectionOfLiterals<Collection> collection_p(opening_bracket, closing_bracket);

    ++pos;
    while (pos.isValid())
    {
        if (!arr.empty())
        {
            if (pos->type == closing_bracket)
            {
                std::shared_ptr<ASTLiteral> literal;

                /// Parse one-element tuples (e.g. (1)) later as single values for backward compatibility.
                if (std::is_same_v<Collection, Tuple> && arr.size() == 1)
                    return false;

                literal = std::make_shared<ASTLiteral>(arr);
                literal->begin = literal_begin;
                literal->end = ++pos;
                node = literal;
                return true;
            }
            else if (pos->type == TokenType::Comma)
            {
                ++pos;
            }
            else if (pos->type == TokenType::Colon && std::is_same_v<Collection, Map> && arr.size() % 2 == 1)
            {
                ++pos;
            }
            else
            {
                expected.add(pos, "comma or closing bracket");
                return false;
            }
        }

        ASTPtr literal_node;
        if (!literal_p.parse(pos, literal_node, expected) && !collection_p.parse(pos, literal_node, expected))
            return false;

        arr.push_back(literal_node->as<ASTLiteral &>().value);
    }

    expected.add(pos, getTokenName(closing_bracket));
    return false;
}

template bool ParserCollectionOfLiterals<Array>::parseImpl(Pos & pos, ASTPtr & node, Expected & expected);
template bool ParserCollectionOfLiterals<Tuple>::parseImpl(Pos & pos, ASTPtr & node, Expected & expected);
template bool ParserCollectionOfLiterals<Map>::parseImpl(Pos & pos, ASTPtr & node, Expected & expected);

bool ParserLiteral::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{
    ParserNull null_p;
    ParserNumber num_p;
    ParserStringLiteral str_p;

    if (null_p.parse(pos, node, expected))
        return true;

    if (num_p.parse(pos, node, expected))
        return true;

    if (str_p.parse(pos, node, expected))
        return true;

    return false;
}


const char * ParserAlias::restricted_keywords[] =
{
    "ALL",
    "ANTI",
    "ANY",
    "ARRAY",
    "ASOF",
    "BETWEEN",
    "CROSS",
    "FINAL",
    "FORMAT",
    "FROM",
    "FULL",
    "GLOBAL",
    "GROUP",
    "HAVING",
    "ILIKE",
    "INNER",
    "INTO",
    "JOIN",
    "LEFT",
    "LIKE",
    "LIMIT",
    "NOT",
    "OFFSET",
    "ON",
    "ONLY", /// YQL synonym for ANTI. Note: YQL is the name of one of Yandex proprietary languages, completely unrelated to ClickHouse.
    "ORDER",
    "PREWHERE",
    "RIGHT",
    "SAMPLE",
    "SEMI",
    "SETTINGS",
    "UNION",
    "USING",
    "WHERE",
    "WINDOW",
    "WITH",
    "INTERSECT",
    "EXCEPT",
    nullptr
};

bool ParserAlias::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{
    ParserKeyword s_as("AS");
    // ParserIdentifier id_p;

    bool has_as_word = s_as.ignore(pos, expected);
    if (!allow_alias_without_as_keyword && !has_as_word)
        return false;

    std::cout << "not implemented: id_p.parse(pos, node, expected)" << std::endl;
    // if (!id_p.parse(pos, node, expected))
    //     return false;

    if (!has_as_word)
    {
        /** In this case, the alias can not match the keyword -
          *  so that in the query "SELECT x FROM t", the word FROM was not considered an alias,
          *  and in the query "SELECT x FR FROM t", the word FR was considered an alias.
          */

        std::cout << "not implemented yet: const String name = getIdentifierName(node);" << __LINE__ << __FUNCTION__ << std::endl;
        // const String name = getIdentifierName(node);
        const String name;

        for (const char ** keyword = restricted_keywords; *keyword != nullptr; ++keyword)
            if (0 == strcasecmp(name.data(), *keyword))
                return false;
    }

    return true;
}


bool ParserAsterisk::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{
    std::cout << "not implemented: ParserAsterisk::parseImpl" << std::endl;
    // if (pos->type == TokenType::Asterisk)
    // {
    //     ++pos;
    //     auto asterisk = std::make_shared<ASTAsterisk>();
    //     ParserColumnsTransformers transformers_p(allowed_transformers);
    //     ASTPtr transformer;
    //     while (transformers_p.parse(pos, transformer, expected))
    //     {
    //         asterisk->children.push_back(transformer);
    //     }
    //     node = asterisk;
    //     return true;
    // }
    return false;
}


bool ParserExpressionElement::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{
    std::cout << "not implemented yet: ParserExpressionElement::parseImpl" << std::endl;
    return false;
    // return ParserSubquery().parse(pos, node, expected)
    //     || ParserCastOperator().parse(pos, node, expected)
    //     || ParserTupleOfLiterals().parse(pos, node, expected)
    //     || ParserParenthesisExpression().parse(pos, node, expected)
    //     || ParserArrayOfLiterals().parse(pos, node, expected)
    //     || ParserArray().parse(pos, node, expected)
    //     || ParserLiteral().parse(pos, node, expected)
    //     || ParserCastAsExpression().parse(pos, node, expected)
    //     || ParserExtractExpression().parse(pos, node, expected)
    //     || ParserDateAddExpression().parse(pos, node, expected)
    //     || ParserDateDiffExpression().parse(pos, node, expected)
    //     || ParserSubstringExpression().parse(pos, node, expected)
    //     || ParserTrimExpression().parse(pos, node, expected)
    //     || ParserLeftExpression().parse(pos, node, expected)
    //     || ParserRightExpression().parse(pos, node, expected)
    //     || ParserCase().parse(pos, node, expected)
    //     || ParserColumnsMatcher().parse(pos, node, expected) /// before ParserFunction because it can be also parsed as a function.
    //     || ParserFunction().parse(pos, node, expected)
    //     || ParserQualifiedAsterisk().parse(pos, node, expected)
    //     || ParserAsterisk().parse(pos, node, expected)
    //     || ParserExistsExpression().parse(pos, node, expected)
    //     || ParserCompoundIdentifier(false, true).parse(pos, node, expected)
    //     || ParserSubstitution().parse(pos, node, expected)
    //     || ParserMySQLGlobalVariable().parse(pos, node, expected);
}

}