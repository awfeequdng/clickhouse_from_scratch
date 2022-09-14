#include <string_view>

#include <Parsers/ASTFunction.h>

#include <Common/quoteString.h>
#include <Common/FieldVisitorToString.h>
#include <Common/SipHash.h>
#include <Common/typeid_cast.h>
#include <DataTypes/IDataType.h>
#include <DataTypes/NumberTraits.h>
#include <IO/Operators.h>
#include <IO/WriteBufferFromString.h>
#include <IO/WriteHelpers.h>
#include <Parsers/ASTWithAlias.h>
#include <Parsers/queryToString.h>
#include <Parsers/ASTIdentifier.h>
#include <Parsers/ASTLiteral.h>
#include <iostream>

using namespace std::literals;


namespace DB
{

namespace ErrorCodes
{
    extern const int UNEXPECTED_EXPRESSION;
    extern const int UNEXPECTED_AST_STRUCTURE;
}

void ASTFunction::appendColumnNameImpl(WriteBuffer & ostr) const
{
    if (name == "view")
        throw Exception("Table function view cannot be used as an expression", ErrorCodes::UNEXPECTED_EXPRESSION);

    writeString(name, ostr);

    if (parameters)
    {
        writeChar('(', ostr);
        for (auto it = parameters->children.begin(); it != parameters->children.end(); ++it)
        {
            if (it != parameters->children.begin())
                writeCString(", ", ostr);

            (*it)->appendColumnName(ostr);
        }
        writeChar(')', ostr);
    }

    writeChar('(', ostr);
    if (arguments)
    {
        for (auto it = arguments->children.begin(); it != arguments->children.end(); ++it)
        {
            if (it != arguments->children.begin())
                writeCString(", ", ostr);

            (*it)->appendColumnName(ostr);
        }
    }

    writeChar(')', ostr);

    if (is_window_function)
    {
        writeCString(" OVER ", ostr);
        if (!window_name.empty())
        {
            ostr << window_name;
        }
        else
        {
            FormatSettings format_settings{ostr, true /* one_line */};
            FormatState state;
            FormatStateStacked frame;
            writeCString("(", ostr);
            window_definition->formatImpl(format_settings, state, frame);
            writeCString(")", ostr);
        }
    }
}

/** Get the text that identifies this element. */
String ASTFunction::getID(char delim) const
{
    return "Function" + (delim + name);
}

ASTPtr ASTFunction::clone() const
{
    auto res = std::make_shared<ASTFunction>(*this);
    res->children.clear();

    if (arguments) { res->arguments = arguments->clone(); res->children.push_back(res->arguments); }
    if (parameters) { res->parameters = parameters->clone(); res->children.push_back(res->parameters); }

    if (window_definition)
    {
        res->window_definition = window_definition->clone();
        res->children.push_back(res->window_definition);
    }

    return res;
}


void ASTFunction::updateTreeHashImpl(SipHash & hash_state) const
{
    hash_state.update(name.size());
    hash_state.update(name);
    IAST::updateTreeHashImpl(hash_state);
}


ASTPtr ASTFunction::toLiteral() const
{
    if (!arguments) return {};

    if (name == "array")
    {
        Array array;

        for (const auto & arg : arguments->children)
        {
            if (auto * literal = arg->as<ASTLiteral>())
                array.push_back(literal->value);
            else if (auto * func = arg->as<ASTFunction>())
            {
                if (auto func_literal = func->toLiteral())
                    array.push_back(func_literal->as<ASTLiteral>()->value);
            }
            else
                /// Some of the Array arguments is not literal
                return {};
        }

        return std::make_shared<ASTLiteral>(array);
    }

    return {};
}


/** A special hack. If it's [I]LIKE or NOT [I]LIKE expression and the right hand side is a string literal,
  *  we will highlight unescaped metacharacters % and _ in string literal for convenience.
  * Motivation: most people are unaware that _ is a metacharacter and forgot to properly escape it with two backslashes.
  * With highlighting we make it clearly obvious.
  *
  * Another case is regexp match. Suppose the user types match(URL, 'www.yandex.ru'). It often means that the user is unaware that . is a metacharacter.
  */
static bool highlightStringLiteralWithMetacharacters(const ASTPtr & node, const IAST::FormatSettings & settings, const char * metacharacters)
{
    if (const auto * literal = node->as<ASTLiteral>())
    {
        if (literal->value.getType() == Field::Types::String)
        {
            auto string = applyVisitor(FieldVisitorToString(), literal->value);

            unsigned escaping = 0;
            for (auto c : string)
            {
                if (c == '\\')
                {
                    settings.ostr << c;
                    if (escaping == 2)
                        escaping = 0;
                    ++escaping;
                }
                else if (nullptr != strchr(metacharacters, c))
                {
                    if (escaping == 2)      /// Properly escaped metacharacter
                        settings.ostr << c;
                    else                    /// Unescaped metacharacter
                        settings.ostr << "\033[1;35m" << c << "\033[0m";
                    escaping = 0;
                }
                else
                {
                    settings.ostr << c;
                    escaping = 0;
                }
            }

            return true;
        }
    }

    return false;
}


String getFunctionName(const IAST * ast)
{
    String res;
    if (tryGetFunctionNameInto(ast, res))
        return res;
    throw Exception(ast ? queryToString(*ast) + " is not an function" : "AST node is nullptr", ErrorCodes::UNEXPECTED_AST_STRUCTURE);
}

std::optional<String> tryGetFunctionName(const IAST * ast)
{
    String res;
    if (tryGetFunctionNameInto(ast, res))
        return res;
    return {};
}

bool tryGetFunctionNameInto(const IAST * ast, String & name)
{
    if (ast)
    {
        if (const auto * node = ast->as<ASTFunction>())
        {
            name = node->name;
            return true;
        }
    }
    return false;
}

}
