
#include <Parsers/ParserQuery.h>
#include <Parsers/ParserQueryWithOutput.h>


namespace DB
{


bool ParserQuery::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{

    ParserQueryWithOutput query_with_output_p(end);

    bool res = query_with_output_p.parse(pos, node, expected);

    return res;
}

}
