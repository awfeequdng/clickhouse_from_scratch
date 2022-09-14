#include <Interpreters/IdentifierSemantic.h>

#include <Common/typeid_cast.h>

#include <Parsers/ASTFunction.h>

namespace DB
{

namespace ErrorCodes
{
    extern const int AMBIGUOUS_COLUMN_NAME;
}

}
