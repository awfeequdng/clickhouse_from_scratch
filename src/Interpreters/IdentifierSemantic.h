#pragma once

#include <Parsers/ASTIdentifier.h>

namespace DB
{

struct IdentifierSemanticImpl
{
    bool special = false;              /// for now it's 'not a column': tables, subselects and some special stuff like FORMAT
    bool can_be_alias = true;          /// if it's a cropped name it could not be an alias
    bool covered = false;              /// real (compound) name is hidden by an alias (short name)
    std::optional<size_t> membership;  /// table position in join
    String table = {};                 /// store table name for columns just to support legacy logic.
    bool legacy_compound = false;      /// true if identifier supposed to be comply for legacy |compound()| behavior
};

/// Static class to manipulate IdentifierSemanticImpl via ASTIdentifier
struct IdentifierSemantic
{
    enum class ColumnMatch
    {
        NoMatch,
        ColumnName,       /// column qualified with column names list
        AliasedTableName, /// column qualified with table name (but table has an alias so its priority is lower than TableName)
        TableName,        /// column qualified with table name
        DBAndTable,       /// column qualified with database and table name
        TableAlias,       /// column qualified with table alias
        Ambiguous,
    };
};


}
