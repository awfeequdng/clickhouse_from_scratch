#pragma once

#include <Core/UUID.h>
#include <Parsers/ASTQueryParameter.h>
#include <Parsers/ASTWithAlias.h>

#include <optional>


namespace DB
{

struct IdentifierSemantic;
struct IdentifierSemanticImpl;


/// FIXME: rewrite code about params - they should be substituted at the parsing stage,
///        or parsed as a separate AST entity.

/// Generic identifier. ASTTableIdentifier - for table identifier.
class ASTIdentifier : public ASTWithAlias
{
public:
    explicit ASTIdentifier(const String & short_name, ASTPtr && name_param = {});
    explicit ASTIdentifier(std::vector<String> && name_parts, bool special = false, std::vector<ASTPtr> && name_params = {});

    /** Get the text that identifies this element. */
    String getID(char delim) const override { return "Identifier" + (delim + name()); }

    /** Get the query param out of a non-compound identifier. */
    ASTPtr getParam() const;

    ASTPtr clone() const override;

    void collectIdentifierNames(IdentifierNameSet & set) const override { set.insert(name()); }

    bool compound() const { return name_parts.size() > 1; }
    bool isShort() const { return name_parts.size() == 1; }
    bool supposedToBeCompound() const;  // TODO(ilezhankin): get rid of this

    void setShortName(const String & new_name);

    /// The composite identifier will have a concatenated name (of the form a.b.c),
    /// and individual components will be available inside the name_parts.
    const String & shortName() const { return name_parts.back(); }
    const String & name() const;


protected:
    String full_name;
    std::vector<String> name_parts;
    std::shared_ptr<IdentifierSemanticImpl> semantic; /// pimpl

    void formatImplWithoutAlias(const FormatSettings & settings, FormatState & state, FormatStateStacked frame) const override;
    void appendColumnNameImpl(WriteBuffer & ostr) const override;

private:
    using ASTWithAlias::children; /// ASTIdentifier is child free

    friend struct IdentifierSemantic;
    friend void setIdentifierSpecial(ASTPtr & ast);

    void resetFullName();
};


/// ASTIdentifier Helpers: hide casts and semantic.

void setIdentifierSpecial(ASTPtr & ast);

String getIdentifierName(const IAST * ast);
std::optional<String> tryGetIdentifierName(const IAST * ast);
bool tryGetIdentifierNameInto(const IAST * ast, String & name);

inline String getIdentifierName(const ASTPtr & ast) { return getIdentifierName(ast.get()); }
inline std::optional<String> tryGetIdentifierName(const ASTPtr & ast) { return tryGetIdentifierName(ast.get()); }
inline bool tryGetIdentifierNameInto(const ASTPtr & ast, String & name) { return tryGetIdentifierNameInto(ast.get(), name); }


}