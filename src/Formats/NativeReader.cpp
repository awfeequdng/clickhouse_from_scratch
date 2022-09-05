#include <Core/Defines.h>

#include <IO/ReadHelpers.h>

#include <Common/typeid_cast.h>

#include <Formats/NativeReader.h>
namespace DB
{

namespace ErrorCodes
{
    extern const int INCORRECT_INDEX;
    extern const int LOGICAL_ERROR;
    extern const int CANNOT_READ_ALL_DATA;
}


NativeReader::NativeReader(ReadBuffer & istr_, UInt64 server_revision_)
    : istr(istr_), server_revision(server_revision_)
{
}

}
