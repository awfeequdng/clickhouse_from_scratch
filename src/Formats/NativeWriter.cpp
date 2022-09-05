#include <Core/ProtocolDefines.h>

#include <IO/WriteHelpers.h>
#include <IO/VarInt.h>

#include <Formats/NativeWriter.h>

#include <Common/typeid_cast.h>

namespace DB
{

namespace ErrorCodes
{
    extern const int LOGICAL_ERROR;
}


NativeWriter::NativeWriter(
    WriteBuffer & ostr_, UInt64 client_revision_)
    : ostr(ostr_), client_revision(client_revision_)
{

}

}
