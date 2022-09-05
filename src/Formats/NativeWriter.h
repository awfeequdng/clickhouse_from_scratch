#pragma once

#include <base/types.h>

namespace DB
{

class WriteBuffer;

/** Serializes the stream of blocks in their native binary format (with names and column types).
  * Designed for communication between servers.
  *
  * A stream can be specified to write the index. The index contains offsets to each part of each column.
  * If an `append` is made to an existing file, and you need to write the index, then specify `initial_size_of_file`.
  */
class NativeWriter
{
public:
    /** If non-zero client_revision is specified, additional block information can be written.
      */
    NativeWriter(
        WriteBuffer & ostr_, UInt64 client_revision_);

    static String getContentType() { return "application/octet-stream"; }

private:
    WriteBuffer & ostr;
    UInt64 client_revision;
};

}
