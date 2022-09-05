#pragma once


namespace DB
{

/** Deserializes the stream of blocks from the native binary format (with names and column types).
  * Designed for communication between servers.
  *
  * Can also be used to store data on disk.
  * In this case, can use the index.
  */
class NativeReader
{
public:
    /// If a non-zero server_revision is specified, additional block information may be expected and read.
    NativeReader(ReadBuffer & istr_, UInt64 server_revision_);

private:
    ReadBuffer & istr;
    UInt64 server_revision;

    bool use_index = false;
};

}
