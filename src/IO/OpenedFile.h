#pragma once

#include <memory>

namespace DB
{

/// RAII for readonly opened file descriptor.
class OpenedFile
{
public:
    OpenedFile(const std::string & file_name_, int flags);
    ~OpenedFile();

    /// Close prematurally.
    void close();

    int getFD() const { return fd; }
    std::string getFileName() const;

private:
    std::string file_name;
    int fd = -1;

    void open(int flags);
};

}

