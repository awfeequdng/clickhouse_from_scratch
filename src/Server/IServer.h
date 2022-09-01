#pragma once

namespace DB
{

class IServer
{
public:
    /// Returns true if shutdown signaled.
    virtual bool isCancelled() const = 0;

    virtual ~IServer() = default;
};

}
