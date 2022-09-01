#pragma once

#include <Common/ThreadStatus.h>
#include <base/StringRef.h>

#include <memory>
#include <string>

namespace DB
{

/** Collection of static methods to work with thread-local objects.
  * Allows to attach and detach query/process (thread group) to a thread
  * (to calculate query-related metrics and to allow to obtain query-related data from a thread).
  * Thread will propagate it's metrics to attached query.
  */
class CurrentThread
{
public:
    /// Return true in case of successful initialization
    static bool isInitialized();

    /// Handler to current thread
    static ThreadStatus & get();

    /// Group to which belongs current thread
    static ThreadGroupStatusPtr getGroup();

    static void setFatalErrorCallback(std::function<void()> callback);


private:
    static void defaultThreadDeleter();
};

}
