#pragma once

#include <Core/SettingsEnums.h>
#include <base/StringRef.h>
#include "base/defines.h"

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_set>
#include <atomic>

#ifdef OS_LINUX
#include <sys/mman.h>
#endif

namespace Poco
{
    class Logger;
}

namespace DB
{
class ThreadStatus;
using ThreadStatusPtr = ThreadStatus *;

/** Thread group is a collection of threads dedicated to single task
  * (query or other process like background merge).
  *
  * ProfileEvents (counters) from a thread are propagated to thread group.
  *
  * Create via CurrentThread::initializeQuery (for queries) or directly (for various background tasks).
  * Use via CurrentThread::getGroup.
  */
class ThreadGroupStatus
{
public:
    mutable std::mutex mutex;

    std::function<void()> fatal_error_callback;

    std::vector<UInt64> thread_ids;
    std::unordered_set<ThreadStatusPtr> threads;

    /// The first thread created this thread group
    UInt64 master_thread_id = 0;

    LogsLevel client_logs_level = LogsLevel::none;

};

using ThreadGroupStatusPtr = std::shared_ptr<ThreadGroupStatus>;


extern thread_local ThreadStatus * current_thread;

/** Encapsulates all per-thread info (ProfileEvents, MemoryTracker, query_id, query context, etc.).
  * The object must be created in thread function and destroyed in the same thread before the exit.
  * It is accessed through thread-local pointer.
  *
  * This object should be used only via "CurrentThread", see CurrentThread.h
  */
class ThreadStatus
{
public:
    /// Linux's PID (or TGID) (the same id is shown by ps util)
    const UInt64 thread_id = 0;
    /// Also called "nice" value. If it was changed to non-zero (when attaching query) - will be reset to zero when query is detached.
    Int32 os_thread_priority = 0;

    using Deleter = std::function<void()>;
    Deleter deleter;

protected:
    ThreadGroupStatusPtr thread_group;

    std::atomic<int> thread_state{ThreadState::DetachedFromQuery};

    Poco::Logger * log = nullptr;

    /// Is used to send logs from logs_queue to client in case of fatal errors.
    std::function<void()> fatal_error_callback;

public:
    ThreadStatus();
    ~ThreadStatus();

    ThreadGroupStatusPtr getThreadGroup() const
    {
        return thread_group;
    }

    enum ThreadState
    {
        DetachedFromQuery = 0,  /// We just created thread or it is a background thread
        AttachedToQuery,        /// Thread executes enqueued query
        Died,                   /// Thread does not exist
    };

    int getCurrentState() const
    {
        return thread_state.load(std::memory_order_relaxed);
    }

    /// Callback that is used to trigger sending fatal error messages to client.
    void setFatalErrorCallback(std::function<void()> callback);
    void onFatalError();

private:
    void setupState(const ThreadGroupStatusPtr & thread_group_);
};

/**
 * Creates ThreadStatus for the main thread.
 */
class MainThreadStatus : public ThreadStatus
{
public:
    static MainThreadStatus & getInstance();
    static ThreadStatus * get() { return main_thread; }
    static bool isMainThread() { return main_thread == current_thread; }

    ~MainThreadStatus();

private:
    MainThreadStatus();

    static ThreadStatus * main_thread;
};

}
