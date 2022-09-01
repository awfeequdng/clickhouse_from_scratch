#include <memory>

#include "CurrentThread.h"
#include "Common/Exception.h"

#include <base/logger_useful.h>
#include <Common/ThreadStatus.h>
#include <base/getThreadId.h>
#include <Poco/Logger.h>


namespace DB
{

namespace ErrorCodes
{
    extern const int LOGICAL_ERROR;
}


bool CurrentThread::isInitialized()
{
    return current_thread;
}

ThreadStatus & CurrentThread::get()
{
    if (unlikely(!current_thread))
        throw Exception("Thread #" + std::to_string(getThreadId()) + " status was not initialized", ErrorCodes::LOGICAL_ERROR);

    return *current_thread;
}

ThreadGroupStatusPtr CurrentThread::getGroup()
{
    if (unlikely(!current_thread))
        return nullptr;

    return current_thread->getThreadGroup();
}

}
