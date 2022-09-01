#include "Exception.h"

#include "Common/ErrorCodes.h"
#include <base/errnoToString.h>

#include <string.h>
#include <cxxabi.h>
#include <cstdlib>
#include <Poco/String.h>

namespace DB
{
namespace ErrorCodes
{
    extern const int POCO_EXCEPTION;
    extern const int STD_EXCEPTION;
    extern const int UNKNOWN_EXCEPTION;
    extern const int LOGICAL_ERROR;
    extern const int CANNOT_ALLOCATE_MEMORY;
    extern const int CANNOT_MREMAP;
}

Exception::Exception(const std::string & msg, int code, bool remote_)
    : Poco::Exception(msg, code)
    , remote(remote_)
{
}

Exception::Exception(const std::string & msg, const Exception & nested, int code)
    : Poco::Exception(msg, nested, code)
{
}

Exception::Exception(CreateFromPocoTag, const Poco::Exception & exc)
    : Poco::Exception(exc.displayText(), ErrorCodes::POCO_EXCEPTION)
{
}

Exception::Exception(CreateFromSTDTag, const std::exception & exc)
    : Poco::Exception(std::string("need_demangle_excution_name") + ": " + String(exc.what()), ErrorCodes::STD_EXCEPTION)
    // : Poco::Exception(demangle(typeid(exc).name()) + ": " + String(exc.what()), ErrorCodes::STD_EXCEPTION)
{

}


std::string getExceptionStackTraceString(const std::exception & e)
{
#ifdef STD_EXCEPTION_HAS_STACK_TRACE
    return StackTrace::toString(e.get_stack_trace_frames(), 0, e.get_stack_trace_size());
#else
    if (const auto * db_exception = dynamic_cast<const Exception *>(&e))
        return db_exception->getStackTraceString();
    return {};
#endif
}

std::string getExceptionStackTraceString(std::exception_ptr e)
{
    try
    {
        std::rethrow_exception(e);
    }
    catch (const std::exception & exception)
    {
        return getExceptionStackTraceString(exception);
    }
    catch (...)
    {
        return {};
    }
}


std::string Exception::getStackTraceString() const
{
    return "unimplemented";
}

Exception::FramePointers Exception::getStackFramePointers() const
{
    FramePointers frame_pointers;
    return frame_pointers;
}


void throwFromErrno(const std::string & s, int code, int the_errno)
{
    throw ErrnoException(s + ", " + errnoToString(code, the_errno), code, the_errno);
}

void throwFromErrnoWithPath(const std::string & s, const std::string & path, int code, int the_errno)
{
    throw ErrnoException(s + ", " + errnoToString(code, the_errno), code, the_errno, path);
}

static void tryLogCurrentExceptionImpl(Poco::Logger * logger, const std::string & start_of_message)
{

}

void tryLogCurrentException(const char * log_name, const std::string & start_of_message)
{

}

void tryLogCurrentException(Poco::Logger * logger, const std::string & start_of_message)
{

}


/** It is possible that the system has enough memory,
  *  but we have shortage of the number of available memory mappings.
  * Provide good diagnostic to user in that case.
  */
static void getNotEnoughMemoryMessage(std::string & msg)
{

}

static std::string getExtraExceptionInfo(const std::exception & e)
{
    String msg;

    return msg;
}

std::string getCurrentExceptionMessage(bool with_stacktrace, bool check_embedded_stacktrace /*= false*/, bool with_extra_info /*= true*/)
{
    return "";
}


int getCurrentExceptionCode()
{
    try
    {
        throw;
    }
    catch (const Exception & e)
    {
        return e.code();
    }
    catch (const Poco::Exception &)
    {
        return ErrorCodes::POCO_EXCEPTION;
    }
    catch (const std::exception &)
    {
        return ErrorCodes::STD_EXCEPTION;
    }
    catch (...)
    {
        return ErrorCodes::UNKNOWN_EXCEPTION;
    }
}

int getExceptionErrorCode(std::exception_ptr e)
{
    try
    {
        std::rethrow_exception(e);
    }
    catch (const Exception & exception)
    {
        return exception.code();
    }
    catch (const Poco::Exception &)
    {
        return ErrorCodes::POCO_EXCEPTION;
    }
    catch (const std::exception &)
    {
        return ErrorCodes::STD_EXCEPTION;
    }
    catch (...)
    {
        return ErrorCodes::UNKNOWN_EXCEPTION;
    }
}


void rethrowFirstException(const Exceptions & exceptions)
{
    for (const auto & exception : exceptions)
        if (exception)
            std::rethrow_exception(exception);
}


void tryLogException(std::exception_ptr e, const char * log_name, const std::string & start_of_message)
{
    try
    {
        std::rethrow_exception(std::move(e)); // NOLINT
    }
    catch (...)
    {
        // tryLogCurrentException(log_name, start_of_message);
    }
}

void tryLogException(std::exception_ptr e, Poco::Logger * logger, const std::string & start_of_message)
{
    try
    {
        std::rethrow_exception(std::move(e)); // NOLINT
    }
    catch (...)
    {
        // tryLogCurrentException(logger, start_of_message);
    }
}

std::string getExceptionMessage(const Exception & e, bool with_stacktrace, bool check_embedded_stacktrace)
{
    return "";
}

std::string getExceptionMessage(std::exception_ptr e, bool with_stacktrace)
{
    return "";
}

std::string ExecutionStatus::serializeText() const
{
    return "";
}

void ExecutionStatus::deserializeText(const std::string & data)
{

}

bool ExecutionStatus::tryDeserializeText(const std::string & data)
{

    return true;
}

ExecutionStatus ExecutionStatus::fromCurrentException(const std::string & start_of_message)
{
    String msg = (start_of_message.empty() ? "" : (start_of_message + ": ")) + getCurrentExceptionMessage(false, true);
    return ExecutionStatus(getCurrentExceptionCode(), msg);
}

ExecutionStatus ExecutionStatus::fromText(const std::string & data)
{
    ExecutionStatus status;
    status.deserializeText(data);
    return status;
}

ParsingException::ParsingException() = default;
ParsingException::ParsingException(const std::string & msg, int code)
    : Exception(msg, code)
{
}
ParsingException::ParsingException(int code, const std::string & message)
    : Exception(message, code)
{
}

/// We use additional field formatted_message_ to make this method const.
std::string ParsingException::displayText() const
{
    try
    {
        if (line_number_ == -1)
            formatted_message_ = message();
        else
            formatted_message_ = message() + fmt::format(": (at row {})\n", line_number_);
    }
    catch (...)
    {}

    if (!formatted_message_.empty())
    {
        std::string result = name();
        result.append(": ");
        result.append(formatted_message_);
        return result;
    }
    else
    {
        return Exception::displayText();
    }
}


}
