#include "DateLUT.h"

#include <Poco/DigestStream.h>
#include <Poco/Exception.h>
#include <Poco/SHA1Engine.h>

// #include <filesystem>
#include <fstream>


namespace
{

Poco::DigestEngine::Digest calcSHA1(const std::string & path)
{
    std::ifstream stream(path);
    if (!stream)
        throw Poco::Exception("Error while opening file: '" + path + "'.");
    Poco::SHA1Engine digest_engine;
    Poco::DigestInputStream digest_stream(digest_engine, stream);
    digest_stream.ignore(std::numeric_limits<std::streamsize>::max());
    if (!stream.eof())
        throw Poco::Exception("Error while reading file: '" + path + "'.");
    return digest_engine.digest();
}

std::string determineDefaultTimeZone()
{
    // TODO: PXCAI
    // SET DEFAULT TIME ZONE
    return "UTC";
}

}

DateLUT::DateLUT()
{
    /// Initialize the pointer to the default DateLUTImpl.
    std::string default_time_zone = determineDefaultTimeZone();
    default_impl.store(&getImplementation(default_time_zone), std::memory_order_release);
}


const DateLUTImpl & DateLUT::getImplementation(const std::string & time_zone) const
{
    std::lock_guard<std::mutex> lock(mutex);

    auto it = impls.emplace(time_zone, nullptr).first;
    if (!it->second)
        it->second = std::unique_ptr<DateLUTImpl>(new DateLUTImpl(time_zone));

    return *it->second;
}

DateLUT & DateLUT::getInstance()
{
    static DateLUT ret;
    return ret;
}
