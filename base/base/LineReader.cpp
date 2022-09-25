#include <base/LineReader.h>

#include <iostream>
#include <string_view>

#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>


#ifdef OS_LINUX
/// We can detect if code is linked with one or another readline variants or open the library dynamically.
#   include <dlfcn.h>
extern "C"
{
    char * readline(const char *) __attribute__((__weak__));
    char * (*readline_ptr)(const char *) = 0;
    // char * (*readline_ptr)(const char *) = readline;
}
#endif

#ifdef HAS_RESERVED_IDENTIFIER
#pragma clang diagnostic ignored "-Wreserved-identifier"
#endif

namespace
{

/// Trim ending whitespace inplace
void trim(String & s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) { return !std::isspace(ch); }).base(), s.end());
}

/// Check if multi-line query is inserted from the paste buffer.
/// Allows delaying the start of query execution until the entirety of query is inserted.
bool hasInputData()
{
    timeval timeout = {0, 0};
    fd_set fds{};
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    return select(1, &fds, nullptr, nullptr, &timeout) == 1;
}

}

std::optional<LineReader::Suggest::WordsRange> LineReader::Suggest::getCompletions(const String & prefix, size_t prefix_length) const
{
    if (!ready)
        return std::nullopt;

    std::string_view last_word;

    auto last_word_pos = prefix.find_last_of(word_break_characters);
    if (std::string::npos == last_word_pos)
        last_word = prefix;
    else
        last_word = std::string_view(prefix).substr(last_word_pos + 1, std::string::npos);

    /// last_word can be empty.

    /// Only perform case sensitive completion when the prefix string contains any uppercase characters
    if (std::none_of(prefix.begin(), prefix.end(), [&](auto c) { return c >= 'A' && c <= 'Z'; }))
        return std::equal_range(
            words_no_case.begin(), words_no_case.end(), last_word, [prefix_length](std::string_view s, std::string_view prefix_searched)
            {
                return strncasecmp(s.data(), prefix_searched.data(), prefix_length) < 0;
            });
    else
        return std::equal_range(words.begin(), words.end(), last_word, [prefix_length](std::string_view s, std::string_view prefix_searched)
        {
            return strncmp(s.data(), prefix_searched.data(), prefix_length) < 0;
        });
}

LineReader::LineReader(const String & history_file_path_, bool multiline_, Patterns extenders_, Patterns delimiters_)
    : history_file_path(history_file_path_), multiline(multiline_), extenders(std::move(extenders_)), delimiters(std::move(delimiters_))
{
    /// FIXME: check extender != delimiter
}

String LineReader::readLine(const String & first_prompt, const String & second_prompt)
{
    String line;
    bool need_next_line = false;

    while (auto status = readOneLine(need_next_line ? second_prompt : first_prompt))
    {
        if (status == RESET_LINE)
        {
            line.clear();
            need_next_line = false;
            continue;
        }

        if (input.empty())
        {
            if (!line.empty() && !multiline && !hasInputData())
                break;
            else
                continue;
        }

        const char * has_extender = nullptr;
        for (const auto * extender : extenders)
        {
            if (input.ends_with(extender))
            {
                has_extender = extender;
                break;
            }
        }

        const char * has_delimiter = nullptr;
        for (const auto * delimiter : delimiters)
        {
            if (input.ends_with(delimiter))
            {
                has_delimiter = delimiter;
                break;
            }
        }

        need_next_line = has_extender || (multiline && !has_delimiter) || hasInputData();

        if (has_extender)
        {
            input.resize(input.size() - strlen(has_extender));
            trim(input);
            if (input.empty())
                continue;
        }

        line += (line.empty() ? "" : "\n") + input;

        if (!need_next_line)
            break;
    }

    if (!line.empty() && line != prev_line)
    {
        addToHistory(line);
        prev_line = line;
    }

    return line;
}

LineReader::InputStatus LineReader::readOneLine(const String & prompt)
{
    input.clear();
    std::cout << " readOneLine 1" << std::endl;
#ifdef OS_LINUX
    if (!readline_ptr)
    {
    std::cout << " readOneLine 2" << std::endl;
        for (const auto * name : {"libreadline.so", "libreadline.so.0", "libeditline.so", "libeditline.so.0"})
        {
    std::cout << " readOneLine 3" << std::endl;
    std::cout << " readOneLine 3" << std::endl;
            void * dl_handle = dlopen(name, RTLD_LAZY);
    std::cout << " readOneLine 4" << std::endl;
            if (dl_handle)
            {
    std::cout << " readOneLine 5" << std::endl;
                auto tmp_readline_ptr = dlsym(dl_handle, "readline");
                std::cout << "dlsym(dl_handle, readline): " << tmp_readline_ptr << std::endl;
                readline_ptr = reinterpret_cast<char * (*)(const char *)>(tmp_readline_ptr);
                if (readline_ptr)
                {
    std::cout << " readOneLine 6： " << readline_ptr << std::endl;
                    break;
                }
            }
        }
    }

    std::cout << " readOneLine 7" << std::endl;
    std::cout << " readOneLine 7" << std::endl;
    /// Minimal support for readline
    if (readline_ptr)
    {
    std::cout << " readOneLine 8: " << readline_ptr << std::endl;
        char * line_read = (*readline_ptr)(prompt.c_str());
        if (!line_read)
            return ABORT;
        input = line_read;
    }
    else
#endif
    {
    std::cout << " readOneLine 9: " << readline_ptr << std::endl;
        std::cout << prompt;
        std::getline(std::cin, input);
        if (!std::cin.good())
            return ABORT;
    }

    trim(input);
    return INPUT_LINE;
}
