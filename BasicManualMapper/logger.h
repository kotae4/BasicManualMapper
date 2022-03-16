#pragma once

#include <source_location>
#include <format>
#include <string>
#include <string_view>
#include <iostream>
#include <fstream>
#include "string_utils.h"

// credit: github.com/tomsa000 aka tomsa#3313
// i made only slight changes (log file and wide version)
class logger
{
    // TO-DO:
    // do i really need a wide version of print? research and think

private:
    std::ofstream m_LogFile;

public:
    enum class e_log_level
    {
        trace,
        info,
        warn,
        error
    };

private:
    logger()
    {
        m_LogFile = std::ofstream("log.txt", std::ios::trunc);
    }

    ~logger()
    {
        m_LogFile.close();
    }

public:

    static logger& getInstance()
    {
        static logger instance;
        return instance;
    }

    logger(logger const&) = delete;
    void operator=(logger const&) = delete;

    // credit: tomsa#3313 (discord) / tomsa000 (github)
    template<logger::e_log_level log_level = logger::e_log_level::info, typename ... ts>
    auto print(const std::string_view message, const std::source_location& loc, ts&&... args)
        -> void
    {
        if (message.empty())
            return;

        std::string formatted_loc_info;
        if (log_level == e_log_level::trace)
        {
            std::string file_name = loc.file_name();
            file_name.erase(0, file_name.find_last_of("\\") + 1);
            formatted_loc_info = std::format("{}({}:{}): {}(): ", file_name, loc.line(), loc.column(), loc.function_name());
        }
        else
        {
            std::string file_name = loc.file_name();
            file_name.erase(0, file_name.find_last_of("\\") + 1);
            formatted_loc_info = std::format("{}!{}:{}(): ", file_name, loc.function_name(), loc.line());
        }

        switch (log_level)
        {
        case e_log_level::trace:
        {
            std::cout << "[TRACE] " << formatted_loc_info << std::format(message, std::forward<ts>(args)...) << std::endl;
            m_LogFile << "[TRACE] " << formatted_loc_info << std::format(message, std::forward<ts>(args)...) << std::endl;
            break;
        }
        case e_log_level::info:
        {
            std::cout << "[INFO] " << formatted_loc_info << std::format(message, std::forward<ts>(args)...) << std::endl;
            m_LogFile << "[INFO] " << formatted_loc_info << std::format(message, std::forward<ts>(args)...) << std::endl;
            break;
        }
        case e_log_level::warn:
        {
            std::cout << "[WARN] " << formatted_loc_info << std::format(message, std::forward<ts>(args)...) << std::endl;
            m_LogFile << "[WARN] " << formatted_loc_info << std::format(message, std::forward<ts>(args)...) << std::endl;
            break;
        }
        case e_log_level::error:
        {
            std::cout << "[ERROR] " << formatted_loc_info << std::format(message, std::forward<ts>(args)...) << std::endl;
            m_LogFile << "[ERROR] " << formatted_loc_info << std::format(message, std::forward<ts>(args)...) << std::endl;
            break;
        }
        default:
        {
            break;
        }
        }
    }

    template<logger::e_log_level log_level = logger::e_log_level::info, typename ... ts>
    auto printW(const std::wstring_view message, const std::source_location& loc, ts&&... args)
        -> void
    {
        if (message.empty())
            return;

        std::string formatted_loc_info;
        if (log_level == e_log_level::trace)
        {
            std::string file_name = loc.file_name();
            file_name.erase(0, file_name.find_last_of("\\") + 1);
            formatted_loc_info = std::format("{}({}:{}): {}(): ", file_name, loc.line(), loc.column(), loc.function_name());
        }
        else
        {
            std::string file_name = loc.file_name();
            file_name.erase(0, file_name.find_last_of("\\") + 1);
            formatted_loc_info = std::format("{}!{}:{}(): ", file_name, loc.function_name(), loc.line());
        }

        std::wstring formatted_messageW = std::format(message, std::forward<ts>(args)...);
        std::string formatted_message;
        BOOL success = FALSE;
        success = string_utils::TryConvertUtf16ToUtf8(formatted_messageW, formatted_message);
        if (success == FALSE)
        {
            print("Could not convert wide log message to narrow", loc);
            return;
        }

        switch (log_level)
        {
        case e_log_level::trace:
        {
            std::cout << "[TRACE] " << formatted_loc_info << formatted_message << std::endl;
            m_LogFile << "[TRACE] " << formatted_loc_info << formatted_message << std::endl;
            break;
        }
        case e_log_level::info:
        {
            std::cout << "[INFO] " << formatted_loc_info << formatted_message << std::endl;
            m_LogFile << "[INFO] " << formatted_loc_info << formatted_message << std::endl;
            break;
        }
        case e_log_level::warn:
        {
            std::cout << "[WARN] " << formatted_loc_info << formatted_message << std::endl;
            m_LogFile << "[WARN] " << formatted_loc_info << formatted_message << std::endl;
            break;
        }
        case e_log_level::error:
        {
            std::cout << "[ERROR] " << formatted_loc_info << formatted_message << std::endl;
            m_LogFile << "[ERROR] " << formatted_loc_info << formatted_message << std::endl;
            break;
        }
        default:
        {
            break;
        }
        }
    }

#define LOG_TRACE(message, ...) logger::getInstance().print<logger::e_log_level::trace>(message, std::source_location::current(), __VA_ARGS__)
#define LOG_TRACEW(message, ...) logger::getInstance().printW<logger::e_log_level::trace>(message, std::source_location::current(), __VA_ARGS__)
#define LOG_INFO(message, ...) logger::getInstance().print<logger::e_log_level::info>(message, std::source_location::current(), __VA_ARGS__)
#define LOG_INFOW(message, ...) logger::getInstance().printW<logger::e_log_level::info>(message, std::source_location::current(), __VA_ARGS__)
#define LOG_WARN(message, ...) logger::getInstance().print<logger::e_log_level::warn>(message, std::source_location::current(), __VA_ARGS__)
#define LOG_WARNW(message, ...) logger::getInstance().printW<logger::e_log_level::warn>(message, std::source_location::current(), __VA_ARGS__)
#define LOG_ERROR(message, ...) logger::getInstance().print<logger::e_log_level::error>(message, std::source_location::current(), __VA_ARGS__)
#define LOG_ERRORW(message, ...) logger::getInstance().printW<logger::e_log_level::error>(message, std::source_location::current(), __VA_ARGS__)
};