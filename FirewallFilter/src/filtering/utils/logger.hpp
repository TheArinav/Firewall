#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <iostream>
#include <fstream>
#include <string>
#include <mutex>

enum class LogLevel {
    ERROR = 3,
    WARNING = 2,
    INFO = 1,
    DEBUG = 0
};


class Logger {
public:
    static void setLogFile(const std::string& filename);
    static void setLogLevel(LogLevel level);

    static void info(const std::string& message);
    static void debug(const std::string& message);
    static void warn(const std::string& message);
    static void error(const std::string& message);

private:
    static std::ofstream logFile;
    static LogLevel currentLogLevel;
    static std::mutex logMutex;

    static void log(const std::string& level, const std::string& message);
};

#endif // LOGGER_HPP
