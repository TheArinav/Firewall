#include "logger.hpp"
#include <ctime>
#include <iomanip>

using namespace std;

ofstream Logger::logFile;
LogLevel Logger::currentLogLevel = LogLevel::INFO;
mutex Logger::logMutex;

void Logger::setLogFile(const string& filename) {
    lock_guard<mutex> lock(logMutex);
    if (logFile.is_open()) {
        logFile.close();
    }
    logFile.open(filename, ios::app);
}

void Logger::setLogLevel(LogLevel level) {
    lock_guard<mutex> lock(logMutex);
    currentLogLevel = level;
}

void Logger::log(const string& level, const string& message) {
    lock_guard<mutex> lock(logMutex);

    // Get timestamp
    time_t now = time(nullptr);
    tm* localTime = localtime(&now);

    ostringstream timestamp;
    timestamp << put_time(localTime, "%Y-%m-%d %H:%M:%S");

    string logMessage = "[" + timestamp.str() + "] [" + level + "] " + message;

    // Print to console
    cout << logMessage << endl;

    // Write to log file if enabled
    if (logFile.is_open()) {
        logFile << logMessage << endl;
    }
}

void Logger::info(const string& message) {
    if (currentLogLevel <= LogLevel::INFO) {
        log("INFO", message);
    }
}

void Logger::debug(const string& message) {
    if (currentLogLevel <= LogLevel::DEBUG) {
        log("DEBUG", message);
    }
}

void Logger::warn(const string& message) {
    if (currentLogLevel <= LogLevel::WARNING) {
        log("WARNING", message);
    }
}

void Logger::error(const string& message) {
    log("ERROR", message);
}
