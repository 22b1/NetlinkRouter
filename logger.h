#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>

// Basic logging function
static inline void Log(const std::wstring& message) {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    
    std::wstringstream wss;
    // On Windows, localtime_s is preferred over localtime
    std::tm buf;
#ifdef _WIN32
    localtime_s(&buf, &in_time_t);
#else
    localtime_r(&in_time_t, &buf); // POSIX
#endif
    // For std::put_time with wstringstream, the format string should be L"..."
    wss << std::put_time(&buf, L"%Y-%m-%d %H:%M:%S") << L": " << message;
    
    std::wcout << wss.str() << std::endl;
}

#endif // LOGGER_H 