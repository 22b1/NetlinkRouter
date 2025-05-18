#pragma once

#include <string>
#include <windows.h> // For MultiByteToWideChar and WideCharToMultiByte

// Converts std::string (UTF-8 assumed) to std::wstring
std::wstring s2ws(const std::string& str);

// Converts std::wstring to std::string (UTF-8)
std::string ws2s(const std::wstring& wstr); 