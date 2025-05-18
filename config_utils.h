#pragma once

#include <string>
#include <vector>
#include <mutex>
#include "framework.h" // For ServiceConfig, Log (if made available)
#include "string_utils.h" // For s2ws, ws2s

// Define CONFIG_FILE_NAME here or pass as argument if it can change
extern const std::string CONFIG_FILE_NAME;

// Forward declaration for Log if it's not made globally accessible via framework.h
// void Log(const std::wstring& message);

// Helper function to trim whitespace from both ends of a string
std::string trim_string_config(const std::string& str);

struct ServiceConfig {
    std::wstring proxyAddress;
    unsigned short proxyPort;
    std::wstring proxyUsername;
    std::wstring proxyPassword;
    std::wstring directRouteCidrs; // Comma-separated CIDRs
    std::vector<std::pair<UINT32, UINT32>> directRouteRanges; // Parsed CIDRs
    bool configured = false;
    bool shouldKillProcess = false;
    DWORD processId = 0; // PID of the process to apply rules for (if any specific)
    bool enablePidFilter = false; // Added: Master switch for PID filtering
    std::vector<DWORD> targetPids; // Added: List of PIDs to filter/allow
    // Potentially add a mode: "allow_listed_pids" or "deny_listed_pids"

    ServiceConfig() : proxyPort(0), configured(false), shouldKillProcess(false), processId(0), enablePidFilter(false) {}
};

extern ServiceConfig g_ServiceConfig;
extern std::mutex g_configMutex; // Declare the global mutex

void LoadConfig(const std::wstring& configPath = L"NetlinkRouterConfig.ini");
void LogConfig();

// Loads configuration from file into g_ServiceConfig
// Returns true if a configuration was successfully loaded and seems plausible,
// false otherwise. Actual PID check is separate.
bool LoadConfigurationFromFile(ServiceConfig& config, std::mutex& configMutex);

// Saves g_ServiceConfig to file
void SaveConfigurationToFile(const ServiceConfig& config, std::mutex& configMutex); 