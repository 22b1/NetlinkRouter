#include "config_utils.h"
#include <fstream>
#include <sstream>
#include <algorithm>

// Global mutex for configuration access
std::mutex g_configMutex;

// Define CONFIG_FILE_NAME
const std::string CONFIG_FILE_NAME = "NetlinkRouterConfig.ini";

std::string trim_string_config(const std::string& str) {
    const std::string whitespace = " \t\n\r\f\v";
    size_t start = str.find_first_not_of(whitespace);
    if (start == std::string::npos) {
        return ""; // string is all whitespace
    }
    size_t end = str.find_last_not_of(whitespace);
    return str.substr(start, end - start + 1);
}

bool LoadConfigurationFromFile(ServiceConfig& config, std::mutex& configMutex) {
    std::ifstream configFile(CONFIG_FILE_NAME);
    std::string line;
    // Log(L"Attempting to load configuration from " + s2ws(CONFIG_FILE_NAME)); // Caller can log
    std::lock_guard<std::mutex> lock(configMutex);

    // Initialize PID filter fields to default before loading
    config.enablePidFilter = false;
    config.targetPids.clear();

    if (!configFile.is_open()) {
        // Log(L"Configuration file not found or could not be opened. Using default/empty values."); // Caller can log
        return false;
    }

    bool loadedSomething = false;
    while (std::getline(configFile, line)) {
        std::istringstream iss_line(line);
        std::string key, value;
        if (std::getline(iss_line, key, '=')) {
            if (std::getline(iss_line, value)) {
                key = trim_string_config(key);
                value = trim_string_config(value);

                // Ensure correct fields from ServiceConfig in config_utils.h are used
                if (key == "TargetProcessID") { 
                    try {
                        config.processId = std::stoul(value);
                        loadedSomething = true;
                    } catch (const std::exception& e) {
                        // Log(L"Invalid TargetProcessID format: " + s2ws(value) + L". Error: " + s2ws(e.what()));
                    }
                } else if (key == "ProxyAddress") { 
                    config.proxyAddress = s2ws(value);
                    loadedSomething = true;
                } else if (key == "ProxyPort") {
                    try {
                        config.proxyPort = static_cast<unsigned short>(std::stoi(value));
                        loadedSomething = true;
                    } catch (const std::exception& e) { 
                        // Log(L"Invalid ProxyPort format: " + s2ws(value) + L". Error: " + s2ws(e.what()));
                    }
                } else if (key == "ProxyUsername") {
                    config.proxyUsername = s2ws(value);
                } else if (key == "ProxyPassword") {
                    config.proxyPassword = s2ws(value);
                } else if (key == "EnablePIDFilter") {
                    std::string lowerVal = value;
                    std::transform(lowerVal.begin(), lowerVal.end(), lowerVal.begin(), ::tolower);
                    config.enablePidFilter = (lowerVal == "true");
                    loadedSomething = true; 
                } else if (key == "TargetPIDs") {
                    std::stringstream ss(value);
                    std::string segment;
                    config.targetPids.clear(); 
                    while(std::getline(ss, segment, ',')) {
                        try {
                            DWORD pid_val = std::stoul(trim_string_config(segment));
                            if (pid_val > 0) { 
                                config.targetPids.push_back(pid_val);
                            }
                        } catch (const std::exception& e) {
                            // Log(L"Invalid PID format in TargetPIDs: " + s2ws(segment) + L". Error: " + s2ws(e.what()));
                        }
                    }
                    if (!config.targetPids.empty() || key == "TargetPIDs") { // Mark as loaded even if list is empty but key exists
                        loadedSomething = true; 
                    }
                } else if (key == "ProcessName" || key == "ProxyIP") {
                    // These keys are deprecated, do nothing or log a warning
                    // Log(L"Deprecated configuration key found: " + s2ws(key));
                }
            }
        }
    }
    // Log(L"Configuration loaded. TargetProcessID: " + std::to_wstring(config.processId) + L", ProxyAddress: " + config.proxyAddress);
    configFile.close();
    return loadedSomething; // Return true if at least some core values were read
}

void SaveConfigurationToFile(const ServiceConfig& config, std::mutex& configMutex) {
    std::ofstream configFile(CONFIG_FILE_NAME);
    // Log(L"Attempting to save configuration to " + s2ws(CONFIG_FILE_NAME)); // Caller can log
    // The lock_guard is removed from here, caller must hold the lock.

    if (!configFile.is_open()) {
        // Log(L"Could not open configuration file for writing."); // Caller can log
        return;
    }

    // Updated to use correct field names from ServiceConfig (config_utils.h)
    configFile << "TargetProcessID=" << config.processId << std::endl;
    configFile << "ProxyAddress=" << ws2s(config.proxyAddress) << std::endl;
    configFile << "ProxyPort=" << config.proxyPort << std::endl;
    configFile << "ProxyUsername=" << ws2s(config.proxyUsername) << std::endl;
    configFile << "ProxyPassword=" << ws2s(config.proxyPassword) << std::endl;
    
    // Save new PID filter settings
    configFile << "EnablePIDFilter=" << (config.enablePidFilter ? "true" : "false") << std::endl;
    std::string pidsStr;
    if (!config.targetPids.empty()) {
        for (size_t i = 0; i < config.targetPids.size(); ++i) {
            pidsStr += std::to_string(config.targetPids[i]);
            if (i < config.targetPids.size() - 1) {
                pidsStr += ",";
            }
        }
    }
    configFile << "TargetPIDs=" << pidsStr << std::endl; // Always write the key, even if value is empty
    
    // Log(L"Configuration saved."); // Caller can log
    configFile.close();
} 