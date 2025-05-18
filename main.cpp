#include "framework.h"
#include "service.h"
#include "string_utils.h"
#include "config_utils.h"
#include "process_utils.h"
#include "named_pipe_server.h" // For NamedPipeServer class
#include "divert_handler.h"  // For DivertHandler class
#include <string>
#include <vector>
#include <windows.h>
#include <winsvc.h> 
#include <stdexcept> // Required for std::runtime_error
#include <sstream>   // Required for std::wstringstream
#include <mutex>     // Required for std::mutex
#include <fstream> // For file operations
#include <algorithm> // For std::remove for trim
#include <chrono> // For timestamps in log
#include <iomanip> // For std::put_time

// Forward declarations
bool InstallService();

// Global variables
SERVICE_STATUS_HANDLE g_ServiceStatusHandle = NULL;
SERVICE_STATUS g_ServiceStatus = {0};
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;

std::atomic<bool> g_IsRunning(false);
std::atomic<bool> g_IsPaused(false);
ServiceConfig g_ServiceConfig;

// Define global handlers (declared extern in framework.h)
NamedPipeServer* g_PipeServer = nullptr;
DivertHandler* g_DivertHandler = nullptr;

// Global log file stream and mutex
std::wofstream g_LogFile;
std::mutex g_LogMutex;
bool g_LogFileOpened = false;
const std::string LOG_FILE_NAME = "NetlinkRouter.log";

// global variables for absolute log path
std::wstring g_FullLogPath;
bool g_LogPathInitialized = false;

// Helper to initialize the log path
void EnsureLogPathInitialized() {
    if (g_LogPathInitialized) return;

    wchar_t szExePath[MAX_PATH];
    if (GetModuleFileName(NULL, szExePath, MAX_PATH) == 0) {
        DWORD error = GetLastError();
        std::wstringstream ss;
        // Use s2ws for LOG_FILE_NAME
        ss << L"LogInitialize: GetModuleFileName failed with error " << error << L". Using relative log path for '" << s2ws(LOG_FILE_NAME) << L"'.\n";
        OutputDebugStringW(ss.str().c_str());
        g_FullLogPath = s2ws(LOG_FILE_NAME); // Fallback to relative path
    } else {
        std::wstring exePathStr = szExePath;
        size_t lastSlash = exePathStr.find_last_of(L"\\/"); // Handle both path separators
        if (lastSlash != std::wstring::npos) {
            g_FullLogPath = exePathStr.substr(0, lastSlash + 1) + s2ws(LOG_FILE_NAME);
        } else {
            OutputDebugStringW(L"LogInitialize: No directory separator found in exe path. Using relative log path.\n");
            g_FullLogPath = s2ws(LOG_FILE_NAME); // Fallback
        }
    }
    g_LogPathInitialized = true;
    std::wstring initMsg = L"Log path target set to: " + g_FullLogPath + L"\n";
    OutputDebugStringW(initMsg.c_str());
}

// Helper to get current timestamp for logging
std::wstring GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::wstringstream ss;
    #pragma warning(suppress : 4996) // Suppress warning for std::localtime
    ss << std::put_time(std::localtime(&in_time_t), L"%Y-%m-%d %X"); 
    return ss.str();
}

// Simple logging to debug output and file
void Log(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    if (!g_LogPathInitialized) { // Ensure path is initialized within the lock
        EnsureLogPathInitialized();
    }

    std::string timedMessage = /* GetCurrentTimestampA() + */ " " + message; 
    OutputDebugStringA(timedMessage.c_str());
    OutputDebugStringA("\n");

    if (!g_LogFileOpened) {
        g_LogFile.open(g_FullLogPath, std::ios_base::app | std::ios_base::out); 
        if (g_LogFile.is_open()) {
            g_LogFileOpened = true;
            g_LogFile << L"--- Log Started: " << GetCurrentTimestamp() << L" ---" << std::endl;
        } else {
            OutputDebugStringA(("Failed to open log file: " + ws2s(g_FullLogPath) + "\n").c_str()); 
        }
    }
    if (g_LogFileOpened) {
        std::wstring wMessage(message.begin(), message.end());
        g_LogFile << GetCurrentTimestamp() << L": " << wMessage << std::endl;
    }
}

void Log(const std::wstring& message) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    if (!g_LogPathInitialized) { // Ensure path is initialized within the lock
        EnsureLogPathInitialized();
    }

    std::wstring timedMessage = GetCurrentTimestamp() + L": " + message;
    OutputDebugStringW(timedMessage.c_str());
    OutputDebugStringW(L"\n");

    if (!g_LogFileOpened) {
        g_LogFile.open(g_FullLogPath, std::ios_base::app | std::ios_base::out); 
        if (g_LogFile.is_open()) {
            g_LogFileOpened = true;
            g_LogFile << L"--- Log Started: " << GetCurrentTimestamp() << L" ---" << std::endl;
        } else {
             OutputDebugStringW((L"Failed to open log file: " + g_FullLogPath + L"\n").c_str()); 
        }
    }
    if (g_LogFileOpened) {
        g_LogFile << timedMessage << std::endl;
    }
}

// Console Control Handler
BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    switch (dwCtrlType) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
            Log(L"Console Ctrl+C or Close event detected. Signaling service logic to stop.");
            if (g_ServiceStopEvent != INVALID_HANDLE_VALUE) {
                SetEvent(g_ServiceStopEvent);
            }
            Sleep(1000); // Give a moment for SetEvent to be processed if needed.
            return TRUE; 
        default:
            return FALSE; 
    }
}

void RunServiceLogicInConsole() {
    Log(L"RunServiceLogicInConsole: Starting service logic directly in console mode.");

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        Log(L"RunServiceLogicInConsole: CreateEvent failed. Error: " + std::to_wstring(GetLastError()));
        return;
    }

    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        Log(L"RunServiceLogicInConsole: SetConsoleCtrlHandler failed. Error: " + std::to_wstring(GetLastError()) + L". Ctrl+C might not stop cleanly.");
    }

    g_IsRunning = true;

    if (g_PipeServer) { delete g_PipeServer; g_PipeServer = nullptr; } // Defensive
    g_PipeServer = new NamedPipeServer();
    std::thread pipeThread(&NamedPipeServer::Start, g_PipeServer);

    if (g_DivertHandler) { delete g_DivertHandler; g_DivertHandler = nullptr; } // Defensive
    g_DivertHandler = new DivertHandler();

    Log(L"RunServiceLogicInConsole: Attempting to load saved configuration...");
    if (LoadConfigurationFromFile(g_ServiceConfig, g_configMutex)) {
        Log(L"RunServiceLogicInConsole: Configuration loaded.");
        std::lock_guard<std::mutex> lock(g_configMutex);
        if (!g_ServiceConfig.proxyAddress.empty() && g_ServiceConfig.proxyPort != 0) {
            if (g_ServiceConfig.processId == 0 && g_ServiceConfig.enablePidFilter) {
                 Log(L"RunServiceLogicInConsole: PID filtering is enabled, but no specific TargetProcessID was found or it was 0. This might mean all PIDs are subject to filtering if targetPids list is also empty, or no PID-specific actions if targetPids is populated but doesn't match.");
            } else if (g_ServiceConfig.processId != 0) {
                 Log(L"RunServiceLogicInConsole: Specific TargetProcessID loaded: " + std::to_wstring(g_ServiceConfig.processId));
            }
            
            g_ServiceConfig.configured = true;
            g_IsPaused = false;
            
            Log(L"RunServiceLogicInConsole: Attempting to auto-start DivertHandler...");
            if (g_DivertHandler && g_DivertHandler->Start()) {
                Log(L"RunServiceLogicInConsole: DivertHandler auto-started successfully.");
            } else {
                Log(L"RunServiceLogicInConsole: Failed to auto-start DivertHandler.");
                g_ServiceConfig.configured = false;
            }
        } else {
            Log(L"RunServiceLogicInConsole: Loaded configuration is incomplete (ProxyAddress or ProxyPort missing). Diversion not auto-started.");
            g_ServiceConfig.configured = false;
        }
    } else {
        Log(L"RunServiceLogicInConsole: No saved configuration or failed to load. Waiting for pipe commands.");
        std::lock_guard<std::mutex> lock(g_configMutex);
        g_ServiceConfig.configured = false;
    }

    Log(L"RunServiceLogicInConsole: Service logic running. Press Ctrl+C to stop.");
    WaitForSingleObject(g_ServiceStopEvent, INFINITE);
    Log(L"RunServiceLogicInConsole: Stop event received. Shutting down...");

    g_IsRunning = false; 

    if (g_DivertHandler) {
        Log(L"RunServiceLogicInConsole: Stopping DivertHandler...");
        g_DivertHandler->Stop();
    }
    if (g_PipeServer) {
        Log(L"RunServiceLogicInConsole: Stopping NamedPipeServer...");
        g_PipeServer->Stop();
        if (pipeThread.joinable()) {
            Log(L"RunServiceLogicInConsole: Joining NamedPipeServer thread...");
            pipeThread.join();
        }
        delete g_PipeServer;
        g_PipeServer = nullptr;
    }
    if (g_DivertHandler) {
        delete g_DivertHandler;
        g_DivertHandler = nullptr;
    }

    if (g_ServiceStopEvent != INVALID_HANDLE_VALUE) {
        CloseHandle(g_ServiceStopEvent);
        g_ServiceStopEvent = INVALID_HANDLE_VALUE;
    }
    SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE); // Remove handler
    Log(L"RunServiceLogicInConsole: Service logic stopped.");
}

// Function to install the service
bool InstallService() {
    Log(std::wstring(L"InstallService: Attempting to install service '") + SERVICE_NAME + L"'.");
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (NULL == schSCManager) {
        Log(L"InstallService: OpenSCManager failed. Error: " + std::to_wstring(GetLastError()));
        return false;
    }

    wchar_t szPath[MAX_PATH];
    if (!GetModuleFileName(NULL, szPath, MAX_PATH)) {
        Log(std::wstring(L"InstallService: GetModuleFileName failed. Error: ") + std::to_wstring(GetLastError()));
        CloseServiceHandle(schSCManager);
        return false;
    }

    SC_HANDLE schService = CreateService(
        schSCManager,
        SERVICE_NAME,           // service name to register
        DISPLAY_NAME,           // display name
        SERVICE_ALL_ACCESS,     // desired access
        SERVICE_WIN32_OWN_PROCESS, // service type
        SERVICE_DEMAND_START,   // start type (manual start)
        SERVICE_ERROR_NORMAL,   // error control type
        szPath,                 // path to service's binary
        NULL,                   // no load ordering group
        NULL,                   // no tag identifier
        NULL,                   // no dependencies
        NULL,                   // LocalSystem account
        NULL                    // no password
    );

    if (schService == NULL) {
        Log(L"InstallService: CreateService failed. Error: " + std::to_wstring(GetLastError()));
        CloseServiceHandle(schSCManager);
        return false;
    }

    Log(std::wstring(L"InstallService: Service '") + SERVICE_NAME + L"' installed successfully.");
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return true;
}

// Function to uninstall the service
bool UninstallService() {
    Log(std::wstring(L"UninstallService: Attempting to uninstall service '") + SERVICE_NAME + L"'.");
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); 
    if (NULL == schSCManager) {
        Log(std::wstring(L"UninstallService: OpenSCManager failed. Error: ") + std::to_wstring(GetLastError()));
        return false;
    }

    SC_HANDLE schService = OpenService(schSCManager, SERVICE_NAME, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (schService == NULL) {
        Log(std::wstring(L"UninstallService: OpenService failed. Error: ") + std::to_wstring(GetLastError()) + L". Might not be installed.");
        CloseServiceHandle(schSCManager);
        return false; 
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    if (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &dwBytesNeeded)) {
        if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING) {
            Log(L"UninstallService: Service is running. Attempting to stop...");
            SERVICE_STATUS status;
            if (ControlService(schService, SERVICE_CONTROL_STOP, &status)) {
                Log(L"UninstallService: Stop signal sent to service. Waiting up to 30s...");
                Sleep(1000); 
                for (int i = 0; i < 30; ++i) { 
                    if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &dwBytesNeeded)) break; 
                    if (ssp.dwCurrentState == SERVICE_STOPPED) {
                        Log(L"UninstallService: Service stopped successfully.");
                        break;
                    }
                    Sleep(1000);
                }
                if (ssp.dwCurrentState != SERVICE_STOPPED) {
                    Log(L"UninstallService: Service did not stop in time.");
                }
            } else {
                Log(L"UninstallService: ControlService failed to stop the service. Error: " + std::to_wstring(GetLastError()));
            }
        }
    } else {
        Log(L"UninstallService: QueryServiceStatusEx failed. Error: " + std::to_wstring(GetLastError()));
    }

    if (!DeleteService(schService)) {
        Log(L"UninstallService: DeleteService failed. Error: " + std::to_wstring(GetLastError()));
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return false;
    }

    Log(std::wstring(L"UninstallService: Service '") + SERVICE_NAME + L"' uninstalled successfully.");
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return true;
}

// Main function for the service
int wmain(int argc, wchar_t *argv[]) {
    // Process command-line arguments first
    if (argc > 1) {
        if (_wcsicmp(argv[1], L"install") == 0) {
            Log(L"Command-line: 'install' received.");
            if (InstallService()) {
                Log(std::wstring(L"Service '") + SERVICE_NAME + L"' installed successfully.");
                return 0;
            } else {
                Log(std::wstring(L"Service '") + SERVICE_NAME + L"' installation failed. See log. Ensure you run as administrator.");
                return 1;
            }
        } else if (_wcsicmp(argv[1], L"uninstall") == 0) {
            Log(L"Command-line: 'uninstall' received.");
            if (UninstallService()) {
                Log(std::wstring(L"Service '") + SERVICE_NAME + L"' uninstalled successfully.");
                return 0;
            } else {
                Log(std::wstring(L"Service '") + SERVICE_NAME + L"' uninstallation failed. See log. Ensure you run as administrator.");
                return 1;
            }
        } else if (_wcsicmp(argv[1], L"--run-in-console") == 0) {
            Log(L"Command-line: '--run-in-console' received. Running service logic directly in console.");
            RunServiceLogicInConsole();
            Log(L"Console service logic finished. Application will now exit.");
            return 0;
        } else {
            // Log unrecognized argument, then proceed to default behavior (try service)
            Log(std::wstring(L"Unrecognized command-line argument: ") + argv[1] + L". Proceeding to attempt service start.");
        }
    }

    Log(L"Attempting to start as a service...");
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {const_cast<LPWSTR>(SERVICE_NAME), (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // This means the application was not started by the SCM.
            Log(L"StartServiceCtrlDispatcher failed with ERROR_FAILED_SERVICE_CONTROLLER_CONNECT. This means the application was not started by the SCM. If you intended to run in console, use --run-in-console. Otherwise, this executable should be managed by the Service Control Manager.");
        } else {
            // Another error occurred when trying to connect to the SCM.
            Log(std::wstring(L"StartServiceCtrlDispatcher failed with error code: ") + std::to_wstring(error) + L". This is unexpected if not ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.");
        }
        // In either case of StartServiceCtrlDispatcher failure, if not handled by --run-in-console, 
        return error; 
    } else {
        Log(L"StartServiceCtrlDispatcher succeeded. Service is now running under SCM control or will be started by SCM.");
    }

    Log(L"Application main function is exiting.");
    return 0;
}