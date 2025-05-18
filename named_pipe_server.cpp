#include "named_pipe_server.h"
#include "process_utils.h"
#include "divert_handler.h"
#include "service.h"
#include "string_utils.h"
#include "config_utils.h"
#include "logger.h"

extern DivertHandler* g_DivertHandler; // Defined in service.cpp
extern ServiceConfig g_ServiceConfig; // Added to make it available
extern std::mutex g_configMutex;    // Added to make it available

NamedPipeServer::NamedPipeServer() : m_hPipe(INVALID_HANDLE_VALUE), m_IsRunning(false) {
    Log(L"NamedPipeServer constructor.");
}

NamedPipeServer::~NamedPipeServer() {
    Stop();
    Log(L"NamedPipeServer destructor.");
}

void NamedPipeServer::Start() {
    Log(L"NamedPipeServer::Start() called.");
    m_IsRunning = true;
    m_ListenerThread = std::thread(&NamedPipeServer::PipeListenerThread, this);
}

void NamedPipeServer::Stop() {
    Log(L"NamedPipeServer::Stop() called.");
    m_IsRunning = false; // Signal the listener thread to stop

    HANDLE pipeHandleToCancel = m_hPipe; // Capture current value
    if (pipeHandleToCancel != INVALID_HANDLE_VALUE) {
        Log(L"NamedPipeServer::Stop(): Attempting to cancel I/O on pipe handle.");
        if (!CancelIoEx(pipeHandleToCancel, NULL)) {
            DWORD error = GetLastError();
            if (error != ERROR_NOT_FOUND) {
                 Log(L"NamedPipeServer::Stop(): CancelIoEx failed. Error: " + std::to_wstring(error));
            }
        }
    }

    if (m_ListenerThread.joinable()) {
        m_ListenerThread.join();
    }

    Log(L"NamedPipeServer::Stop() completed.");
}

void NamedPipeServer::PipeListenerThread() {
    Log(L"PipeListenerThread started.");
    char buffer[BUFFER_SIZE];
    DWORD bytesRead;

    while (m_IsRunning && g_IsRunning) {
        m_hPipe = CreateNamedPipe(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0, // Default timeout
            NULL);

        if (m_hPipe == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            try {
                Log(L"CreateNamedPipe failed. Error: " + std::to_wstring(error));
            } catch (const std::exception& e) {
                std::wstring errMsg = L"PipeListenerThread: EXCEPTION during logging CreateNamedPipe failure: ";
                errMsg += s2ws(e.what());
                errMsg += L", Original CreateNamedPipe Error: " + std::to_wstring(error);
                OutputDebugStringW(errMsg.c_str());
            } catch (...) {
                std::wstring errMsg = L"PipeListenerThread: UNKNOWN EXCEPTION during logging CreateNamedPipe failure. Original CreateNamedPipe Error: " + std::to_wstring(error);
                OutputDebugStringW(errMsg.c_str());
            }

            if (m_IsRunning && g_IsRunning) Sleep(1000); // Avoid busy loop on persistent failure
            continue;
        }

        Log(L"Named pipe created. Waiting for client connection...");

        // Wait for a client to connect
        BOOL connected = ConnectNamedPipe(m_hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        
        if (!m_IsRunning || !g_IsRunning) { // Check after potentially blocking call
             Log(L"PipeListenerThread: shutting down while waiting for connection or after connection.");
             // Ensure pipe is disconnected and closed if it was connected or ConnectNamedPipe was aborted
             if (m_hPipe != INVALID_HANDLE_VALUE) { // Check if handle is still valid before operations
                DisconnectNamedPipe(m_hPipe);
                CloseHandle(m_hPipe);
                m_hPipe = INVALID_HANDLE_VALUE;
             }
             break;
        }

        if (connected) {
            Log(L"Client connected to named pipe.");
            HandleClient(m_hPipe);
        } else {
            Log(L"ConnectNamedPipe failed. Error: " + std::to_wstring(GetLastError()));
        }
        // Close the pipe instance for this client. The loop will create a new one.
        if (m_hPipe != INVALID_HANDLE_VALUE) { // Check if handle is still valid before operations
            DisconnectNamedPipe(m_hPipe); 
            CloseHandle(m_hPipe);
            m_hPipe = INVALID_HANDLE_VALUE; // Important to reset for the next iteration
        }
    }
    Log(L"PipeListenerThread exiting.");
}

void NamedPipeServer::HandleClient(HANDLE hPipe) {
    char buffer[BUFFER_SIZE];
    DWORD bytesRead;
    BOOL success = FALSE;

    success = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
    if (success && bytesRead > 0) {
        buffer[bytesRead] = '\0'; // Null-terminate the received string
        std::string commandStr(buffer);
        Log("Received command: " + commandStr);

        if (ParseCommand(commandStr)) {
            const char* response = "OK";
            DWORD bytesWritten;
            WriteFile(hPipe, response, strlen(response), &bytesWritten, NULL);
        } else {
            const char* response = "ERROR: Invalid command or failed to execute";
            DWORD bytesWritten;
            WriteFile(hPipe, response, strlen(response), &bytesWritten, NULL);
        }
    } else {
        Log(L"ReadFile from pipe failed or read 0 bytes. Error: " + std::to_wstring(GetLastError()));
    }
    FlushFileBuffers(hPipe);
}


bool NamedPipeServer::ParseCommand(const std::string& commandStr) {
    std::istringstream iss(commandStr);
    std::string command;
    iss >> command;
    std::transform(command.begin(), command.end(), command.begin(), ::toupper);

    std::lock_guard<std::mutex> lock(g_configMutex); // Use global g_configMutex

    if (command == "START") {
        std::string targetIdStr, proxyAddressStr, proxyPortStr, usernameStr, passwordStr;
        // Expecting TargetID (can be PID or ProcessName), ProxyAddress, ProxyPort, Username, Password
        iss >> targetIdStr >> proxyAddressStr >> proxyPortStr >> usernameStr >> passwordStr;

        if (proxyAddressStr.empty() || proxyPortStr.empty()) {
            Log(L"START command: Missing required proxy address or port parameters.");
            return false;
        }
        
        // If targetIdStr is provided, try to use it.
        // For simplicity, assume targetIdStr is a process name if not empty, or it could be a PID.
        // The config now stores processId (DWORD).
        if (!targetIdStr.empty()) {
            // Attempt to convert targetIdStr to DWORD (PID)
            try {
                g_ServiceConfig.processId = std::stoul(targetIdStr);
                Log(L"START command: Parsed TargetID as PID: " + std::to_wstring(g_ServiceConfig.processId));
            } catch (const std::invalid_argument&) {
                // If not a number, assume it's a process name
                std::wstring processNameWstr = s2ws(targetIdStr);
                g_ServiceConfig.processId = GetProcessIdByName(processNameWstr.c_str());
                if (g_ServiceConfig.processId == 0) {
                    Log(L"START command: Process ID not found for name '" + processNameWstr + L"', but continuing with PID=0 if PID filtering is not strictly required or if it means 'all PIDs'.");
                } else {
                    Log(L"START command: Looked up PID for name '" + processNameWstr + L"': " + std::to_wstring(g_ServiceConfig.processId));
                }
            } catch (const std::out_of_range&) {
                 Log(L"START command: TargetID '" + s2ws(targetIdStr) + L"' is out of range for PID. Treating as invalid for direct PID.");
                 g_ServiceConfig.processId = 0; // Or handle as error
            }
        } else {
            g_ServiceConfig.processId = 0; // No target ID provided, effectively system-wide or no specific PID focus.
            Log(L"START command: No TargetID provided. PID set to 0.");
        }

        g_ServiceConfig.proxyAddress = s2ws(proxyAddressStr);
        try {
            g_ServiceConfig.proxyPort = static_cast<unsigned short>(std::stoi(proxyPortStr));
        } catch (const std::exception& e) {
            Log(L"START command: Invalid port number. " + s2ws(e.what()));
            return false;
        }
        g_ServiceConfig.proxyUsername = s2ws(usernameStr);
        g_ServiceConfig.proxyPassword = s2ws(passwordStr);

        Log(L"START command parsed: TargetPID=" + std::to_wstring(g_ServiceConfig.processId) +
            L", ProxyAddress=" + g_ServiceConfig.proxyAddress +
            L":" + std::to_wstring(g_ServiceConfig.proxyPort) +
            L", User=" + g_ServiceConfig.proxyUsername);

        g_ServiceConfig.configured = true;
        g_IsPaused = false; 
        if (g_DivertHandler) {
            Log(L"ParseCommand: Calling g_DivertHandler->Stop() before starting.");
            g_DivertHandler->Stop(); 
            Log(L"ParseCommand: g_DivertHandler->Stop() completed. Now calling g_DivertHandler->Start().");
            bool startResult = false; 
            try {
                startResult = g_DivertHandler->Start();
                Log(L"ParseCommand: g_DivertHandler->Start() returned: " + std::wstring(startResult ? L"true" : L"false"));
            } catch (const std::exception& e) {
                Log(L"ParseCommand: EXCEPTION caught while calling g_DivertHandler->Start(): " + s2ws(e.what()));
                startResult = false; 
            } catch (...) {
                Log(L"ParseCommand: UNKNOWN EXCEPTION caught while calling g_DivertHandler->Start().");
                startResult = false; 
            }
            // If start failed, should we mark configured as false?
            if (!startResult) g_ServiceConfig.configured = false;
            return startResult;
        } else {
            Log(L"g_DivertHandler is null when processing START command. Creating new instance.");
            g_DivertHandler = new DivertHandler();
            if (g_DivertHandler) {
                Log(L"ParseCommand: New DivertHandler instance created. Calling g_DivertHandler->Start().");
                bool startResult = false;
                try {
                    startResult = g_DivertHandler->Start();
                    Log(L"ParseCommand: g_DivertHandler->Start() (for new instance) returned: " + std::wstring(startResult ? L"true" : L"false"));
                } catch (const std::exception& e) {
                    Log(L"ParseCommand: EXCEPTION caught while calling g_DivertHandler->Start() (for new instance): " + s2ws(e.what()));
                    startResult = false;
                } catch (...) {
                    Log(L"ParseCommand: UNKNOWN EXCEPTION caught while calling g_DivertHandler->Start() (for new instance).");
                    startResult = false; 
                }
                if (!startResult) g_ServiceConfig.configured = false;
                return startResult;
            } else {
                Log(L"Failed to create new DivertHandler instance.");
                g_ServiceConfig.configured = false; // Cannot configure if handler cannot be created
                return false;
            }
        }

    } else if (command == "STOP") {
        Log("STOP command parsed.");
        g_ServiceConfig.configured = false;
        if (g_DivertHandler) {
            g_DivertHandler->Stop();
        }
        return true;

    } else if (command == "PAUSE") {
        Log("PAUSE command parsed.");
        g_IsPaused = true;
        // DivertHandler loop should check g_IsPaused
        if (g_DivertHandler) {} // empty function leave as is currently
        ReportSvcStatus(SERVICE_PAUSED, NO_ERROR, 0); 
        return true;

    } else if (command == "RESUME") {
        Log("RESUME command parsed.");
        g_IsPaused = false;
        // DivertHandler loop should check g_IsPaused
         if (g_DivertHandler && g_ServiceConfig.configured) {
            if (!g_DivertHandler->IsRunning()) {
                 g_DivertHandler->Start();
            }
        }
        ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
        return true;
    }

    Log(L"Unknown command: " + s2ws(command));
    return false;
} 