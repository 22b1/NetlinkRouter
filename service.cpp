#include "service.h"
#include "named_pipe_server.h"
#include "divert_handler.h"
#include "config_utils.h"
#include "process_utils.h"
#include "string_utils.h"
#include <windows.h> // For OutputDebugStringW and other API calls
#include <string>    // For std::to_wstring
#include <ws2tcpip.h> // For getaddrinfo, inet_ntop, freeaddrinfo
#include <iphlpapi.h> // Not directly used here but often with network utils
#include <vector>     // For std::vector, if needed for future enhancements
#include <algorithm>  // For std::transform etc.

// External globals declared in main.cpp and framework.h
extern SERVICE_STATUS_HANDLE g_ServiceStatusHandle;
extern SERVICE_STATUS g_ServiceStatus;
extern HANDLE g_ServiceStopEvent;
extern std::atomic<bool> g_IsRunning;
extern std::atomic<bool> g_IsPaused;
extern NamedPipeServer *g_PipeServer;
extern DivertHandler *g_DivertHandler;
extern ServiceConfig g_ServiceConfig;
extern std::mutex g_configMutex; // Added extern for global config mutex

VOID WINAPI ServiceMain(DWORD dwArgc, LPWSTR *lpszArgv)
{
    OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Entered.");
    Log(L"ServiceMain: Entered.");

    g_ServiceStatusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, ServiceCtrlHandler, NULL);
    if (g_ServiceStatusHandle == NULL)
    {
        DWORD error = GetLastError();
        OutputDebugStringW((L"[NetlinkRouter] ServiceMain: RegisterServiceCtrlHandlerExW FAILED. Error: " + std::to_wstring(error) + L"").c_str());
        Log(L"ServiceMain: RegisterServiceCtrlHandlerExW FAILED. Error: " + std::to_wstring(error));
        return;
    }
    OutputDebugStringW(L"[NetlinkRouter] ServiceMain: RegisterServiceCtrlHandlerExW SUCCEEDED.");
    Log(L"ServiceMain: RegisterServiceCtrlHandlerExW SUCCEEDED.");

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;

    ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 5000);
    OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Reported SERVICE_START_PENDING.");
    Log(L"ServiceMain: Reported SERVICE_START_PENDING.");

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL)
    {
        DWORD error = GetLastError();
        OutputDebugStringW((L"[NetlinkRouter] ServiceMain: CreateEvent for g_ServiceStopEvent FAILED. Error: " + std::to_wstring(error) + L"").c_str());
        Log(L"ServiceMain: CreateEvent for g_ServiceStopEvent FAILED. Error: " + std::to_wstring(error));
        ReportSvcStatus(SERVICE_STOPPED, error, 0);
        return;
    }
    OutputDebugStringW(L"[NetlinkRouter] ServiceMain: CreateEvent for g_ServiceStopEvent SUCCEEDED.");
    Log(L"ServiceMain: CreateEvent for g_ServiceStopEvent SUCCEEDED.");

    std::thread pipeThread;

    try
    {
        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Initializing components (PipeServer, DivertHandler)...");
        Log(L"ServiceMain: Initializing components (PipeServer, DivertHandler)...");

        if (g_PipeServer)
        {
            delete g_PipeServer;
            g_PipeServer = nullptr;
        }
        g_PipeServer = new NamedPipeServer();
        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: NamedPipeServer instance created.");
        Log(L"ServiceMain: NamedPipeServer instance created.");

        if (g_DivertHandler)
        {
            delete g_DivertHandler;
            g_DivertHandler = nullptr;
        }
        g_DivertHandler = new DivertHandler();
        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: DivertHandler instance created.");
        Log(L"ServiceMain: DivertHandler instance created.");

        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Attempting to load saved configuration...");
        Log(L"ServiceMain: Attempting to load saved configuration...");
        if (LoadConfigurationFromFile(g_ServiceConfig, g_configMutex))
        {
            OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Configuration loaded from file.");
            Log(L"ServiceMain: Configuration loaded from file.");
        }
        else
        {
            OutputDebugStringW(L"[NetlinkRouter] ServiceMain: No configuration file found or failed to load.");
            Log(L"ServiceMain: No configuration file found or failed to load. Service will wait for pipe commands.");
            std::lock_guard<std::mutex> lock(g_configMutex); // Use global g_configMutex
            g_ServiceConfig.configured = false;
        }

        std::string loaded_proxy_ip_for_fw;
        unsigned short loaded_proxy_port_for_fw = 0;
        bool proceed_with_fw_rules = false;

        {
            std::lock_guard<std::mutex> lock(g_configMutex); // Use global g_configMutex
            if (!g_ServiceConfig.proxyAddress.empty() && g_ServiceConfig.proxyPort != 0) {
                std::string proxy_addr_str = ws2s(g_ServiceConfig.proxyAddress);
                addrinfo hints = {0}, *res = nullptr;
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;
                std::string port_str_lookup = std::to_string(g_ServiceConfig.proxyPort);

                if (getaddrinfo(proxy_addr_str.c_str(), port_str_lookup.c_str(), &hints, &res) == 0) {
                    char ipstr_buffer[INET6_ADDRSTRLEN];
                    void *addr_ptr = nullptr;
                    if (res->ai_family == AF_INET) {
                        addr_ptr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
                    } else {
                        addr_ptr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
                    }
                    if (inet_ntop(res->ai_family, addr_ptr, ipstr_buffer, sizeof(ipstr_buffer)) != nullptr) {
                        loaded_proxy_ip_for_fw = ipstr_buffer;
                    } else {
                        Log(L"ServiceMain: inet_ntop failed for firewall rule IP resolution. Using original config value.");
                        loaded_proxy_ip_for_fw = proxy_addr_str; // Fallback to stringified original
                    }
                    freeaddrinfo(res);
                } else {
                    IN_ADDR ipv4_addr_check;
                    IN6_ADDR ipv6_addr_check;
                    if (inet_pton(AF_INET, proxy_addr_str.c_str(), &ipv4_addr_check) == 1 ||
                        inet_pton(AF_INET6, proxy_addr_str.c_str(), &ipv6_addr_check) == 1) {
                        Log(L"ServiceMain: getaddrinfo failed for firewall rule IP resolution, but original value is a valid IP. Using: " + g_ServiceConfig.proxyAddress);
                        loaded_proxy_ip_for_fw = proxy_addr_str;
                    } else {
                        Log(L"ServiceMain: Failed to resolve proxy hostname for firewall rule and it's not a valid IP: " + g_ServiceConfig.proxyAddress + L". Cannot create specific FW rule.");
                    }
                }
                loaded_proxy_port_for_fw = g_ServiceConfig.proxyPort;
                if (!loaded_proxy_ip_for_fw.empty()) {
                    proceed_with_fw_rules = true;
                }
            }
        }

        if (proceed_with_fw_rules) {
            Log(L"ServiceMain: Attempting to add firewall rules for resolved proxy " + s2ws(loaded_proxy_ip_for_fw) + L":" + std::to_wstring(loaded_proxy_port_for_fw) + L" based on loaded config...");
            std::string proxy_port_str = std::to_string(loaded_proxy_port_for_fw);

            std::string tcp_rule_cmd = "netsh advfirewall firewall add rule name=\\\"NetlinkRouter Allow Proxy TCP " + loaded_proxy_ip_for_fw + ":" + proxy_port_str + "\\\" dir=out action=allow protocol=TCP remoteip=" + loaded_proxy_ip_for_fw + " remoteport=" + proxy_port_str + " > nul 2>&1";
            Log(L"ServiceMain: Executing TCP rule: " + s2ws(tcp_rule_cmd));
            system(tcp_rule_cmd.c_str());

            std::string udp_rule_cmd = "netsh advfirewall firewall add rule name=\\\"NetlinkRouter Allow Proxy UDP " + loaded_proxy_ip_for_fw + ":" + proxy_port_str + "\\\" dir=out action=allow protocol=UDP remoteip=" + loaded_proxy_ip_for_fw + " remoteport=" + proxy_port_str + " > nul 2>&1";
            Log(L"ServiceMain: Executing UDP rule: " + s2ws(udp_rule_cmd));
            system(udp_rule_cmd.c_str());
            Log(L"ServiceMain: Firewall rule attempts for loaded config completed.");
        } else {
            Log(L"ServiceMain: No valid proxy configuration loaded from file, or proxy IP/port is invalid/unresolvable. Skipping firewall rule addition at startup.");
        }

        {
            std::lock_guard<std::mutex> lock(g_configMutex); // Use global g_configMutex
            if (!g_ServiceConfig.proxyAddress.empty() && g_ServiceConfig.proxyPort != 0)
            {
                Log(L"ServiceMain: Found Proxy: " + g_ServiceConfig.proxyAddress + L":" + std::to_wstring(g_ServiceConfig.proxyPort));
                if (g_ServiceConfig.processId == 0 && g_ServiceConfig.enablePidFilter) {
                     Log(L"ServiceMain: PID filtering is enabled, but no specific TargetProcessID was found or it was 0.");
                } else if (g_ServiceConfig.processId != 0) {
                     Log(L"ServiceMain: Specific TargetProcessID loaded: " + std::to_wstring(g_ServiceConfig.processId));
                }
                
                g_ServiceConfig.configured = true;
                g_IsPaused = false;
                
                Log(L"ServiceMain: Attempting to auto-start DivertHandler...");
                if (g_DivertHandler && g_DivertHandler->Start()) {
                    Log(L"ServiceMain: DivertHandler auto-started successfully based on loaded configuration.");
                } else {
                    Log(L"ServiceMain: Failed to auto-start DivertHandler. Service will run but not divert traffic until configured via pipe.");
                    g_ServiceConfig.configured = false;
                }
            }
            else {
                Log(L"ServiceMain: Loaded configuration is incomplete (ProxyAddress or ProxyPort missing). Diversion not started.");
                g_ServiceConfig.configured = false;
            }
        }

        ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
        Log(L"ServiceMain: Reported SERVICE_RUNNING.");
        g_IsRunning = true;

        if (g_PipeServer) {
             OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Starting NamedPipeServer thread...");
             Log(L"ServiceMain: Starting NamedPipeServer thread...");
             pipeThread = std::thread(&NamedPipeServer::Start, g_PipeServer);
        }

        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Entering main wait loop (WaitForSingleObject).");
        Log(L"ServiceMain: Entering main wait loop (WaitForSingleObject).");
        WaitForSingleObject(g_ServiceStopEvent, INFINITE);

        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Stop event received.");
        Log(L"ServiceMain: Stop event received.");
    }
    catch (const std::exception &e)
    {
        std::string errorMessage = "ServiceMain caught C++ exception: ";
        errorMessage += e.what();
        OutputDebugStringW((L"[NetlinkRouter] ServiceMain: EXCEPTION: " + s2ws(errorMessage) + L"").c_str());
        Log(s2ws(errorMessage));
        ReportSvcStatus(SERVICE_STOPPED, ERROR_EXCEPTION_IN_SERVICE, 0);
        g_IsRunning = false; 
        if (g_PipeServer) {
            delete g_PipeServer;
            g_PipeServer = nullptr; }
        if (g_DivertHandler) {
            delete g_DivertHandler;
            g_DivertHandler = nullptr; }
        if (g_ServiceStopEvent != INVALID_HANDLE_VALUE) {
            CloseHandle(g_ServiceStopEvent);
            g_ServiceStopEvent = INVALID_HANDLE_VALUE; }
        return;
    }
    catch (...)
    {
        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Caught UNKNOWN exception.");
        Log(L"ServiceMain: Caught UNKNOWN exception.");
        ReportSvcStatus(SERVICE_STOPPED, ERROR_EXCEPTION_IN_SERVICE, 0);
        g_IsRunning = false;
        if (g_PipeServer) {
            delete g_PipeServer;
            g_PipeServer = nullptr; }
        if (g_DivertHandler) {
            delete g_DivertHandler;
            g_DivertHandler = nullptr; }
        if (g_ServiceStopEvent != INVALID_HANDLE_VALUE) {
            CloseHandle(g_ServiceStopEvent);
            g_ServiceStopEvent = INVALID_HANDLE_VALUE; }
        return;
    }

    g_IsRunning = false;

    ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Reported SERVICE_STOP_PENDING for cleanup.");
    Log(L"ServiceMain: Reported SERVICE_STOP_PENDING for cleanup.");

    if (g_PipeServer) {
        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Stopping NamedPipeServer...");
        Log(L"ServiceMain: Stopping NamedPipeServer...");
        g_PipeServer->Stop();
    }

    if (pipeThread.joinable()) {
        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Joining NamedPipeServer thread...");
        Log(L"ServiceMain: Joining NamedPipeServer thread...");
        pipeThread.join();
        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: NamedPipeServer thread joined.");
        Log(L"ServiceMain: NamedPipeServer thread joined.");
    }
    delete g_PipeServer;
    g_PipeServer = nullptr;
    OutputDebugStringW(L"[NetlinkRouter] ServiceMain: NamedPipeServer resources released.");
    Log(L"ServiceMain: NamedPipeServer resources released.");

    if (g_DivertHandler) {
        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Stopping DivertHandler...");
        Log(L"ServiceMain: Stopping DivertHandler...");
        g_DivertHandler->Stop();
        delete g_DivertHandler;
        g_DivertHandler = nullptr;
        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: DivertHandler resources released.");
        Log(L"ServiceMain: DivertHandler resources released.");
    }

    if (g_ServiceStopEvent != INVALID_HANDLE_VALUE) {
        CloseHandle(g_ServiceStopEvent);
        g_ServiceStopEvent = INVALID_HANDLE_VALUE;
        OutputDebugStringW(L"[NetlinkRouter] ServiceMain: ServiceStopEvent handle closed.");
        Log(L"ServiceMain: ServiceStopEvent handle closed.");
    }

    ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
    OutputDebugStringW(L"[NetlinkRouter] ServiceMain: Reported SERVICE_STOPPED. Exiting normally.");
    Log(L"ServiceMain: Reported SERVICE_STOPPED. Exiting normally.");
}

DWORD WINAPI ServiceCtrlHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    OutputDebugStringW((L"[NetlinkRouter] ServiceCtrlHandler: Received control code: " + std::to_wstring(dwControl) + L"").c_str());
    Log(L"ServiceCtrlHandler: Received control code: " + std::to_wstring(dwControl));

    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
            OutputDebugStringW(L"[NetlinkRouter] ServiceCtrlHandler: STOP or SHUTDOWN requested.");
            Log(L"ServiceCtrlHandler: STOP or SHUTDOWN requested.");
            ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
            if (g_ServiceStopEvent != INVALID_HANDLE_VALUE) {
            SetEvent(g_ServiceStopEvent);
            }
            g_IsRunning = false;
            g_IsPaused = false;
            break;
        case SERVICE_CONTROL_PAUSE:
            OutputDebugStringW(L"[NetlinkRouter] ServiceCtrlHandler: PAUSE requested.");
            Log(L"ServiceCtrlHandler: PAUSE requested.");
            if (g_IsRunning && !g_IsPaused)
            {
                ReportSvcStatus(SERVICE_PAUSE_PENDING, NO_ERROR, 1000);
                g_IsPaused = true;
                if (g_DivertHandler) g_DivertHandler->Stop();
                ReportSvcStatus(SERVICE_PAUSED, NO_ERROR, 0);
            }
            break;
        case SERVICE_CONTROL_CONTINUE:
            OutputDebugStringW(L"[NetlinkRouter] ServiceCtrlHandler: CONTINUE requested.");
            Log(L"ServiceCtrlHandler: CONTINUE requested.");
            if (g_IsRunning && g_IsPaused)
            {
                ReportSvcStatus(SERVICE_CONTINUE_PENDING, NO_ERROR, 1000);
                g_IsPaused = false;
                if (g_DivertHandler) {
                    std::lock_guard<std::mutex> lock(g_configMutex);
                    if (!g_ServiceConfig.proxyAddress.empty()) {
                        OutputDebugStringW((L"[NetlinkRouter] ServiceCtrlHandler: Re-evaluating PID for " + g_ServiceConfig.proxyAddress + L" on CONTINUE.").c_str());
                        Log(L"ServiceCtrlHandler: Re-evaluating PID for " + g_ServiceConfig.proxyAddress + L" on CONTINUE.");
                        
                        DWORD newPid = GetProcessIdByName(g_ServiceConfig.proxyAddress.c_str());
                        if (newPid == 0) {
                            Log(L"ServiceCtrlHandler: PID not found for " + g_ServiceConfig.proxyAddress + L" on CONTINUE, but continuing anyway with PID=0");
                        }
                        
                        g_ServiceConfig.processId = newPid;
                        g_ServiceConfig.configured = true;

                        OutputDebugStringW((L"[NetlinkRouter] ServiceCtrlHandler: Using PID " + std::to_wstring(newPid) + L". Restarting DivertHandler.").c_str());
                        Log(L"ServiceCtrlHandler: Using PID " + std::to_wstring(newPid) + L". Restarting DivertHandler.");
                        
                        g_DivertHandler->Stop();
                        if (g_DivertHandler->Start()) {
                            OutputDebugStringW(L"[NetlinkRouter] ServiceCtrlHandler: DivertHandler restarted successfully on CONTINUE.");
                            Log(L"ServiceCtrlHandler: DivertHandler restarted successfully on CONTINUE.");
                        } else {
                            OutputDebugStringW(L"[NetlinkRouter] ServiceCtrlHandler: Failed to restart DivertHandler on CONTINUE.");
                            Log(L"ServiceCtrlHandler: Failed to restart DivertHandler on CONTINUE. Traffic may not be diverted.");
                            g_ServiceConfig.configured = false;
                        }
                    } else {
                        OutputDebugStringW(L"[NetlinkRouter] ServiceCtrlHandler: Process name empty on CONTINUE. DivertHandler not (re)started.");
                        Log(L"ServiceCtrlHandler: Process name empty on CONTINUE. DivertHandler not (re)started.");
                        if (g_ServiceConfig.configured) {
                             g_DivertHandler->Stop();
                             g_ServiceConfig.configured = false;
                        }
                    }
                } else {
                    OutputDebugStringW(L"[NetlinkRouter] ServiceCtrlHandler: g_DivertHandler is null on CONTINUE. Cannot manage diversion.");
                    Log(L"ServiceCtrlHandler: g_DivertHandler is null on CONTINUE. Cannot manage diversion.");
                }
                ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
                Log(L"ServiceCtrlHandler: Reported SERVICE_RUNNING (from CONTINUE).");
            }
            break;
        case SERVICE_CONTROL_INTERROGATE:
            OutputDebugStringW(L"[NetlinkRouter] ServiceCtrlHandler: INTERROGATE received.");
            Log(L"ServiceCtrlHandler: INTERROGATE received.");
            break;
        default:
            OutputDebugStringW((L"[NetlinkRouter] ServiceCtrlHandler: Unhandled control code: " + std::to_wstring(dwControl) + L"").c_str());
            Log(L"ServiceCtrlHandler: Unhandled control code: " + std::to_wstring(dwControl));
            break;
    }

    if (dwControl != SERVICE_CONTROL_PAUSE && dwControl != SERVICE_CONTROL_CONTINUE && dwControl != SERVICE_CONTROL_STOP && dwControl != SERVICE_CONTROL_SHUTDOWN) {
        ReportSvcStatus(g_ServiceStatus.dwCurrentState, g_ServiceStatus.dwWin32ExitCode, 0);
    }
    
    return NO_ERROR;
}

VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;

    if (g_ServiceStatusHandle == NULL)
    {
        OutputDebugStringW(L"[NetlinkRouter] ReportSvcStatus: g_ServiceStatusHandle is NULL. Cannot set status.");
        Log(L"ReportSvcStatus: g_ServiceStatusHandle is NULL in ReportSvcStatus.");
        return;
    }

    g_ServiceStatus.dwCurrentState = dwCurrentState;
    g_ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
    g_ServiceStatus.dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_START_PENDING || dwCurrentState == SERVICE_STOP_PENDING || dwCurrentState == SERVICE_PAUSE_PENDING || dwCurrentState == SERVICE_CONTINUE_PENDING)
    {
        g_ServiceStatus.dwControlsAccepted = 0;
    }
    else
    {
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PAUSE_CONTINUE;
    }

    if (dwCurrentState == SERVICE_RUNNING || dwCurrentState == SERVICE_STOPPED || dwCurrentState == SERVICE_PAUSED)
    {
        g_ServiceStatus.dwCheckPoint = 0;
    }
    else
    {
        g_ServiceStatus.dwCheckPoint = dwCheckPoint++;
    }

    if (!SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus))
    {
        DWORD error = GetLastError();
        OutputDebugStringW((L"[NetlinkRouter] ReportSvcStatus: SetServiceStatus FAILED. Error: " + std::to_wstring(error) + L"").c_str());
        Log(L"ReportSvcStatus: SetServiceStatus FAILED. Error: " + std::to_wstring(error));
    }
}