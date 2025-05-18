#include "divert_handler.h"
#include "packet_processor.h"
#include "ip_utils.h"
#include "string_utils.h" // For s2ws function
#include <sstream>      // For std::wstringstream
#include <ws2tcpip.h>   // For InetNtopW, ntohs, etc.
#include "config_utils.h" // Added to resolve g_ServiceConfig
#include "logger.h"

DivertHandler::DivertHandler() : m_hDivert(INVALID_HANDLE_VALUE), m_IsRunning(false), m_ShouldStop(false) {
    Log(L"DivertHandler constructor.");
    m_PacketProcessor = new PacketProcessor();
}

DivertHandler::~DivertHandler() {
    Stop();
    delete m_PacketProcessor;
    m_PacketProcessor = nullptr;
    Log(L"DivertHandler destructor.");
}

bool DivertHandler::Start() {
    if (!g_ServiceConfig.configured) {
        Log(L"DivertHandler::Start - Not configured. Cannot start (caller should ensure config is locked and valid).");
        return false;
    }
    
    // Note: We're no longer requiring g_ServiceConfig.processId to be non-zero
    // since we're capturing all outbound traffic regardless of PID
    // TODO: Capture only traffic from PID =========================================================================== <================================

    if (m_IsRunning) {
        Log(L"DivertHandler::Start - Already running.");
        return true;
    }

    Log(L"DivertHandler::Start() called for PID: " + std::to_wstring(g_ServiceConfig.processId));

#ifdef WITH_WINDIVERT
    if (!m_PacketProcessor->Initialize(ws2s(g_ServiceConfig.proxyAddress), 
                                     g_ServiceConfig.proxyPort, 
                                     ws2s(g_ServiceConfig.proxyUsername), 
                                     ws2s(g_ServiceConfig.proxyPassword), 
                                     m_hDivert)) {
        Log(L"PacketProcessor initialization failed.");
        // m_hDivert might be opened by PacketProcessor, ensure it's closed if init fails
        if (m_hDivert != INVALID_HANDLE_VALUE) {
             WinDivertClose(m_hDivert);
             m_hDivert = INVALID_HANDLE_VALUE;
        }
        return false;
    }

    // Filter to capture all outbound IPv4 TCP and UDP traffic, excluding loopback.
    // Proxy exclusion is removed from the filter string itself.
    // PacketProcessor must identify and correctly handle packets already destined for the proxy.
    std::string main_filter_logic = "(outbound and ip and tcp) or (outbound and ip and udp and udp.DstPort != 53)";
    
    // Combine main logic and loopback exclusion
    std::string filter = "(" + main_filter_logic + ") and not loopback";

    Log(L"WinDivert filter: " + std::wstring(filter.begin(), filter.end()));
    // For WINDIVERT_LAYER_NETWORK, use 0 for flags to intercept and allow reinjection.
    m_hDivert = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (m_hDivert == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        Log(L"WinDivertOpen failed. Error code: " + std::to_wstring(error));
        
        switch(error) {
            case ERROR_FILE_NOT_FOUND:
                Log(L"WinDivert driver files not found (ERROR_FILE_NOT_FOUND).");
                break;
            case ERROR_ACCESS_DENIED:
                Log(L"Access denied - application requires Administrator privileges (ERROR_ACCESS_DENIED).");
                break;
            case ERROR_INVALID_PARAMETER:
                Log(L"Invalid parameter - bad filter string, layer, priority, or flags (ERROR_INVALID_PARAMETER).");
                break;
            case ERROR_INVALID_IMAGE_HASH:
                Log(L"Invalid driver signature - WinDivert driver does not have a valid digital signature (ERROR_INVALID_IMAGE_HASH).");
                break;
            default:
                Log(L"Unknown error when opening WinDivert. Make sure the service is running with Administrator privileges.");
                break;
        }
        
        Log(L"Ensure WinDivert driver is loaded and app has admin rights.");
        return false;
    }

    if (!WinDivertSetParam(m_hDivert, WINDIVERT_PARAM_QUEUE_LENGTH, 8192)) {
        Log(L"Failed to set WINDIVERT_PARAM_QUEUE_LENGTH. Error: " + std::to_wstring(GetLastError()));
        WinDivertClose(m_hDivert); // Clean up
        m_hDivert = INVALID_HANDLE_VALUE;
        return false; // Critical failure
    }
    if (!WinDivertSetParam(m_hDivert, WINDIVERT_PARAM_QUEUE_TIME, 2000)) {
        Log(L"Failed to set WINDIVERT_PARAM_QUEUE_TIME. Error: " + std::to_wstring(GetLastError()));
        WinDivertClose(m_hDivert); // Clean up
        m_hDivert = INVALID_HANDLE_VALUE;
        return false; // Critical failure
    }

    m_ShouldStop = false;
    m_DivertThread = std::thread(&DivertHandler::DivertLoop, this);
    m_IsRunning = true;
    Log(L"WinDivert started successfully.");
    return true;
#else
    Log(L"WinDivert support is not compiled.");
    return false;
#endif
}

void DivertHandler::Stop() {
    Log(L"DivertHandler::Stop() called.");
    if (!m_IsRunning && m_hDivert == INVALID_HANDLE_VALUE) {
        Log(L"DivertHandler::Stop - Handler was not active (already stopped or not yet started).");
        return;
    }

    Log(L"DivertHandler::Stop - Handler is active, proceeding with shutdown sequence.");
    m_ShouldStop = true;
    m_IsRunning = false;

#ifdef WITH_WINDIVERT
    if (m_hDivert != INVALID_HANDLE_VALUE) {
        Log(L"Closing WinDivert handle...");
        // WinDivertClose should unblock WinDivertRecv
        if (!WinDivertShutdown(m_hDivert, WINDIVERT_SHUTDOWN_BOTH)) {
             Log(L"WinDivertShutdown failed. Error: " + std::to_wstring(GetLastError()));
        }
        if (!WinDivertClose(m_hDivert)) {
            Log(L"WinDivertClose failed. Error: " + std::to_wstring(GetLastError()));
        }
        m_hDivert = INVALID_HANDLE_VALUE;
        Log(L"WinDivert handle closed.");
    }
#endif

    if (m_DivertThread.joinable()) {
        Log(L"Joining divert thread...");
        m_DivertThread.join();
        Log(L"Divert thread joined.");
    }

    if (m_PacketProcessor) {
        m_PacketProcessor->Shutdown();
    }
    Log(L"DivertHandler stopped.");
}

void DivertHandler::DivertLoop() {
    Log(L"DivertLoop started.");
#ifdef WITH_WINDIVERT
    unsigned char packet[0xFFFF]; // Buffer for raw packet data
    UINT packetLen;               // Length of the received packet
    WINDIVERT_ADDRESS addr;       // Address structure for packet info and reinjection
    
    while (!m_ShouldStop && g_IsRunning) {
        try {
            if (g_IsPaused) {
                Sleep(100); // Sleep while paused
                continue;
            }

            if (m_hDivert == INVALID_HANDLE_VALUE) {
                Log(L"DivertLoop: m_hDivert is INVALID_HANDLE_VALUE. Exiting loop.");
                break;
            }
            
            // Receive raw packet data for WINDIVERT_LAYER_NETWORK
            if (!WinDivertRecv(m_hDivert, packet, sizeof(packet), &packetLen, &addr)) {
                DWORD error = GetLastError();
                if (error == ERROR_OPERATION_ABORTED || error == ERROR_INVALID_HANDLE || error == ERROR_NO_DATA) {
                     Log(L"WinDivertRecv indicated shutdown or no data (Error: " + std::to_wstring(error) + L"). Loop will terminate if m_ShouldStop is true.");
                } else if (error != 0) {
                     Log(L"WinDivertRecv failed. Error: " + std::to_wstring(error) + L". Loop will terminate if m_ShouldStop is true.");
                }
                if (m_ShouldStop || !g_IsRunning) break;
                continue;
            }

            Log(L"DivertLoop: WinDivertRecv successful. PacketLen: " + std::to_wstring(packetLen));

            // Pass the raw packet to PacketProcessor
            if (m_PacketProcessor) {
                m_PacketProcessor->ProcessPacket(packet, packetLen, &addr, m_hDivert);
            }
        }
        catch (const std::exception& e) {
            // Log any exception that occurs during packet processing to prevent silent failures
            Log(L"EXCEPTION in DivertLoop: " + s2ws(e.what()));
            
            if (m_hDivert != INVALID_HANDLE_VALUE && packet && packetLen > 0) {
                Log(L"Attempting to reinject the original packet after exception");
                if (!WinDivertSend(m_hDivert, packet, packetLen, NULL, &addr)) {
                    Log(L"WinDivertSend (exception recovery) failed. Error: " + std::to_wstring(GetLastError()));
                }
            }
            
            // Short sleep to avoid tight error loops
            Sleep(10);
        }
        catch (...) {
            // Catch-all for any other exceptions
            Log(L"UNKNOWN EXCEPTION in DivertLoop!");
            
            if (m_hDivert != INVALID_HANDLE_VALUE && packet && packetLen > 0) {
                Log(L"Attempting to reinject the original packet after unknown exception");
                if (!WinDivertSend(m_hDivert, packet, packetLen, NULL, &addr)) {
                    Log(L"WinDivertSend (unknown exception recovery) failed. Error: " + std::to_wstring(GetLastError()));
                }
            }
            
            // Short sleep to avoid tight error loops
            Sleep(10);
        }
    }
#else
    Log(L"DivertLoop: WinDivert support not compiled.");
#endif
    m_IsRunning = false; // Ensure running state is false when loop exits
    Log(L"DivertLoop finished.");
} 