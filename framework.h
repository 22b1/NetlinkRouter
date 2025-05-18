#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <ws2tcpip.h> // For SOCKS5, sockaddr_in, sockaddr_in6 etc.
#include <mswsock.h>   // For SIO_LOOPBACK_FAST_PATH

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <iostream> // For initial debugging, remove for production
#include <sstream>
#include <algorithm>
#include <map>
#include <set>

#pragma comment(lib, "Ws2_32.lib")

#define WITH_WINDIVERT
#ifdef WITH_WINDIVERT
#include "windivert.h"
#pragma comment(lib, "WinDivert.lib")
#endif

#define PIPE_NAME L"\\\\.\\pipe\\NLRouterPipe"
#define SERVICE_NAME L"NetlinkRouterService"
#define DISPLAY_NAME L"Netlink Router Service"

#define BUFFER_SIZE 4096
#define MAX_PACKET_SIZE 65535

// For SOCKS5
#define SOCKS_VERSION 0x05
#define SOCKS_AUTH_METHOD_NONE 0x00
#define SOCKS_AUTH_METHOD_USERPASS 0x02
#define SOCKS_AUTH_VERSION 0x01

#define SOCKS_CMD_CONNECT 0x01
#define SOCKS_CMD_BIND 0x02
#define SOCKS_CMD_UDP_ASSOCIATE 0x03

#define SOCKS_ADDR_TYPE_IPV4 0x01
#define SOCKS_ADDR_TYPE_DOMAIN 0x03
#define SOCKS_ADDR_TYPE_IPV6 0x04

// Forward declarations
class NamedPipeServer;
class DivertHandler;
class Socks5Client;
class PacketProcessor;

// Global service status handle
extern SERVICE_STATUS_HANDLE g_ServiceStatusHandle;
extern SERVICE_STATUS g_ServiceStatus;
extern HANDLE g_ServiceStopEvent;

extern std::atomic<bool> g_IsRunning;
extern std::atomic<bool> g_IsPaused;

// Configuration structure will be defined in config_utils.h
// struct ServiceConfig { ... }; // REMOVE THIS DEFINITION
// extern ServiceConfig g_ServiceConfig; // REMOVE THIS EXTERN, it's in config_utils.h

// Add extern declarations for global handlers
extern NamedPipeServer* g_PipeServer;
extern DivertHandler* g_DivertHandler;

// Logging (simple version, can be expanded)
void Log(const std::string& message);
void Log(const std::wstring& message); 