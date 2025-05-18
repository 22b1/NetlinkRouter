#pragma once

#include "framework.h"
#include <tlhelp32.h> // For Process32First/Next
#include <winsock2.h> // For IN_ADDR, UINT16, UINT32
#include <ws2tcpip.h> // For IN_ADDR (ensure it's available, though winsock2.h usually brings it)
#include <iphlpapi.h> // For GetExtendedTcpTable, GetExtendedUdpTable

// Function to get Process ID by its name
DWORD GetProcessIdByName(const wchar_t* processName);

// Function to get Process ID for a TCP connection
// Addr parameters are expected in network byte order
DWORD GetPidFromTcpConnection(UINT32 localAddr, UINT16 localPort, UINT32 remoteAddr, UINT16 remotePort);

// Function to get Process ID for a UDP listener (local port)
// Port parameter is expected in host byte order (as GetExtendedUdpTable returns it)
DWORD GetPidFromUdpListener(UINT16 localPort); 