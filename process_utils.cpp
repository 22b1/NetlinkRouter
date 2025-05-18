#include "process_utils.h"
#include "logger.h" // Assuming logger.h provides Log function used elsewhere
#include <vector>    // For std::vector

// Link with Iphlpapi.lib
#pragma comment(lib, "Iphlpapi.lib")

DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pid = 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    if (pid == 0) {
        Log(L"Process not found: " + std::wstring(processName));
    }
    return pid;
}

DWORD GetPidFromTcpConnection(UINT32 localAddr, UINT16 localPort, UINT32 remoteAddr, UINT16 remotePort) {
    PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;
    ULONG ulSize = 0;
    DWORD dwResult = 0;
    DWORD processId = 0;

    // Get the size of the TCP table
    dwResult = GetExtendedTcpTable(NULL, &ulSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (dwResult == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID) new BYTE[ulSize];
        if (pTcpTable == nullptr) {
            Log(L"GetPidFromTcpConnection: Failed to allocate memory for TCP table");
            return 0;
        }
    } else if (dwResult != NO_ERROR && dwResult != ERROR_NO_DATA) { // ERROR_NO_DATA is ok, table is empty
        Log(L"GetPidFromTcpConnection: GetExtendedTcpTable initial call failed with error " + std::to_wstring(dwResult));
        return 0;
    }

    // Get the TCP table
    if (pTcpTable) { // only if memory was allocated
        dwResult = GetExtendedTcpTable(pTcpTable, &ulSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (dwResult == NO_ERROR) {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
                MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];
                // localAddr and remoteAddr are already in network byte order
                // localPort and remotePort are in host byte order
                // Table ports are in network byte order, convert to host for comparison
                if (row.dwLocalAddr == localAddr && ntohs(row.dwLocalPort) == localPort &&
                    row.dwRemoteAddr == remoteAddr && ntohs(row.dwRemotePort) == remotePort) {
                    processId = row.dwOwningPid;
                    break;
                }
            }
        } else if (dwResult != ERROR_NO_DATA) { // ERROR_NO_DATA means table became empty, not an error for lookup
             Log(L"GetPidFromTcpConnection: GetExtendedTcpTable failed with error " + std::to_wstring(dwResult));
        }
        delete[] pTcpTable;
    } else if (dwResult == ERROR_NO_DATA) {
        // Table was empty from the start, no connections to find.
        Log(L"GetPidFromTcpConnection: TCP table is empty.");
    }

    return processId;
}

DWORD GetPidFromUdpListener(UINT16 localPort) {
    PMIB_UDPTABLE_OWNER_PID pUdpTable = nullptr;
    ULONG ulSize = 0;
    DWORD dwResult = 0;
    DWORD processId = 0;

    // Get the size of the UDP table
    dwResult = GetExtendedUdpTable(NULL, &ulSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (dwResult == ERROR_INSUFFICIENT_BUFFER) {
        pUdpTable = (PMIB_UDPTABLE_OWNER_PID) new BYTE[ulSize];
        if (pUdpTable == nullptr) {
            Log(L"GetPidFromUdpListener: Failed to allocate memory for UDP table");
            return 0;
        }
    } else if (dwResult != NO_ERROR && dwResult != ERROR_NO_DATA) { // ERROR_NO_DATA is ok, table is empty
        Log(L"GetPidFromUdpListener: GetExtendedUdpTable initial call failed with error " + std::to_wstring(dwResult));
        return 0;
    }

    // Get the UDP table
    if (pUdpTable) { // only if memory was allocated
        dwResult = GetExtendedUdpTable(pUdpTable, &ulSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (dwResult == NO_ERROR) {
            for (DWORD i = 0; i < pUdpTable->dwNumEntries; ++i) {
                MIB_UDPROW_OWNER_PID row = pUdpTable->table[i];
                // localPort is in host byte order
                // Table port is in network byte order, convert to host for comparison
                if (ntohs(row.dwLocalPort) == localPort) {
                    processId = row.dwOwningPid;
                    break; // Found first listener on this port
                }
            }
        } else if (dwResult != ERROR_NO_DATA) { // ERROR_NO_DATA means table became empty, not an error for lookup
            Log(L"GetPidFromUdpListener: GetExtendedUdpTable failed with error " + std::to_wstring(dwResult));
        }
        delete[] pUdpTable;
    } else if (dwResult == ERROR_NO_DATA) {
        // Table was empty from the start, no listeners to find.
        Log(L"GetPidFromUdpListener: UDP table is empty.");
    }

    return processId;
} 