#pragma once

#include "framework.h"

// Service Main function
VOID WINAPI ServiceMain(DWORD argc, LPWSTR *argv);

// Service Control Handler
DWORD WINAPI ServiceCtrlHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);

// Initializes and starts the core service operations
DWORD ServiceInit(DWORD argc, LPWSTR *argv);

// Stops the core service operations
VOID ServiceStop();

// Call this to update the service status
VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint); 