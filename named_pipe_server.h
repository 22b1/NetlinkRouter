#pragma once

#include "framework.h"

class NamedPipeServer {
public:
    NamedPipeServer();
    ~NamedPipeServer();

    void Start();
    void Stop();

private:
    void PipeListenerThread();
    void HandleClient(HANDLE hPipe);
    bool ParseCommand(const std::string& commandStr);

    HANDLE m_hPipe;
    std::thread m_ListenerThread;
    std::atomic<bool> m_IsRunning;
}; 