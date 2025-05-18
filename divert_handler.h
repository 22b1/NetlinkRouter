#pragma once

#include "framework.h"

class PacketProcessor;

class DivertHandler {
public:
    DivertHandler();
    ~DivertHandler();

    bool Start();
    void Stop();
    bool IsRunning() const { return m_IsRunning; }
    HANDLE GetDivertHandle() const { return m_hDivert; }

private:
    void DivertLoop();

    HANDLE m_hDivert;
    std::thread m_DivertThread;
    std::atomic<bool> m_IsRunning;
    std::atomic<bool> m_ShouldStop;
    PacketProcessor* m_PacketProcessor;
}; 