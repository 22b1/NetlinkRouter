#pragma once

#include "framework.h"
#include <queue>
#include <utility>
#include "process_utils.h"

#ifdef WITH_WINDIVERT
#include "windivert.h"
#endif

class Socks5Client;

struct ConnectionTuple {
    UINT32 srcAddr;
    UINT32 dstAddr;
    UINT16 srcPort;
    UINT16 dstPort;
    UINT8 protocol; // IPPROTO_TCP or IPPROTO_UDP
    DWORD owningPid;

    bool operator<(const ConnectionTuple& other) const {
        if (srcAddr != other.srcAddr) return srcAddr < other.srcAddr;
        if (dstAddr != other.dstAddr) return dstAddr < other.dstAddr;
        if (srcPort != other.srcPort) return srcPort < other.srcPort;
        if (dstPort != other.dstPort) return dstPort < other.dstPort;
        return protocol < other.protocol;
    }
     bool operator==(const ConnectionTuple& other) const {
        if (srcAddr != other.srcAddr) return false;
        if (dstAddr != other.dstAddr) return false;
        return srcPort == other.srcPort && dstPort == other.dstPort && protocol == other.protocol;
    }
};

// Represents an active proxied TCP connection
struct TcpProxyConnection {
    SOCKET proxySocket = INVALID_SOCKET;
    ConnectionTuple originalTuple;
    WINDIVERT_ADDRESS originalAddr;
    std::thread forwardAppToProxyThread;
    std::thread forwardProxyToAppThread;
    std::atomic<bool> active{true};

    std::queue<std::vector<char>> appPacketPayloadQueue;
    std::mutex appQueueMutex;
    std::condition_variable appQueueCv;

    ~TcpProxyConnection() {
        active = false;
        appQueueCv.notify_all();
        if (proxySocket != INVALID_SOCKET) {
            shutdown(proxySocket, SD_BOTH);
            closesocket(proxySocket);
            proxySocket = INVALID_SOCKET;
        }
        if (forwardAppToProxyThread.joinable()) forwardAppToProxyThread.join();
        if (forwardProxyToAppThread.joinable()) forwardProxyToAppThread.join();
    }
};

// Represents an active proxied UDP association
struct UdpProxyAssociation {
    SOCKET localProxySideSocket = INVALID_SOCKET;
    SOCKET controlSocket = INVALID_SOCKET;
    // SSL* controlSslSession = nullptr;
    
    std::string proxyRelayIp;
    unsigned short proxyRelayPort = 0;

    struct UdpFlowKey {
        UINT32 originalSrcAddr; // App's src IPv4
        UINT16 originalSrcPort;
        // Equality and hash for map key
        bool operator<(const UdpFlowKey& other) const {
            if (originalSrcAddr != other.originalSrcAddr) return originalSrcAddr < other.originalSrcAddr;
            return originalSrcPort < other.originalSrcPort;
        }
        bool operator==(const UdpFlowKey& other) const {
            if (originalSrcAddr != other.originalSrcAddr) return false;
            return originalSrcPort == other.originalSrcPort;
        }
    };

    struct QueuedUdpPacket {
        std::vector<unsigned char> packetData;
        UINT packetLen;
    };

    std::thread forwardAppToProxyUdpThread;
    std::thread forwardProxyToAppUdpThread;
    std::atomic<bool> active{true};

    // Queue for packets from App to Proxy
    std::queue<QueuedUdpPacket> appPacketQueue;
    std::mutex appQueueMutex;
    std::condition_variable appQueueCv;

    ~UdpProxyAssociation() {
        active = false;
        appQueueCv.notify_all();
        
        // if (controlSslSession) {
        //     SSL_shutdown(controlSslSession);
        //     SSL_free(controlSslSession);
        //     controlSslSession = nullptr;
        // }
        if (controlSocket != INVALID_SOCKET) {
            closesocket(controlSocket);
            controlSocket = INVALID_SOCKET;
        }
        if (localProxySideSocket != INVALID_SOCKET) {
            closesocket(localProxySideSocket);
            localProxySideSocket = INVALID_SOCKET;
        }
        if (forwardAppToProxyUdpThread.joinable()) forwardAppToProxyUdpThread.join();
        if (forwardProxyToAppUdpThread.joinable()) forwardProxyToAppUdpThread.join();
    }
};


class PacketProcessor {
public:
    PacketProcessor();
    ~PacketProcessor();

    bool Initialize(const std::string& proxyIp, unsigned short proxyPort, 
                    const std::string& username, const std::string& password, HANDLE hDivert);
    void Shutdown();

#ifdef WITH_WINDIVERT
    void ProcessPacket(unsigned char* packet, UINT packetLen, WINDIVERT_ADDRESS* addr, HANDLE hDivert);
#endif

    const std::string& GetResolvedProxyIpForBypassLogicString() const;

private:
#ifdef WITH_WINDIVERT
    void HandleIPv4(unsigned char* packet, UINT packetLen, WINDIVERT_ADDRESS* addr, HANDLE hDivert);
    void HandleTCP(unsigned char* packet, UINT packetLen, WINDIVERT_ADDRESS* addr, bool isIPv6, void* ipHeaderPtr, void* L4HeaderPtr, HANDLE hDivert, const std::string& resolvedDstIp);
    void HandleUDP(unsigned char* packet, UINT packetLen, WINDIVERT_ADDRESS* addr, bool isIPv6, void* ipHeaderPtr, void* L4HeaderPtr, HANDLE hDivert, const std::string& resolvedDstIp);

    void ForwardAppToProxyTCP(TcpProxyConnection* conn, ConnectionTuple tuple);
    void ForwardProxyToAppTCP(TcpProxyConnection* conn, HANDLE hDivert);

    void ForwardAppToProxyUDP(UdpProxyAssociation* assoc, ConnectionTuple originalClientTuple, HANDLE hDivert);
    void ForwardProxyToAppUDP(UdpProxyAssociation* assoc, ConnectionTuple originalClientTuple, HANDLE hDivert);

    bool IsPacketForProxyServer(const std::string& destHostIpOrName, USHORT destPort) const;
#endif

    Socks5Client* m_socksClient;
    std::string m_proxyOriginalInput;
    std::string m_proxyUsername;
    std::string m_proxyPassword;
    unsigned short m_proxyPort;

    Socks5Client* m_udpAssociationSocksClient = nullptr; // Client instance for UDP association control channel

    std::map<ConnectionTuple, std::shared_ptr<TcpProxyConnection>> m_tcpConnections;
    std::mutex m_tcpConnMutex;

    // For UDP, one SOCKS5 UDP association can handle multiple UDP "flows" from the app.
    std::shared_ptr<UdpProxyAssociation> m_udpAssociation;
    std::mutex m_udpAssocMutex;
    HANDLE m_hDivertGlobal;
}; 