#include "packet_processor.h"
#include "socks5_client.h"
#include "string_utils.h"
#include "divert_handler.h"
#include "ip_utils.h"
#include "process_utils.h"
#include "config_utils.h"
#include "logger.h"
#include <vector>
#include <string>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <WinDivert.h>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <algorithm> // Required for std::transform
#include <cctype>    // Required for std::tolower

// Helper to convert ConnectionTuple to string for logging
std::wstring ConvertTupleToString(const ConnectionTuple& tuple) {
    // Convert UINT32 IP addresses to string format
    char srcIpStr[INET_ADDRSTRLEN], dstIpStr[INET_ADDRSTRLEN];
    struct in_addr src_in_addr, dst_in_addr;
    src_in_addr.s_addr = tuple.srcAddr; // Already in network byte order if from ip_header
    dst_in_addr.s_addr = tuple.dstAddr; // Already in network byte order if from ip_header

    // Convert network byte order IP back to string for logging
    // Assuming they are stored as they appear in packet (network byte order)
    inet_ntop(AF_INET, &src_in_addr, srcIpStr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_in_addr, dstIpStr, INET_ADDRSTRLEN);

    std::wstringstream wss;
    wss << L"Src: " << s2ws(srcIpStr) << L":" << tuple.srcPort
        << L", Dst: " << s2ws(dstIpStr) << L":" << tuple.dstPort
        << L", Proto: " << (int)tuple.protocol;
    return wss.str();
}

static inline void WinDivertHelperInitAddr(WINDIVERT_ADDRESS *addr) {
    if (addr) {
        memset(addr, 0, sizeof(*addr));
    }
}

PacketProcessor::PacketProcessor() 
    : m_socksClient(nullptr), 
      m_proxyOriginalInput(""),
      m_proxyPort(0), 
      m_hDivertGlobal(INVALID_HANDLE_VALUE),
      m_udpAssociationSocksClient(nullptr) {
    Log(L"PacketProcessor constructor.");
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        Log(L"PacketProcessor: WSAStartup failed. Error: " + std::to_wstring(GetLastError()));
    }
}

PacketProcessor::~PacketProcessor() {
    Shutdown();
    WSACleanup(); 
    Log(L"PacketProcessor destructor.");
}

bool PacketProcessor::Initialize(const std::string& proxyConfigurationString, unsigned short proxyPort,
                               const std::string& username, const std::string& password, HANDLE hDivert) {
    Log(L"PacketProcessor::Initialize called.");
    m_hDivertGlobal = hDivert;
    m_proxyPort = proxyPort;
    m_proxyUsername = username;
    m_proxyPassword = password;

    std::string finalProxyStringToUse = proxyConfigurationString;
    std::string lowerConf = proxyConfigurationString;
    std::transform(lowerConf.begin(), lowerConf.end(), lowerConf.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    bool has_socks_scheme = (lowerConf.rfind("socks5h://", 0) == 0 || lowerConf.rfind("socks5://", 0) == 0);

    if (has_socks_scheme) {
        Log(L"PacketProcessor::Initialize: Proxy string '" + s2ws(proxyConfigurationString) + L"' already has a SOCKS scheme.");
        // finalProxyStringToUse remains proxyConfigurationString, as it already includes the scheme.
    } else {
        auto isIPv4Address = [](const std::string& s) {
            struct sockaddr_in sa;
            return inet_pton(AF_INET, s.c_str(), &(sa.sin_addr)) == 1;
        };
        auto isIPv6Address = [](const std::string& s) {
            struct sockaddr_in6 sa6;
            return inet_pton(AF_INET6, s.c_str(), &(sa6.sin6_addr)) == 1;
        };

        if (!isIPv4Address(proxyConfigurationString) && !isIPv6Address(proxyConfigurationString)) {
            // Hostname without any SOCKS scheme
            Log(L"PacketProcessor::Initialize: Proxy string '" + s2ws(proxyConfigurationString) + L"' is a hostname and lacks a SOCKS scheme. Prepending 'socks5h://'.");
            finalProxyStringToUse = "socks5h://" + proxyConfigurationString;
        } else {
            // IP address without any SOCKS scheme
            Log(L"PacketProcessor::Initialize: Proxy string '" + s2ws(proxyConfigurationString) + L"' is an IP address and lacks a SOCKS scheme. Prepending 'socks5://'.");
            finalProxyStringToUse = "socks5://" + proxyConfigurationString;
        }
    }
    
    m_proxyOriginalInput = finalProxyStringToUse; // Store the processed string

    if (m_socksClient) {
        delete m_socksClient;
        m_socksClient = nullptr;
    }
    m_socksClient = new Socks5Client(m_proxyOriginalInput, m_proxyPort, m_proxyUsername, m_proxyPassword);
    
    if (!m_socksClient) {
        Log(L"PacketProcessor: Failed to allocate Socks5Client.");
        return false;
    }

    Log(L"PacketProcessor: Testing SOCKS5 proxy connection to www.google.com:80...");
    if (!m_socksClient->TestProxyConnection("www.google.com", 80)) {
        Log(L"PacketProcessor: SOCKS5 proxy test connection failed. Check proxy settings, credentials, and reachability.");
        delete m_socksClient;
        m_socksClient = nullptr;
        return false;
    }
    Log(L"PacketProcessor: SOCKS5 proxy test connection successful.");

    return true;
}

void PacketProcessor::Shutdown() {
    Log(L"PacketProcessor::Shutdown called.");
    if (m_socksClient) {
        delete m_socksClient;
        m_socksClient = nullptr;
    }
    if (m_udpAssociationSocksClient) {
        delete m_udpAssociationSocksClient;
        m_udpAssociationSocksClient = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(m_tcpConnMutex);
        // Phase 1: Signal all threads to terminate
        for (auto const& pair : m_tcpConnections) {
            const std::shared_ptr<TcpProxyConnection>& conn = pair.second;
            if (conn) {
                conn->active = false;
                // Optionally shutdown socket's read side to unblock thread's recv/select,
                // if (conn->proxySocket != INVALID_SOCKET) {
                //    shutdown(conn->proxySocket, SD_RECEIVE); 
                // }
            }
        }

        // Phase 2: Join all threads
        for (auto const& pair : m_tcpConnections) {
            const std::shared_ptr<TcpProxyConnection>& conn = pair.second;
            // Assuming TcpProxyConnection has a std::thread member named forwardProxyToAppThread
            if (conn && conn->forwardProxyToAppThread.joinable()) {
                try {
                    conn->forwardProxyToAppThread.join();
                } catch (const std::system_error& e) {
                    Log(L"PacketProcessor::Shutdown: Exception joining TCP thread: " + s2ws(e.what()));
                    // Log and continue to allow other cleanup
                }
            }
        }

        // Phase 3: Close sockets and clear the map
        for (auto const& pair : m_tcpConnections) {
            const std::shared_ptr<TcpProxyConnection>& conn = pair.second;
            if (conn && conn->proxySocket != INVALID_SOCKET) {
                shutdown(conn->proxySocket, SD_BOTH); // Ensure socket is fully shutdown
                closesocket(conn->proxySocket);
                conn->proxySocket = INVALID_SOCKET; 
            }
        }
        m_tcpConnections.clear();
    }
    {
        std::lock_guard<std::mutex> lock(m_udpAssocMutex);
        if (m_udpAssociation) {
            m_udpAssociation->active = false;
            m_udpAssociation->appQueueCv.notify_all(); // Wake up ForwardAppToProxyUDP

            if (m_udpAssociation->forwardAppToProxyUdpThread.joinable()) {
                try {
                    m_udpAssociation->forwardAppToProxyUdpThread.join();
                } catch (const std::system_error& e) {
                    Log(L"PacketProcessor::Shutdown: Exception joining UDP AppToProxy thread: " + s2ws(e.what()));
                }
            }

            // Now it's safe to close sockets
            if (m_udpAssociation->localProxySideSocket != INVALID_SOCKET) {
                 closesocket(m_udpAssociation->localProxySideSocket);
                 m_udpAssociation->localProxySideSocket = INVALID_SOCKET;
            }
            if (m_udpAssociation->controlSocket != INVALID_SOCKET) { 
                 closesocket(m_udpAssociation->controlSocket);
                 m_udpAssociation->controlSocket = INVALID_SOCKET;
            }
            
            m_udpAssociation.reset();
        }
    }
    Log(L"PacketProcessor connections cleared.");
}

void PacketProcessor::ProcessPacket(unsigned char* packet, UINT packetLen, WINDIVERT_ADDRESS* addr, HANDLE hDivert) {
    if (hDivert == INVALID_HANDLE_VALUE || hDivert == NULL) {
        Log(L"PacketProcessor::ProcessPacket: Received NULL or INVALID_HANDLE_VALUE for hDivert parameter. Cannot process packet.");
        return; 
    }

    Log(std::wstring(L"ProcessPacket: Raw packet - Direction: ") + (addr->Outbound ? L"Outbound" : L"Inbound") + 
        L", IfIdx: " + std::to_wstring(addr->Network.IfIdx) + L", SubIfIdx: " + std::to_wstring(addr->Network.SubIfIdx) + 
        L", Configured PID (for context): " + std::to_wstring(g_ServiceConfig.processId) + 
        L", PacketLen: " + std::to_wstring(packetLen));

    if (g_IsPaused || !g_ServiceConfig.configured) {
        if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
            Log(L"PacketProcessor: WinDivertSend (passthrough - paused/unconfigured) failed. Error: " + std::to_wstring(GetLastError()));
        }
        return;
    }

    UINT8 ip_ver = packet[0] >> 4;
    Log(L"ProcessPacket: Detected IP version: " + std::to_wstring(ip_ver));
    
    if (ip_ver == 4) {
        Log(L"ProcessPacket: Processing IPv4 packet, forwarding to HandleIPv4");
        HandleIPv4(packet, packetLen, addr, hDivert);
    } else if (ip_ver == 6) {
        Log(L"ProcessPacket: Received IPv6 packet, IPv6 support is disabled. Letting packet pass.");
        if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
            Log(L"PacketProcessor: WinDivertSend (passthrough IPv6 - unsupported) failed. Error: " + std::to_wstring(GetLastError()));
        }
    } else {
        Log(L"ProcessPacket: Unknown IP version: " + std::to_wstring(ip_ver) + L". First byte: " + 
            std::to_wstring(static_cast<unsigned int>(packet[0])) + L". Letting packet pass.");
        if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
            Log(L"PacketProcessor: WinDivertSend (unknown IP) failed. Error: " + std::to_wstring(GetLastError()));
        }
    }
}

void PacketProcessor::HandleIPv4(unsigned char* packet, UINT packetLen, WINDIVERT_ADDRESS* addr, HANDLE hDivert) {
    Log(L"HandleIPv4: Entered.");
    if (packetLen < sizeof(WINDIVERT_IPHDR)) {
        Log(L"HandleIPv4: Packet too short for IP header. PacketLen: " + std::to_wstring(packetLen));
        if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
            Log(L"HandleIPv4: WinDivertSend (short packet) failed. Error: " + std::to_wstring(GetLastError()));
        }
        return;
    }

    WINDIVERT_IPHDR* ip_header = (WINDIVERT_IPHDR*)packet;
    UINT ip_header_len = ip_header->HdrLength * 4;

    if (ip_header_len < sizeof(WINDIVERT_IPHDR)) {
        Log(L"HandleIPv4: Invalid IP header length: " + std::to_wstring(ip_header_len));
        if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
            Log(L"HandleIPv4: WinDivertSend (invalid IP hdr len) failed. Error: " + std::to_wstring(GetLastError()));
        }
        return;
    }
    if (ip_header_len > packetLen) {
        Log(L"HandleIPv4: IP header length exceeds packet length. IPHdrLen: " + std::to_wstring(ip_header_len) + L", PacketLen: " + std::to_wstring(packetLen));
        if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
            Log(L"HandleIPv4: WinDivertSend (IP hdr len > packet len) failed. Error: " + std::to_wstring(GetLastError()));
        }
        return;
    }

    char srcIpStr[INET_ADDRSTRLEN], dstIpStr[INET_ADDRSTRLEN];
    struct in_addr src_in_addr, dst_in_addr;
    src_in_addr.s_addr = htonl(ip_header->SrcAddr); // Convert to network byte order for inet_ntop if needed
    dst_in_addr.s_addr = htonl(ip_header->DstAddr); // Convert to network byte order for inet_ntop if needed
    
    src_in_addr.s_addr = ip_header->SrcAddr; 
    dst_in_addr.s_addr = ip_header->DstAddr;

    inet_ntop(AF_INET, &src_in_addr, srcIpStr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_in_addr, dstIpStr, INET_ADDRSTRLEN);

    std::wstring resolvedDstIpW = s2ws(dstIpStr); // For consistency in logging

    Log(L"HandleIPv4: SrcIP: " + s2ws(srcIpStr) + L", DstIP: " + resolvedDstIpW + L", Protocol: " + std::to_wstring(ip_header->Protocol));

    // Simple check: if destination is one of the well-known DNS servers (e.g. 8.8.8.8, 1.1.1.1)
    // and it's UDP, it's likely a DNS query.
    bool is_likely_dns = false;
    if (ip_header->Protocol == IPPROTO_UDP) {
        if (dstIpStr == std::string("8.8.8.8") || dstIpStr == std::string("8.8.4.4") || 
            dstIpStr == std::string("1.1.1.1") || dstIpStr == std::string("1.0.0.1")) {
            // Further check if it's port 53
            if (packetLen >= ip_header_len + sizeof(WINDIVERT_UDPHDR)) {
                WINDIVERT_UDPHDR* udp_header = (WINDIVERT_UDPHDR*)(packet + ip_header_len);
                if (ntohs(udp_header->DstPort) == 53) {
                    is_likely_dns = true;
                    Log(L"HandleIPv4: Packet to " + s2ws(dstIpStr) + L":53 (UDP) - Likely DNS query.");
                }
            }
        }
    }

    sockaddr_in packet_dst_sockaddr;
    memset(&packet_dst_sockaddr, 0, sizeof(packet_dst_sockaddr));
    packet_dst_sockaddr.sin_family = AF_INET;
    packet_dst_sockaddr.sin_addr.s_addr = ip_header->DstAddr; // Already network order
    

    if (ip_header->Protocol == IPPROTO_TCP) {
        if (packetLen < ip_header_len + sizeof(WINDIVERT_TCPHDR)) {
            Log(L"HandleIPv4: Packet too short for TCP header. IPHdrLen: " + std::to_wstring(ip_header_len) + L", PacketLen: " + std::to_wstring(packetLen));
            if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
                 Log(L"HandleIPv4: WinDivertSend (short TCP packet) failed. Error: " + std::to_wstring(GetLastError()));
            }
            return;
        }
        WINDIVERT_TCPHDR* tcp_header = (WINDIVERT_TCPHDR*)(packet + ip_header_len);
        Log(L"HandleIPv4: Forwarding to HandleTCP. DstPort: " + std::to_wstring(ntohs(tcp_header->DstPort)));
        HandleTCP(packet, packetLen, addr, false, ip_header, tcp_header, hDivert, std::string(dstIpStr));
    } else if (ip_header->Protocol == IPPROTO_UDP) {
        if (packetLen < ip_header_len + sizeof(WINDIVERT_UDPHDR)) {
            Log(L"HandleIPv4: Packet too short for UDP header. IPHdrLen: " + std::to_wstring(ip_header_len) + L", PacketLen: " + std::to_wstring(packetLen));
             if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
                 Log(L"HandleIPv4: WinDivertSend (short UDP packet) failed. Error: " + std::to_wstring(GetLastError()));
            }
            return;
        }
        WINDIVERT_UDPHDR* udp_header = (WINDIVERT_UDPHDR*)(packet + ip_header_len);
        Log(L"HandleIPv4: Forwarding to HandleUDP. DstPort: " + std::to_wstring(ntohs(udp_header->DstPort)));
        HandleUDP(packet, packetLen, addr, false, ip_header, udp_header, hDivert, std::string(dstIpStr));
    } else {
        Log(L"HandleIPv4: Unsupported protocol: " + std::to_wstring(ip_header->Protocol) + L". Letting packet pass.");
        if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
            Log(L"HandleIPv4: WinDivertSend (unsupported protocol) failed. Error: " + std::to_wstring(GetLastError()));
        }
    }
}

void PacketProcessor::HandleTCP(unsigned char* packet, UINT packetLen, WINDIVERT_ADDRESS* addr, bool isIPv6, void* ip_header_from_caller, void* tcp_header_from_caller, HANDLE hDivert, const std::string& resolvedDstIp) {
    if (isIPv6) {
        Log(L"HandleTCP: Called for IPv6 packet, but IPv6 is not fully supported. Passing through.");
        if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
            Log(L"PacketProcessor: WinDivertSend (HandleTCP IPv6 passthrough) failed. Error: " + std::to_wstring(GetLastError()));
        }
        return;
    }

    PWINDIVERT_IPHDR ip_header = (PWINDIVERT_IPHDR)ip_header_from_caller;
    PWINDIVERT_TCPHDR tcp_header = (PWINDIVERT_TCPHDR)tcp_header_from_caller;

    if (!ip_header || !tcp_header) {
        Log(L"HandleTCP: IP or TCP header is null. Letting packet pass.");
        if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
            Log(L"PacketProcessor: WinDivertSend (HandleTCP null headers) failed. Error: " + std::to_wstring(GetLastError()));
        }
        return;
    }

    char srcIpStr[INET_ADDRSTRLEN], dstIpStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->SrcAddr, srcIpStr, sizeof(srcIpStr));
    inet_ntop(AF_INET, &ip_header->DstAddr, dstIpStr, sizeof(dstIpStr));
    
    std::wstring flagsStr = L"";
    if (tcp_header->Syn) flagsStr += L"SYN ";
    if (tcp_header->Ack) flagsStr += L"ACK ";
    if (tcp_header->Fin) flagsStr += L"FIN ";
    if (tcp_header->Rst) flagsStr += L"RST ";
    if (tcp_header->Psh) flagsStr += L"PSH ";
    if (tcp_header->Urg) flagsStr += L"URG ";
    // Trim trailing space if any flags were added
    if (!flagsStr.empty()) {
        flagsStr.pop_back();
    }

    Log(L"HandleTCP: Packet details - Src: " + s2ws(srcIpStr) + L":" + std::to_wstring(ntohs(tcp_header->SrcPort)) +
        L", Dst: " + s2ws(dstIpStr) + L":" + std::to_wstring(ntohs(tcp_header->DstPort)) +
        L", Flags: [" + flagsStr + L"]" + 
        L", Direction: " + (addr->Outbound ? L"Outbound" : L"Inbound") +
        L", IfIdx: " + std::to_wstring(addr->Network.IfIdx) + L", SubIfIdx: " + std::to_wstring(addr->Network.SubIfIdx));

    ConnectionTuple connTuple; 
    connTuple.protocol = IPPROTO_TCP;
    connTuple.srcAddr = ip_header->SrcAddr;
    connTuple.dstAddr = ip_header->DstAddr;
    connTuple.srcPort = ntohs(tcp_header->SrcPort);
    connTuple.dstPort = ntohs(tcp_header->DstPort);
    connTuple.owningPid = 0; // Initialize PID

    // Get PID for the connection
    if (addr->Outbound) {
        connTuple.owningPid = GetPidFromTcpConnection(connTuple.srcAddr, connTuple.srcPort, connTuple.dstAddr, connTuple.dstPort);
    } else { // Inbound
        connTuple.owningPid = GetPidFromTcpConnection(connTuple.dstAddr, connTuple.dstPort, connTuple.srcAddr, connTuple.srcPort);
    }
    if (connTuple.owningPid != 0) {
        Log(std::wstring(L"HandleTCP: Associated PID: ") + std::to_wstring(connTuple.owningPid) + L" for " + (addr->Outbound ? L"outbound" : L"inbound") + L" connection " + ConvertTupleToString(connTuple));
    } else {
        Log(std::wstring(L"HandleTCP: Could not find PID for ") + (addr->Outbound ? L"outbound" : L"inbound") + L" connection " + ConvertTupleToString(connTuple));
    }

    // PID-based Filtering Logic
    // Ensure g_ServiceConfig is properly initialized and populated elsewhere
    if (g_ServiceConfig.enablePidFilter && connTuple.owningPid != 0) {
        bool isAllowed = false;
        for (DWORD allowedPid : g_ServiceConfig.targetPids) { // Assuming targetPids is a list/vector
            if (connTuple.owningPid == allowedPid) {
                isAllowed = true;
                break;
            }
        }

        // Example: if filter mode is "allow", and PID is not in allowed list, then drop/bypass
        // More sophisticated logic for "deny" mode or multiple lists can be added here.
        if (!isAllowed) { 
            Log(L"HandleTCP: PID " + std::to_wstring(connTuple.owningPid) + L" is not in the allowed list. Passing packet through (or could be dropped).");
            // Option 1: Pass through
            if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
                Log(L"PacketProcessor: WinDivertSend (PID filter passthrough) failed. Error: " + std::to_wstring(GetLastError()));
            }
            // Option 2: Drop (alternative to passthrough)
            // Log(L"HandleTCP: PID " + std::to_wstring(connTuple.owningPid) + L" is not allowed. Dropping packet.");
            return; // Packet is handled (bypassed or dropped)
        } else {
            Log(L"HandleTCP: PID " + std::to_wstring(connTuple.owningPid) + L" is allowed. Proceeding with packet processing.");
        }
    } else if (g_ServiceConfig.enablePidFilter && connTuple.owningPid == 0) {
        // How to handle packets where PID couldn't be found but filtering is on?
        // Depending on policy, these could be allowed, denied, or passed through.
        // Current behavior: allow them to proceed to IsPacketForProxyServer and further logic.
        Log(L"HandleTCP: PID not found for connection, and PID filtering is enabled. Packet will proceed to standard processing logic.");
    }

    Log(L"HandleTCP: Checking if " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort) + L" is for proxy server. Configured proxy input: " + s2ws(m_proxyOriginalInput) + L", Port: " + std::to_wstring(m_proxyPort) + L")");
    if (this->IsPacketForProxyServer(resolvedDstIp, connTuple.dstPort)) {
        Log(L"HandleTCP: Packet to " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort) + L" is for the proxy server. Letting it pass directly.");
        if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
            Log(L"PacketProcessor: WinDivertSend (to proxy) failed. Error: " + std::to_wstring(GetLastError()));
        }
        return;
    }

    Log(L"HandleTCP: Evaluating SYN block. SYN: " + std::to_wstring(tcp_header->Syn) + L", ACK: " + std::to_wstring(tcp_header->Ack) + L", Outbound: " + (addr->Outbound ? L"true" : L"false"));

    if (addr->Outbound) {
        std::lock_guard<std::mutex> lock(m_tcpConnMutex);
        auto it = m_tcpConnections.find(connTuple);

        if (tcp_header->Syn && !tcp_header->Ack) {
            if (it != m_tcpConnections.end()) {
                Log(L"HandleTCP: Received SYN for an already tracked connection tuple: " + s2ws(dstIpStr) + L":" + std::to_wstring(connTuple.dstPort) + L". Possibly a retransmission. Current state: active=" + std::to_wstring(it->second->active));
            } else {
                Log(L"HandleTCP: SYN packet for new outbound connection to " + s2ws(dstIpStr) + L":" + std::to_wstring(connTuple.dstPort) + L". Attempting SOCKS.");
                if (!m_socksClient) {
                    Log(L"HandleTCP: m_socksClient is null. Cannot initiate SOCKS connection.");
                    if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
                        Log(L"PacketProcessor: WinDivertSend (passthrough SYN, null socksClient) failed. Error: " + std::to_wstring(GetLastError()));
                    }
                    return;
                }
                SOCKET proxySock = m_socksClient->Connect(resolvedDstIp, connTuple.dstPort);
                
                if (proxySock != INVALID_SOCKET) {
                    auto newConn = std::make_shared<TcpProxyConnection>();
                    newConn->proxySocket = proxySock;
                    newConn->originalTuple = connTuple;
                    newConn->active = true;
                    newConn->originalAddr = *addr;
                    
                    m_tcpConnections[connTuple] = newConn;
                    Log(L"HandleTCP: SOCKS connection established for " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort) + L" (Tuple: " + ConvertTupleToString(connTuple) + L"). Starting forwarding thread.");
                    
                    newConn->forwardProxyToAppThread = std::thread(&PacketProcessor::ForwardProxyToAppTCP, this, newConn.get(), hDivert);
                    return; 
                } else {
                    Log(L"HandleTCP: SOCKS5 connection attempt (m_socksClient->Connect) failed for " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort) + L". Letting original SYN packet pass.");
                    if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
                        Log(L"PacketProcessor: WinDivertSend (passthrough SYN after SOCKS fail) failed. Error: " + std::to_wstring(GetLastError()));
                    }
                    return;
                }
            }
        } else {
            Log(L"HandleTCP: Outbound non-SYN for " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort) + L" (Tuple: " + ConvertTupleToString(connTuple) + L"). Searching m_tcpConnections (size: " + std::to_wstring(m_tcpConnections.size()) + L")");
            it = m_tcpConnections.find(connTuple);

            if (it != m_tcpConnections.end()) {
                std::shared_ptr<TcpProxyConnection> conn = it->second;
                if (conn && conn->active && conn->proxySocket != INVALID_SOCKET) {
                    PVOID payload_ptr = (PVOID)((unsigned char*)tcp_header + (tcp_header->HdrLength * 4));
                    UINT ip_total_len = ntohs(ip_header->Length);
                    UINT ip_hdr_len = ip_header->HdrLength * 4;
                    UINT tcp_hdr_len = tcp_header->HdrLength * 4;
                    UINT payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

                    if (payload_len > packetLen) {
                        Log(L"HandleTCP: Calculated payload length is greater than packet length. Clamping.");
                        payload_len = packetLen - ip_hdr_len - tcp_hdr_len;
                        if (((int)payload_len) < 0) payload_len = 0;
                    }

                    if (payload_len > 0) {
                        Log(L"HandleTCP: Forwarding " + std::to_wstring(payload_len) + L" bytes of TCP payload to SOCKS proxy for " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort));
                        int bytes_sent = send(conn->proxySocket, (const char*)payload_ptr, payload_len, 0);
                        if (bytes_sent == SOCKET_ERROR) {
                            Log(L"HandleTCP: send to proxySocket failed. Error: " + std::to_wstring(WSAGetLastError()) + L" for " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort));
                            conn->active = false;
                            closesocket(conn->proxySocket);
                            conn->proxySocket = INVALID_SOCKET;
                        } else if (bytes_sent < (int)payload_len) {
                            Log(L"HandleTCP: Warning - sent fewer bytes (" + std::to_wstring(bytes_sent) + L") to proxySocket than expected (" + std::to_wstring(payload_len) + L").");
                        }
                    } else {
                        Log(L"HandleTCP: Outbound non-SYN for SOCKS connection has no payload (e.g., pure ACK). Not sending to proxy socket. Packet: " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort));
                    }
                    return;
                } else {
                    Log(L"HandleTCP: Found connection for " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort) + L" but it's inactive or socket is invalid. Defaulting to passthrough.");
                }
            } else {
                Log(L"HandleTCP: No specific SOCKS handling path taken for outbound non-SYN packet to " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort) + L". Defaulting to passthrough. (Tuple not found in m_tcpConnections)");
            }
        }
        Log(L"HandleTCP: Defaulting to passthrough for outbound packet to " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort));
        if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
            Log(L"PacketProcessor: WinDivertSend (HandleTCP outbound passthrough) failed. Error: " + std::to_wstring(GetLastError()));
        }
        return;
    } else {
        ConnectionTuple replyTuple; 
        replyTuple.protocol = IPPROTO_TCP;
        replyTuple.srcAddr = ip_header->DstAddr;
        replyTuple.dstAddr = ip_header->SrcAddr;
        replyTuple.srcPort = ntohs(tcp_header->DstPort);
        replyTuple.dstPort = ntohs(tcp_header->SrcPort);

        std::lock_guard<std::mutex> lock(m_tcpConnMutex);
        auto it = m_tcpConnections.find(replyTuple);

        if (it != m_tcpConnections.end()) {
            std::shared_ptr<TcpProxyConnection> conn = it->second;
            if (conn && conn->active) {
                Log(L"HandleTCP: Inbound packet for tracked SOCKS flow " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort) + L" received directly, not via proxy socket tunnel. This is unusual. Letting it pass.");
            } else {
                Log(L"HandleTCP: Inbound packet matches a tuple in m_tcpConnections but conn is inactive/invalid. Passthrough. " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort));
            }
        } else {
            Log(L"HandleTCP: Inbound packet for " + s2ws(resolvedDstIp) + L":" + std::to_wstring(connTuple.dstPort) + L" does not match any tracked SOCKS connection. Letting it pass.");
        }

        if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
            Log(L"PacketProcessor: WinDivertSend (HandleTCP inbound passthrough) failed. Error: " + std::to_wstring(GetLastError()));
        }
        return;
    }
}

void PacketProcessor::HandleUDP(unsigned char* packet, UINT packetLen, WINDIVERT_ADDRESS* addr, bool isIPv6, void* ip_header_from_caller, void* udp_header_from_caller, HANDLE hDivert, const std::string& resolvedDstIp) {
    if (isIPv6) {
        Log(L"HandleUDP: Received IPv6 packet (unexpected). Letting packet pass.");
        if (hDivert != INVALID_HANDLE_VALUE) WinDivertSend(hDivert, packet, packetLen, NULL, addr); // Added hDivert check
        return;
    }

    PWINDIVERT_IPHDR ip_header = (PWINDIVERT_IPHDR)ip_header_from_caller; // Cast from void*
    PWINDIVERT_UDPHDR udp_header = (PWINDIVERT_UDPHDR)udp_header_from_caller; // Cast from void*


    if (!ip_header || !udp_header) { // Check both headers
        Log(L"HandleUDP: IP or UDP header is null. Letting packet pass.");
        if (hDivert != INVALID_HANDLE_VALUE) WinDivertSend(hDivert, packet, packetLen, NULL, addr); // Added hDivert check
        return;
    }

    char srcIpStr[INET_ADDRSTRLEN], dstIpStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->SrcAddr, srcIpStr, INET_ADDRSTRLEN); // Use ip_header
    inet_ntop(AF_INET, &ip_header->DstAddr, dstIpStr, INET_ADDRSTRLEN); // Use ip_header
    unsigned short srcPort = ntohs(udp_header->SrcPort);
    unsigned short dstPort = ntohs(udp_header->DstPort);

    Log(L"HandleUDP: Packet details - Src: " + s2ws(srcIpStr) + L":" + std::to_wstring(srcPort) +
        L", Dst: " + s2ws(dstIpStr) + L":" + std::to_wstring(dstPort) +
        L", Direction: " + (addr->Outbound ? L"Outbound" : L"Inbound") +
        L", IfIdx: " + std::to_wstring(addr->Network.IfIdx) + L", SubIfIdx: " + std::to_wstring(addr->Network.SubIfIdx));

    ConnectionTuple connTuple;
    connTuple.protocol = IPPROTO_UDP;
    connTuple.srcAddr = ip_header->SrcAddr;
    connTuple.dstAddr = ip_header->DstAddr;
    connTuple.srcPort = srcPort; // Already host order
    connTuple.dstPort = dstPort; // Already host order
    connTuple.owningPid = 0; // Initialize PID

    // Get PID for the connection
    // For UDP, GetPidFromUdpListener uses the local port.
    if (addr->Outbound) {
        connTuple.owningPid = GetPidFromUdpListener(connTuple.srcPort);
    } else { // Inbound
        connTuple.owningPid = GetPidFromUdpListener(connTuple.dstPort);
    }

    if (connTuple.owningPid != 0) {
        Log(L"HandleUDP: Associated PID: " + std::to_wstring(connTuple.owningPid) + L" for local port " + 
            std::to_wstring(addr->Outbound ? connTuple.srcPort : connTuple.dstPort) + 
            L" (" + (addr->Outbound ? L"outbound" : L"inbound") + L" packet " + ConvertTupleToString(connTuple) + L")");
    } else {
        Log(L"HandleUDP: Could not find PID for local port " + 
            std::to_wstring(addr->Outbound ? connTuple.srcPort : connTuple.dstPort) +
            L" (" + (addr->Outbound ? L"outbound" : L"inbound") + L" packet " + ConvertTupleToString(connTuple) + L")");
    }

    // PID-based Filtering Logic (similar to HandleTCP)
    if (g_ServiceConfig.enablePidFilter && connTuple.owningPid != 0) {
        bool isAllowed = false;
        for (DWORD allowedPid : g_ServiceConfig.targetPids) {
            if (connTuple.owningPid == allowedPid) {
                isAllowed = true;
                break;
            }
        }
        if (!isAllowed) {
            Log(L"HandleUDP: PID " + std::to_wstring(connTuple.owningPid) + L" is not in the allowed list. Passing packet through.");
            if (hDivert != INVALID_HANDLE_VALUE) {
                if (!WinDivertSend(hDivert, packet, packetLen, NULL, addr)) {
                    Log(L"PacketProcessor: WinDivertSend (PID filter UDP passthrough) failed. Error: " + std::to_wstring(GetLastError()));
                }
            }
            return;
        } else {
            Log(L"HandleUDP: PID " + std::to_wstring(connTuple.owningPid) + L" is allowed. Proceeding.");
        }
    } else if (g_ServiceConfig.enablePidFilter && connTuple.owningPid == 0) {
        Log(L"HandleUDP: PID not found, and PID filtering is enabled. Packet will proceed to standard processing logic.");
    }

    Log(L"HandleUDP: Checking if " + s2ws(resolvedDstIp) + L":" + std::to_wstring(dstPort) + L" is for proxy server...");

    if (this->IsPacketForProxyServer(resolvedDstIp, dstPort)) {
         Log(L"PacketProcessor: UDP traffic to proxy's IP/port detected (via IsPacketForProxyServer). Dst: " + s2ws(resolvedDstIp) + L":" + std::to_wstring(dstPort) + L". Bypassing SOCKS.");
         if (hDivert != INVALID_HANDLE_VALUE) WinDivertSend(hDivert, packet, packetLen, NULL, addr);
         return;
    }

    ConnectionTuple currentAppTuple; 
    currentAppTuple.protocol = IPPROTO_UDP;
    currentAppTuple.srcAddr = ip_header->SrcAddr; // Network byte order
    currentAppTuple.dstAddr = ip_header->DstAddr; // Network byte order
    currentAppTuple.srcPort = srcPort; // Host byte order
    currentAppTuple.dstPort = dstPort; // Host byte order
    
    std::shared_ptr<UdpProxyAssociation> localUdpAssociationRef;
    {
        std::lock_guard<std::mutex> lock(m_udpAssocMutex);
        if (!m_udpAssociation || !m_udpAssociation->active) {
            Log(L"No active UDP association or association is inactive. Creating new one for Dst: " + s2ws(resolvedDstIp) + L":" + std::to_wstring(dstPort));
            
            try {
                if (!m_udpAssociationSocksClient) {
                    Log(L"HandleUDP: Creating dedicated SOCKS client for UDP association.");
                    m_udpAssociationSocksClient = new Socks5Client(m_proxyOriginalInput, m_proxyPort, m_proxyUsername, m_proxyPassword);
                }

                if (!m_udpAssociationSocksClient) {
                    Log(L"HandleUDP: Failed to create or get SOCKS client for UDP (nullptr). Cannot create UDP association.");
                    if (hDivert != INVALID_HANDLE_VALUE) WinDivertSend(hDivert, packet, packetLen, NULL, addr);
                    return; 
                }
                
                Log(L"HandleUDP: Establishing SOCKS5 UDP association for traffic to " + s2ws(resolvedDstIp) + L":" + std::to_wstring(currentAppTuple.dstPort));

                m_udpAssociation = std::make_shared<UdpProxyAssociation>();
                m_udpAssociation->active = true;
                
                SOCKET proxyRelaySock = m_udpAssociationSocksClient->UdpAssociate(
                    m_udpAssociation->proxyRelayIp, 
                    m_udpAssociation->proxyRelayPort
                );

                if (proxyRelaySock == INVALID_SOCKET) {
                    Log(L"SOCKS5 UDP Associate failed. Error: " + std::to_wstring(WSAGetLastError()) + L". Original UDP packet will be passed through.");
                    m_udpAssociation->active = false;
                    m_udpAssociation.reset(); 
                    if (hDivert != INVALID_HANDLE_VALUE) WinDivertSend(hDivert, packet, packetLen, NULL, addr);
                    return; 
                }
                m_udpAssociation->localProxySideSocket = proxyRelaySock;
                m_udpAssociation->controlSocket = m_udpAssociationSocksClient->DetachControlSocket();

                if (m_udpAssociation->controlSocket == INVALID_SOCKET) {
                    Log(L"SOCKS5 UDP Associate: DetachControlSocket failed. Association aborted.");
                    m_udpAssociation->active = false;
                    if (m_udpAssociation->localProxySideSocket != INVALID_SOCKET) {
                        closesocket(m_udpAssociation->localProxySideSocket);
                        m_udpAssociation->localProxySideSocket = INVALID_SOCKET;
                    }
                    m_udpAssociation.reset();
                    if (hDivert != INVALID_HANDLE_VALUE) WinDivertSend(hDivert, packet, packetLen, NULL, addr);
                    return; 
                }

                Log(L"SOCKS5 UDP Associate successful. Relay IP: " + s2ws(m_udpAssociation->proxyRelayIp) + L" Port: " + std::to_wstring(m_udpAssociation->proxyRelayPort) +
                    L". Control Socket: " + std::to_wstring(m_udpAssociation->controlSocket));

                try {
                    m_udpAssociation->forwardAppToProxyUdpThread = std::thread(&PacketProcessor::ForwardAppToProxyUDP, this, m_udpAssociation.get(), currentAppTuple, hDivert);
                    m_udpAssociation->forwardProxyToAppUdpThread = std::thread(&PacketProcessor::ForwardProxyToAppUDP, this, m_udpAssociation.get(), currentAppTuple, hDivert);
                } catch (const std::system_error& e) {
                    Log(L"HandleUDP: Failed to launch UDP forwarding threads: " + s2ws(std::string(e.what())));
                    m_udpAssociation->active = false; 
                    if(m_udpAssociation->localProxySideSocket != INVALID_SOCKET) closesocket(m_udpAssociation->localProxySideSocket);
                    if(m_udpAssociation->controlSocket != INVALID_SOCKET) closesocket(m_udpAssociation->controlSocket);
                    m_udpAssociation.reset();
                    if (hDivert != INVALID_HANDLE_VALUE) WinDivertSend(hDivert, packet, packetLen, NULL, addr);
                    return; 
                }
                Log(L"HandleUDP: Started UDP forwarding threads.");
            } catch (const std::exception& e) {
                Log(L"HandleUDP: Exception during UDP association setup: " + s2ws(e.what()));
                if (m_udpAssociation) { 
                    m_udpAssociation->active = false;
                    if (m_udpAssociation->localProxySideSocket != INVALID_SOCKET) closesocket(m_udpAssociation->localProxySideSocket);
                    if (m_udpAssociation->controlSocket != INVALID_SOCKET) closesocket(m_udpAssociation->controlSocket);
                    m_udpAssociation.reset();
                }
                if (hDivert != INVALID_HANDLE_VALUE) WinDivertSend(hDivert, packet, packetLen, NULL, addr);
                return; 
            }
        }
        localUdpAssociationRef = m_udpAssociation; 
    }

    if (localUdpAssociationRef && localUdpAssociationRef->active && addr->Outbound) {
        UdpProxyAssociation::QueuedUdpPacket q_packet_data;
        q_packet_data.packetData.assign(packet, packet + packetLen); 
        q_packet_data.packetLen = packetLen;
        {
            std::lock_guard<std::mutex> q_lock(localUdpAssociationRef->appQueueMutex);
            localUdpAssociationRef->appPacketQueue.push(q_packet_data);
        }
        localUdpAssociationRef->appQueueCv.notify_one();
        return; 
    } else if (!addr->Outbound) { 
         if (hDivert != INVALID_HANDLE_VALUE) WinDivertSend(hDivert, packet, packetLen, NULL, addr);
    } else { 
         Log(L"HandleUDP: No active UDP association for outbound packet or packet not outbound. Letting pass. Dst: " + s2ws(resolvedDstIp) + L":" + std::to_wstring(dstPort));
         if (hDivert != INVALID_HANDLE_VALUE) WinDivertSend(hDivert, packet, packetLen, NULL, addr);
    }
}

void PacketProcessor::ForwardProxyToAppTCP(TcpProxyConnection* conn, HANDLE divertHandle) {
    if (!conn || divertHandle == INVALID_HANDLE_VALUE || divertHandle == NULL) {
        Log(L"ForwardProxyToAppTCP: Invalid arguments.");
        if(conn) conn->active = false;
        return;
    }
    Log(L"ForwardProxyToAppTCP started for IPv4 connection. Original Dst: " + ConvertTupleToString(conn->originalTuple) + L", ProxySocket: " + std::to_wstring(conn->proxySocket));
    char data_buffer[65535]; 
    WINDIVERT_ADDRESS addr_inject;
    
    while (conn->active && conn->proxySocket != INVALID_SOCKET) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(conn->proxySocket, &read_fds);
        TIMEVAL timeout = {1, 0}; // 1 second timeout

        int select_ret = select(0, &read_fds, NULL, NULL, &timeout);
        if (!conn->active) {
            Log(L"ForwardProxyToAppTCP: conn->active is false. Exiting loop for " + ConvertTupleToString(conn->originalTuple));
            break;
        }

        if (select_ret == SOCKET_ERROR) {
            Log(L"ForwardProxyToAppTCP: select failed for " + ConvertTupleToString(conn->originalTuple) + L". Error: " + std::to_wstring(WSAGetLastError()));
            conn->active = false; break;
        }

        if (select_ret > 0 && FD_ISSET(conn->proxySocket, &read_fds)) {
            Log(L"ForwardProxyToAppTCP: select indicated data is available on proxySocket " + std::to_wstring(conn->proxySocket) + L" for " + ConvertTupleToString(conn->originalTuple));
            int bytes_recv = recv(conn->proxySocket, data_buffer, sizeof(data_buffer), 0);
            Log(L"ForwardProxyToAppTCP: recv() from proxySocket " + std::to_wstring(conn->proxySocket) + L" for " + ConvertTupleToString(conn->originalTuple) + L" returned: " + std::to_wstring(bytes_recv));
            
            if (bytes_recv > 0) {
                Log(L"ForwardProxyToAppTCP: Received " + std::to_wstring(bytes_recv) + L" bytes from proxy for " + ConvertTupleToString(conn->originalTuple) + L", injecting back to original application");
                std::vector<unsigned char> packet_buffer_inject;
                PWINDIVERT_IPHDR ip_header_inject = nullptr;
                PWINDIVERT_TCPHDR tcp_header_inject = nullptr;
                unsigned char* payload_inject_ptr = nullptr;
                UINT tcp_hdr_size = sizeof(WINDIVERT_TCPHDR); 
                UINT ip_hdr_size = sizeof(WINDIVERT_IPHDR);
                UINT total_hdr_size = ip_hdr_size + tcp_hdr_size;
                UINT injected_packet_len = total_hdr_size + bytes_recv;
                packet_buffer_inject.resize(injected_packet_len);

                ip_header_inject = (PWINDIVERT_IPHDR)packet_buffer_inject.data();
                tcp_header_inject = (PWINDIVERT_TCPHDR)(packet_buffer_inject.data() + ip_hdr_size);
                payload_inject_ptr = packet_buffer_inject.data() + total_hdr_size;
                ip_header_inject->Version = 4;
                ip_header_inject->HdrLength = ip_hdr_size / 4;
                ip_header_inject->Length = htons(injected_packet_len); 
                ip_header_inject->FragOff0 = htons(0x4000); 
                ip_header_inject->TTL = 64;
                ip_header_inject->Protocol = IPPROTO_TCP;
                ip_header_inject->Checksum = 0; 
                ip_header_inject->SrcAddr = conn->originalTuple.dstAddr;
                ip_header_inject->DstAddr = conn->originalTuple.srcAddr;

                tcp_header_inject->SrcPort = htons(conn->originalTuple.dstPort); 
                tcp_header_inject->DstPort = htons(conn->originalTuple.srcPort); 
                tcp_header_inject->SeqNum = htonl(0); 
                tcp_header_inject->AckNum = htonl(0); 
                tcp_header_inject->HdrLength = tcp_hdr_size / 4;
                tcp_header_inject->Reserved1 = 0; 
                ((UINT8*)tcp_header_inject)[13] = (1 << 3) | (1 << 4); // PSH, ACK
                tcp_header_inject->Window = htons(65535); 
                tcp_header_inject->Checksum = 0; 
                tcp_header_inject->UrgPtr = 0;

                memcpy(payload_inject_ptr, data_buffer, bytes_recv);

                WinDivertHelperInitAddr(&addr_inject);
                addr_inject.Loopback = 1; addr_inject.Impostor = 1; addr_inject.Outbound = 0; 
                addr_inject.IPChecksum = 1; // Always IPv4
                addr_inject.TCPChecksum = 1;
                
                if (!WinDivertHelperCalcChecksums(packet_buffer_inject.data(), injected_packet_len, &addr_inject, 0)) {
                    Log(L"ForwardProxyToAppTCP: WinDivertHelperCalcChecksums failed. Error: " + std::to_wstring(GetLastError()));
                }
                if (divertHandle != INVALID_HANDLE_VALUE && !WinDivertSend(divertHandle, packet_buffer_inject.data(), injected_packet_len, NULL, &addr_inject)) {
                    Log(L"ForwardProxyToAppTCP: WinDivertSend failed. Error: " + std::to_wstring(GetLastError()));
                } else {
                    Log(L"ForwardProxyToAppTCP: Successfully injected " + std::to_wstring(injected_packet_len) + L" bytes back to the application");
                }
            } else if (bytes_recv == 0) {
                Log(L"ForwardProxyToAppTCP: Proxy closed connection (recv returned 0) for " + ConvertTupleToString(conn->originalTuple) + L"."); 
                conn->active = false; 
                break;
            } else { // SOCKET_ERROR
                Log(L"ForwardProxyToAppTCP: recv failed for " + ConvertTupleToString(conn->originalTuple) + L". Error: " + std::to_wstring(WSAGetLastError())); 
                conn->active = false; 
                break;
            }
        }
        // If select_ret == 0 (timeout), loop continues and checks conn->active
    }
    Log(L"ForwardProxyToAppTCP stopping for " + ConvertTupleToString(conn->originalTuple) + L". conn->active: " + (conn->active ? L"true" : L"false"));
    conn->active = false; 
}

void PacketProcessor::ForwardAppToProxyUDP(UdpProxyAssociation* assoc, ConnectionTuple originalClientTuple, HANDLE hDivert) {
    if (!assoc) { Log(L"ForwardAppToProxyUDP: Invalid UdpProxyAssociation."); return; }
    (void)hDivert; // Mark hDivert as unused as this function sends via socket
    (void)originalClientTuple;

    Log(L"ForwardAppToProxyUDP started for IPv4 association.");

    while (assoc->active) {
        UdpProxyAssociation::QueuedUdpPacket q_packet_data;
        {
            std::unique_lock<std::mutex> lock(assoc->appQueueMutex);
            assoc->appQueueCv.wait(lock, [&assoc] { return !assoc->active || !assoc->appPacketQueue.empty(); });
            if (!assoc->active && assoc->appPacketQueue.empty()) break;
            if (assoc->appPacketQueue.empty()) continue;
            q_packet_data = assoc->appPacketQueue.front();
            assoc->appPacketQueue.pop();
        } 

        PWINDIVERT_IPHDR ip_header_v4_orig = nullptr;
        PWINDIVERT_UDPHDR udp_header_orig = nullptr;
        PVOID payload_orig_ptr = nullptr; UINT payload_orig_len = 0; UINT8 proto_unused_orig = 0;

        if (!WinDivertHelperParsePacket(q_packet_data.packetData.data(), q_packet_data.packetLen,
                                       &ip_header_v4_orig, nullptr, &proto_unused_orig,
                                       nullptr, nullptr, nullptr, &udp_header_orig, 
                                       &payload_orig_ptr, &payload_orig_len, nullptr, nullptr)) {
            Log(L"ForwardAppToProxyUDP: Failed to parse queued packet."); continue;
        }
        if (!udp_header_orig || !payload_orig_ptr || !ip_header_v4_orig) {
            Log(L"ForwardAppToProxyUDP: Parsed packet headers or payload is null."); continue;
        }

        std::vector<unsigned char> socks5_udp_request;
        socks5_udp_request.insert(socks5_udp_request.end(), {0x00, 0x00, 0x00}); // RSV, FRAG
        unsigned short original_dst_port_net_order = udp_header_orig->DstPort;
        socks5_udp_request.push_back(0x01); // ATYP_IPV4
        UINT32 original_dst_addr_net_order = ip_header_v4_orig->DstAddr; 
        socks5_udp_request.push_back((original_dst_addr_net_order >> 0) & 0xFF);
        socks5_udp_request.push_back((original_dst_addr_net_order >> 8) & 0xFF);
        socks5_udp_request.push_back((original_dst_addr_net_order >> 16) & 0xFF);
        socks5_udp_request.push_back((original_dst_addr_net_order >> 24) & 0xFF);
        socks5_udp_request.push_back((original_dst_port_net_order >> 8) & 0xFF); 
        socks5_udp_request.push_back(original_dst_port_net_order & 0xFF);  
        if (payload_orig_len > 0) {
            socks5_udp_request.insert(socks5_udp_request.end(), (unsigned char*)payload_orig_ptr, (unsigned char*)payload_orig_ptr + payload_orig_len);
        }

        sockaddr_storage remote_sas = {0};
        sockaddr_in& remote_addr_ipv4 = reinterpret_cast<sockaddr_in&>(remote_sas);
        remote_addr_ipv4.sin_family = AF_INET;
        remote_addr_ipv4.sin_port = htons(assoc->proxyRelayPort);
        InetPtonW(AF_INET, s2ws(assoc->proxyRelayIp).c_str(), &remote_addr_ipv4.sin_addr);
        int remote_sas_len = sizeof(sockaddr_in);
        if (assoc->localProxySideSocket == INVALID_SOCKET) {
            Log(L"ForwardAppToProxyUDP: localProxySideSocket is invalid."); continue; 
        }
        if (sendto(assoc->localProxySideSocket, reinterpret_cast<const char*>(socks5_udp_request.data()),
                   static_cast<int>(socks5_udp_request.size()), 0, 
                   reinterpret_cast<const sockaddr*>(&remote_sas), remote_sas_len) == SOCKET_ERROR) {
            Log(L"ForwardAppToProxyUDP: sendto to SOCKS proxy UDP relay failed. Error: " + std::to_wstring(WSAGetLastError()));
        }
    }
    Log(L"ForwardAppToProxyUDP stopping.");
}

void PacketProcessor::ForwardProxyToAppUDP(UdpProxyAssociation* assoc, ConnectionTuple originalClientTuple, HANDLE divertHandle) {
    if (!assoc || divertHandle == INVALID_HANDLE_VALUE || divertHandle == NULL) {
        Log(L"ForwardProxyToAppUDP: Invalid arguments."); if(assoc) assoc->active = false; return;
    }
    Log(L"ForwardProxyToAppUDP started for IPv4 association.");
    char recv_buffer[65535];
    WINDIVERT_ADDRESS addr_inject_udp;
    
    while (assoc->active && assoc->localProxySideSocket != INVALID_SOCKET) {
        fd_set read_fds; FD_ZERO(&read_fds); FD_SET(assoc->localProxySideSocket, &read_fds);
        TIMEVAL timeout = {1,0};
        int select_ret = select(0, &read_fds, NULL, NULL, &timeout);

        if (!assoc->active) break;
        if (select_ret == SOCKET_ERROR) {
            Log(L"ForwardProxyToAppUDP: select failed. Error: " + std::to_wstring(WSAGetLastError())); assoc->active = false; break;
        }
        
        if (select_ret > 0 && FD_ISSET(assoc->localProxySideSocket, &read_fds)) {
            sockaddr_storage sender_addr_ignored; int sender_addr_len_ignored = sizeof(sender_addr_ignored);
            int bytes_recv = recvfrom(assoc->localProxySideSocket, recv_buffer, sizeof(recv_buffer), 0, (sockaddr*)&sender_addr_ignored, &sender_addr_len_ignored);

            if (bytes_recv > 0) {
                if (bytes_recv < 10) { Log(L"ForwardProxyToAppUDP: SOCKS5 UDP packet too short."); continue; }

                unsigned char* p_recv = (unsigned char*)recv_buffer;
                if (p_recv[2] != 0x00) { Log(L"ForwardProxyToAppUDP: SOCKS5 UDP fragmentation not supported."); continue; }
                unsigned char atyp = p_recv[3];
                
                PVOID actual_payload_from_proxy_ptr = nullptr; UINT actual_payload_from_proxy_len = 0;
                IN_ADDR original_sender_ipv4 = {0}; unsigned short original_sender_port_host_order = 0;
                p_recv += 4; int current_offset = 4;

                if (atyp == 0x01) { 
                    if (bytes_recv < current_offset + 4 + 2) { Log(L"ForwardProxyToAppUDP: SOCKS5 UDP IPv4 packet too short."); continue; }
                    memcpy(&original_sender_ipv4.s_addr, p_recv, 4);
                    p_recv += 4; current_offset += 4;
                } else {
                    Log(L"ForwardProxyToAppUDP: SOCKS5 UDP response ATYP not IPv4. ATYP: " + std::to_wstring(atyp) + L". Dropping."); continue;
                }
                original_sender_port_host_order = ntohs(*(USHORT*)p_recv);
                p_recv += 2; current_offset += 2;
                actual_payload_from_proxy_ptr = p_recv;
                actual_payload_from_proxy_len = bytes_recv - current_offset;

                std::vector<unsigned char> packet_buffer_inject;
                PWINDIVERT_IPHDR ip_header_inject = nullptr;
                PWINDIVERT_UDPHDR udp_header_inject = nullptr; unsigned char* payload_inject_ptr = nullptr;
                UINT udp_hdr_size_inject = sizeof(WINDIVERT_UDPHDR);
                UINT ip_hdr_size_inject = sizeof(WINDIVERT_IPHDR);
                UINT total_hdr_size_inject = ip_hdr_size_inject + udp_hdr_size_inject;
                UINT injected_packet_len = total_hdr_size_inject + actual_payload_from_proxy_len;
                packet_buffer_inject.resize(injected_packet_len);

                ip_header_inject = (PWINDIVERT_IPHDR)packet_buffer_inject.data();
                udp_header_inject = (PWINDIVERT_UDPHDR)(packet_buffer_inject.data() + ip_hdr_size_inject);
                payload_inject_ptr = packet_buffer_inject.data() + total_hdr_size_inject;
                ip_header_inject->Version = 4; ip_header_inject->HdrLength = ip_hdr_size_inject / 4;
                ip_header_inject->Length = htons(injected_packet_len); 
                ip_header_inject->Id = 0; ip_header_inject->FragOff0 = htons(0x4000); 
                ip_header_inject->TTL = 64; ip_header_inject->Protocol = IPPROTO_UDP; ip_header_inject->Checksum = 0; 
                ip_header_inject->SrcAddr = original_sender_ipv4.s_addr; 
                ip_header_inject->DstAddr = originalClientTuple.srcAddr;

                udp_header_inject->SrcPort = htons(original_sender_port_host_order); 
                udp_header_inject->DstPort = htons(originalClientTuple.srcPort); 
                udp_header_inject->Length = htons(udp_hdr_size_inject + actual_payload_from_proxy_len);
                udp_header_inject->Checksum = 0; 
                if (actual_payload_from_proxy_len > 0) {
                    memcpy(payload_inject_ptr, actual_payload_from_proxy_ptr, actual_payload_from_proxy_len);
                }

                WinDivertHelperInitAddr(&addr_inject_udp);
                addr_inject_udp.Loopback = 1; addr_inject_udp.Impostor = 1; addr_inject_udp.Outbound = 0;
                addr_inject_udp.IPChecksum = 1; // Always IPv4
                addr_inject_udp.UDPChecksum = 1;
                
                if (!WinDivertHelperCalcChecksums(packet_buffer_inject.data(), injected_packet_len, &addr_inject_udp, 0)) {
                    Log(L"ForwardProxyToAppUDP: WinDivertHelperCalcChecksums failed: " + std::to_wstring(GetLastError()));
                }
                if (divertHandle != INVALID_HANDLE_VALUE && !WinDivertSend(divertHandle, packet_buffer_inject.data(), injected_packet_len, NULL, &addr_inject_udp)) {
                    Log(L"ForwardProxyToAppUDP: WinDivertSend failed: " + std::to_wstring(GetLastError()));
                }
            } else if (bytes_recv == 0) {
                Log(L"ForwardProxyToAppUDP: recvfrom returned 0 bytes.");
            } else { 
                int error = WSAGetLastError();
                if (error != WSAECONNRESET) { 
                    Log(L"ForwardProxyToAppUDP: recvfrom failed. Error: " + std::to_wstring(error));
                }
            }
        }
    }
    Log(L"ForwardProxyToAppUDP stopping.");
}

bool PacketProcessor::IsPacketForProxyServer(const std::string& destHostIpOrName, USHORT destPort) const {
    if (!m_socksClient) {
        Log(L"IsPacketForProxyServer: m_socksClient is null, cannot determine proxy address.");
        return false; // Cannot determine if it's for the proxy
    }

    // Construct a sockaddr for the destination to pass to m_socksClient->IsAddressProxy
    sockaddr_storage packet_dest_ss;
    memset(&packet_dest_ss, 0, sizeof(sockaddr_storage));
    int addr_len = 0;

    // Try to interpret destHostIpOrName as an IP address first
    struct in_addr ipv4_addr;
    struct in6_addr ipv6_addr;

    if (inet_pton(AF_INET, destHostIpOrName.c_str(), &ipv4_addr) == 1) {
        sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(&packet_dest_ss);
        sa_in->sin_family = AF_INET;
        sa_in->sin_addr = ipv4_addr;
        sa_in->sin_port = htons(destPort);
        addr_len = sizeof(sockaddr_in);
    } else if (inet_pton(AF_INET6, destHostIpOrName.c_str(), &ipv6_addr) == 1) {
        sockaddr_in6* sa_in6 = reinterpret_cast<sockaddr_in6*>(&packet_dest_ss);
        sa_in6->sin6_family = AF_INET6;
        sa_in6->sin6_addr = ipv6_addr;
        sa_in6->sin6_port = htons(destPort);
        addr_len = sizeof(sockaddr_in6);
    } else {
        std::string comparableProxyInput = m_proxyOriginalInput;
        size_t scheme_pos = comparableProxyInput.find("://");
        if (scheme_pos != std::string::npos) {
            comparableProxyInput = comparableProxyInput.substr(scheme_pos + 3);
        }
        
        if (destHostIpOrName == comparableProxyInput && destPort == m_proxyPort) {
            Log(L"IsPacketForProxyServer: Destination " + s2ws(destHostIpOrName) + L":" + std::to_wstring(destPort) + L" matches configured proxy hostname/port. Considered for proxy.");
             Log(L"IsPacketForProxyServer: Destination is a hostname. If it matches configured proxy string " + s2ws(m_proxyOriginalInput) + L", assuming it IS the proxy and will be handled by SOCKS client connect logic or direct send.");
             return true; // Simplified: if hostname & port match comparableProxyInput, it's the proxy.
        }
        // If it's a different hostname, it's not the proxy.
        return false;
    }

    if (addr_len == 0) { // Should not happen if inet_pton succeeded
        return false;
    }
    return m_socksClient->IsAddressProxy(reinterpret_cast<const sockaddr*>(&packet_dest_ss), destPort);
}

