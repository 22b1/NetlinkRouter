#include "socks5_client.h"
#include "ip_utils.h"
#include "string_utils.h" // Added for s2ws and ws2s functions
#include <stdexcept> // For std::runtime_error


Socks5Client::Socks5Client(const std::string& proxyIp, unsigned short proxyPort,
                           const std::string& username, const std::string& password)
    : m_proxyIp(proxyIp), m_proxyPort(proxyPort), 
      m_username(username), m_password(password), 
      m_controlSocket(INVALID_SOCKET), 
      m_proxyServerSockAddrValid(false) {
    Log(L"SOCKS5CLIENT_CONSTRUCTOR_ENTRY_TEST_LOG"); // Diagnostic log
    Log(L"Socks5Client constructor for proxy (plain TCP): " + s2ws(proxyIp) + L":" + std::to_wstring(proxyPort));
    memset(&m_proxyServerSockAddr, 0, sizeof(m_proxyServerSockAddr)); // Zero out the new sockaddr_storage
    // No SSL_CTX or global SSL init needed
}

Socks5Client::~Socks5Client() {
    Log(L"Socks5Client destructor.");
    CloseControlSocket(); 
    // No SSL_CTX_free needed
}

void Socks5Client::CloseSocketGeneric(SOCKET& sock) {
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
}

void Socks5Client::CloseControlSocket() {
    // No SSL_shutdown or SSL_free needed
    if (m_controlSocket != INVALID_SOCKET) {
        closesocket(m_controlSocket);
        m_controlSocket = INVALID_SOCKET;
        Log(L"SOCKS5: Control socket closed.");
    }
}

bool Socks5Client::ConnectToProxyServer() {
    CloseControlSocket(); 
    m_proxyServerSockAddrValid = false; 

    addrinfo hints = {0}, *res = nullptr, *rp = nullptr;
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string actual_host_to_resolve = m_proxyIp;
    const std::string scheme_socks5h = "socks5h://";
    const std::string scheme_socks5 = "socks5://";

    if (actual_host_to_resolve.rfind(scheme_socks5h, 0) == 0) { // starts with socks5h://
        actual_host_to_resolve = actual_host_to_resolve.substr(scheme_socks5h.length());
    } else if (actual_host_to_resolve.rfind(scheme_socks5, 0) == 0) { // starts with socks5://
        actual_host_to_resolve = actual_host_to_resolve.substr(scheme_socks5.length());
    }
    // Remove potential trailing slash if it's the last character after scheme stripping
    if (!actual_host_to_resolve.empty() && actual_host_to_resolve.back() == '/') {
        actual_host_to_resolve.pop_back();
    }

    Log(L"SOCKS5 ConnectToProxyServer: Original proxy input [" + s2ws(m_proxyIp) + L"], attempting to resolve host [" + s2ws(actual_host_to_resolve) + L"] port [" + std::to_wstring(m_proxyPort) + L"]");

    std::string portStr = std::to_string(m_proxyPort); // Keep as std::string for getaddrinfo
    int gai_ret = getaddrinfo(actual_host_to_resolve.c_str(), portStr.c_str(), &hints, &res);
    if (gai_ret != 0) {
        Log(L"SOCKS5 ConnectToProxyServer: getaddrinfo failed for proxy host '" + s2ws(actual_host_to_resolve) + L"'. Error: " + std::to_wstring(gai_ret) + L" (WSAGetLastError: " + std::to_wstring(WSAGetLastError()) + L")");
        return false;
    }

    SOCKET tempSockFd = INVALID_SOCKET;
    Log(L"SOCKS5 ConnectToProxyServer: Resolved addresses for proxy host '" + s2ws(actual_host_to_resolve) + L"':");
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        char ip_str_log_char[INET6_ADDRSTRLEN]; // Use char buffer for inet_ntop
        std::string ip_str_log_std;
        if (p->ai_family == AF_INET) {
            inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, ip_str_log_char, sizeof(ip_str_log_char));
            ip_str_log_std = ip_str_log_char;
            Log(L"  - IPv4: " + s2ws(ip_str_log_std));
        } else if (p->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &((sockaddr_in6*)p->ai_addr)->sin6_addr, ip_str_log_char, sizeof(ip_str_log_char));
            ip_str_log_std = ip_str_log_char;
            Log(L"  - IPv6: " + s2ws(ip_str_log_std));
        } else {
            Log(L"  - Unknown family: " + std::to_wstring(p->ai_family));
        }
    }

    for (rp = res; rp != nullptr; rp = rp->ai_next) {
        tempSockFd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (tempSockFd == INVALID_SOCKET) {
            Log(L"SOCKS5 ConnectToProxyServer: socket() call failed. Error: " + std::to_wstring(WSAGetLastError()));
            continue; 
        }

        char ipStr_char[INET6_ADDRSTRLEN]; 
        std::string ipStr_std;
        std::string familyStr_std = (rp->ai_family == AF_INET) ? "IPv4" : "IPv6";
        
        if (rp->ai_family == AF_INET) {
            inet_ntop(AF_INET, &((sockaddr_in*)rp->ai_addr)->sin_addr, ipStr_char, sizeof(ipStr_char));
        } else if (rp->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &((sockaddr_in6*)rp->ai_addr)->sin6_addr, ipStr_char, sizeof(ipStr_char));
        } else {
            strcpy_s(ipStr_char, INET6_ADDRSTRLEN, "UnknownFamily");
        }
        ipStr_std = ipStr_char;

        Log(L"SOCKS5 ConnectToProxyServer: Attempting TCP connect to proxy (" + s2ws(familyStr_std) + L"): " + s2ws(ipStr_std) + L" Port: " + s2ws(portStr));

        if (connect(tempSockFd, rp->ai_addr, (int)rp->ai_addrlen) == SOCKET_ERROR) {
            Log(L"SOCKS5 ConnectToProxyServer: TCP connect to proxy " + s2ws(familyStr_std) + L" " + s2ws(ipStr_std) + L" failed. Error: " + std::to_wstring(WSAGetLastError()));
            closesocket(tempSockFd); tempSockFd = INVALID_SOCKET;
            continue; 
        }
        
        Log(L"SOCKS5 ConnectToProxyServer: TCP connected successfully to proxy " + s2ws(familyStr_std) + L": " + s2ws(ipStr_std));
        m_controlSocket = tempSockFd; 
        memcpy(&m_proxyServerSockAddr, rp->ai_addr, rp->ai_addrlen);
        m_proxyServerSockAddrValid = true;
        Log(L"SOCKS5 ConnectToProxyServer: Stored connected proxy address: " + s2ws(ipStr_std) + L" Port: " + s2ws(portStr));

        DWORD timeout = 10000; 
        if (setsockopt(m_controlSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
            Log(L"SOCKS5: Failed to set SO_SNDTIMEO on control socket. Error: " + std::to_wstring(WSAGetLastError()));
            // Proceed, but sends might block indefinitely
        }
        if (setsockopt(m_controlSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
            Log(L"SOCKS5: Failed to set SO_RCVTIMEO on control socket. Error: " + std::to_wstring(WSAGetLastError()));
            // This is more critical, as recvs could hang.
            CloseControlSocket(); // Close socket as it's not usable with reliable timeouts
            m_proxyServerSockAddrValid = false; // Connection is not usable
            break; 
        }
        Log(L"SOCKS5: Send and Receive timeouts set to 10s on control socket.");
        break; 
    }
    freeaddrinfo(res); // Free the address information list

    if (m_controlSocket == INVALID_SOCKET) {
        Log(L"SOCKS5: Could not connect to any resolved address for proxy server '" + s2ws(actual_host_to_resolve) + L":" + s2ws(portStr) + L"'.");
        m_proxyServerSockAddrValid = false; // Ensure it's marked invalid
        return false;
    }
    return true;
}

bool Socks5Client::Authenticate() {
    if (m_controlSocket == INVALID_SOCKET) {
        Log(L"SOCKS5: Authenticate - No active connection to proxy for authentication.");
        return false;
    }

    char authRequest[4];
    int reqLen = 0;
    authRequest[reqLen++] = SOCKS_VERSION;
    bool useUserPass = !m_username.empty();

    if (useUserPass) {
        Log(L"SOCKS5: Proposing methods: No Auth, Username/Password.");
        authRequest[reqLen++] = 2; 
        authRequest[reqLen++] = SOCKS_AUTH_METHOD_NONE;
        authRequest[reqLen++] = SOCKS_AUTH_METHOD_USERPASS;
    } else {
        Log(L"SOCKS5: Proposing method: No Auth.");
        authRequest[reqLen++] = 1; 
        authRequest[reqLen++] = SOCKS_AUTH_METHOD_NONE;
    }

    if (send(m_controlSocket, authRequest, reqLen, 0) <= 0) {
        Log(L"SOCKS5: send for auth method selection failed. Error: " + std::to_wstring(WSAGetLastError()));
        return false;
    }

    char authResponse[2];
    int len = recv(m_controlSocket, authResponse, sizeof(authResponse), 0);

    if (len <= 0) {
        Log(L"SOCKS5: recv for auth method response failed. Error: " + std::to_wstring(WSAGetLastError()) + (len == 0 ? L" (Connection closed by peer)" : L""));
        return false;
    }

    if (len != 2 || authResponse[0] != SOCKS_VERSION) {
        Log(L"SOCKS5: Invalid auth method response from proxy. Len: " + std::to_wstring(len) + (len > 0 ? L", Ver: " + std::to_wstring(static_cast<unsigned char>(authResponse[0])) : L""));
        return false;
    }

    char selectedMethod = authResponse[1];
    Log(L"SOCKS5: Proxy selected auth method: 0x" + s2ws(ByteToHex(selectedMethod)));

    if (selectedMethod == SOCKS_AUTH_METHOD_USERPASS) {
        if (!useUserPass || m_password.empty()) {
            Log(L"SOCKS5: Proxy requires username/password, but not configured or password missing.");
            return false;
        }
        Log(L"SOCKS5: Performing username/password authentication.");
        
        if (m_username.length() > 255 || m_password.length() > 255) {
            Log(L"SOCKS5: Username or password too long (max 255 bytes).");
            return false;
        }

        std::vector<char> userPassRequestVec;
        userPassRequestVec.push_back(SOCKS_AUTH_VERSION);
        userPassRequestVec.push_back(static_cast<char>(m_username.length()));
        userPassRequestVec.insert(userPassRequestVec.end(), m_username.begin(), m_username.end());
        userPassRequestVec.push_back(static_cast<char>(m_password.length()));
        userPassRequestVec.insert(userPassRequestVec.end(), m_password.begin(), m_password.end());

        if (send(m_controlSocket, userPassRequestVec.data(), static_cast<int>(userPassRequestVec.size()), 0) <= 0) {
            Log(L"SOCKS5: send for username/password auth failed. Error: " + std::to_wstring(WSAGetLastError()));
            return false;
        }

        char userPassResponse[2];
        len = recv(m_controlSocket, userPassResponse, sizeof(userPassResponse), 0);
        if (len <= 0) {
            Log(L"SOCKS5: recv for username/password response failed. Error: " + std::to_wstring(WSAGetLastError()) + (len == 0 ? L" (Connection closed by peer)" : L""));
            return false;
        }

        if (len != 2 || userPassResponse[0] != SOCKS_AUTH_VERSION || userPassResponse[1] != 0x00 /* success */) {
            Log(L"SOCKS5: Username/password authentication failed. Ver: " + (len > 0 ? std::to_wstring(static_cast<unsigned char>(userPassResponse[0])) : L"N/A") + L", Status: " + (len > 1 ? std::to_wstring(static_cast<unsigned char>(userPassResponse[1])) : L"N/A"));
            return false;
        }
        Log(L"SOCKS5: Username/password authentication successful.");
        return true;

    } else if (selectedMethod == SOCKS_AUTH_METHOD_NONE) {
        Log(L"SOCKS5: No authentication required by proxy, and selected.");
        return true;
    } else {
        Log(L"SOCKS5: Proxy selected unsupported authentication method: 0x" + s2ws(ByteToHex(selectedMethod)) + L". Authentication failed.");
        return false;
    }
}

SOCKET Socks5Client::Connect(const std::string& targetHostOrIp, unsigned short targetPort) {
    Log(L"Socks5Client::Connect CALLED for target: " + s2ws(targetHostOrIp) + L":" + std::to_wstring(targetPort));
    CloseControlSocket(); 
    if (!ConnectToProxyServer()) {
        Log(L"SOCKS5 Connect: ConnectToProxyServer failed for target " + s2ws(targetHostOrIp) + L":" + std::to_wstring(targetPort));
        return INVALID_SOCKET;
    }
    Log(L"Socks5Client::Connect: ConnectToProxyServer SUCCEEDED. Proceeding to Authenticate.");
    if (!Authenticate()) {
        Log(L"SOCKS5 Connect: Authenticate failed for target " + s2ws(targetHostOrIp) + L":" + std::to_wstring(targetPort));
        CloseControlSocket();
        return INVALID_SOCKET;
    }
    Log(L"Socks5Client::Connect: Authenticate SUCCEEDED. Proceeding to send SOCKS CONNECT command.");

    Log(L"SOCKS5: Authenticated. Sending CONNECT request for target " + s2ws(targetHostOrIp) + L":" + std::to_wstring(targetPort));

    char buffer[BUFFER_SIZE]; 
    buffer[0] = SOCKS_VERSION;    
    buffer[1] = SOCKS_CMD_CONNECT; 
    buffer[2] = 0x00;             
    int currentPos = 3;

    IN_ADDR ipv4AddrBinary;
    IN6_ADDR ipv6AddrBinary;

    if (inet_pton(AF_INET, targetHostOrIp.c_str(), &ipv4AddrBinary) == 1) {
        Log(L"SOCKS5 Connect: Target '" + s2ws(targetHostOrIp) + L"' is an IPv4 address. Using ATYP_IPV4.");
        buffer[currentPos++] = SOCKS_ADDR_TYPE_IPV4; 
        memcpy(buffer + currentPos, &ipv4AddrBinary.s_addr, sizeof(ipv4AddrBinary.s_addr));
        currentPos += sizeof(ipv4AddrBinary.s_addr);
    } else if (inet_pton(AF_INET6, targetHostOrIp.c_str(), &ipv6AddrBinary) == 1) {
        Log(L"SOCKS5 Connect: Target '" + s2ws(targetHostOrIp) + L"' is an IPv6 address. Using ATYP_IPV6.");
        buffer[currentPos++] = SOCKS_ADDR_TYPE_IPV6; 
        memcpy(buffer + currentPos, &ipv6AddrBinary.s6_addr, sizeof(ipv6AddrBinary.s6_addr));
        currentPos += sizeof(ipv6AddrBinary.s6_addr);
    } else {
        Log(L"SOCKS5 Connect: Target '" + s2ws(targetHostOrIp) + L"' is a Domain Name. Using ATYP_DOMAIN.");
        if (targetHostOrIp.empty() || targetHostOrIp.length() > 255) {
            Log(L"SOCKS5 Connect: Invalid domain name length: " + std::to_wstring(targetHostOrIp.length()));
            CloseControlSocket(); 
            return INVALID_SOCKET;
        }
        buffer[currentPos++] = SOCKS_ADDR_TYPE_DOMAIN; 
        buffer[currentPos++] = static_cast<unsigned char>(targetHostOrIp.length());
        memcpy(buffer + currentPos, targetHostOrIp.c_str(), targetHostOrIp.length());
        currentPos += targetHostOrIp.length();
    }

    *(unsigned short*)(buffer + currentPos) = htons(targetPort); 
    currentPos += sizeof(unsigned short);

    if (send(m_controlSocket, buffer, currentPos, 0) <= 0) {
        Log(L"SOCKS5: send for CONNECT request failed for target " + s2ws(targetHostOrIp) + L". Error: " + std::to_wstring(WSAGetLastError()));
        CloseControlSocket(); 
        return INVALID_SOCKET;
    }

    int len = recv(m_controlSocket, buffer, BUFFER_SIZE, 0); 
    DWORD lastErrorAfterRecv = WSAGetLastError();

    if (len == SOCKET_ERROR) {
        Log(L"SOCKS5: recv for CONNECT response failed (SOCKET_ERROR) for target " + s2ws(targetHostOrIp) + L". Error: " + std::to_wstring(lastErrorAfterRecv));
        CloseControlSocket(); 
        return INVALID_SOCKET;
    } else if (len == 0) {
        Log(L"SOCKS5: recv for CONNECT response returned 0 (connection closed by peer) for target " + s2ws(targetHostOrIp) + L".");
        CloseControlSocket(); 
        return INVALID_SOCKET;
    } else if (len < 4) { 
        Log(L"SOCKS5: recv for CONNECT response too short. Len: " + std::to_wstring(len) + L" for target " + s2ws(targetHostOrIp) + L". Error: " + std::to_wstring(lastErrorAfterRecv));
        CloseControlSocket(); 
        return INVALID_SOCKET;
    }

    if (buffer[0] != SOCKS_VERSION) {
        Log(L"SOCKS5: Invalid SOCKS version in CONNECT reply for target " + s2ws(targetHostOrIp) + L". Expected 0x05, Got: " + s2ws(ByteToHex(buffer[0])));
        CloseControlSocket();
        return INVALID_SOCKET;
    }

    if (buffer[1] != 0x00) { 
        std::string repErrorCodeStr = ByteToHex(buffer[1]);
        std::string repErrorMsg = "Unknown error";
        switch (buffer[1]) {
            case 0x01: repErrorMsg = "General SOCKS server failure"; break;
            case 0x02: repErrorMsg = "Connection not allowed by ruleset"; break;
            case 0x03: repErrorMsg = "Network unreachable"; break;
            case 0x04: repErrorMsg = "Host unreachable"; break;
            case 0x05: repErrorMsg = "Connection refused"; break;
            case 0x06: repErrorMsg = "TTL expired"; break;
            case 0x07: repErrorMsg = "Command not supported"; break;
            case 0x08: repErrorMsg = "Address type not supported"; break;
        }
        Log(L"SOCKS5: CONNECT command failed for target " + s2ws(targetHostOrIp) + L". Proxy replied with error: " + s2ws(repErrorCodeStr) + L" (" + s2ws(repErrorMsg) + L"). Full response Len: " + std::to_wstring(len));
        CloseControlSocket(); 
        return INVALID_SOCKET;
    }

    Log(L"SOCKS5: CONNECT to target " + s2ws(targetHostOrIp) + L":" + std::to_wstring(targetPort) + L" successful via proxy. Bound ADDR/PORT in reply (len=" + std::to_wstring(len) + L"): ATYP=" + s2ws(ByteToHex(buffer[3])));
    
    SOCKET dataSocket = m_controlSocket;
    m_controlSocket = INVALID_SOCKET; 
    Log(L"Socks5Client::Connect RETURNING valid dataSocket: " + std::to_wstring(dataSocket));
    return dataSocket; 
}

SOCKET Socks5Client::UdpAssociate(std::string& relayIp, unsigned short& relayPort) {
    if (!ConnectToProxyServer()) { 
        return INVALID_SOCKET;
    }
    if (!Authenticate()) { CloseControlSocket(); return INVALID_SOCKET; }

    Log(L"SOCKS5: Authenticated. Sending UDP ASSOCIATE request (expecting IPv4 relay).");

    char buffer[BUFFER_SIZE];
    buffer[0] = SOCKS_VERSION;
    buffer[1] = SOCKS_CMD_UDP_ASSOCIATE;
    buffer[2] = 0x00; 
    buffer[3] = SOCKS_ADDR_TYPE_IPV4;
    *(unsigned int*)(buffer + 4) = htonl(INADDR_ANY); 
    *(unsigned short*)(buffer + 4 + 4) = htons(0);    
    int reqLen = 4 + 4 + 2;

    if (send(m_controlSocket, buffer, reqLen, 0) <= 0) { 
        Log(L"SOCKS5: send for UDP ASSOCIATE request failed. Error: " + std::to_wstring(WSAGetLastError()));
        CloseControlSocket();
        return INVALID_SOCKET; 
    }

    DWORD udpAssociateRecvTimeout = 5000; 
    if (setsockopt(m_controlSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&udpAssociateRecvTimeout, sizeof(udpAssociateRecvTimeout)) == SOCKET_ERROR) {
        Log(L"SOCKS5: Failed to set SO_RCVTIMEO for UDP ASSOCIATE response. Error: " + std::to_wstring(WSAGetLastError()));
    }

    Log(L"SOCKS5: Waiting for UDP ASSOCIATE response from proxy...");
    int len = recv(m_controlSocket, buffer, BUFFER_SIZE, 0);
    DWORD lastErrorAfterRecv = WSAGetLastError(); 

    if (len == SOCKET_ERROR) {
        Log(L"SOCKS5: recv for UDP ASSOCIATE response failed (SOCKET_ERROR). Actual len: " + std::to_wstring(len) + L". Error: " + std::to_wstring(lastErrorAfterRecv));
        CloseControlSocket(); 
        return INVALID_SOCKET;
    } else if (len == 0) {
        Log(L"SOCKS5: recv for UDP ASSOCIATE response returned 0 (connection closed by peer).");
        CloseControlSocket(); 
        return INVALID_SOCKET;
    } else if (len < 0) { 
        Log(L"SOCKS5: recv for UDP ASSOCIATE response returned unexpected negative value: " + std::to_wstring(len) + L". Error: " + std::to_wstring(lastErrorAfterRecv));
        CloseControlSocket(); 
        return INVALID_SOCKET;
    }
    
    Log(L"SOCKS5: Received UDP ASSOCIATE response, len: " + std::to_wstring(len));

    if (len < 10 || buffer[0] != SOCKS_VERSION || buffer[1] != 0x00 /*success*/ || buffer[3] != SOCKS_ADDR_TYPE_IPV4) {
        Log(L"SOCKS5: UDP ASSOCIATE command failed, invalid/IPv6 response, or not IPv4 ATYP. Len: " + std::to_wstring(len) + 
            L", Rep: " + (len > 1 ? s2ws(ByteToHex(buffer[1])) : L"N/A") +
            L", ATYP: " + (len > 3 ? s2ws(ByteToHex(buffer[3])) : L"N/A") +
            L". Winsock Error (if any from recv): " + std::to_wstring(lastErrorAfterRecv));
        CloseControlSocket(); return INVALID_SOCKET;
    }

    char ipStrBuffer[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, (const void*)(buffer + 4), ipStrBuffer, INET_ADDRSTRLEN) == nullptr) {
        Log(L"SOCKS5: inet_ntop failed for UDP ASSOCIATE IPv4 relay address. Error: " + std::to_wstring(WSAGetLastError()));
        CloseControlSocket(); return INVALID_SOCKET;
    }
    relayIp = ipStrBuffer; // relayIp is std::string, ipStrBuffer is char[]
    relayPort = ntohs(*(unsigned short*)(buffer + 4 + 4));

    Log(L"SOCKS5: UDP ASSOCIATE successful. Relay IPv4: " + s2ws(relayIp) + L":" + std::to_wstring(relayPort));

    SOCKET udpRelaySocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpRelaySocket == INVALID_SOCKET) {
        Log(L"SOCKS5: Failed to create local UDP socket for relay. Error: " + std::to_wstring(WSAGetLastError()));
        CloseControlSocket(); 
        return INVALID_SOCKET;
    }
    return udpRelaySocket;
}

SOCKET Socks5Client::DetachControlSocket() { 
    Log(L"SOCKS5: DetachControlSocket() called.");
    SOCKET detachedSock = m_controlSocket;
    m_controlSocket = INVALID_SOCKET; 

    if (detachedSock != INVALID_SOCKET) {
        Log(L"SOCKS5: Detached control socket " + std::to_wstring(detachedSock) + L". Caller must manage it.");
    } else {
        Log(L"SOCKS5: DetachControlSocket() called on an invalid or already detached socket.");
    }
    return detachedSock;
}

bool Socks5Client::TestProxyConnection(const std::string& testHost, unsigned short testPort) {
    Log(L"SOCKS5: Attempting test connection to " + s2ws(testHost) + L":" + std::to_wstring(testPort) + L" via proxy.");

    SOCKET originalControlSocket = m_controlSocket;
    sockaddr_storage originalProxySockAddr;
    memcpy(&originalProxySockAddr, &m_proxyServerSockAddr, sizeof(sockaddr_storage));
    bool originalProxySockAddrValid = m_proxyServerSockAddrValid;

    m_controlSocket = INVALID_SOCKET; 
    m_proxyServerSockAddrValid = false; 

    if (!ConnectToProxyServer()) {
        Log(L"SOCKS5 Test: ConnectToProxyServer failed.");
        m_controlSocket = originalControlSocket;
        memcpy(&m_proxyServerSockAddr, &originalProxySockAddr, sizeof(sockaddr_storage));
        m_proxyServerSockAddrValid = originalProxySockAddrValid;
        return false;
    }

    if (!Authenticate()) {
        Log(L"SOCKS5 Test: Authenticate failed.");
        CloseControlSocket(); 
        m_controlSocket = originalControlSocket; 
        m_proxyServerSockAddrValid = originalProxySockAddrValid;
        return false;
    }

    Log(L"SOCKS5 Test: Authenticated. Sending CONNECT request for test target " + s2ws(testHost) + L":" + std::to_wstring(testPort));

    char buffer[BUFFER_SIZE]; 
    buffer[0] = SOCKS_VERSION;
    buffer[1] = SOCKS_CMD_CONNECT;
    buffer[2] = 0x00; 
    int currentPos = 3;

    if (testHost.empty() || testHost.length() > 255) {
        Log(L"SOCKS5 Test Connect: Invalid domain name length for testHost: " + std::to_wstring(testHost.length()));
        CloseControlSocket();
        m_controlSocket = originalControlSocket;
        m_proxyServerSockAddrValid = originalProxySockAddrValid;
        return false;
    }
    buffer[currentPos++] = SOCKS_ADDR_TYPE_DOMAIN; 
    buffer[currentPos++] = static_cast<unsigned char>(testHost.length());
    memcpy(buffer + currentPos, testHost.c_str(), testHost.length());
    currentPos += testHost.length();

    *(unsigned short*)(buffer + currentPos) = htons(testPort);
    currentPos += sizeof(unsigned short);

    if (send(m_controlSocket, buffer, currentPos, 0) <= 0) {
        Log(L"SOCKS5 Test: send for CONNECT request failed. Error: " + std::to_wstring(WSAGetLastError()));
        CloseControlSocket();
        m_controlSocket = originalControlSocket;
        m_proxyServerSockAddrValid = originalProxySockAddrValid;
        return false;
    }

    int len = recv(m_controlSocket, buffer, BUFFER_SIZE, 0); 
    DWORD lastErrorAfterRecvTest = WSAGetLastError();
    
    SOCKET tempTestSocket = m_controlSocket; 
    m_controlSocket = INVALID_SOCKET; 
    CloseSocketGeneric(tempTestSocket);

    m_controlSocket = originalControlSocket;
    memcpy(&m_proxyServerSockAddr, &originalProxySockAddr, sizeof(sockaddr_storage));
    m_proxyServerSockAddrValid = originalProxySockAddrValid;

    if (len == SOCKET_ERROR) {
        Log(L"SOCKS5 Test: recv for CONNECT response failed (SOCKET_ERROR). Error: " + std::to_wstring(lastErrorAfterRecvTest));
        return false;
    } else if (len == 0) {
        Log(L"SOCKS5 Test: recv for CONNECT response returned 0 (connection closed by peer).");
        return false;
    } else if (len < 4) {
         Log(L"SOCKS5 Test: recv for CONNECT response too short. Len: " + std::to_wstring(len) + L". Error: " + std::to_wstring(lastErrorAfterRecvTest));
        return false;
    }

    if (buffer[0] != SOCKS_VERSION || buffer[1] != 0x00 /* Success */) {
        std::string repErrorCodeStrTest_std = (len > 1) ? ByteToHex(buffer[1]) : "N/A";
        Log(L"SOCKS5 Test: CONNECT command failed or invalid response. Len: " + std::to_wstring(len) +
            L", Ver: " + (len > 0 ? s2ws(ByteToHex(buffer[0])) : L"N/A") +
            L", Rep: " + s2ws(repErrorCodeStrTest_std));
        return false;
    }

    Log(L"SOCKS5 Test: Connection to " + s2ws(testHost) + L":" + std::to_wstring(testPort) + L" successful via proxy.");
    return true;
}

bool Socks5Client::IsAddressProxy(const sockaddr* packet_dst_addr, unsigned short packet_dst_port_host_order) const {
    if (!m_proxyServerSockAddrValid || !packet_dst_addr) {
        Log(L"IsAddressProxy: Not valid or packet_dst_addr is null. ProxyValid: " + s2ws(std::string(m_proxyServerSockAddrValid ? "true" : "false")));
        return false;
    }

    char proxyIpStr_char[INET6_ADDRSTRLEN];
    char packetIpStr_char[INET6_ADDRSTRLEN];
    std::string proxyIpStr_std;
    std::string packetIpStr_std;
    unsigned short proxyStoredPortHostOrder = m_proxyPort; 

    if (m_proxyServerSockAddr.ss_family == AF_INET) {
        inet_ntop(AF_INET, &((const sockaddr_in*)&m_proxyServerSockAddr)->sin_addr, proxyIpStr_char, sizeof(proxyIpStr_char));
    } else if (m_proxyServerSockAddr.ss_family == AF_INET6) {
        inet_ntop(AF_INET6, &((const sockaddr_in6*)&m_proxyServerSockAddr)->sin6_addr, proxyIpStr_char, sizeof(proxyIpStr_char));
    } else {
        strcpy_s(proxyIpStr_char, "UnknownFamily");
    }
    proxyIpStr_std = proxyIpStr_char;
    Log(L"IsAddressProxy: Comparing with stored proxy: " + s2ws(proxyIpStr_std) + L":" + std::to_wstring(proxyStoredPortHostOrder) + 
        L" (family: " + std::to_wstring(m_proxyServerSockAddr.ss_family) + L")");

    if (packet_dst_addr->sa_family == AF_INET) {
        inet_ntop(AF_INET, &((const sockaddr_in*)packet_dst_addr)->sin_addr, packetIpStr_char, sizeof(packetIpStr_char));
    } else if (packet_dst_addr->sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &((const sockaddr_in6*)packet_dst_addr)->sin6_addr, packetIpStr_char, sizeof(packetIpStr_char));
    } else {
        strcpy_s(packetIpStr_char, "UnknownFamily");
    }
    packetIpStr_std = packetIpStr_char;
    Log(L"IsAddressProxy: Packet destination: " + s2ws(packetIpStr_std) + L":" + std::to_wstring(packet_dst_port_host_order) + 
        L" (family: " + std::to_wstring(packet_dst_addr->sa_family) + L")");

    if (m_proxyServerSockAddr.ss_family != packet_dst_addr->sa_family) {
        Log(L"IsAddressProxy: Address family mismatch.");
        return false;
    }

    if (proxyStoredPortHostOrder != packet_dst_port_host_order) {
        Log(L"IsAddressProxy: Port mismatch. ProxyPort: " + std::to_wstring(proxyStoredPortHostOrder) + L" PacketPort: " + std::to_wstring(packet_dst_port_host_order));
        return false;
    }

    if (m_proxyServerSockAddr.ss_family == AF_INET) {
        const sockaddr_in* proxy_addr_ipv4 = reinterpret_cast<const sockaddr_in*>(&m_proxyServerSockAddr);
        const sockaddr_in* packet_addr_ipv4 = reinterpret_cast<const sockaddr_in*>(packet_dst_addr);
        if (proxy_addr_ipv4->sin_addr.s_addr != packet_addr_ipv4->sin_addr.s_addr) {
            Log(L"IsAddressProxy: IPv4 address mismatch.");
            return false;
        }
    } else if (m_proxyServerSockAddr.ss_family == AF_INET6) {
        const sockaddr_in6* proxy_addr_ipv6 = reinterpret_cast<const sockaddr_in6*>(&m_proxyServerSockAddr);
        const sockaddr_in6* packet_addr_ipv6 = reinterpret_cast<const sockaddr_in6*>(packet_dst_addr);
        if (memcmp(&proxy_addr_ipv6->sin6_addr, &packet_addr_ipv6->sin6_addr, sizeof(in6_addr)) != 0) {
            Log(L"IsAddressProxy: IPv6 address mismatch.");
            return false;
        }
    } else {
        Log(L"IsAddressProxy: Unknown address family in comparison logic.");
        return false; 
    }

    Log(L"IsAddressProxy: Match! Packet is destined for the proxy.");
    return true;
}