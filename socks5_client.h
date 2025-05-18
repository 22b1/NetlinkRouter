#ifndef SOCKS5_CLIENT_H
#define SOCKS5_CLIENT_H

#include <string>
#include <vector>
#include <utility>
#include <winsock2.h>
#include <ws2tcpip.h>
// Remove OpenSSL headers
// #include <openssl/ssl.h>
// #include <openssl/err.h>
#include "logger.h" // Assuming logger.h provides Log()
#include <windows.h>

// Forward declaration
// struct SSL_CTX; // No longer needed with direct include
// struct SSL;    // No longer needed with direct include

// Define SOCKS constants if not already universally available
#ifndef SOCKS_VERSION
#define SOCKS_VERSION 0x05
#endif
#define SOCKS_AUTH_VERSION 0x01 // For Username/Password auth sub-negotiation
#define SOCKS_AUTH_METHOD_NONE 0x00
#define SOCKS_AUTH_METHOD_GSSAPI 0x01
#define SOCKS_AUTH_METHOD_USERPASS 0x02
#define SOCKS_CMD_CONNECT 0x01
#define SOCKS_CMD_BIND 0x02
#define SOCKS_CMD_UDP_ASSOCIATE 0x03
#define SOCKS_ADDR_TYPE_IPV4 0x01
#define SOCKS_ADDR_TYPE_DOMAIN 0x03
#define BUFFER_SIZE 4096


class Socks5Client {
public:
    Socks5Client(const std::string& proxyIp, unsigned short proxyPort,
                 const std::string& username = "", const std::string& password = "");
    ~Socks5Client();

    // Establishes a TCP connection to the target via the SOCKS5 proxy
    // Target is assumed to be IPv4
    SOCKET Connect(const std::string& targetHostOrIp, unsigned short targetPort);

    // Establishes a UDP association with the SOCKS5 proxy
    // Relay IP/Port will be IPv4
    SOCKET UdpAssociate(std::string& relayIp, unsigned short& relayPort);

    // Closes the main control socket
    void CloseControlSocket();

    // Getter for the current SSL session associated with m_controlSocket
    // SSL* GetCurrentSslSession() const; // Removed

    // Static methods for global OpenSSL initialization and cleanup
    // static bool InitOpenSSLGlobally(); // Removed
    // static void CleanupOpenSSLGlobally(); // Removed

    // Detaches the control socket.
    // The caller becomes responsible for managing it.
    SOCKET DetachControlSocket();

    // Tests the SOCKS5 proxy connection by attempting to connect to a test host.
    bool TestProxyConnection(const std::string& testHost, unsigned short testPort);

    // New method to check if a given address matches the connected proxy
    bool IsAddressProxy(const sockaddr* packet_dst_addr, unsigned short packet_dst_port) const;

private:
    std::string m_proxyIp; // This should be the DOMAIN NAME for SNI
    unsigned short m_proxyPort;
    std::string m_username;
    std::string m_password;
    
    SOCKET m_controlSocket; // Main socket for SOCKS operations (Connect command, UDP Associate control)
                           // This socket will be a plain TCP socket.

    sockaddr_storage m_proxyServerSockAddr; // Stores the resolved address of the proxy we connected to
    bool m_proxyServerSockAddrValid;      // True if m_proxyServerSockAddr is valid

    // OpenSSL related members
    // SSL_CTX* m_tls_ctx; // Removed
    // SSL* m_tls_ssl; // Removed

    // Creates a TCP socket and connects to the proxy.
    // Assigns to m_controlSocket on success.
    // Proxy address is assumed to be resolvable to IPv4.
    bool ConnectToProxyServer();

    // Authenticates on the given socket
    bool Authenticate(); // Operates on m_controlSocket

    // Helper to close a generic socket
    void CloseSocketGeneric(SOCKET& sock); 
};

#endif // SOCKS5_CLIENT_H 