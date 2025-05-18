#include "ip_utils.h"
#include "packet_processor.h" // For full definition of ConnectionTuple
#include <sstream> // Required for std::stringstream
#include <iomanip> // Required for std::setw, std::setfill, std::hex
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <cstring> // For memset
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

std::string Ipv4ToString(UINT32 ipv4Addr) {
    char buffer[INET_ADDRSTRLEN];
    // ipv4Addr is expected in network byte order. inet_ntop expects network byte order.
    if (inet_ntop(AF_INET, &ipv4Addr, buffer, sizeof(buffer)) != NULL) {
        return std::string(buffer);
    }
    return "<invalid_ipv4>";
}

std::string Ipv6ToString(const IN6_ADDR& ipv6Addr) {
    char buffer[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &ipv6Addr, buffer, sizeof(buffer)) != NULL) {
        return std::string(buffer);
    }
    return "<invalid_ipv6>";
}

std::string IpAddrToString(bool isIPv6, const void* pAddr) {
    if (pAddr == nullptr) {
        return "<null_addr_ptr>";
    }
    if (isIPv6) {
        return Ipv6ToString(*(static_cast<const IN6_ADDR*>(pAddr)));
    } else {
        // pAddr points to a UINT32 in network byte order
        return Ipv4ToString(*(static_cast<const UINT32*>(pAddr)));
    }
}


bool IsSystemIPv6Enabled() {
    ULONG family = AF_UNSPEC; // Check for both IPv4 and IPv6 initially, but we care about IPv6 presence
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME;
    ULONG outBufLen = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = nullptr;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = nullptr;


    // Using a 15KB buffer as recommended by MSDN examples.
    outBufLen = 15000; 
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (pAddresses == nullptr) {
        // Log(L"IsSystemIPv6Enabled: Failed to allocate memory for GetAdaptersAddresses (initial alloc)");
        return false;
    }

    DWORD dwRetVal = GetAdaptersAddresses(family, flags, nullptr, pAddresses, &outBufLen);

    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        // Log(L"IsSystemIPv6Enabled: Buffer too small, reallocating.");
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (pAddresses == nullptr) {
            // Log(L"IsSystemIPv6Enabled: Failed to allocate memory for GetAdaptersAddresses (realloc)");
            return false;
        }
        dwRetVal = GetAdaptersAddresses(family, flags, nullptr, pAddresses, &outBufLen);
    }

    if (dwRetVal != NO_ERROR) {
        // Log(L"IsSystemIPv6Enabled: GetAdaptersAddresses failed with error: " + std::to_wstring(dwRetVal));
        if (pAddresses) {
            free(pAddresses);
        }
        return false;
    }

    bool ipv6Found = false;
    pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
        // Consider only operational adapters
        if (pCurrAddresses->OperStatus == IfOperStatusUp) {
            pUnicast = pCurrAddresses->FirstUnicastAddress;
            while (pUnicast) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                    PSOCKADDR_IN6 sockaddr_ipv6 = (PSOCKADDR_IN6)pUnicast->Address.lpSockaddr;
                    // Check if it's not a link-local (fe80::/10) or loopback (::1)
                    if (!IN6_IS_ADDR_LINKLOCAL(&sockaddr_ipv6->sin6_addr) &&
                        !IN6_IS_ADDR_LOOPBACK(&sockaddr_ipv6->sin6_addr)) {
                        if (pUnicast->DadState == IpDadStatePreferred && 
                            pUnicast->Address.lpSockaddr->sa_family == AF_INET6) { // Double check family
                           ipv6Found = true;
                           break; 
                        }
                    }
                }
                pUnicast = pUnicast->Next;
            }
        }
        if (ipv6Found) {
            break;
        }
        pCurrAddresses = pCurrAddresses->Next;
    }

    if (pAddresses) {
        free(pAddresses);
    }
    
    return ipv6Found;
} 

std::string ResolveHost(const std::string& host, int port, bool& isIPv6, sockaddr_storage* pAddrStore) {
    if (!pAddrStore) {
        return "pAddrStore cannot be null.";
    }

    struct addrinfo hints;
    struct addrinfo *result = nullptr;
    int s;
    std::string service = std::to_string(port);

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;     // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // Assuming TCP. For UDP, this might need to be SOCK_DGRAM or 0.
    if (host.empty()) {
        hints.ai_flags = AI_PASSIVE; // Suitable for bind operations (e.g., host is nullptr or empty string)
    } else {
        hints.ai_flags = 0;          // Suitable for connect operations
    }

    s = getaddrinfo(host.empty() ? nullptr : host.c_str(), service.c_str(), &hints, &result);
    if (s != 0) {
        std::string errorMsg = "getaddrinfo failed: ";
        errorMsg += gai_strerrorA(s); // gai_strerrorA for char* version on Windows
        return errorMsg;
    }

    bool found = false;
    // Iterate through the list of addresses and take the first suitable one
    for (struct addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) {
            if (rp->ai_addrlen <= sizeof(sockaddr_storage)) {
                 memcpy(pAddrStore, rp->ai_addr, rp->ai_addrlen);
                 isIPv6 = (rp->ai_family == AF_INET6);
                 found = true;
                 break; // Found a suitable address
            }
        }
    }

    if (result) { // Always free the addrinfo list if getaddrinfo succeeded
        freeaddrinfo(result);
    }

    if (!found) {
        return "Could not resolve host to a usable IPv4 or IPv6 address.";
    }

    return ""; // Success
}

std::string SockAddrToString(const sockaddr_storage* pAddr, bool* outIsIPv6) {
    // Initialize outIsIPv6 to a defined state if the pointer is valid.
    if (outIsIPv6) {
        *outIsIPv6 = false; // Default to IPv4 or unknown. Will be set true for IPv6.
    }

    if (!pAddr) {
        return "<null_sockaddr_ptr>";
    }

    std::string ipStrPart;
    unsigned short port_host_order; // Use unsigned short for port
    std::string resultText; 

    if (pAddr->ss_family == AF_INET) {
        const sockaddr_in* sa_in = reinterpret_cast<const sockaddr_in*>(pAddr);
        ipStrPart = Ipv4ToString(sa_in->sin_addr.s_addr);
        port_host_order = ntohs(sa_in->sin_port); // ntohs converts network to host short
        
        resultText = ipStrPart + ":" + std::to_string(port_host_order);

    } else if (pAddr->ss_family == AF_INET6) {
        if (outIsIPv6) {
            *outIsIPv6 = true;
        }
        const sockaddr_in6* sa_in6 = reinterpret_cast<const sockaddr_in6*>(pAddr);
        // Ipv6ToString expects const IN6_ADDR&.
        ipStrPart = Ipv6ToString(sa_in6->sin6_addr);
        port_host_order = ntohs(sa_in6->sin6_port);

        resultText = "[" + ipStrPart + "]:" + std::to_string(port_host_order);

    } else {
        // For unknown families, outIsIPv6 remains as its initial value (false or caller-set).
        return "<unknown_address_family:" + std::to_string(pAddr->ss_family) + ">";
    }

    return resultText;
}

// Function to convert a single byte to its 2-character hex string representation
std::string ByteToHex(unsigned char byte) {
    std::stringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    return ss.str();
}

// Function to check if an IPv4 address (network byte order) is a loopback address.
bool IsLoopbackAddress(UINT32 ipv4Addr) {
    return (ipv4Addr & 0xFF) == 127;
} 