#pragma once

#include "framework.h"
#include <string>
#include <vector>
#include <ws2tcpip.h> // For sockadd_storage, etc.
#include <iphlpapi.h> // For GetAdaptersAddresses and related structures

// Forward declare ConnectionTuple to avoid circular dependencies with packet_processor.h
struct ConnectionTuple;

// Helper function to convert IPv4 address from UINT32 (network byte order) to string
std::string Ipv4ToString(UINT32 ipv4Addr); // Not used in current code directly, but useful

// Helper to convert IPv6 address from IN6_ADDR to string
std::string Ipv6ToString(const IN6_ADDR& ipv6Addr); // Not used in current code directly, but useful

// New utility function
std::string IpAddrToString(bool isIPv6, const void* pAddr);

// Placeholder for checksum calculation if not using WinDivertHelperCalcChecksums directly
// void CalculateIpChecksum(PWINDIVERT_IPHDR ip_header);
// void CalculateTcpChecksum(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header, PVOID payload, UINT payload_len);
// void CalculateUdpChecksum(PWINDIVERT_IPHDR ip_header, PWINDIVERT_UDPHDR udp_header, PVOID payload, UINT payload_len);

// Function to resolve a hostname to an IP address string (IPv4 or IPv6)
// Returns empty string on failure
std::string ResolveHost(const std::string& host, int port, bool& isIPv6, sockaddr_storage* pAddrStore = nullptr);

// Function to convert sockaddr_storage to a human-readable IP address string
std::string SockAddrToString(const sockaddr_storage* pAddr, bool* isIPv6 = nullptr);

// Function to check if the system has IPv6 enabled and configured on any active adapter
bool IsSystemIPv6Enabled();

// Function to convert a single byte to its 2-character hex string representation
std::string ByteToHex(unsigned char byte);

// Function to check if an IPv4 address (network byte order) is a loopback address.
bool IsLoopbackAddress(UINT32 ipv4Addr);

// Converts a ConnectionTuple to a string representation for logging
std::wstring ConvertTupleToString(const ConnectionTuple& tuple);