#include <ctime>
#include <fstream>
#include <mutex>
#include <tchar.h>
#include <Windows.h>
#include "main.h"
#include "ui.h"

// Max size of packets to actually capture - anything bigger will be cut off
#define MAX_PACKETDATA_SIZE 8192

// Statistics for UI
unsigned int numPacketsRecvd = 0;
unsigned int numPacketsRecvdSize = 0;
unsigned int numPacketsSent = 0;
unsigned int numPacketsSentSize = 0;

// Threaded variables for UI start/stop actions
std::mutex recordingMutex;
bool isRecording = true;
bool recordingChanged = true;

// Vars to keep track of packet timing
std::time_t timeLogStart = 0;
double qpcFreq = 0.0;
__int64 qpcLogStart = 0;

// Winsock function signatures
typedef int(PASCAL FAR *fptr_recvfrom)(
    _In_ SOCKET s,
    _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
    _In_ int len,
    _In_ int flags,
    _Out_writes_bytes_to_opt_(*fromlen, *fromlen) struct sockaddr FAR * from,
    _Inout_opt_ int FAR * fromlen
);
typedef int(PASCAL FAR *fptr_sendto)(
    _In_ SOCKET s,
    _In_reads_bytes_(len) const char FAR * buf,
    _In_ int len,
    _In_ int flags,
    _In_reads_bytes_opt_(tolen) const struct sockaddr FAR *to,
    _In_ int tolen
);

// Vars for winsock/loading hook addresses
void* addr_recvfrom_ac1 = (void*)0x7935AC; // 0x7935AC for current build 0x7925AC for 2013 build
void* addr_sendto_ac1 = (void*)0x7935A4; // 0x7935A4 for current build 0x7925A4 for 2013 build
void* addr_loadlibcheck_ac1 = (void*)0x5577C3; // 0x5577C3 for current build 0x556B83 for 2013 build

void* addr_recvfrom_ac2 = (void*)0x9D267C;
void* addr_sendto_ac2 = (void*)0x9D2688;
void* addr_loadlibcheck_ac2 = (void*)0x4C9E83;

void* addr_recvfrom = NULL;
void* addr_sendto = NULL;
void* addr_loadlibcheck = NULL;

fptr_recvfrom original_recvfrom = nullptr;
fptr_sendto original_sendto = nullptr;

// Other vars
static std::FILE* logFile = NULL;
bool alreadyAttached = false;

// No compiler padding - it would screw up the file format
#pragma pack(push, 1)
typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct ethhdr {
    uint8_t h_dest[6];       /* destination eth addr */
    uint8_t h_source[6];     /* source ether addr */
    uint16_t h_proto;        /* packet type ID field */
} ethhdr;

typedef struct ip_address {
    uint8_t byte1;
    uint8_t byte2;
    uint8_t byte3;
    uint8_t byte4;
} ip_address;

typedef struct ip_header {
    uint8_t  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    uint8_t  tos;            // Type of service 
    uint16_t tlen;           // Total length 
    uint16_t identification; // Identification
    uint16_t flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t  ttl;            // Time to live
    uint8_t  proto;          // Protocol
    uint16_t crc;            // Header checksum
    ip_address  saddr;       // Source address
    ip_address  daddr;       // Destination address
} ip_header;

typedef struct udp_header {
    uint16_t sport;          // Source port
    uint16_t dport;          // Destination port
    uint16_t len;            // Datagram length
    uint16_t crc;            // Checksum
} udp_header;
#pragma pack(pop)

bool startCounter() {
    LARGE_INTEGER freq;
    if (!QueryPerformanceFrequency(&freq)) {
        return false;
    }

    qpcFreq = double(freq.QuadPart);

    LARGE_INTEGER qpcCount;
    QueryPerformanceCounter(&qpcCount);
    qpcLogStart = qpcCount.QuadPart;

    return true;
}

double getSecElapsed() {
    LARGE_INTEGER qpcCount;
    QueryPerformanceCounter(&qpcCount);
    return double(qpcCount.QuadPart - qpcLogStart) / qpcFreq;
}

void closeLogFile() {
    if (logFile != NULL) {
        std::fflush(logFile);
        std::fclose(logFile);
        logFile = NULL;
    }
}

bool openLogFile() {
    recordingMutex.lock();

    // Don't do anything unless some UI action actually occurred
    if (!recordingChanged) {
        recordingMutex.unlock();
        return false;
    }

    recordingChanged = false;

    if (!isRecording) {
        // Stopped recording, so close the current log file
        closeLogFile();

        recordingMutex.unlock();
        return false;
    } else {
        // Started recording, zero the packet timer
        std::time(&timeLogStart);
        startCounter();

        tm* localTime = std::localtime(&timeLogStart);

        // Write out the description text file
        char fileName[256];
        std::sprintf(fileName, "pkt_%d-%d-%d_%lld_desc.txt", 1900 + localTime->tm_year, 1 + localTime->tm_mon, localTime->tm_mday, timeLogStart);

        std::FILE* fp = std::fopen(fileName, "wb");

        double secSinceStart = getSecElapsed();

        uint32_t ts_sec = timeLogStart + secSinceStart;
        double intpart;
        uint32_t ts_usec = (uint32_t)(std::modf(secSinceStart, &intpart) * 1000000);

        std::fwrite(&ts_sec, sizeof(ts_sec), 1, fp);
        std::fwrite(&ts_usec, sizeof(ts_usec), 1, fp);
        uint16_t recordingMessageSize = strlen(recordingMessage);
        std::fwrite(&recordingMessageSize, sizeof(recordingMessageSize), 1, fp);
        std::fwrite(&recordingMessage, sizeof(char), recordingMessageSize, fp);

        std::fflush(fp);
        std::fclose(fp);

        // Open a new log file
        std::sprintf(fileName, "pkt_%d-%d-%d_%lld_log.pcap", 1900 + localTime->tm_year, 1 + localTime->tm_mon, localTime->tm_mday, timeLogStart);

        logFile = std::fopen(fileName, "ab");

        if (logFile == NULL) {
            MessageBox(NULL, _T("Could not open a new packet log file for writing."), _T("Packet Logging Error!"), MB_OK);
            recordingMutex.unlock();
            return false;
        }

        // Write out pcap header to log file
        pcap_hdr_t pcapHeader;
        pcapHeader.magic_number = 0xA1B2C3D4;
        pcapHeader.version_major = 2;
        pcapHeader.version_minor = 4;
        pcapHeader.thiszone = 0;
        pcapHeader.sigfigs = 0;
        pcapHeader.snaplen = sizeof(ethhdr) + sizeof(ip_header) + sizeof(udp_header) + MAX_PACKETDATA_SIZE;
        pcapHeader.network = 1;

        std::fwrite(&pcapHeader, sizeof(pcapHeader), 1, logFile);

        std::fflush(logFile);
    }

    recordingMutex.unlock();
    return true;
}

int PASCAL FAR detour_recvfrom(
    _In_ SOCKET s,
    _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
    _In_ int len,
    _In_ int flags,
    _Out_writes_bytes_to_opt_(*fromlen, *fromlen) struct sockaddr FAR * from,
    _Inout_opt_ int FAR * fromlen
) {
    // Check to see if we need to reopen log file due to UI start/stop
    openLogFile();

    // Pass data on to original function
    int bytesRecvd = original_recvfrom(s, buf, len, flags, from, fromlen);

    // Only save packet if we're recording
    recordingMutex.lock();
    bool copyIsRecording = isRecording;
    recordingMutex.unlock();
    
    if (copyIsRecording) {
        sockaddr_in* addr = (sockaddr_in*)from;
        int packetLen = min(bytesRecvd, len);
        packetLen = min(packetLen, MAX_PACKETDATA_SIZE);

        if (packetLen > 0) {
            // Update UI stats
            numPacketsRecvd++;
            numPacketsRecvdSize += packetLen;
            redrawUI();

            // Header for pcap record
            double secSinceStart = getSecElapsed();

            pcaprec_hdr_t pcapRecordHeader;
            pcapRecordHeader.ts_sec = timeLogStart + secSinceStart;
            double intpart;
            pcapRecordHeader.ts_usec = (uint32_t)(std::modf(secSinceStart, &intpart) * 1000000);
            pcapRecordHeader.incl_len = packetLen;
            pcapRecordHeader.orig_len = len;

            // Mostly-hardcoded headers to make packet properly parseable
            ethhdr ethHeader;
            ethHeader.h_dest[0] = 0x00;
            ethHeader.h_dest[1] = 0x24;
            ethHeader.h_dest[2] = 0xB2;
            ethHeader.h_dest[3] = 0x01;
            ethHeader.h_dest[4] = 0x02;
            ethHeader.h_dest[5] = 0x03;
            ethHeader.h_source[0] = 0x08;
            ethHeader.h_source[1] = 0x00;
            ethHeader.h_source[2] = 0x27;
            ethHeader.h_source[3] = 0x01;
            ethHeader.h_source[4] = 0x02;
            ethHeader.h_source[5] = 0x03;
            ethHeader.h_proto = 0x0008;
            pcapRecordHeader.incl_len += sizeof(ethHeader);
            pcapRecordHeader.orig_len += sizeof(ethHeader);

            ip_header ipHeader;
            ipHeader.ver_ihl = 0x45;
            ipHeader.tos = 0;
            ipHeader.tlen = 0;
            ipHeader.identification = 0;
            ipHeader.flags_fo = 0;
            ipHeader.ttl = 0;
            ipHeader.proto = 17;
            ipHeader.crc = 0;
            ipHeader.saddr.byte1 = addr->sin_addr.S_un.S_un_b.s_b1;
            ipHeader.saddr.byte2 = addr->sin_addr.S_un.S_un_b.s_b2;
            ipHeader.saddr.byte3 = addr->sin_addr.S_un.S_un_b.s_b3;
            ipHeader.saddr.byte4 = addr->sin_addr.S_un.S_un_b.s_b4;
            ipHeader.daddr.byte1 = 127;
            ipHeader.daddr.byte2 = 0;
            ipHeader.daddr.byte3 = 0;
            ipHeader.daddr.byte4 = 1;
            pcapRecordHeader.incl_len += sizeof(ipHeader);
            pcapRecordHeader.orig_len += sizeof(ipHeader);

            udp_header udpHeader;
            udpHeader.sport = addr->sin_port;
            udpHeader.dport = _byteswap_ushort(12345);
            udpHeader.len = _byteswap_ushort(sizeof(udpHeader) + packetLen);
            udpHeader.crc = 0;
            pcapRecordHeader.incl_len += sizeof(udpHeader);
            pcapRecordHeader.orig_len += sizeof(udpHeader);

            // Write headers and data to log
            std::fwrite(&pcapRecordHeader, sizeof(pcapRecordHeader), 1, logFile);
            std::fwrite(&ethHeader, sizeof(ethHeader), 1, logFile);
            std::fwrite(&ipHeader, sizeof(ipHeader), 1, logFile);
            std::fwrite(&udpHeader, sizeof(udpHeader), 1, logFile);
            std::fwrite(buf, sizeof(char), packetLen, logFile);

            std::fflush(logFile);
        }
    }

    return bytesRecvd;
}

int PASCAL FAR detour_sendto(
    _In_ SOCKET s,
    _In_reads_bytes_(len) const char FAR * buf,
    _In_ int len,
    _In_ int flags,
    _In_reads_bytes_opt_(tolen) const struct sockaddr FAR *to,
    _In_ int tolen
) {
    // Check to see if we need to reopen log file due to UI start/stop
    openLogFile();

    // Only save packet if we're recording
    recordingMutex.lock();
    bool copyIsRecording = isRecording;
    recordingMutex.unlock();

    if (copyIsRecording) {
        sockaddr_in* addr = (sockaddr_in*)to;
        int packetLen = min(len, MAX_PACKETDATA_SIZE);

        if (packetLen > 0) {
            // Update UI stats
            numPacketsSent++;
            numPacketsSentSize += packetLen;
            redrawUI();

            // Header for pcap record
            double secSinceStart = getSecElapsed();

            pcaprec_hdr_t pcapRecordHeader;
            pcapRecordHeader.ts_sec = timeLogStart + secSinceStart;
            double intpart;
            pcapRecordHeader.ts_usec = (uint32_t)(std::modf(secSinceStart, &intpart) * 1000000);
            pcapRecordHeader.incl_len = packetLen;
            pcapRecordHeader.orig_len = len;

            // Mostly-hardcoded headers to make packet properly parseable
            ethhdr ethHeader;
            ethHeader.h_dest[0] = 0x00;
            ethHeader.h_dest[1] = 0x24;
            ethHeader.h_dest[2] = 0xB2;
            ethHeader.h_dest[3] = 0x01;
            ethHeader.h_dest[4] = 0x02;
            ethHeader.h_dest[5] = 0x03;
            ethHeader.h_source[0] = 0x08;
            ethHeader.h_source[1] = 0x00;
            ethHeader.h_source[2] = 0x27;
            ethHeader.h_source[3] = 0x01;
            ethHeader.h_source[4] = 0x02;
            ethHeader.h_source[5] = 0x03;
            ethHeader.h_proto = 0x0008;
            pcapRecordHeader.incl_len += sizeof(ethHeader);
            pcapRecordHeader.orig_len += sizeof(ethHeader);

            ip_header ipHeader;
            ipHeader.ver_ihl = 0x45;
            ipHeader.tos = 0;
            ipHeader.tlen = 0;
            ipHeader.identification = 0;
            ipHeader.flags_fo = 0;
            ipHeader.ttl = 0;
            ipHeader.proto = 17;
            ipHeader.crc = 0;
            ipHeader.saddr.byte1 = 127;
            ipHeader.saddr.byte2 = 0;
            ipHeader.saddr.byte3 = 0;
            ipHeader.saddr.byte4 = 1;
            ipHeader.daddr.byte1 = addr->sin_addr.S_un.S_un_b.s_b1;
            ipHeader.daddr.byte2 = addr->sin_addr.S_un.S_un_b.s_b2;
            ipHeader.daddr.byte3 = addr->sin_addr.S_un.S_un_b.s_b3;
            ipHeader.daddr.byte4 = addr->sin_addr.S_un.S_un_b.s_b4;
            pcapRecordHeader.incl_len += sizeof(ipHeader);
            pcapRecordHeader.orig_len += sizeof(ipHeader);

            udp_header udpHeader;
            udpHeader.sport = _byteswap_ushort(12345);
            udpHeader.dport = addr->sin_port;
            udpHeader.len = _byteswap_ushort(sizeof(udpHeader) + packetLen);
            udpHeader.crc = 0;
            pcapRecordHeader.incl_len += sizeof(udpHeader);
            pcapRecordHeader.orig_len += sizeof(udpHeader);

            // Write headers and data to log
            std::fwrite(&pcapRecordHeader, sizeof(pcapRecordHeader), 1, logFile);
            std::fwrite(&ethHeader, sizeof(ethHeader), 1, logFile);
            std::fwrite(&ipHeader, sizeof(ipHeader), 1, logFile);
            std::fwrite(&udpHeader, sizeof(udpHeader), 1, logFile);
            std::fwrite(buf, sizeof(char), packetLen, logFile);

            std::fflush(logFile);
        }
    }

    // Pass data on to original function
    return original_sendto(s, buf, len, flags, to, tolen);
}

DWORD WINAPI unpatchThread(LPVOID lpParam) {
    // Delay for a tiny bit to make sure we get beyond the patch
    Sleep(5);

    DWORD oldProtect;

    // Unpatch to clean state
    VirtualProtect(addr_loadlibcheck, sizeof(uint16_t), PAGE_READWRITE, &oldProtect);
    *(uint16_t*)addr_loadlibcheck = 0xF08B;
    VirtualProtect(addr_loadlibcheck, sizeof(uint16_t), oldProtect, &oldProtect);

    return 0;
}

BOOLEAN WINAPI DllMain(IN HINSTANCE hDllHandle, IN DWORD nReason, IN LPVOID Reserved) {
    switch (nReason) {
    case DLL_PROCESS_ATTACH: {
        // Don't call main when attaching to other threads
        DisableThreadLibraryCalls(hDllHandle);

        // Don't ever attach more than once
        if (alreadyAttached) {
            return FALSE;
        }

        alreadyAttached = true;

        // Shakey detection for AC1 or AC2. Just don't rename your client executable...
        char exeName[256];
        DWORD exeNameLen = GetModuleFileName(NULL, exeName, sizeof(exeName) - 1);

        for (DWORD i = 0; i < exeNameLen; ++i) {
            exeName[i] = tolower(exeName[i]);
        }

        bool matchedGame = false;

        if (strstr(exeName, "acclient.exe") != nullptr) {
            addr_recvfrom = addr_recvfrom_ac1;
            addr_sendto = addr_sendto_ac1;
            addr_loadlibcheck = addr_loadlibcheck_ac1;

            original_recvfrom = *(fptr_recvfrom*)addr_recvfrom_ac1;
            original_sendto = *(fptr_sendto*)addr_sendto_ac1;

            matchedGame = true;
        } else if (strstr(exeName, "ac2client.exe") != nullptr) {
            addr_recvfrom = addr_recvfrom_ac2;
            addr_sendto = addr_sendto_ac2;
            addr_loadlibcheck = addr_loadlibcheck_ac2;

            original_recvfrom = *(fptr_recvfrom*)addr_recvfrom_ac2;
            original_sendto = *(fptr_sendto*)addr_sendto_ac2;

            matchedGame = true;
        }

        if (!matchedGame) {
            MessageBox(NULL, _T("Could not match game executable name to 'acclient.exe' or 'ac2client.exe'. Logger will not load in this session."), _T("Packet Logging Error!"), MB_OK);
            return FALSE;
        }

        // Open initial packet log
        if (!openLogFile()) {
            MessageBox(NULL, _T("Could not open a new packet log file for writing. Logger will not load in this session."), _T("Packet Logging Error!"), MB_OK);
            return FALSE;
        }

        DWORD oldProtect;

        // Patch recvfrom
        VirtualProtect((LPVOID)addr_recvfrom, sizeof(fptr_recvfrom), PAGE_READWRITE, &oldProtect);
        *(fptr_recvfrom*)addr_recvfrom = (fptr_recvfrom)detour_recvfrom;
        VirtualProtect((LPVOID)addr_recvfrom, sizeof(fptr_recvfrom), oldProtect, &oldProtect);

        // Patch sendto
        VirtualProtect(addr_sendto, sizeof(fptr_sendto), PAGE_READWRITE, &oldProtect);
        *(fptr_sendto*)addr_sendto = (fptr_sendto)detour_sendto;
        VirtualProtect(addr_sendto, sizeof(fptr_sendto), oldProtect, &oldProtect);

        // Create UI thread
        CreateThread(NULL, 0, uiThread, NULL, 0, NULL);

        // Temporary patch to make sure AC doesn't unload this dll
        VirtualProtect(addr_loadlibcheck, sizeof(uint16_t), PAGE_READWRITE, &oldProtect);
        *(uint16_t*)addr_loadlibcheck = 0xF633;
        VirtualProtect(addr_loadlibcheck, sizeof(uint16_t), oldProtect, &oldProtect);

        // Create delayed unpatch thread to let us execute the patch above then revert to clean state
        CreateThread(NULL, 0, unpatchThread, NULL, 0, NULL);

        break;
    }
    case DLL_PROCESS_DETACH: {
        closeLogFile();
        break;
    }
    }

    return TRUE;
}
