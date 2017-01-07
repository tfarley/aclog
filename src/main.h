#pragma once

#include <mutex>

// Statistics for UI
extern unsigned int numPacketsRecvd;
extern unsigned int numPacketsRecvdSize;
extern unsigned int numPacketsSent;
extern unsigned int numPacketsSentSize;

// Threaded variables for UI start/stop actions
extern std::mutex recordingMutex;
extern bool isRecording;
extern bool recordingChanged;
