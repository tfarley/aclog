#pragma once

#include <Windows.h>

DWORD WINAPI uiThread(LPVOID lpParam);
void redrawUI();

extern char recordingMessage[];
