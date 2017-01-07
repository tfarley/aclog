#include <ctime>
#include <fstream>
#include <mutex>
#include <tchar.h>
#include <Windows.h>
#include "main.h"
#include "ui.h"

static TCHAR windowClass[] = _T("aclogWin");
static TCHAR windowTitle[] = _T("AC Packet Logger");
static TCHAR stopStr[256] = TEXT("Stop");
static TCHAR startStr[256] = TEXT("Start");

static COLORREF textboxDisabledColor = RGB(200, 200, 200);

HWND hWndUI = NULL;
HWND hWndDescTxt = NULL;
HWND hWndStartBtn = NULL;

char recordingMessage[8192] = "Game start!";

#define IDC_DESC_TXT (100)
#define IDC_START_BTN (101)

LRESULT CALLBACK uiWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    PAINTSTRUCT ps;
    HDC hdc;
    TCHAR statusStr[256] = _T("Packets: ---");
    LRESULT lRet = 0;

    switch (message) {
    case WM_PAINT: {
        hdc = BeginPaint(hWnd, &ps);

        // Packet stats text
        sprintf(statusStr, "Packets: %d received (%d bytes), %d sent (%d bytes)", numPacketsRecvd, numPacketsRecvdSize, numPacketsSent, numPacketsSentSize);
        TextOut(hdc, 5, 5, statusStr, _tcslen(statusStr));

        EndPaint(hWnd, &ps);
        break;
    }
    case WM_COMMAND: {
        // Handler for start/stop button presses
        if (LOWORD(wParam) == IDC_START_BTN) {
            recordingMutex.lock();

            if (!recordingChanged) {
                isRecording = !isRecording;

                EnableWindow(hWndDescTxt, !isRecording);

                GetWindowText(hWndDescTxt, recordingMessage, 8192 - 1);

                SetDlgItemText(hWndUI, IDC_START_BTN, (isRecording ? stopStr : startStr));

                recordingChanged = true;
            }

            recordingMutex.unlock();
        }
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HDC msgHDC = (HDC)wParam;
        HWND msghWnd = (HWND)lParam;

        // Handler for greying out description textbox when disabled
        if (GetDlgCtrlID(msghWnd) == IDC_DESC_TXT) {
            recordingMutex.lock();
            if (isRecording) {
                SetBkColor(msgHDC, textboxDisabledColor);
                SetDCBrushColor(msgHDC, textboxDisabledColor);
                lRet = (LRESULT)GetStockObject(DC_BRUSH);
            }
            recordingMutex.unlock();
        } else {
            lRet = DefWindowProc(hWnd, message, wParam, lParam);
        }
        break;
    }
    case WM_DESTROY: {
        PostQuitMessage(0);
        break;
    }
    default: {
        lRet = DefWindowProc(hWnd, message, wParam, lParam);
        break;
    }
    }

    return lRet;
}

DWORD WINAPI uiThread(LPVOID lpParam) {
    char failMsg[256];

    // UI window class
    WNDCLASSEX wcex;
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = uiWndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = NULL;
    wcex.hIcon = LoadIcon(NULL, MAKEINTRESOURCE(IDI_APPLICATION));
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = windowClass;
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_APPLICATION));

    if (!RegisterClassEx(&wcex)) {
        sprintf(failMsg, "Call to RegisterClassEx failed! UI not created! [%d]", GetLastError());
        MessageBox(NULL, failMsg, windowTitle, NULL);
        return 1;
    }

    // Main UI window
    hWndUI = CreateWindow(windowClass, windowTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 600, 400, NULL, NULL, NULL, NULL);

    if (!hWndUI) {
        sprintf(failMsg, "Call to CreateWindow failed! UI not created! [%d]", GetLastError());
        MessageBox(NULL, failMsg, windowTitle, NULL);
        return 1;
    }

    // Description text, initially disabled
    hWndDescTxt = CreateWindow(TEXT("Edit"), TEXT("Replace this text with a detailed description of what packets you're about to log (+ game context), and it will be saved as a .txt alongside the log."), WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL, 5, 25, 600 - 25, 300, hWndUI, (HMENU)IDC_DESC_TXT, NULL, NULL);
    EnableWindow(hWndDescTxt, false);

    // Start/stop button
    hWndStartBtn = CreateWindow(TEXT("BUTTON"), stopStr, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 5, 325 + 5, 60, 25, hWndUI, (HMENU)IDC_START_BTN, NULL, NULL);

    // Show UI window
    ShowWindow(hWndUI, SW_SHOW);
    UpdateWindow(hWndUI);

    // Main UI message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

// Threaded function to redraw the UI when stats change
void redrawUI() {
    if (hWndUI) {
        InvalidateRect(hWndUI, NULL, TRUE);
    }
}
