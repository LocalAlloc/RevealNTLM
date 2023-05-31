#include <windows.h>
#include <stdio.h>
#include "resource.h"
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

bool ExtractResource(int iId, LPCWSTR pDest) {
    HRSRC aResourceH = FindResource(NULL, MAKEINTRESOURCE(iId), L"PS1");
    if (!aResourceH) {
        MessageBoxA(NULL, "Unable to find resource.", "", MB_OK | MB_ICONHAND);
        return false;
    }

    HGLOBAL aResourceHGlobal = LoadResource(NULL, aResourceH);
    if (!aResourceHGlobal) {
        MessageBoxA(NULL, "Unable to load resource.", "", MB_OK | MB_ICONHAND);
        return false;
    }

    unsigned char* aFilePtr = (unsigned char*)LockResource(aResourceHGlobal);
    if (!aFilePtr) {
        MessageBoxA(NULL, "Unable to lock resource.", "", MB_OK | MB_ICONHAND);
        return false;
    }

    unsigned long aFileSize = SizeofResource(NULL, aResourceH);

    HANDLE file_handle = CreateFile(pDest, FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (INVALID_HANDLE_VALUE == file_handle) {
        int err = GetLastError();
        if ((ERROR_ALREADY_EXISTS == err) || (32 == err)) {
            return true;
        }
        return false;
    }

    unsigned long numWritten;
    WriteFile(file_handle, aFilePtr, aFileSize, &numWritten, NULL);
    CloseHandle(file_handle);

    return true;
}
BOOL IsProcessElevated(VOID) {
    BOOL IsElevated = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (hToken) {
            CloseHandle(hToken);
            hToken = NULL;
            return FALSE;
        }
    }


    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        if (hToken) {
            CloseHandle(hToken);
            hToken = NULL;
            return FALSE;
        }
    }

    return elevation.TokenIsElevated;
}
int main()
{
    if (!IsProcessElevated()) {
        MessageBoxA(NULL, "Please Run This Program As An Administrator", NULL, MB_OK | MB_ICONSTOP);
        return 0;
    }
    if (!ExtractResource(IDR_PS11, L"C:\\Windows\\System32\\all.ps1")) {
        MessageBoxA(NULL, "Unable To Extract Resource, Exiting...!", NULL, MB_OK | MB_ICONSTOP);
        return -1;
    }
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD exitCode;

    // Initialize the STARTUPINFO structure
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    // Create pipe for redirecting output
    HANDLE hPipeRead, hPipeWrite;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    CreatePipe(&hPipeRead, &hPipeWrite, &sa, 0);
    SetHandleInformation(hPipeRead, HANDLE_FLAG_INHERIT, 0);
    si.hStdOutput = hPipeWrite;

    // Create the PowerShell process
    if (!CreateProcessA(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",  // Application name
        (LPSTR)"                  -ExecutionPolicy Bypass -File C:\\Windows\\System32\\all.ps1",  // Command line
        NULL,                           // Process security attributes
        NULL,                           // Thread security attributes
        TRUE,                           // Inherit handles
        0,                              // Creation flags
        NULL,                           // Environment variables (NULL to use the current environment)
        NULL,                           // Current directory (NULL to use the current directory)
        &si,                            // STARTUPINFO structure
        &pi                             // PROCESS_INFORMATION structure
    ))
    {
        printf("Failed to create process (%d)\n", GetLastError());
        MessageBoxA(NULL, "Failed to Create Process\n", "", MB_OK | MB_ICONSTOP);
        return 1;
    }

    // Close the write end of the pipe as it's not needed in this process
    CloseHandle(hPipeWrite);

    // Wait for the PowerShell process to exit
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Get the exit code of the PowerShell process
    GetExitCodeProcess(pi.hProcess, &exitCode);

    // Read the output from the pipe and print it in the terminal
    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hPipeRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead != 0)
    {
        buffer[bytesRead] = '\0';
        printf("%s", buffer);
    }

    // Close pipe and process handles
    CloseHandle(hPipeRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    system("del C:\\Windows\\System32\\all.ps1 && pause");

    return exitCode;
}
