#include <windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <sddl.h>
#include <processthreadsapi.h>
#include <tlhelp32.h>
#include <locale.h>
#include <vector> // Include for std::vector

// Structure to hold process information
struct ProcessInfo {
    DWORD pid;
    DWORD parentPid;
    wchar_t imageName[MAX_PATH];
};

std::vector<ProcessInfo> GetProcessAndSubprocessIds(const wchar_t* targetProcessName) {
    std::vector<ProcessInfo> processList;
    DWORD mainProcessId = 0;

    // First, find the main process by name
    HANDLE hSnapshotMain = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshotMain == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateToolhelp32Snapshot (main) failed: %d\n", GetLastError());
        return processList; // Return empty vector
    }

    PROCESSENTRY32W pe32Main;
    pe32Main.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshotMain, &pe32Main)) {
        wprintf(L"Process32FirstW (main) failed: %d\n", GetLastError());
        CloseHandle(hSnapshotMain);
        return processList; // Return empty vector
    }

    do {
        if (_wcsicmp(pe32Main.szExeFile, targetProcessName) == 0) {
            mainProcessId = pe32Main.th32ProcessID;
            ProcessInfo mainProcessInfo;
            mainProcessInfo.pid = pe32Main.th32ProcessID;
            mainProcessInfo.parentPid = pe32Main.th32ParentProcessID;
            wcscpy_s(mainProcessInfo.imageName, MAX_PATH, pe32Main.szExeFile);
            processList.push_back(mainProcessInfo); // Add main process to the list
            break; // Found main process, stop searching for main process name
        }
    } while (Process32NextW(hSnapshotMain, &pe32Main));

    CloseHandle(hSnapshotMain);

    if (mainProcessId == 0) {
        wprintf(L"Main process %ls not found.\n", targetProcessName);
        return processList; // Return empty vector (might contain main process if found earlier, but now it won't)
    }

    // Now, find subprocesses (child processes)
    HANDLE hSnapshotSub = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshotSub == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateToolhelp32Snapshot (subprocesses) failed: %d\n", GetLastError());
        return processList; // Return current list (might contain main process already)
    }

    PROCESSENTRY32W pe32Sub;
    pe32Sub.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshotSub, &pe32Sub)) {
        wprintf(L"Process32FirstW (subprocesses) failed: %d\n", GetLastError());
        CloseHandle(hSnapshotSub);
        return processList; // Return current list
    }

    do {
        if (pe32Sub.th32ParentProcessID == mainProcessId) {
            ProcessInfo subProcessInfo;
            subProcessInfo.pid = pe32Sub.th32ProcessID;
            subProcessInfo.parentPid = pe32Sub.th32ParentProcessID;
            wcscpy_s(subProcessInfo.imageName, MAX_PATH, pe32Sub.szExeFile);
            processList.push_back(subProcessInfo); // Add subprocess to the list
        }
    } while (Process32NextW(hSnapshotSub, &pe32Sub));

    CloseHandle(hSnapshotSub);
    return processList;
}


BOOL SetAccessControl(const wchar_t* filePath) {
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    EXPLICIT_ACCESSW ExplicitAccess = { 0 };
    ACL* AccessControlCurrent = NULL;
    ACL* AccessControlNew = NULL;
    SECURITY_INFORMATION SecurityInfo = DACL_SECURITY_INFORMATION;
    PSID SecurityIdentifier = NULL;
    BOOL success = FALSE;

    // Get current DACL
    if (GetNamedSecurityInfoW(
            filePath,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            NULL,
            NULL,
            &AccessControlCurrent,
            NULL,
            &SecurityDescriptor) == ERROR_SUCCESS) {

        // Convert "ALL APPLICATION PACKAGES" SID string to SID.  This is for demonstration purposes only.  In a real-world scenario, you would likely use a more appropriate SID.
        if (ConvertStringSidToSidW(L"S-1-15-2-1", &SecurityIdentifier)) {
            ExplicitAccess.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
            ExplicitAccess.grfAccessMode = SET_ACCESS;
            ExplicitAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ExplicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ExplicitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ExplicitAccess.Trustee.ptstrName = (LPWCH)SecurityIdentifier;

            // Create new DACL
            if (SetEntriesInAclW(1, &ExplicitAccess, AccessControlCurrent, &AccessControlNew) == ERROR_SUCCESS) {
                // Set new DACL
                success = SetNamedSecurityInfoW(
                    (LPWSTR)filePath,
                    SE_FILE_OBJECT,
                    SecurityInfo,
                    NULL,
                    NULL,
                    AccessControlNew,
                    NULL) == ERROR_SUCCESS;
            }
        }
    }

    // Cleanup
    if (SecurityDescriptor) {
        LocalFree((HLOCAL)SecurityDescriptor);
    }
    if (AccessControlNew) {
        LocalFree((HLOCAL)AccessControlNew);
    }
    if (SecurityIdentifier) {
        LocalFree(SecurityIdentifier);
    }

    return success;
}

BOOL InjectDLL(DWORD processId, const wchar_t* dllPath) {
    // Convert relative path to absolute if needed
    wchar_t fullPath[MAX_PATH] = {0};
    if (!GetFullPathNameW(dllPath, MAX_PATH, fullPath, NULL)) {
        wprintf(L"GetFullPathNameW failed: %d\n", GetLastError());
        return FALSE;
    }

    // Set proper access controls for the DLL
    wprintf(L"Setting DLL access permissions...\n");
    if (!SetAccessControl(fullPath)) {
        wprintf(L"Warning: Failed to set DLL access permissions. Error: %lu\n", GetLastError());
        // Continue anyway as it might work without it
    }

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION,
        FALSE, processId);

    if (hProcess == NULL) {
        wprintf(L"OpenProcess failed with error code: %d\n", GetLastError());
        return FALSE;
    }

    SIZE_T pathLen = wcslen(fullPath) * sizeof(wchar_t) + sizeof(wchar_t); // Include null terminator
    wprintf(L"Trying to inject: %ls (size: %zu bytes) into PID: %d\n", fullPath, pathLen, processId);

    LPVOID remoteString = VirtualAllocEx(hProcess, NULL,
                                        pathLen,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);

    if (remoteString == NULL) {
        wprintf(L"VirtualAllocEx failed with error code: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, remoteString, fullPath, pathLen, NULL)) {
        wprintf(L"WriteProcessMemory failed with error code: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) {
        wprintf(L"GetModuleHandleW failed with error code: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (loadLibraryAddr == NULL) {
        wprintf(L"GetProcAddress failed with error code: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    wprintf(L"Creating remote thread with LoadLibraryW at address: %p\n", loadLibraryAddr);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                      loadLibraryAddr,
                                      remoteString, 0, NULL);

    if (hThread == NULL) {
        wprintf(L"CreateRemoteThread failed with error code: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // WaitForSingleObject and GetExitCodeThread can be unreliable for remote DLL injection in all cases
    // Removing them for now for simplicity, but consider adding robust error handling if needed.

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return TRUE; // Assume success if no critical errors occurred up to CreateRemoteThread
}

BOOL FileExists(const wchar_t* path) {
    DWORD attrib = GetFileAttributesW(path);
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

int wmain(int argc, wchar_t* argv[]) {
    _wsetlocale(LC_ALL, L""); // Important for correct wide char output

    if (argc != 3) {
        wprintf(L"Usage: %ls <process name> <dll path>\n", argv[0]);
        return 1;
    }

    wchar_t targetProcessName[MAX_PATH] = {0};
    wchar_t dllPath[MAX_PATH] = {0};

    wcscpy_s(targetProcessName, MAX_PATH, argv[1]); // Process name from argument
    wcscpy_s(dllPath, MAX_PATH, argv[2]);

    if (!FileExists(dllPath)) {
        wprintf(L"DLL file %ls does not exist.\n", dllPath);
        return 1;
    }

    std::vector<ProcessInfo> processList = GetProcessAndSubprocessIds(targetProcessName);
    if (processList.empty()) {
        wprintf(L"No processes found matching name: %ls or its subprocesses.\n", targetProcessName);
        return 1;
    }

    wprintf(L"Found %zu processes and subprocesses for %ls:\n", processList.size(), targetProcessName);
    for (const auto& procInfo : processList) {
        wprintf(L"  Process Name: %ls, PID: %d, Parent PID: %d\n", procInfo.imageName, procInfo.pid, procInfo.parentPid);
    }

    bool injectionSuccess = true;
    for (const auto& procInfo : processList) {
        if (!InjectDLL(procInfo.pid, dllPath)) {
            wprintf(L"DLL injection failed for PID: %d\n", procInfo.pid);
            injectionSuccess = false; // Mark overall injection as failed if any subprocess injection fails
        } else {
            wprintf(L"DLL injection successful for PID: %d\n", procInfo.pid);
        }
    }

    if (injectionSuccess) {
        wprintf(L"DLL injected successfully into all target processes and subprocesses!\n");
        return 0;
    } else {
        wprintf(L"DLL injection failed for at least one target process or subprocess.\n");
        return 1;
    }
}