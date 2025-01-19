#include <windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <sddl.h>
#include <processthreadsapi.h>
#include <tlhelp32.h>
#include <locale.h>

DWORD GetProcessIdByName(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateToolhelp32Snapshot failed: %d\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        wprintf(L"Process32FirstW failed: %d\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_wcsicmp(pe32.szExeFile, processName) == 0) {
            DWORD pid = pe32.th32ProcessID;
            CloseHandle(hSnapshot);
            return pid;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
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
    wprintf(L"Attempting to inject: %ls (size: %zu bytes)\n", fullPath, pathLen);

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

    DWORD waitResult = WaitForSingleObject(hThread, 5000); // 5 second timeout
    if (waitResult != WAIT_OBJECT_0) {
        wprintf(L"WaitForSingleObject failed or timed out: %d\n", waitResult);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    DWORD exitCode = 0;
    if (GetExitCodeThread(hThread, &exitCode)) {
        wprintf(L"Thread exit code: %lu (0x%08lX)\n", exitCode, exitCode);
        if (exitCode == 0) {
            wprintf(L"LoadLibrary failed in target process\n");
        }
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return exitCode != 0;
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

    wcscpy_s(targetProcessName, MAX_PATH, argv[1]);
    wcscpy_s(dllPath, MAX_PATH, argv[2]);

    if (!FileExists(dllPath)) {
        wprintf(L"DLL file %ls does not exist.\n", dllPath);
        return 1;
    }

    DWORD processId = GetProcessIdByName(targetProcessName);
    if (processId == 0) {
        wprintf(L"Process %ls not found.\n", targetProcessName);
        return 1;
    }

    wprintf(L"Found process %ls with PID: %d\n", targetProcessName, processId);

    if (InjectDLL(processId, dllPath) ) {
        wprintf(L"DLL injected successfully! Name: %ls\n", dllPath);
        return 0;
    } else {
        wprintf(L"DLL injection failed.\n");
        return 1;
    }
}
