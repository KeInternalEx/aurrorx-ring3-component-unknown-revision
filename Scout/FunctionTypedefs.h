#ifndef __FUNCTION_TYPEDEFS_
#define __FUNCTION_TYPEDEFS_

#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <winternl.h>

typedef enum _EVENT_TYPE {
	NotificationEvent = 0,
	SynchronizationEvent = 1
} EVENT_TYPE;

typedef struct tagPROCESSENTRY32 {
	DWORD     dwSize;
	DWORD     cntUsage;
	DWORD     th32ProcessID;
	ULONG_PTR th32DefaultHeapID;
	DWORD     th32ModuleID;
	DWORD     cntThreads;
	DWORD     th32ParentProcessID;
	LONG      pcPriClassBase;
	DWORD     dwFlags;
	WCHAR     szExeFile[MAX_PATH];
} PROCESSENTRY32W, *PPROCESSENTRY32W;

typedef LPVOID(WINAPI *fnVirtualAlloc)(
	_In_opt_ LPVOID lpAddress,
	_In_     SIZE_T dwSize,
	_In_     DWORD  flAllocationType,
	_In_     DWORD  flProtect
	);

typedef HRSRC(WINAPI *fnFindResourceW)(
	_In_opt_ HMODULE hModule,
	_In_     LPCWSTR lpName,
	_In_     LPCWSTR lpType
	);

typedef HGLOBAL(WINAPI *fnLoadResource)(
	_In_opt_ HMODULE hModule,
	_In_     HRSRC   hResInfo
	);

typedef LPVOID(WINAPI *fnLockResource)(
	_In_ HGLOBAL hResData
	);

typedef DWORD(WINAPI *fnSizeofResource)(
	_In_opt_ HMODULE hModule,
	_In_     HRSRC   hResInfo
	);

typedef PVOID(WINAPI *fnRtlAddVectoredExceptionHandler)(
	_In_ ULONG                       FirstHandler,
	_In_ PVECTORED_EXCEPTION_HANDLER VectoredHandler
	);

typedef BOOL(WINAPI *fnIsWow64Process)(
	_In_  HANDLE hProcess,
	_Out_ PBOOL  Wow64Process
	);

typedef LONG(WINAPI *fnRegGetValueW)(
	_In_        HKEY    hkey,
	_In_opt_    LPCWSTR lpSubKey,
	_In_opt_    LPCWSTR lpValue,
	_In_opt_    DWORD   dwFlags,
	_Out_opt_   LPDWORD pdwType,
	_Out_opt_   PVOID   pvData,
	_Inout_opt_ LPDWORD pcbData
	);

typedef HMODULE(WINAPI *fnLoadLibraryW)(
	_In_ LPCWSTR lpFileName
	);

typedef BOOL(WINAPI *fnFlushInstructionCache)(
	_In_ HANDLE  hProcess,
	_In_ LPCVOID lpBaseAddress,
	_In_ SIZE_T  dwSize
	);

typedef BOOL(WINAPI *fnVirtualFree)(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD  dwFreeType
	);

typedef ULONGLONG(WINAPI *fnGetTickCount64)(void);
typedef ULONG(WINAPI *fnRtlRandomEx)(
	_Inout_ PULONG Seed
	);

typedef BOOL(WINAPI *fnVirtualProtect)(
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD  flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);

typedef VOID(WINAPI *fnRtlInitUnicodeString)(
	_Out_    PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR          SourceString
	);

typedef NTSTATUS(WINAPI *fnNtCreateEvent)(
	_Out_    PHANDLE            EventHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_     EVENT_TYPE         EventType,
	_In_     BOOLEAN            InitialState
	);

typedef NTSTATUS(WINAPI *fnNtCreateFile)(
	_Out_    PHANDLE            FileHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_    PIO_STATUS_BLOCK   IoStatusBlock,
	_In_opt_ PLARGE_INTEGER     AllocationSize,
	_In_     ULONG              FileAttributes,
	_In_     ULONG              ShareAccess,
	_In_     ULONG              CreateDisposition,
	_In_     ULONG              CreateOptions,
	_In_     PVOID              EaBuffer,
	_In_     ULONG              EaLength
	);

typedef NTSTATUS(WINAPI *fnNtDeviceIoControlFile)(
	_In_  HANDLE           FileHandle,
	_In_  HANDLE           Event,
	_In_  PIO_APC_ROUTINE  ApcRoutine,
	_In_  PVOID            ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_  ULONG            IoControlCode,
	_In_  PVOID            InputBuffer,
	_In_  ULONG            InputBufferLength,
	_Out_ PVOID            OutputBuffer,
	_In_  ULONG            OutputBufferLength
	);

typedef NTSTATUS(WINAPI *fnNtWriteFile)(
	_In_     HANDLE           FileHandle,
	_In_opt_ HANDLE           Event,
	_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
	_In_opt_ PVOID            ApcContext,
	_Out_    PIO_STATUS_BLOCK IoStatusBlock,
	_In_     PVOID            Buffer,
	_In_     ULONG            Length,
	_In_opt_ PLARGE_INTEGER   ByteOffset,
	_In_opt_ PULONG           Key
	);

typedef NTSTATUS(WINAPI *fnNtWaitForSingleObject)(
	_In_ HANDLE         Handle,
	_In_ BOOLEAN        Alertable,
	_In_ PLARGE_INTEGER Timeout
	);

typedef NTSTATUS(WINAPI *fnNtReadFile)(
	_In_     HANDLE           FileHandle,
	_In_opt_ HANDLE           Event,
	_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
	_In_opt_ PVOID            ApcContext,
	_Out_    PIO_STATUS_BLOCK IoStatusBlock,
	_Out_    PVOID            Buffer,
	_In_     ULONG            Length,
	_In_opt_ PLARGE_INTEGER   ByteOffset,
	_In_opt_ PULONG           Key
	);

typedef BOOL(WINAPI *fnAdjustTokenPrivileges)(
	_In_      HANDLE            TokenHandle,
	_In_      BOOL              DisableAllPrivileges,
	_In_opt_  PTOKEN_PRIVILEGES NewState,
	_In_      DWORD             BufferLength,
	_Out_opt_ PTOKEN_PRIVILEGES PreviousState,
	_Out_opt_ PDWORD            ReturnLength
);

typedef BOOL(WINAPI *fnOpenProcessToken)(
	_In_  HANDLE  ProcessHandle,
	_In_  DWORD   DesiredAccess,
	_Out_ PHANDLE TokenHandle
);

typedef BOOL(WINAPI *fnCloseHandle)(
	_In_ HANDLE hObject
);

typedef BOOL(WINAPI *fnLookupPrivilegeValueW)(
	_In_opt_ LPCWSTR lpSystemName,
	_In_     LPCWSTR lpName,
	_Out_    PLUID   lpLuid
);

typedef HANDLE(WINAPI *fnCreateToolhelp32Snapshot)(
	_In_ DWORD dwFlags,
	_In_ DWORD th32ProcessID
);

typedef BOOL(WINAPI *fnProcess32FirstW)(
	_In_    HANDLE           hSnapshot,
	_Inout_ PPROCESSENTRY32W  lppe
);

typedef BOOL(WINAPI *fnProcess32NextW)(
	_In_  HANDLE           hSnapshot,
	_Out_ PPROCESSENTRY32W  lppe
);

typedef struct _FUNCION_POINTER_BLOCK {
	fnVirtualAlloc VirtualAlloc;
	fnFindResourceW FindResourceW;
	fnLoadResource LoadResource;
	fnLockResource LockResource;
	fnSizeofResource SizeofResource;
	fnRtlAddVectoredExceptionHandler RtlAddVectoredExceptionHandler;
	fnIsWow64Process IsWow64Process;
	fnLoadLibraryW LoadLibraryW;
	fnRegGetValueW RegGetValueW;
	fnFlushInstructionCache FlushInstructionCache;
	fnVirtualFree VirtualFree;
	fnGetTickCount64 GetTickCount64;
	fnRtlRandomEx RtlRandomEx;
	fnVirtualProtect VirtualProtect;
	fnNtReadFile NtReadFile;
	fnNtWaitForSingleObject NtWaitForSingleObject;
	fnNtWriteFile NtWriteFile;
	fnNtDeviceIoControlFile NtDeviceIoControlFile;
	fnNtCreateFile NtCreateFile;
	fnNtCreateEvent NtCreateEvent;
	fnRtlInitUnicodeString RtlInitUnicodeString;
	fnAdjustTokenPrivileges AdjustTokenPrivileges;
	fnOpenProcessToken OpenProcessToken;
	fnCloseHandle CloseHandle;
	fnLookupPrivilegeValueW LookupPrivilegeValueW;
	fnCreateToolhelp32Snapshot CreateToolhelp32Snapshot;
	fnProcess32FirstW Process32FirstW;
	fnProcess32NextW Process32NextW;
} FUNCTION_POINTER_BLOCK, *PFUNCTION_POINTER_BLOCK;

#endif