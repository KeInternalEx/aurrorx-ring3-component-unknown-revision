#include "Utilities.h"
#include "ModuleResolver.h"


typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

ModuleResolver::ModuleResolver(PVOID ModuleBase){
	this->OriginalModuleBase = this->LocalModuleBase = ModuleBase;
};
ModuleResolver::ModuleResolver(ULONG Crc){
	this->OriginalModuleBase = this->LocalModuleBase = this->ResolveModuleByCrc(Crc);
};
ModuleResolver::ModuleResolver(PCHAR ModuleName){
	this->OriginalModuleBase = this->LocalModuleBase = this->ResolveModuleByName(ModuleName, Utils::GetLength(ModuleName));
};
ModuleResolver::ModuleResolver(PWCHAR ModuleName){
	this->OriginalModuleBase = this->LocalModuleBase = this->ResolveModuleByCrc(Utils::Crc(ModuleName, Utils::GetLength(ModuleName)));	
};
LPCVOID ModuleResolver::ModuleBase(){
	return this->OriginalModuleBase;
};

PVOID ModuleResolver::ResolveModuleByCrc(ULONG Hash){
	PVOID Peb;
	PVOID DllBase = NULL;
	PLIST_ENTRY ListHead, CurrentEntry;
	PVOID LoaderBlock = NULL;
	PRTL_CRITICAL_SECTION LoaderLock = NULL;

	__asm
	{
		mov eax, fs:[30h]
		mov [Peb], eax
	}

	LoaderLock = *(PRTL_CRITICAL_SECTION*)((PUCHAR)Peb + 0xa0);
	
	EnterCriticalSection(LoaderLock);
	
	LoaderBlock = *(PVOID*)((PUCHAR)Peb + 0x0c);
	ListHead = (PLIST_ENTRY)((PUCHAR)LoaderBlock + 0x0c);
	CurrentEntry = ListHead->Flink;

	

	while (CurrentEntry != ListHead){
		PVOID ModuleInfo = (PVOID)((PUCHAR)CurrentEntry - 0);
		UNICODE_STRING BaseName = *(UNICODE_STRING*)((PUCHAR)ModuleInfo + 0x2c);
		PWCHAR Name = Utils::Lower(BaseName.Buffer, BaseName.Length / sizeof(WCHAR));
		
		if (Utils::Crc(Name, BaseName.Length / sizeof(WCHAR)) == Hash){
			DllBase = *(PVOID*)((PUCHAR)ModuleInfo + 0x18);
			delete[] Name;
			break;
		}

		delete[] Name;

		CurrentEntry = CurrentEntry->Flink;
	}

	LeaveCriticalSection(LoaderLock);

	return DllBase;
};
PVOID ModuleResolver::ResolveModuleByName(PCHAR Name, ULONG Size){
	return this->ResolveModuleByCrc(Utils::Crc(Name, Size));
};
PVOID ModuleResolver::ResolveForwardedFunction(PVOID ModuleName, ULONG ModuleNameLength, PVOID FunctionName, ULONG FunctionNameLength){
	PVOID FunctionAddress = NULL;
	PVOID Module = NULL;
	ULONG Ordinal = -1;
	ULONG FunctionHash;
	ModuleResolver *ModuleResolver = NULL;

	if ((Module = this->ResolveModuleByName((PCHAR)ModuleName, ModuleNameLength)) == NULL){
		// load the module
		Module = LoadLibraryA((PCHAR)ModuleName); // need to pass control to FS utility to read raw ntfs partition and find the module ourselves...
	}
	
	if (Module == NULL)
		goto ExitPoint;

	this->LocalModuleBase = Module;

	if (*((CHAR*)FunctionName) == '#')
		Ordinal = Utils::StrToUlong((PCHAR)FunctionName + 1, FunctionNameLength);

	if (Ordinal != -1)
		FunctionAddress = this->ResolveFunctionByOrdinal(Ordinal);
	else
	{
		FunctionHash = Utils::Crc((PCHAR)FunctionName, FunctionNameLength);
		FunctionAddress = this->ResolveFunctionByCrc(FunctionHash);
	}

ExitPoint:
	this->LocalModuleBase = this->OriginalModuleBase;
	return FunctionAddress;
};
PVOID ModuleResolver::ResolveFunctionByOrdinal(ULONG Ordinal){
	PVOID FunctionAddress = NULL;
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;
	ULONG DataSize;
	PULONG FunctionTable;
	ULONG Split;

	if (this->LocalModuleBase == NULL)
		goto ExitPoint;

	DosHeader = (PIMAGE_DOS_HEADER)this->LocalModuleBase;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		goto ExitPoint;

	NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)this->LocalModuleBase + DosHeader->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		goto ExitPoint;

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)this->LocalModuleBase + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DataSize = (ULONG)NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	FunctionTable = (PULONG)((PUCHAR)this->LocalModuleBase + ExportDirectory->AddressOfFunctions);
	FunctionAddress = (PVOID)((PUCHAR)this->LocalModuleBase + FunctionTable[Ordinal]);

	if (((ULONG)FunctionAddress > (ULONG)ExportDirectory) && ((ULONG)FunctionAddress - (ULONG)ExportDirectory < DataSize)){
		Split = Utils::FindOccurrence((PCHAR)FunctionAddress, Utils::GetLength((PCHAR)FunctionAddress), '.');
		if (Split == 0)
			goto ExitPoint;

		FunctionAddress = this->ResolveForwardedFunction(FunctionAddress, Split - 1, (PVOID)((PUCHAR)FunctionAddress + Split), Utils::GetLength((PCHAR)FunctionAddress) - Split);
	}

ExitPoint:
	return FunctionAddress;
};
PVOID ModuleResolver::ResolveFunctionByCrc(ULONG Crc){
	PVOID FunctionAddress = NULL;
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;
	ULONG DataSize;
	INT Ordinal = -1;
	PULONG NamesTable;
	PULONG FunctionTable;
	PUSHORT OrdinalTable;
	PCHAR FunctionName;
	ULONG Split;

	if (this->LocalModuleBase == NULL)
		goto ExitPoint;

	DosHeader = (PIMAGE_DOS_HEADER)this->LocalModuleBase;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		goto ExitPoint;

	NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)this->LocalModuleBase + DosHeader->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		goto ExitPoint;

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)this->LocalModuleBase + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DataSize = (ULONG)NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (HIWORD(Crc) == 0)
		Ordinal = LOWORD(Crc) - ExportDirectory->Base;
	else
	{
		NamesTable = (PULONG)((PUCHAR)this->LocalModuleBase + ExportDirectory->AddressOfNames);
		OrdinalTable = (PUSHORT)((PUCHAR)this->LocalModuleBase + ExportDirectory->AddressOfNameOrdinals);

		for (unsigned int i = 0; i < ExportDirectory->NumberOfNames; i++){
			FunctionName = (PCHAR)((PUCHAR)this->LocalModuleBase + NamesTable[i]);
			if (Utils::Crc(FunctionName, Utils::GetLength(FunctionName)) == Crc){
				Ordinal = OrdinalTable[i];
				break;
			}
		}
	}

	if (Ordinal == -1)
		goto ExitPoint;


	FunctionTable = (PULONG)((PUCHAR)this->LocalModuleBase + ExportDirectory->AddressOfFunctions);
	FunctionAddress = (PVOID)((PUCHAR)this->LocalModuleBase + FunctionTable[Ordinal]);

	if (((ULONG)FunctionAddress > (ULONG)ExportDirectory) && ((ULONG)FunctionAddress < (ULONG)ExportDirectory + DataSize)){
		Split = Utils::FindOccurrence((PCHAR)FunctionAddress, Utils::GetLength((PCHAR)FunctionAddress), '.');
		if (Split == 0)
			goto ExitPoint;


		FunctionAddress = this->ResolveForwardedFunction(FunctionAddress, Split - 1, (PVOID)((PUCHAR)FunctionAddress + Split), Utils::GetLength((PCHAR)FunctionAddress) - Split);
	}

ExitPoint:
	return FunctionAddress;
};
PVOID ModuleResolver::ResolveFunctionByName(PCHAR Name){
	return this->ResolveFunctionByCrc(Utils::Crc(Name, Utils::GetLength(Name)));
};
PVOID ModuleResolver::ResolveFunctionByName(PWCHAR Name){
	return this->ResolveFunctionByCrc(Utils::Crc(Name, Utils::GetLength(Name)));
};


