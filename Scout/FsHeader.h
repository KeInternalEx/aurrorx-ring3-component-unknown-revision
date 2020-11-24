#ifndef __FS_HEADER_
#define __FS_HEADER_

#ifndef _WINDOWS_
#include <Windows.h>
#endif

#ifndef __FUNCTION_POINTERS_
#include "FunctionTypedefs.h"
#endif

#ifndef __FILE_SYSTEM_ENTRIES_
#include "..\..\..\Common\FileSystemEntries.h"
#endif


#include <vector>




typedef struct _HEAT_PSEUDO_FILE {
	ULONGLONG Lba;
	ULONG FileSize;
	PVOID Buffer;
	CHAR Name[16];
} HEAT_PSEUDO_FILE, *PHEAT_PSEUDO_FILE;

class HeatFileSystem {
	HANDLE FsHandle;
	ULONGLONG DataSector[64];

	IO_STATUS_BLOCK IoStatusBlock;
	LARGE_INTEGER SectorOffset;
	HANDLE EventHandle;
	ULONG FsSize;
	PFUNCTION_POINTER_BLOCK FunctionPointers;
	std::vector<PHEAT_PSEUDO_FILE> FileArray;
	bool ChangesMade;

public:
	ULONGLONG DiskSize;

	HeatFileSystem(PWCHAR BootDevice, PFUNCTION_POINTER_BLOCK FpBlock);
	VOID SetDataSectorEntry(UCHAR Entry, ULONGLONG Value);
	ULONGLONG GetDataSectorEntry(UCHAR Entry);

	VOID AddFile(ULONGLONG StartingSector, PVOID Buffer, ULONG BufferSize, PCHAR Name);
	VOID RemoveFile(PCHAR Name);
	BOOLEAN FlushChangesToDisk();
	BOOLEAN WriteDiskRaw(ULONGLONG StartingSector, ULONG NumberOfBytes, PVOID BufferIn);
	BOOLEAN ReadDiskRaw(ULONGLONG StartingSector, ULONG NumberOfBytes, PVOID *BufferOut);
};


#endif