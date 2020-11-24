#include "FsHeader.h"
#include "DebugHeader.h"
#include "Utilities.h"

VOID genkeybits(UCHAR kb[16]){
	for (unsigned char i = 0; i < 4; i++)
		((unsigned long*)kb)[i] = Utils::Rand();
};


HeatFileSystem::HeatFileSystem(PWCHAR BootDevice, PFUNCTION_POINTER_BLOCK FpBlock){
	NTSTATUS Status = 0;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	UNICODE_STRING BootString = { 0 };
	DISK_GEOMETRY_EX DiskGeometry = { 0 };
	ULONG ProxyFunction = 0;

	this->SectorOffset.QuadPart = 0;
	this->SectorOffset.LowPart = 0;
	this->SectorOffset.HighPart = 0;
	this->FsHandle = NULL;
	this->EventHandle = NULL;
	this->ChangesMade = false;
	this->FsSize = 0;
	this->DiskSize = 0;
	this->FunctionPointers = FpBlock;


	FpBlock->RtlInitUnicodeString(&BootString, BootDevice);

	InitializeObjectAttributes(&ObjectAttributes, NULL, NULL, NULL, NULL);


	if (!NT_SUCCESS(Status = FpBlock->NtCreateEvent(&this->EventHandle, EVENT_ALL_ACCESS, &ObjectAttributes, NotificationEvent, FALSE))){
		DebugPrint("Unable to create fs event: %#x\r\n", Status);
		goto ExitPoint;
	}

	InitializeObjectAttributes(&ObjectAttributes, &BootString, OBJ_KERNEL_HANDLE, 0, 0); // Still need to set OBJ_KERNEL_HANDLE if in usermode
	DebugPrint("Attempting to open drive: %ws\r\n", BootDevice);

	if (!NT_SUCCESS(Status = FpBlock->NtCreateFile(&this->FsHandle, FILE_READ_DATA | FILE_WRITE_DATA, &ObjectAttributes, &this->IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0))){
		DebugPrint("Unable to open file system for raw sector access: %#x\r\n", Status);
		goto ExitPoint;
	}

	if (!NT_SUCCESS(Status = FpBlock->NtDeviceIoControlFile(this->FsHandle, this->EventHandle, NULL, NULL, &this->IoStatusBlock, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, NULL, &DiskGeometry, sizeof(DISK_GEOMETRY_EX)))){
		DebugPrint("Unable to query size of disk: %#x\r\n", Status);
		goto ExitPoint;
	}

	if (Status == STATUS_PENDING){
		if (!NT_SUCCESS(Status = FpBlock->NtWaitForSingleObject(this->EventHandle, FALSE, NULL)))
			goto ExitPoint;

		Status = IoStatusBlock.Status;
	}

	Utils::memset(this->DataSector, 0, 64 * sizeof(ULONGLONG));

	this->DiskSize = DiskGeometry.DiskSize.QuadPart / 0x200; // get sectors//
//	this->ModuleTable = (PHEAT_MODULE_TABLE)malloc(sizeof(HEAT_MODULE_TABLE));
//	genkeybits(this->ModuleTable->KeyBits);

	DebugPrint("Disk Size: %llx sectors\r\n", this->DiskSize);
	DebugPrint("Obtained handle to boot drive\r\n");

ExitPoint:
	return;
};

ULONGLONG HeatFileSystem::GetDataSectorEntry(UCHAR Entry){
	return this->DataSector[Entry];
};
VOID HeatFileSystem::SetDataSectorEntry(UCHAR Entry, ULONGLONG Value){
	this->ChangesMade = true;
	this->DataSector[Entry] = Value;
};
BOOLEAN HeatFileSystem::FlushChangesToDisk(){
	BOOLEAN Status = FALSE;

	if (!this->ChangesMade)
		goto ExitPoint;

	if (!(Status = this->WriteDiskRaw(this->DiskSize - 1, 0x200, this->DataSector)))
		goto ExitPoint;

	for each(PHEAT_PSEUDO_FILE File in this->FileArray){
		if (!this->WriteDiskRaw(File->Lba, File->FileSize, File->Buffer))
			goto ExitPoint;
	}

	Status = TRUE;
	this->ChangesMade = false;

ExitPoint:
	return Status;
};

BOOLEAN HeatFileSystem::WriteDiskRaw(ULONGLONG StartingSector, ULONG NumberOfBytes, PVOID BufferIn){
	NTSTATUS Status = 0;
	LARGE_INTEGER ByteOffset = { 0 };
	ULONG ProxyFunction = 0;

	ByteOffset.QuadPart = StartingSector * 0x200;



	if (!NT_SUCCESS(Status = this->FunctionPointers->NtWriteFile(this->FsHandle, this->EventHandle, NULL, NULL, &this->IoStatusBlock, BufferIn, NumberOfBytes, &ByteOffset, NULL)))
		goto ExitPoint;


	if (Status == STATUS_PENDING){
		if (!NT_SUCCESS(Status = this->FunctionPointers->NtWaitForSingleObject(this->EventHandle, FALSE, NULL)))
			goto ExitPoint;

		Status = IoStatusBlock.Status;
	}

ExitPoint:
	return NT_SUCCESS(Status);
};
BOOLEAN HeatFileSystem::ReadDiskRaw(ULONGLONG StartingSector, ULONG NumberOfBytes, PVOID *BufferOut){
	NTSTATUS Status = 0;
	LARGE_INTEGER ByteOffset = { 0 };
	PVOID ReadBuffer = NULL;
	ULONG ProxyFunction = 0;


	ByteOffset.QuadPart = StartingSector * 0x200;
	ReadBuffer = reinterpret_cast<void*>(new char[NumberOfBytes]());
	if (ReadBuffer == NULL)
		goto ExitPoint;



	if (!NT_SUCCESS(Status = this->FunctionPointers->NtReadFile(this->FsHandle, this->EventHandle, NULL, NULL, &this->IoStatusBlock, ReadBuffer, NumberOfBytes, &ByteOffset, NULL)))
		goto ExitPoint;

	if (Status == STATUS_PENDING){
		if (!NT_SUCCESS(Status = this->FunctionPointers->NtWaitForSingleObject(this->EventHandle, FALSE, NULL)))
			goto ExitPoint;

		Status = IoStatusBlock.Status;
	}

	*BufferOut = ReadBuffer;

ExitPoint:
	return NT_SUCCESS(Status);
};
VOID HeatFileSystem::AddFile(ULONGLONG StartingSector, PVOID Buffer, ULONG BufferSize, PCHAR Name){
	PHEAT_PSEUDO_FILE File = NULL;
	ULONG nlen = Utils::GetLength(Name);

	File = new HEAT_PSEUDO_FILE();
	if (File == NULL)
		goto ExitPoint;

	File->Lba = StartingSector;
	File->Buffer = Buffer;
	File->FileSize = BufferSize;
	
	Utils::memset(File->Name, 0, 16);
	Utils::memcpy(File->Name, Name,  nlen > 15 ? 15 : nlen);

	this->FileArray.push_back(File);
	this->ChangesMade = true;

ExitPoint:
	return;
};
VOID HeatFileSystem::RemoveFile(PCHAR Name){
	int k = 0;
	for each(PHEAT_PSEUDO_FILE File in this->FileArray){
		if (!strncmp(File->Name, Name, 16)){
			this->FileArray.erase(this->FileArray.begin() + k);
			this->ChangesMade = true;
			break;
		}
		k++;
	}
};

