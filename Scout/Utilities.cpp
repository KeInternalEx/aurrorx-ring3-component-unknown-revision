#include "Utilities.h"
#include <ctime>

#pragma warning(disable : 4244) // conversion from 'int64' to 'unsigned long'
#pragma warning(disable : 4035) // no return value

#define CRC32_POLYNOMIAL 0xEDB88320


unsigned long __fastcall crc32v(int i){
	unsigned long Crc = i;
	for (int j = 8; j > 0; j--){
		if (Crc & 1)
			Crc = (Crc >> 1) ^ CRC32_POLYNOMIAL;
		else Crc >>= 1;
	}
	return Crc;
};


unsigned long Utils::Crc(PWCHAR Buffer, ULONG Length){
	unsigned long h = 0;
	unsigned long t1, t2;
	for (unsigned long i = 0; i < Length; i++){
		t1 = (h >> 8) & 0x00ffffff;
		t2 = crc32v((h ^ Buffer[i]) & 0xff);
		h = t1 ^ t2;
	}

	return h;
};
unsigned long Utils::Crc(PCHAR Buffer, ULONG Length){
	unsigned long h = 0;
	unsigned long t1, t2;
	for (unsigned long i = 0; i < Length; i++){
		t1 = (h >> 8) & 0x00ffffff;
		t2 = crc32v((h ^ Buffer[i]) & 0xff);
		h = t1 ^ t2;
	}

	return h;
};
unsigned long Utils::GetLength(PCHAR Buffer){
	char *ptr = Buffer;
	while (*ptr++ != 0);
	return ptr - Buffer - 1;
};
unsigned long Utils::GetLength(PWCHAR Buffer){
	wchar_t *ptr = Buffer;
	while (*ptr++ != 0);
	return ptr - Buffer - 1;
};
unsigned long Utils::FindOccurrence(PCHAR Buffer, ULONG Length, CHAR Seek){
	char *ptr = Buffer;
	while (*ptr++ != Seek){
		if ((ULONG)(ptr - Buffer) > Length)
			break;
	}
	if (*(ptr-1) == Seek)
		return ptr - Buffer;

	return 0;
};
unsigned long Utils::FindOccurrence(PWCHAR Buffer, ULONG Length, WCHAR Seek){
	wchar_t *ptr = Buffer;
	while (*ptr++ != Seek){
		if ((ULONG)(ptr - Buffer) > Length)
			break;
	}
	if (*(ptr - 1) == Seek)
		return ptr - Buffer;

	return 0;
};
unsigned long Utils::FindOccurrence(PCHAR Buffer, ULONG Length, PCHAR Seek) {
	unsigned long len = Utils::GetLength(Seek);

	for (unsigned long i = 0; i < Length - len; i++) {
		char *ptr = &Buffer[i];
		if (Utils::memcmp(ptr, Seek, len))
			return (ptr + len) - Buffer;
	}

	return 0;
};
unsigned long Utils::FindOccurrence(PWCHAR Buffer, ULONG Length, PWCHAR Seek) {
	unsigned long len = Utils::GetLength(Seek);

	for (unsigned long i = 0; i < Length - len; i++) {
		wchar_t *ptr = &Buffer[i];
		if (Utils::memcmp(ptr, Seek, len))
			return (ptr + len) - Buffer;
	}

	return 0;
};
unsigned long Utils::StrToUlong(PCHAR Buffer, ULONG Length){
	unsigned long n = 0;
	for (unsigned long i = 0; i < Length; i++)
		n = n * 10 + (Buffer[i] - 0x30);

	return n;
};
unsigned long Utils::StrToUlong(PWCHAR Buffer, ULONG Length){
	unsigned long n = 0;
	for (unsigned long i = 0; i < Length; i++)
		n = n * 10 + (Buffer[i] - 0x30);

	return n ;
};

void Utils::memcpy(void *dst, void *src, unsigned long Length) {
	if (dst == NULL || src == NULL || Length == 0)
		return;

	for (unsigned long i = 0; i < Length; i++)
		((unsigned char*)dst)[i] = ((unsigned char*)src)[i];
};
void Utils::memset(void *dst, unsigned char value, unsigned long Length) {
	if (dst == NULL || Length == 0)
		return;

	for (unsigned long i = 0; i < Length; i++)
		((unsigned char*)dst)[i] = value;
};
wchar_t *Utils::NarrowToWide(char *In, unsigned long Length) {
	wchar_t *NewBuffer = new wchar_t[Length + 1]();

	for (unsigned long i = 0; i < Length; i++)
		NewBuffer[i] = (wchar_t)In[i];

	return NewBuffer;
};
char *Utils::WideToNarrow(wchar_t *In, unsigned long Length) {
	char *NewBuffer = new char[Length + 1]();

	for (unsigned long i = 0; i < Length; i++)
		NewBuffer[i] = In[i];

	return NewBuffer;
};

unsigned long Utils::CurrentPid32() {
	__asm mov eax, dword ptr fs:[20h] // Offset 20h in TEB is a CLIENT_ID structure, containing the PID and TID of the current thread.
	return;
};

unsigned long Utils::Log10(unsigned long n) {
	return
		(n >= 1000000000) ? 9 : (n >= 100000000) ? 8 :
		(n >= 10000000) ? 7 : (n >= 1000000) ? 6 :
		(n >= 100000) ? 5 : (n >= 10000) ? 4 :
		(n >= 1000) ? 3 : (n >= 100) ? 2 : (n >= 10) ? 1 : 0;
};

wchar_t *Utils::Lower(wchar_t *In, unsigned long Length) {
	wchar_t *n = new wchar_t[Length + 1]();
	for (unsigned long i = 0; i < Length; i++)
		n[i] = towlower(In[i]);

	return n;
};
char *Utils::Lower(char *In, unsigned long Length) {
	char *n = new char[Length + 1]();
	for (unsigned long i = 0; i < Length; i++)
		n[i] = tolower(In[i]);

	return n;
};

unsigned long Utils::Rand() {
	unsigned State = 0;
	static unsigned long RngSeed = time(NULL);
	
	/* [32, 22, 2, 1] */
	
	State = RngSeed & 1;
	RngSeed >>= 1;
	if (State)
		RngSeed = ~(RngSeed ^ 0x80200003); // 10000000001000000000000000000011b

	return RngSeed;
};

bool Utils::memcmp(void *f, void *b, unsigned long Length) {
	unsigned char *p1 = (unsigned char*)f, *p2 = (unsigned char*)b;

	for (unsigned long i = 0; i < Length; i++)
		if (p1[i] != p2[i])
			return false;

	return true;
};

