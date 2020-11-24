#ifndef __UTILITIES_
#define __UTILITIES_

#ifndef _WINDOWS_
#include <Windows.h>
#endif


#define CHECKFLAG(in, flg) (((in) & (flg)) == (flg))
#define CHECKBIT(in, pos)  ((in) & (1 << (pos)))

class Utils
{
public:
	static unsigned long Crc(PWCHAR Buffer, ULONG Length);
	static unsigned long Crc(PCHAR Buffer, ULONG Length);
	static unsigned long GetLength(PCHAR Buffer);
	static unsigned long GetLength(PWCHAR Buffer);
	static unsigned long FindOccurrence(PCHAR Buffer, ULONG Length, CHAR Seek);
	static unsigned long FindOccurrence(PWCHAR Buffer, ULONG Length, WCHAR Seek);
	static unsigned long FindOccurrence(PCHAR Buffer, ULONG Length, PCHAR Seek);
	static unsigned long FindOccurrence(PWCHAR Buffer, ULONG Length, PWCHAR Seek);

	static unsigned long StrToUlong(PCHAR Buffer, ULONG Length);
	static unsigned long StrToUlong(PWCHAR Buffer, ULONG Length);

	static void memcpy(void *dst, void *src, unsigned long Length);
	static void memset(void *dst, unsigned char value, unsigned long Length);
	static bool memcmp(void *f, void *b, unsigned long Length);
	static wchar_t *NarrowToWide(char *In, unsigned long Length);
	static char *WideToNarrow(wchar_t *In, unsigned long Length);

	static unsigned long Log10(unsigned long n);
	static unsigned long CurrentPid32();

	static wchar_t *Lower(wchar_t *In, unsigned long Length);
	static char *Lower(char *In, unsigned long Length);

	/*** Linear Feedback Shift Based ***/
	static unsigned long Rand();
};






#endif