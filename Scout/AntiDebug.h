#ifndef __ANTI_DEBUG_
#define __ANTI_DEBUG_

#ifndef _WINDOWS_
#include <Windows.h>
#endif

#define CLEAR_RF_FLAG    \
	__asm pushfd         \
	__asm pop eax        \
	__asm btr eax, 16    \
	__asm push eax       \
	__asm popfd

#define MAGIC_ADBG       0x39ffa8bb

#define SET_RF_FLAG      \
	__asm pushfd         \
	__asm pop eax        \
	__asm bts eax, 16    \
	__asm push eax       \
	__asm popfd


#define TRANSIENT_DISABLE_DEBUG \
	__asm pushad                \
	__asm push ss               \
	__asm ud2                   \
	__asm pop ss                \
	__asm cmp eax, MAGIC_ADBG   \
	__asm popad                 \
	__asm jne $-13


// todo: check 64 bit PEB if running in WoW64




#endif