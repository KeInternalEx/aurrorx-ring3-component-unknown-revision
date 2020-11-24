#ifndef __DEBUG_HEADER_
#define __DEBUG_HEADER_

#define DEBUGGING

#ifdef DEBUGGING
#ifndef _WINDOWS_
#include <Windows.h>
#endif
#define DebugPrint(...) printf(__VA_ARGS__)
#define PauseExecution() system("Pause")
#else
#pragma warning(disable : 4390) // Controlled statement
#define DebugPrint(...)
#define PauseExecution()
#endif






#endif