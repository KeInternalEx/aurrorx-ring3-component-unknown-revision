#include "AntiDebug.h"
#include "ModuleResolver.h"
#include "FunctionTypedefs.h"
#include "AsmLinkage.h"

#include "DebugHeader.h"

#pragma warning(disable : 4244) // conversion from 'ULONG' to 'BYTE'


extern "C" IMAGE_DOS_HEADER __ImageBase;

