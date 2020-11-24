#ifndef __MODULE_RESOLVER_
#define __MODULE_RESOLVER_

#ifndef _WINDOWS_
#include <Windows.h>
#endif


class ModuleResolver
{
private:
	PVOID LocalModuleBase;
	PVOID OriginalModuleBase;
	PVOID ResolveModuleByCrc(ULONG Crc);
	PVOID ResolveModuleByName(PCHAR Name, ULONG Size);
	PVOID ResolveForwardedFunction(PVOID ModuleName, ULONG ModuleNameLength, PVOID FunctionName, ULONG FunctionNameLength);

public:
	ModuleResolver(PVOID ModuleBase);
	ModuleResolver(ULONG ModuleCrc);
	ModuleResolver(PCHAR ModuleName);
	ModuleResolver(PWCHAR ModuleName);

	PVOID ResolveFunctionByOrdinal(ULONG Ordinal);
	PVOID ResolveFunctionByCrc(ULONG Crc);
	PVOID ResolveFunctionByName(PCHAR Name);
	PVOID ResolveFunctionByName(PWCHAR Name);

	LPCVOID ModuleBase();

};




#endif
