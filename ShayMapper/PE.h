#pragma once
#include "utils.h"


namespace PortableExecutable {
	PIMAGE_DOS_HEADER GetDosHeader(PVOID ImageBase);
	PIMAGE_NT_HEADERS64 GetNtHeaders(PVOID ImageBase, PIMAGE_DOS_HEADER ImageDosHeader);
}