#include "PE.h"
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)


PIMAGE_DOS_HEADER PortableExecutable::GetDosHeader(PVOID ImageBase) {
	if (ImageBase == NULL || ((PIMAGE_DOS_HEADER)ImageBase)->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	return (PIMAGE_DOS_HEADER)ImageBase;
}


PIMAGE_NT_HEADERS64 PortableExecutable::GetNtHeaders(PVOID ImageBase, PIMAGE_DOS_HEADER ImageDosHeader) {
	if (ImageDosHeader == NULL) {
		ImageDosHeader = PortableExecutable::GetDosHeader(ImageBase);
		if (ImageDosHeader == NULL) {
			return NULL;
		}
	}
	if (ImageBase == NULL || ((PIMAGE_DOS_HEADER)ImageBase)->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	return (PIMAGE_NT_HEADERS64)ImageBase;
}