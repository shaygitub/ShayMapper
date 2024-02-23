#include "utils.h"
#pragma warning(disable : 4244)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)																				


BOOL VulnurableDriver::HelperFunctions::IsAlreadyRunning(const char* SymbolicLink) {
	HANDLE DummyHandle = CreateFileA(SymbolicLink, FILE_ANY_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (DummyHandle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	return TRUE;
}


PVOID VulnurableDriver::HelperFunctions::FindSectionFromKernelModule(HANDLE* DeviceHandle, const char* SectionName, PVOID ModulePointer, ULONG* SectionSize) {
	BYTE ModuleHeaders[0x1000] = { 0 };
	PVOID ModuleSection = NULL;
	ULONG TemporarySize = 0;
	if (ModulePointer == NULL || !VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, ModulePointer, ModuleHeaders, 0x1000)) {
		printf("[-] Cannot read header data of kernel module\n");
		return NULL;
	}
	ModuleSection = specific::FindSectionOfKernelModule(SectionName, ModuleHeaders, &TemporarySize);
	if (ModuleSection == NULL || TemporarySize == 0) {
		printf("[-] Cannot find section %s (return values = %p, %lu)\n", SectionName, ModuleSection, TemporarySize);
		return NULL;
	}
	if (SectionSize != NULL) {
		*SectionSize = TemporarySize;
	}
	return (PVOID)((ULONG64)ModuleSection - (ULONG64)ModuleHeaders + (ULONG64)ModulePointer);
}


PVOID VulnurableDriver::HelperFunctions::FindPatternInKernelModule(HANDLE* DeviceHandle, PVOID SearchAddress, ULONG64 SearchLength, BYTE CompareAgainst[], const char* SearchMask) {
	PVOID KernelData = NULL;
	PVOID PatternInKernelData = NULL;  // Offset address
	PVOID PatternAddress = NULL;
	if (SearchAddress == NULL) {
		return NULL;
	}
	if (SearchLength > 1024 * 1024 * 1024) {
		printf("[-] Cannot find pattern in kernel module, search length (%llu) > 1GB\n", SearchLength);
		return NULL;
	}
	KernelData = malloc(SearchLength);
	if (KernelData == NULL) {
		printf("[-] Cannot allocate memory for kernel data, size = %llu bytes\n", SearchLength);
		return NULL;
	}
	if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, SearchAddress, KernelData, SearchLength)) {
		printf("[-] Failed to read kernel data to find pattern in, address = %p, size = %llu bytes\n", SearchAddress, SearchLength);
		free(KernelData);
		return NULL;
	}
	PatternInKernelData = specific::FindPattern(KernelData, SearchLength, CompareAgainst, SearchMask);
	if (PatternInKernelData == NULL) {
		printf("[-] Failed to find pattern in kernel data, search size = %llu bytes, mask = %s, search address = %p\n", SearchLength, SearchMask, KernelData);
		free(KernelData);
		return NULL;
	}
	PatternAddress = (PVOID)((ULONG64)SearchAddress - (ULONG64)KernelData + (ULONG64)PatternInKernelData);  // Actual address = actual base - relative base + relative offset address
	return PatternAddress;
}


PVOID VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(HANDLE* DeviceHandle, const char* SectionName, PVOID ModulePointer, BYTE CompareAgainst[], const char* SearchMask) {
	ULONG SectionSize = 0;
	PVOID MatchingSection = VulnurableDriver::HelperFunctions::FindSectionFromKernelModule(DeviceHandle, SectionName, ModulePointer, &SectionSize);
	if (MatchingSection != NULL) {
		return VulnurableDriver::HelperFunctions::FindPatternInKernelModule(DeviceHandle, MatchingSection, SectionSize, CompareAgainst, SearchMask);
	}
	printf("[-] Could not find section address to find pattern in (section name = %s, system module pointer = %p)\n", SectionName, ModulePointer);
	return NULL;
}


PVOID VulnurableDriver::HelperFunctions::RelativeAddressToActual(HANDLE* DeviceHandle, PVOID Instruction, ULONG Offset, ULONG InstructionSize) {
	LONG RelativeInstructionOffset = 0;
	if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress(Instruction, Offset, TRUE), &RelativeInstructionOffset, sizeof(RelativeInstructionOffset))) {
		return NULL;
	}
	return general::ManipulateAddress(Instruction, InstructionSize + RelativeInstructionOffset, TRUE);  // relative instruction + instruction size + relative instruction offset (actual address)
}