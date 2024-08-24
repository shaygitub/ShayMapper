#pragma once

#if defined(DISABLE_OUTPUT)
	#define Log(content) 
#else
	#define Log(content) std::wcout << content
#endif


#include <Windows.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>

#include "nt.hpp"
#include "intel_driver.hpp"

namespace utils
{
	bool IsRunning(LPCWSTR SymbolicLink);
	std::wstring GetDriverNameW(char* DriverPath);
	std::wstring GetDriverPath(char* DriverPath);
	std::wstring GetFullTempPath();
	bool ReadFileToMemory(const std::wstring& file_path, std::vector<uint8_t>* out_buffer);
	bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size);
	uint64_t GetKernelModuleAddress(const std::string& module_name);
	PVOID FindSection(const char* sectionName, uintptr_t modulePtr, PULONG size);
}

namespace memory_utils {
	BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
	uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);
	uintptr_t FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	uintptr_t FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size);
	uintptr_t FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask);
}

namespace kernel_api
{
	uint64_t MmAllocateIndependentPagesEx(uint32_t size);
	bool MmFreeIndependentPages(uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect);
	uint64_t AllocatePool(nt::POOL_TYPE pool_type, uint64_t size);
	uint64_t MmAllocatePagesForMdl(LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes);
	uint64_t MmMapLockedPagesSpecifyCache(uint64_t pmdl, nt::KPROCESSOR_MODE AccessMode, nt::MEMORY_CACHING_TYPE CacheType, uint64_t RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority);
	bool MmProtectMdlSystemAddress(uint64_t MemoryDescriptorList, ULONG NewProtect);
	bool MmUnmapLockedPages(uint64_t BaseAddress, uint64_t pmdl);
	bool MmFreePagesFromMdl(uint64_t MemoryDescriptorList);
	bool FreePool(uint64_t address);
	bool ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(PVOID Resource);
}