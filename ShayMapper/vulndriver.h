#pragma once
#include "additional_nt.h"

namespace VulnurableDriver {
	namespace IoctlFunctions {
		BOOL MemoryCopy(HANDLE* DeviceHandle, PVOID DestinationAddress, PVOID SourceAddress, ULONG64 CopySize);  // Case number 0x33
		BOOL MemoryWrite(HANDLE* DeviceHandle, PVOID WriteToAddress, PVOID WriteFromAddress, ULONG64 WriteSize);  // Macro for writing with MemoryCopy()
		BOOL MemoryRead(HANDLE* DeviceHandle, PVOID ReadFromAddress, PVOID ReadIntoAddress, ULONG64 ReadSize);  // Macro for reading with MemoryCopy()
		BOOL MemoryFill(HANDLE* DeviceHandle, PVOID FillAddress, ULONG FillValue, ULONG64 FillSize);  // Case number 0x30
		BOOL VirtualToPhysical(HANDLE* DeviceHandle, PVOID VirtualAddress, PVOID* PhysicalAddress);  // Case number 0x25
		PVOID MapIoSpace(HANDLE* DeviceHandle, PVOID PhysicalAddress, ULONG MappingSize);  // Case number 0x19
		BOOL UnmapIoSpace(HANDLE* DeviceHandle, PVOID MappingAddress, ULONG MappingSize);  // Case number 0x1A
	}
	namespace HelperFunctions {
		BOOL IsAlreadyRunning(const char* SymbolicLink);  // Checked by the device handle, not the file/full path handle
		PVOID FindSectionFromKernelModule(HANDLE* DeviceHandle, const char* SectionName, PVOID ModulePointer, ULONG* SectionSize);
		PVOID FindPatternInKernelModule(HANDLE* DeviceHandle, PVOID SearchAddress, ULONG64 SearchLength, BYTE CompareAgainst[], const char* SearchMask);
		PVOID FindPatternInSectionOfKernelModule(HANDLE* DeviceHandle, const char* SectionName, PVOID ModulePointer, BYTE CompareAgainst[], const char* SearchMask);
		PVOID RelativeAddressToActual(HANDLE* DeviceHandle, PVOID Instruction, ULONG Offset, ULONG InstructionSize);
	}
	namespace PersistenceFunctions {
		nt::PPiDDBCacheEntry LookupEntryInPiDDBTable(HANDLE* DeviceHandle, PVOID KernelBaseAddress, nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG EntryTimestamp,
			LPCWSTR DriverName);  // PiDDBCacheTable entry is added for driver when loaded
		NTSTATUS CleanPiDDBCacheTable(HANDLE* DeviceHandle, PVOID KernelBaseAddress, LPCWSTR DriverName,
			PVOID* ActualPiDDBLock, nt::PRTL_AVL_TABLE* ActualPiDDBCacheTable, ULONG DriverTimestamp);  // PiDDB table holds data about loaded drivers
		NTSTATUS CleanKernelHashBucketList(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID* ActualHashBucketList, PVOID* ActualHashBucketLock,
			LPCWSTR DriverName, LPCWSTR DriverFullPath);   // Hash bucket list holds information about a driver, iterate over it and delete entry like process DKOM
		NTSTATUS CleanWdFilterDriverList(HANDLE* DeviceHandle, PVOID KernelBaseAddress, LPCWSTR DriverName,
			PVOID* ActualDriversList, PVOID* ActualDriversCount, PVOID* ActualFreeDriverInfo);  // Clear the loaded driver list of wdfilter.sys
		BOOL CleanMmUnloadedDrivers(HANDLE* DeviceHandle, PVOID KernelBaseAddress, LPCWSTR DriverName);  // List of unloaded documented drivers
	}
	NTSTATUS LoadVulnurableDriver(HANDLE* VulnHandle, LPCWSTR VulnDriverName, const char* SymbolicLink, const char* ServiceName, const BYTE DriverData[], ULONG DriverTimestamp, PVOID* MainKernelBase, ULONG64 VulnSize);

}


namespace VulnurableService {
	NTSTATUS UnloadVulnurableDriver(HANDLE* VulnHandle, char VulnDriverPath[], const char* ServiceName);
	NTSTATUS RegisterVulnurableDriver(char VulnDriverPath[], const char* ServiceName);
	NTSTATUS StartVulnurableDriver(const char* ServiceName);
}