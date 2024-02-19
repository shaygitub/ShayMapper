#pragma once
#include "utils.h"


namespace UnsignedDriver {
	BOOL ResolveImports(HANDLE* VulnDriverHandle, PVOID KernelBaseAddress, PVOID ImageBase, PIMAGE_DOS_HEADER ImageDosHeader);
	BOOL ResolveRelocations(HANDLE* VulnDriverHandle, PVOID KernelBaseAddress, ULONG64 RvaToActualDelta, PVOID ImageBase, PIMAGE_DOS_HEADER ImageDosHeader);
	BOOL FixSecurityCookie(PVOID LocalImageBase, PVOID KernelImageBase, PIMAGE_DOS_HEADER ImageDosHeader);
	PVOID LoadDriver(HANDLE* VulnDeviceHandle, PVOID KernelBaseAddress, PVOID UnsignedDataPool, ULONG PoolType, NTSTATUS* ReturnStatus);
}