#include "stealth_driver.hpp"


bool stealth_functions::ClearMmUnloadedDrivers() {
	ULONG buffer_size = 0;
	void* buffer = nullptr;
	HANDLE* LocalRunningDrivers = NULL;
	ULONG64 LocalRunningDriversCount = 0;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status) || buffer == 0)
	{
		if (buffer != 0)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}

	uint64_t object = 0;

	auto system_handle_inforamtion = static_cast<nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);

	for (auto i = 0u; i < system_handle_inforamtion->HandleCount; ++i)
	{
		const nt::SYSTEM_HANDLE current_system_handle = system_handle_inforamtion->Handles[i];

		if (current_system_handle.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
			continue;

		LocalRunningDrivers = (HANDLE*)DriverMapper::GetLoaderResource(L"RunningDrivers");
		LocalRunningDriversCount = *((ULONG64*)DriverMapper::GetLoaderResource(L"RunningDriversCount"));

		if (current_system_handle.HandleValue == LocalRunningDrivers[LocalRunningDriversCount - 1])
		{
			object = reinterpret_cast<uint64_t>(current_system_handle.Object);
			break;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);

	if (!object)
		return false;

	uint64_t device_object = 0;

	if (!DriverMapper::ReadMemory(object + 0x8, &device_object, sizeof(device_object)) || !device_object) {
		Log(L"[!] Failed to find device_object" << std::endl);
		return false;
	}

	uint64_t driver_object = 0;

	if (!DriverMapper::ReadMemory(device_object + 0x8, &driver_object, sizeof(driver_object)) || !driver_object) {
		Log(L"[!] Failed to find driver_object" << std::endl);
		return false;
	}

	uint64_t driver_section = 0;

	if (!DriverMapper::ReadMemory(driver_object + 0x28, &driver_section, sizeof(driver_section)) || !driver_section) {
		Log(L"[!] Failed to find driver_section" << std::endl);
		return false;
	}

	UNICODE_STRING us_driver_base_dll_name = { 0 };

	if (!DriverMapper::ReadMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)) || us_driver_base_dll_name.Length == 0) {
		Log(L"[!] Failed to find driver name" << std::endl);
		return false;
	}

	auto unloadedName = std::make_unique<wchar_t[]>((ULONG64)us_driver_base_dll_name.Length / 2ULL + 1ULL);
	if (!DriverMapper::ReadMemory((uintptr_t)us_driver_base_dll_name.Buffer, unloadedName.get(), us_driver_base_dll_name.Length)) {
		Log(L"[!] Failed to read driver name" << std::endl);
		return false;
	}

	us_driver_base_dll_name.Length = 0; //MiRememberUnloadedDriver will check if the length > 0 to save the unloaded driver

	if (!DriverMapper::WriteMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name))) {
		Log(L"[!] Failed to write driver name length" << std::endl);
		return false;
	}

	Log(L"[+] MmUnloadedDrivers Cleaned: " << unloadedName << std::endl);
	return true;
}


bool stealth_functions::ClearKernelHashBucketList() {
	ULONG64* LocalRunningDriversCount = (ULONG64*)DriverMapper::GetLoaderResource(L"RunningDriversCount");
	DriverMapper::FILE_NAME* LocalDriverNames =
		(DriverMapper::FILE_NAME*)DriverMapper::GetLoaderResource(L"DriverNames");

	uint64_t ci = utils::GetKernelModuleAddress("ci.dll");
	if (!ci) {
		Log(L"[-] Can't Find ci.dll module address" << std::endl);
		return false;
	}

	//Thanks @KDIo3 and @Swiftik from UnknownCheats
	auto sig = memory_utils::FindPatternInSectionAtKernel("PAGE", ci, PUCHAR("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"), "xxx????x?xxxxxxx");
	if (!sig) {
		Log(L"[-] Can't Find g_KernelHashBucketList" << std::endl);
		return false;
	}
	auto sig2 = memory_utils::FindPatternAtKernel((uintptr_t)sig - 50, 50, PUCHAR("\x48\x8D\x0D"), "xxx");
	if (!sig2) {
		Log(L"[-] Can't Find g_HashCacheLock" << std::endl);
		return false;
	}
	const auto g_KernelHashBucketList = memory_utils::ResolveRelativeAddress((PVOID)sig, 3, 7);
	const auto g_HashCacheLock = memory_utils::ResolveRelativeAddress((PVOID)sig2, 3, 7);
	if (!g_KernelHashBucketList || !g_HashCacheLock)
	{
		Log(L"[-] Can't Find g_HashCache relative address" << std::endl);
		return false;
	}

	Log(L"[+] g_KernelHashBucketList Found 0x" << std::hex << g_KernelHashBucketList << std::endl);

	if (!kernel_api::ExAcquireResourceExclusiveLite(g_HashCacheLock, true)) {
		Log(L"[-] Can't lock g_HashCacheLock" << std::endl);
		return false;
	}
	Log(L"[+] g_HashCacheLock Locked" << std::endl);

	HashBucketEntry* prev = (HashBucketEntry*)g_KernelHashBucketList;
	HashBucketEntry* entry = 0;
	if (!DriverMapper::ReadMemory((uintptr_t)prev, &entry, sizeof(entry))) {
		Log(L"[-] Failed to read first g_KernelHashBucketList entry!" << std::endl);
		if (!kernel_api::ExReleaseResourceLite(g_HashCacheLock)) {
			Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
		}
		return false;
	}
	if (!entry) {
		Log(L"[!] g_KernelHashBucketList looks empty!" << std::endl);
		if (!kernel_api::ExReleaseResourceLite(g_HashCacheLock)) {
			Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
		}
		return true;
	}

	std::wstring wdname = utils::GetDriverNameW(LocalDriverNames[*LocalRunningDriversCount].DriverName);
	std::wstring search_path = utils::GetDriverPath(LocalDriverNames[*LocalRunningDriversCount].DriverName);
	SIZE_T expected_len = (search_path.length() - 2) * 2;

	while (entry) {

		USHORT wsNameLen = 0;
		if (!DriverMapper::ReadMemory((uintptr_t)entry + offsetof(HashBucketEntry, DriverName.Length), &wsNameLen, sizeof(wsNameLen)) || wsNameLen == 0) {
			Log(L"[-] Failed to read g_KernelHashBucketList entry text len!" << std::endl);
			if (!kernel_api::ExReleaseResourceLite(g_HashCacheLock)) {
				Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}

		if (expected_len == wsNameLen) {
			wchar_t* wsNamePtr = 0;
			if (!DriverMapper::ReadMemory((uintptr_t)entry + offsetof(HashBucketEntry, DriverName.Buffer), &wsNamePtr, sizeof(wsNamePtr)) || !wsNamePtr) {
				Log(L"[-] Failed to read g_KernelHashBucketList entry text ptr!" << std::endl);
				if (!kernel_api::ExReleaseResourceLite(g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

			auto wsName = std::make_unique<wchar_t[]>((ULONG64)wsNameLen / 2ULL + 1ULL);
			if (!DriverMapper::ReadMemory((uintptr_t)wsNamePtr, wsName.get(), wsNameLen)) {
				Log(L"[-] Failed to read g_KernelHashBucketList entry text!" << std::endl);
				if (!kernel_api::ExReleaseResourceLite(g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

			size_t find_result = std::wstring(wsName.get()).find(wdname);
			if (find_result != std::wstring::npos) {
				Log(L"[+] Found In g_KernelHashBucketList: " << std::wstring(&wsName[find_result]) << std::endl);
				HashBucketEntry* Next = 0;
				if (!DriverMapper::ReadMemory((uintptr_t)entry, &Next, sizeof(Next))) {
					Log(L"[-] Failed to read g_KernelHashBucketList next entry ptr!" << std::endl);
					if (!kernel_api::ExReleaseResourceLite(g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!DriverMapper::WriteMemory((uintptr_t)prev, &Next, sizeof(Next))) {
					Log(L"[-] Failed to write g_KernelHashBucketList prev entry ptr!" << std::endl);
					if (!kernel_api::ExReleaseResourceLite(g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!kernel_api::FreePool((uintptr_t)entry)) {
					Log(L"[-] Failed to clear g_KernelHashBucketList entry pool!" << std::endl);
					if (!kernel_api::ExReleaseResourceLite(g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}
				Log(L"[+] g_KernelHashBucketList Cleaned" << std::endl);
				if (!kernel_api::ExReleaseResourceLite(g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					if (!kernel_api::ExReleaseResourceLite(g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}
				return true;
			}
		}
		prev = entry;
		//read next
		if (!DriverMapper::ReadMemory((uintptr_t)entry, &entry, sizeof(entry))) {
			Log(L"[-] Failed to read g_KernelHashBucketList next entry!" << std::endl);
			if (!kernel_api::ExReleaseResourceLite(g_HashCacheLock)) {
				Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}
	}

	if (!kernel_api::ExReleaseResourceLite(g_HashCacheLock)) {
		Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
	}
	return false;
}


bool stealth_functions::ClearWdFilterDriverList() {
	ULONG64* LocalRunningDriversCount = (ULONG64*)DriverMapper::GetLoaderResource(L"RunningDriversCount");
	DriverMapper::FILE_NAME* LocalDriverNames =
		(DriverMapper::FILE_NAME*)DriverMapper::GetLoaderResource(L"DriverNames");

	auto WdFilter = utils::GetKernelModuleAddress("WdFilter.sys");
	if (!WdFilter) {
		Log("[+] WdFilter.sys not loaded, clear skipped" << std::endl);
		return true;
	}

	auto RuntimeDriversList = memory_utils::FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05", "xxx????xx");
	if (!RuntimeDriversList) {
		Log("[!] Failed to find WdFilter RuntimeDriversList" << std::endl);
		return false;
	}

	auto RuntimeDriversCountRef = memory_utils::FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\xFF\x05\x00\x00\x00\x00\x48\x39\x11", "xx????xxx");
	if (!RuntimeDriversCountRef) {
		Log("[!] Failed to find WdFilter RuntimeDriversCount" << std::endl);
		return false;
	}

	// MpCleanupDriverInfo->MpFreeDriverInfoEx 23110
	/*
		49 8B C9                      mov     rcx, r9         ; P
		49 89 50 08                   mov     [r8+8], rdx
		E8 FB F0 FD FF                call    MpFreeDriverInfoEx
		48 8B 0D FC AA FA FF          mov     rcx, cs:qword_1C0021BF0
		E9 21 FF FF FF                jmp     loc_1C007701A
	*/
	auto MpFreeDriverInfoExRef = memory_utils::FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x49\x8B\xC9\x00\x89\x00\x08\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", "xxx?x?xx???????????x");
	if (!MpFreeDriverInfoExRef) {
		// 24010 
		/*
			48 89 4A 08                   mov     [rdx+8], rcx
			49 8B C8                      mov     rcx, r8         ; P
			E8 C3 58 FE FF                call    sub_1C0065308
			48 8B 0D 44 41 FA FF          mov     rcx, cs:qword_1C0023B90
			E9 39 FF FF FF                jmp     loc_1C007F98A
		*/
		MpFreeDriverInfoExRef = memory_utils::FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x48\x89\x4A\x00\x49\x8b\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", "xxx?xx?x???????????x");
		if (!MpFreeDriverInfoExRef) {
			Log("[!] Failed to find WdFilter MpFreeDriverInfoEx" << std::endl);
			return false;
		}
		else {
			Log("[+] Found WdFilter MpFreeDriverInfoEx with second pattern" << std::endl);
		}

	}

	MpFreeDriverInfoExRef += 0x7; // skip until call instruction

	RuntimeDriversList = (uintptr_t)memory_utils::ResolveRelativeAddress((PVOID)RuntimeDriversList, 3, 7);
	uintptr_t RuntimeDriversList_Head = RuntimeDriversList - 0x8;
	uintptr_t RuntimeDriversCount = (uintptr_t)memory_utils::ResolveRelativeAddress((PVOID)RuntimeDriversCountRef, 2, 6);
	uintptr_t RuntimeDriversArray = RuntimeDriversCount + 0x8;
	DriverMapper::ReadMemory(RuntimeDriversArray, &RuntimeDriversArray, sizeof(uintptr_t));
	uintptr_t MpFreeDriverInfoEx = (uintptr_t)memory_utils::ResolveRelativeAddress((PVOID)MpFreeDriverInfoExRef, 1, 5);

	auto ReadListEntry = [&](uintptr_t Address) -> LIST_ENTRY* { // Usefull lambda to read LIST_ENTRY
		LIST_ENTRY* Entry;
		if (!DriverMapper::ReadMemory(Address, &Entry, sizeof(LIST_ENTRY*))) return 0;
		return Entry;
		};

	for (LIST_ENTRY* Entry = ReadListEntry(RuntimeDriversList_Head);
		Entry != (LIST_ENTRY*)RuntimeDriversList_Head;
		Entry = ReadListEntry((uintptr_t)Entry + (offsetof(struct _LIST_ENTRY, Flink))))
	{
		UNICODE_STRING Unicode_String;
		if (DriverMapper::ReadMemory((uintptr_t)Entry + 0x10, &Unicode_String, sizeof(UNICODE_STRING))) {
			auto ImageName = std::make_unique<wchar_t[]>((ULONG64)Unicode_String.Length / 2ULL + 1ULL);
			if (DriverMapper::ReadMemory((uintptr_t)Unicode_String.Buffer, ImageName.get(), Unicode_String.Length)) {
				if (wcsstr(ImageName.get(), utils::GetDriverNameW(LocalDriverNames[*LocalRunningDriversCount].DriverName).c_str())) {

					//remove from RuntimeDriversArray
					bool removedRuntimeDriversArray = false;
					PVOID SameIndexList = (PVOID)((uintptr_t)Entry - 0x10);
					for (int k = 0; k < 256; k++) { // max RuntimeDriversArray elements
						PVOID value = 0;
						DriverMapper::ReadMemory(RuntimeDriversArray + (k * 8), &value, sizeof(PVOID));
						if (value == SameIndexList) {
							PVOID emptyval = (PVOID)(RuntimeDriversCount + 1); // this is not count+1 is position of cout addr+1
							DriverMapper::WriteMemory(RuntimeDriversArray + (k * 8), &emptyval, sizeof(PVOID));
							removedRuntimeDriversArray = true;
							break;
						}
					}

					if (!removedRuntimeDriversArray) {
						Log("[!] Failed to remove from RuntimeDriversArray" << std::endl);
						return false;
					}

					auto NextEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Flink)));
					auto PrevEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Blink)));

					DriverMapper::WriteMemory(uintptr_t(NextEntry) + (offsetof(struct _LIST_ENTRY, Blink)), &PrevEntry, sizeof(LIST_ENTRY::Blink));
					DriverMapper::WriteMemory(uintptr_t(PrevEntry) + (offsetof(struct _LIST_ENTRY, Flink)), &NextEntry, sizeof(LIST_ENTRY::Flink));


					// decrement RuntimeDriversCount
					ULONG current = 0;
					DriverMapper::ReadMemory(RuntimeDriversCount, &current, sizeof(ULONG));
					current--;
					DriverMapper::WriteMemory(RuntimeDriversCount, &current, sizeof(ULONG));

					// call MpFreeDriverInfoEx
					uintptr_t DriverInfo = (uintptr_t)Entry - 0x20;

					//verify DriverInfo Magic
					USHORT Magic = 0;
					DriverMapper::ReadMemory(DriverInfo, &Magic, sizeof(USHORT));
					if (Magic != 0xDA18) {
						Log("[!] DriverInfo Magic is invalid, new wdfilter version?, driver info will not be released to prevent bsod" << std::endl);
					}
					else {
						DriverMapper::CallKernelFunction<void>(nullptr, MpFreeDriverInfoEx, DriverInfo);
					}

					Log("[+] WdFilterDriverList Cleaned: " << ImageName << std::endl);
					return true;
				}
			}
		}
	}
	return false;
}


bool stealth_functions::ClearPiDDBCacheTable(uintptr_t* PiDDBLockPtr, uintptr_t* PiDDBCacheTablePtr, ULONG DriverTimestamp) { //PiDDBCacheTable added on LoadDriver
	ULONG64* LocalRunningDriversCount = (ULONG64*)DriverMapper::GetLoaderResource(L"RunningDriversCount");
	DriverMapper::FILE_NAME* LocalDriverNames =
		(DriverMapper::FILE_NAME*)DriverMapper::GetLoaderResource(L"DriverNames");
	*PiDDBLockPtr = memory_utils::FindPatternInSectionAtKernel("PAGE",
		*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x"); // 8B D8 85 C0 0F 88 ? ? ? ? 65 48 8B 04 25 ? ? ? ? 66 FF 88 ? ? ? ? B2 01 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B ? 24 update for build 22000.132
	*PiDDBCacheTablePtr = memory_utils::FindPatternInSectionAtKernel("PAGE", 
		*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), (PUCHAR)"\x66\x03\xD2\x48\x8D\x0D", "xxxxxx"); // 66 03 D2 48 8D 0D

	if (*PiDDBLockPtr == NULL) { // PiDDBLock pattern changes a lot from version 1607 of windows and we will need a second pattern if we want to keep simple as posible
		*PiDDBLockPtr = memory_utils::FindPatternInSectionAtKernel("PAGE",
			*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", "xxx????xxxxx????xxx????x????x"); // 48 8B 0D ? ? ? ? 48 85 C9 0F 85 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? E8 build 22449+ (pattern can be improved but just fine for now)
		if (*PiDDBLockPtr == NULL) {
			Log(L"[-] Warning PiDDBLock not found" << std::endl);
			return false;
		}
		Log(L"[+] PiDDBLock found with second pattern" << std::endl);
		*PiDDBLockPtr += 16; //second pattern offset
	}
	else {
		*PiDDBLockPtr += 28; //first pattern offset
	}

	if (*PiDDBCacheTablePtr == NULL) {
		Log(L"[-] Warning PiDDBCacheTable not found" << std::endl);
		return false;
	}

	Log("[+] PiDDBLock Ptr 0x" << std::hex << *PiDDBLockPtr << std::endl);
	Log("[+] PiDDBCacheTable Ptr 0x" << std::hex << *PiDDBCacheTablePtr << std::endl);

	PVOID PiDDBLock = memory_utils::ResolveRelativeAddress((PVOID)*PiDDBLockPtr, 3, 7);
	RTL_AVL_TABLE* PiDDBCacheTable = (RTL_AVL_TABLE*)memory_utils::ResolveRelativeAddress((PVOID)*PiDDBCacheTablePtr, 6, 10);

	//context part is not used by lookup, lock or delete why we should use it?

	if (!kernel_api::ExAcquireResourceExclusiveLite(PiDDBLock, true)) {
		Log(L"[-] Can't lock PiDDBCacheTable" << std::endl);
		return false;
	}
	Log(L"[+] PiDDBLock Locked" << std::endl);

	auto n = utils::GetDriverNameW(LocalDriverNames[*LocalRunningDriversCount].DriverName);

	// search our entry in the table
	PiDDBCacheEntry* pFoundEntry = (PiDDBCacheEntry*)stealth_functions::LookupEntry(PiDDBCacheTable, DriverTimestamp, n.c_str());
	if (pFoundEntry == nullptr) {
		Log(L"[-] Not found in cache" << std::endl);
		kernel_api::ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	// first, unlink from the list
	PLIST_ENTRY prev;
	if (!DriverMapper::ReadMemory((uintptr_t)pFoundEntry + (offsetof(_PiDDBCacheEntry, List.Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't get prev entry" << std::endl);
		kernel_api::ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	PLIST_ENTRY next;
	if (!DriverMapper::ReadMemory((uintptr_t)pFoundEntry + (offsetof(_PiDDBCacheEntry, List.Flink)), &next, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't get next entry" << std::endl);
		kernel_api::ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	Log("[+] Found Table Entry = 0x" << std::hex << pFoundEntry << std::endl);

	if (!DriverMapper::WriteMemory((uintptr_t)prev + (offsetof(struct _LIST_ENTRY, Flink)), &next, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't set next entry" << std::endl);
		kernel_api::ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	if (!DriverMapper::WriteMemory((uintptr_t)next + (offsetof(struct _LIST_ENTRY, Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't set prev entry" << std::endl);
		kernel_api::ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	// then delete the element from the avl table
	if (!stealth_functions::RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry)) {
		Log(L"[-] Can't delete from PiDDBCacheTable" << std::endl);
		kernel_api::ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	//Decrement delete count
	ULONG cacheDeleteCount = 0;
	DriverMapper::ReadMemory((uintptr_t)PiDDBCacheTable + (offsetof(_RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	if (cacheDeleteCount > 0) {
		cacheDeleteCount--;
		DriverMapper::WriteMemory((uintptr_t)PiDDBCacheTable + (offsetof(_RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	}

	// release the ddb resource lock
	kernel_api::ExReleaseResourceLite(PiDDBLock);

	Log(L"[+] PiDDBCacheTable Cleaned" << std::endl);

	return true;
}


PiDDBCacheEntry* stealth_functions::LookupEntry(RTL_AVL_TABLE* PiDDBCacheTable, ULONG timestamp, const wchar_t* name) {

	PiDDBCacheEntry localentry = { 0 };
	localentry.TimeDateStamp = timestamp;
	localentry.DriverName.Buffer = (PWSTR)name;
	localentry.DriverName.Length = (USHORT)(wcslen(name) * 2);
	localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;
	return (PiDDBCacheEntry*)stealth_functions::RtlLookupElementGenericTableAvl(PiDDBCacheTable, (PVOID)&localentry);
}


BOOLEAN stealth_functions::RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer) {
	if (!Table)
		return false;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl =
		DriverMapper::GetKernelModuleExport(*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), "RtlDeleteElementGenericTableAvl");

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		Log(L"[!] Failed to find RtlDeleteElementGenericTableAvl" << std::endl);
		return false;
	}

	bool out;
	return (DriverMapper::CallKernelFunction(&out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer) && out);
}


PVOID stealth_functions::RtlLookupElementGenericTableAvl(RTL_AVL_TABLE* Table, PVOID Buffer) {
	if (!Table)
		return nullptr;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = 
		DriverMapper::GetKernelModuleExport(*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), "RtlLookupElementGenericTableAvl");

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		Log(L"[!] Failed to find RtlLookupElementGenericTableAvl" << std::endl);
		return nullptr;
	}

	PVOID out;

	if (!DriverMapper::CallKernelFunction(&out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer))
		return 0;

	return out;
}