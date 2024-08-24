#include "utils.hpp"

std::wstring utils::GetFullTempPath() {
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
		Log(L"[-] Failed to get temp path" << std::endl);
		return L"";
	}
	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
		temp_directory[wcslen(temp_directory) - 1] = 0x0;

	return std::wstring(temp_directory);
}

std::wstring utils::GetDriverNameW(char* DriverPath) {
	if (DriverPath == NULL) {
		return NULL;
	}
	std::string t(DriverPath);
	std::wstring name(t.begin(), t.end());
	return name;
}

std::wstring utils::GetDriverPath(char* DriverPath) {
	std::wstring temp = utils::GetFullTempPath();
	if (temp.empty()) {
		return L"";
	}
	return temp + L"\\" + utils::GetDriverNameW(DriverPath);
}

bool utils::IsRunning(LPCWSTR SymbolicLink) {
	const HANDLE file_handle = CreateFileW(SymbolicLink, FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_handle);
		return true;
	}
	return false;
}

bool utils::ReadFileToMemory(const std::wstring& file_path, std::vector<uint8_t>* out_buffer) {
	std::ifstream file_ifstream(file_path, std::ios::binary);

	if (!file_ifstream)
		return false;

	out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
	file_ifstream.close();

	return true;
}

bool utils::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size) {
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size)) {
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}

uint64_t utils::GetKernelModuleAddress(const std::string& module_name) {
	void* buffer = nullptr;
	DWORD buffer_size = 0;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status)) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);
	if (!modules)
		return 0;

	for (auto i = 0u; i < modules->NumberOfModules; ++i) {
		const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

		if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
		{
			const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}


PVOID utils::FindSection(const char* sectionName, uintptr_t modulePtr, PULONG size) {
	size_t namelength = strlen(sectionName);
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(modulePtr + ((PIMAGE_DOS_HEADER)modulePtr)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, sectionName, namelength) == 0 &&
			namelength == strlen((char*)section->Name)) {
			if (!section->VirtualAddress) {
				return 0;
			}
			if (size) {
				*size = section->Misc.VirtualSize;
			}
			return (PVOID)(modulePtr + section->VirtualAddress);
		}
	}
	return 0;
}


BOOLEAN memory_utils::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;
	return (*szMask) == 0;
}

uintptr_t memory_utils::FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	size_t max_len = dwLen - strlen(szMask);
	for (uintptr_t i = 0; i < max_len; i++)
		if (memory_utils::bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (uintptr_t)(dwAddress + i);
	return 0;
}


PVOID memory_utils::ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = 0;
	if (!DriverMapper::ReadMemory(Instr + OffsetOffset, &RipOffset, sizeof(LONG))) {
		return nullptr;
	}
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}


uintptr_t memory_utils::FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	if (!dwAddress) {
		Log(L"[-] No module address to find pattern" << std::endl);
		return 0;
	}

	if (dwLen > 1024 * 1024 * 1024) { //if read is > 1GB
		Log(L"[-] Can't find pattern, Too big section" << std::endl);
		return 0;
	}

	auto sectionData = std::make_unique<BYTE[]>(dwLen);
	if (!DriverMapper::ReadMemory(dwAddress, sectionData.get(), dwLen)) {
		Log(L"[-] Read failed in FindPatternAtKernel" << std::endl);
		return 0;
	}

	auto result = memory_utils::FindPattern((uintptr_t)sectionData.get(), dwLen, bMask, szMask);

	if (result <= 0) {
		return 0;
	}
	result = dwAddress - (uintptr_t)sectionData.get() + result;
	return result;
}


uintptr_t memory_utils::FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size) {
	if (!modulePtr)
		return 0;
	BYTE headers[0x1000];
	if (!DriverMapper::ReadMemory(modulePtr, headers, 0x1000)) {
		Log(L"[-] Can't read module headers" << std::endl);
		return 0;
	}
	ULONG sectionSize = 0;
	uintptr_t section = (uintptr_t)utils::FindSection(sectionName, (uintptr_t)headers, &sectionSize);
	if (!section || !sectionSize) {
		Log(L"[-] Can't find section" << std::endl);
		return 0;
	}
	if (size)
		*size = sectionSize;
	return section - (uintptr_t)headers + modulePtr;
}


uintptr_t memory_utils::FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask) {
	ULONG sectionSize = 0;
	uintptr_t section = memory_utils::FindSectionAtKernel(sectionName, modulePtr, &sectionSize);
	return memory_utils::FindPatternAtKernel(section, sectionSize, bMask, szMask);
}


bool kernel_api::MmFreePagesFromMdl(uint64_t MemoryDescriptorList)
{
	static uint64_t kernel_MmFreePagesFromMdl =
		DriverMapper::GetKernelModuleExport(*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), "MmFreePagesFromMdl");

	if (!kernel_MmFreePagesFromMdl)
	{
		Log(L"[!] Failed to find MmFreePagesFromMdl" << std::endl);
		return 0;
	}

	void* result;
	return DriverMapper::CallKernelFunction(&result, kernel_MmFreePagesFromMdl, MemoryDescriptorList);
}


uint64_t kernel_api::AllocatePool(nt::POOL_TYPE pool_type, uint64_t size) {
	if (!size)
		return 0;

	static uint64_t kernel_ExAllocatePool = DriverMapper::GetKernelModuleExport(*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), "ExAllocatePoolWithTag");

	if (!kernel_ExAllocatePool) {
		Log(L"[!] Failed to find ExAllocatePool" << std::endl);
		return 0;
	}

	uint64_t allocated_pool = 0;

	if (!DriverMapper::CallKernelFunction(&allocated_pool, kernel_ExAllocatePool, pool_type, size, 'BwtE')) //Changed pool tag since an extremely meme checking diff between allocation size and average for detection....
		return 0;

	return allocated_pool;
}


bool kernel_api::FreePool(uint64_t address) {
	if (!address)
		return 0;

	static uint64_t kernel_ExFreePool = DriverMapper::GetKernelModuleExport(*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), "ExFreePool");

	if (!kernel_ExFreePool) {
		Log(L"[!] Failed to find ExAllocatePool" << std::endl);
		return 0;
	}

	return DriverMapper::CallKernelFunction<void>(nullptr, kernel_ExFreePool, address);
}


uint64_t kernel_api::MmAllocateIndependentPagesEx(uint32_t size)
{
	uint64_t allocated_pages{};

	static uint64_t kernel_MmAllocateIndependentPagesEx = 0;

	if (!kernel_MmAllocateIndependentPagesEx)
	{
		kernel_MmAllocateIndependentPagesEx = memory_utils::FindPatternInSectionAtKernel((char*)"PAGELK", *((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")),
			(BYTE*)"\xE8\x00\x00\x00\x00\x48\x8B\xF0\x48\x85\xC0\x0F\x84\x00\x00\x00\x00\x44\x8B\xC5\x33\xD2\x48\x8B\xC8\xE8\x00\x00\x00\x00\x48\x8D\x46\x3F\x48\x83\xE0\xC0",
			(char*)"x????xxxxxxxx????xxxxxxxxx????xxxxxxxx");
		if (!kernel_MmAllocateIndependentPagesEx) {
			Log(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}

		kernel_MmAllocateIndependentPagesEx = (uint64_t)memory_utils::ResolveRelativeAddress((PVOID)kernel_MmAllocateIndependentPagesEx, 1, 5);
		if (!kernel_MmAllocateIndependentPagesEx) {
			Log(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}
	}

	if (!DriverMapper::CallKernelFunction(&allocated_pages, kernel_MmAllocateIndependentPagesEx, size, -1, 0, 0))
		return 0;

	return allocated_pages;
}


bool kernel_api::MmFreeIndependentPages(uint64_t address, uint32_t size)
{
	static uint64_t kernel_MmFreeIndependentPages = 0;

	if (!kernel_MmFreeIndependentPages)
	{
		kernel_MmFreeIndependentPages = memory_utils::FindPatternInSectionAtKernel("PAGE", *((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")),
			(BYTE*)"\xBA\x00\x60\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\xF0\xFF\xFF",
			(char*)"xxxxxxxxx????xxxxxxx");
		if (!kernel_MmFreeIndependentPages) {
			Log(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
			return false;
		}

		kernel_MmFreeIndependentPages += 8;

		kernel_MmFreeIndependentPages = (uint64_t)memory_utils::ResolveRelativeAddress((PVOID)kernel_MmFreeIndependentPages, 1, 5);
		if (!kernel_MmFreeIndependentPages) {
			Log(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
			return false;
		}
	}

	uint64_t result{};
	return DriverMapper::CallKernelFunction(&result, kernel_MmFreeIndependentPages, address, size);
}


BOOLEAN kernel_api::MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect)
{
	if (!address)
	{
		Log(L"[!] Invalid address passed to MmSetPageProtection" << std::endl);
		return FALSE;
	}

	static uint64_t kernel_MmSetPageProtection = 0;

	if (!kernel_MmSetPageProtection)
	{
		kernel_MmSetPageProtection = memory_utils::FindPatternInSectionAtKernel("PAGE", *((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")),
			(BYTE*)"\x41\xB8\x00\x00\x00\x00\x48\x00\x00\x00\x8B\x00\xE8\x00\x00\x00\x00\x84\xC0\x74\x09\x48\x81\xEB\x00\x00\x00\x00\xEB",
			(char*)"xx????x???x?x????xxxxxxx????x");
		if (!kernel_MmSetPageProtection) {
			Log(L"[!] Failed to find MmSetPageProtection" << std::endl);
			return FALSE;
		}

		kernel_MmSetPageProtection += 12;

		kernel_MmSetPageProtection = (uint64_t)memory_utils::ResolveRelativeAddress((PVOID)kernel_MmSetPageProtection, 1, 5);
		if (!kernel_MmSetPageProtection) {
			Log(L"[!] Failed to find MmSetPageProtection" << std::endl);
			return FALSE;
		}
	}

	BOOLEAN set_prot_status{};
	if (!DriverMapper::CallKernelFunction(&set_prot_status, kernel_MmSetPageProtection, address, size, new_protect))
		return FALSE;

	return set_prot_status;
}


uint64_t kernel_api::MmAllocatePagesForMdl(LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes)
{
	static uint64_t kernel_MmAllocatePagesForMdl = DriverMapper::GetKernelModuleExport(*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), "MmAllocatePagesForMdl");

	if (!kernel_MmAllocatePagesForMdl)
	{
		Log(L"[!] Failed to find MmAlocatePagesForMdl" << std::endl);
		return 0;
	}

	uint64_t allocated_pages = 0;

	if (!DriverMapper::CallKernelFunction(&allocated_pages, kernel_MmAllocatePagesForMdl, LowAddress, HighAddress, SkipBytes, TotalBytes))
		return 0;

	return allocated_pages;
}


uint64_t kernel_api::MmMapLockedPagesSpecifyCache(uint64_t pmdl, nt::KPROCESSOR_MODE AccessMode, nt::MEMORY_CACHING_TYPE CacheType, uint64_t RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority)
{
	static uint64_t kernel_MmMapLockedPagesSpecifyCache = DriverMapper::GetKernelModuleExport(*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), "MmMapLockedPagesSpecifyCache");

	if (!kernel_MmMapLockedPagesSpecifyCache)
	{
		Log(L"[!] Failed to find MmMapLockedPagesSpecifyCache" << std::endl);
		return 0;
	}

	uint64_t starting_address = 0;

	if (!DriverMapper::CallKernelFunction(&starting_address, kernel_MmMapLockedPagesSpecifyCache, pmdl, AccessMode, CacheType, RequestedAddress, BugCheckOnFailure, Priority))
		return 0;

	return starting_address;
}


bool kernel_api::MmProtectMdlSystemAddress(uint64_t MemoryDescriptorList, ULONG NewProtect)
{
	static uint64_t kernel_MmProtectMdlSystemAddress = DriverMapper::GetKernelModuleExport(*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), "MmProtectMdlSystemAddress");

	if (!kernel_MmProtectMdlSystemAddress)
	{
		Log(L"[!] Failed to find MmProtectMdlSystemAddress" << std::endl);
		return 0;
	}

	NTSTATUS status;

	if (!DriverMapper::CallKernelFunction(&status, kernel_MmProtectMdlSystemAddress, MemoryDescriptorList, NewProtect))
		return 0;

	return NT_SUCCESS(status);
}


bool kernel_api::MmUnmapLockedPages(uint64_t BaseAddress, uint64_t pmdl)
{
	static uint64_t kernel_MmUnmapLockedPages = DriverMapper::GetKernelModuleExport(*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), "MmUnmapLockedPages");

	if (!kernel_MmUnmapLockedPages)
	{
		Log(L"[!] Failed to find MmUnmapLockedPages" << std::endl);
		return 0;
	}

	void* result;
	return DriverMapper::CallKernelFunction(&result, kernel_MmUnmapLockedPages, BaseAddress, pmdl);
}


bool kernel_api::ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait) {
	if (!Resource)
		return 0;

	static uint64_t kernel_ExAcquireResourceExclusiveLite = DriverMapper::GetKernelModuleExport(*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), "ExAcquireResourceExclusiveLite");

	if (!kernel_ExAcquireResourceExclusiveLite) {
		Log(L"[!] Failed to find ExAcquireResourceExclusiveLite" << std::endl);
		return 0;
	}

	BOOLEAN out;

	return (DriverMapper::CallKernelFunction(&out, kernel_ExAcquireResourceExclusiveLite, Resource, wait) && out);
}


bool kernel_api::ExReleaseResourceLite(PVOID Resource) {
	if (!Resource)
		return false;

	static uint64_t kernel_ExReleaseResourceLite = DriverMapper::GetKernelModuleExport(*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), "ExReleaseResourceLite");

	if (!kernel_ExReleaseResourceLite) {
		Log(L"[!] Failed to find ExReleaseResourceLite" << std::endl);
		return false;
	}

	return DriverMapper::CallKernelFunction<void>(nullptr, kernel_ExReleaseResourceLite, Resource);
}