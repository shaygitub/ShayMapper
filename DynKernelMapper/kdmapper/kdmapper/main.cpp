#ifndef KDLIBMODE

#include <Windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include "kdmapper.hpp"


DWORD getParentProcess()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
	}
	return ppid;
}


//Help people that don't understand how to open a console
void PauseIfParentIsExplorer() {
	DWORD explorerPid = 0;
	GetWindowThreadProcessId(GetShellWindow(), &explorerPid);
	DWORD parentPid = getParentProcess();
	if (parentPid == explorerPid) {
		Log(L"[+] Pausing to allow for debugging" << std::endl);
		Log(L"[+] Press enter to close" << std::endl);
		std::cin.get();
	}
}


void DriverMapper::DriverCleanup() {
	HANDLE* LocalRunningDrivers =
		(HANDLE*)DriverMapper::GetLoaderResource(L"RunningDrivers");
	DriverMapper::SYMBOLICLINK* LocalRunningSymbolicLinks =
		(DriverMapper::SYMBOLICLINK*)DriverMapper::GetLoaderResource(L"RunningSymbolicLinks");
	ULONG64* LocalRunningDriversCount = (ULONG64*)DriverMapper::GetLoaderResource(L"RunningDriversCount");
	DriverMapper::FILE_NAME* LocalDriverNames =
		(DriverMapper::FILE_NAME*)DriverMapper::GetLoaderResource(L"DriverNames");
	for (int RunningDriver = 0; RunningDriver < *LocalRunningDriversCount; RunningDriver++) {
		if (!DriverMapper::Unload(LocalRunningDrivers[RunningDriver],
			LocalDriverNames[*LocalRunningDriversCount].DriverName)) {
			Log(L"[-] Warning failed to fully unload vulnerable driver " <<
				LocalRunningSymbolicLinks[*LocalRunningDriversCount].SymbolicLink << std::endl);
			PauseIfParentIsExplorer();
			break;
		}
	}
}


LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		Log(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
	else
		Log(L"[!!] Crash" << std::endl);
	DriverMapper::DriverCleanup();
	return EXCEPTION_EXECUTE_HANDLER;
}


int paramExists(const int argc, wchar_t** argv, const wchar_t* param) {
	size_t plen = wcslen(param);
	for (int i = 1; i < argc; i++) {
		if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') { // with slash
			return i;
		}
		else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') { // with double dash
			return i;
		}
	}
	return -1;
}

void help() {
	Log(L"\r\n\r\n[!] Incorrect Usage!" << std::endl);
	Log(L"[+] Usage: kdmapper.exe [--free][--mdl][--PassAllocationPtr] driver" << std::endl);
}

bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize, ULONG64 mdlptr) {
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(allocationPtr);
	UNREFERENCED_PARAMETER(allocationSize);
	UNREFERENCED_PARAMETER(mdlptr);
	Log("[+] Callback example called" << std::endl);
	
	/*
	This callback occurs before call driver entry and
	can be usefull to pass more customized params in 
	the last step of the mapping procedure since you 
	know now the mapping address and other things
	*/
	return true;
}


int wmain(const int argc, wchar_t** argv) {
	SetUnhandledExceptionFilter(SimplestCrashHandler);
	uintptr_t PiDDBLockPtr;
	uintptr_t PiDDBCacheTablePtr;
	HANDLE IntelDriverHandle = INVALID_HANDLE_VALUE;

	bool free = paramExists(argc, argv, L"free") > 0;
	bool mdlMode = paramExists(argc, argv, L"mdl") > 0;
	bool indPagesMode = paramExists(argc, argv, L"indPages") > 0;
	bool passAllocationPtr = paramExists(argc, argv, L"PassAllocationPtr") > 0;

	if (free) {
		Log(L"[+] Free pool memory after usage enabled" << std::endl);
	}

	if (mdlMode) {
		Log(L"[+] Mdl memory usage enabled" << std::endl);
	}

	if (indPagesMode) {
		Log(L"[+] Allocate Independent Pages mode enabled" << std::endl);
	}

	if (passAllocationPtr) {
		Log(L"[+] Pass Allocation Ptr as first param enabled" << std::endl);
	}

	int drvIndex = -1;
	for (int i = 1; i < argc; i++) {
		if (std::filesystem::path(argv[i]).extension().string().compare(".sys") == 0) {
			drvIndex = i;
			break;
		}
	}

	if (drvIndex <= 0) {
		help();
		return -1;
	}

	const std::wstring driver_path = argv[drvIndex];

	if (!std::filesystem::exists(driver_path)) {
		Log(L"[-] File " << driver_path << L" doesn't exist" << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}


	// Load the intel vulnerable driver:
	IntelDriverHandle = DriverMapper::LoadVulnerableDriver(INTELDRIVER_SYMLINK, &PiDDBLockPtr, &PiDDBCacheTablePtr,
		intel_driver::IntelDriverTimestamp);
	if (IntelDriverHandle == INVALID_HANDLE_VALUE) {
		DriverMapper::DriverCleanup();
		PauseIfParentIsExplorer();
		return -1;
	}

	std::vector<uint8_t> raw_image = { 0 };
	if (!utils::ReadFileToMemory(driver_path, &raw_image)) {
		Log(L"[-] Failed to read image to memory" << std::endl);
		DriverMapper::DriverCleanup();
		PauseIfParentIsExplorer();
		return -1;
	}

	kdmapper::AllocationMode mode = kdmapper::AllocationMode::AllocatePool;

	if (mdlMode && indPagesMode) {
		Log(L"[-] Too many allocation modes" << std::endl);
		DriverMapper::DriverCleanup();
		PauseIfParentIsExplorer();
		return -1;
	}
	else if (mdlMode) {
		mode = kdmapper::AllocationMode::AllocateMdl;
	}
	else if (indPagesMode) {
		mode = kdmapper::AllocationMode::AllocateIndependentPages;
	}

	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(raw_image.data(), 0, 0, free, true, mode, passAllocationPtr, callbackExample, &exitCode)) {
		Log(L"[-] Failed to map " << driver_path << std::endl);
		DriverMapper::DriverCleanup();
		PauseIfParentIsExplorer();
		return -1;
	}

	DriverMapper::DriverCleanup();
	Log(L"[+] success" << std::endl);
}

#endif