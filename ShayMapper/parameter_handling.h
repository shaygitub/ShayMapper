#pragma once
#include <Windows.h>
#include <iostream>
#define INDEPENDENT_PAGES 0x1000
#define REGULAR_NONPAGED_POOL 0x2000
#define DESCRIPTOR_MODULE 0x8000


BOOL ValidateParameters(int argc, char* argv[], ULONG* PoolType) {
	char DriverExtension[5] = { 0 };
	struct stat CheckExists = { 0 };
	if (argc < 2 || argc > 3) {
		printf("[-] USAGE: ShayMapper.exe [path to driver] [(optional) -Ind/-Reg/-Mdl]\n");
		return FALSE;
	}
	if (strlen(argv[1]) < 5) {
		printf("[-] USAGE: ShayMapper.exe [path to driver] [(optional) -Ind/-Reg/-Mdl]\n");
		return FALSE;
	}
	RtlCopyMemory(DriverExtension, (PVOID)((ULONG64)argv[1] + strlen(argv[1]) - 4), 5);
	if (strcmp(DriverExtension, ".sys") != 0) {
		printf("[-] USAGE: ShayMapper.exe [path to driver] [(optional) -Ind/-Reg/-Mdl]\n");
		return FALSE;
	}
	if (stat(argv[1], &CheckExists) != 0) {
		printf("[-] USAGE: ShayMapper.exe [EXISTING path to driver] [(optional) -Ind/-Reg/-Mdl]\n");
		return FALSE;
	}
	if (argc == 3) {
		if (strcmp(argv[2], "-Ind") == 0) {
			*PoolType = INDEPENDENT_PAGES;
		}
		else if (strcmp(argv[2], "-Reg") == 0) {
			*PoolType = REGULAR_NONPAGED_POOL;
		}
		else if (strcmp(argv[2], "-Mdl") == 0) {
			*PoolType = DESCRIPTOR_MODULE;
		}
		else {
			printf("[-] USAGE: ShayMapper.exe [path to driver] [(optional) -Ind/-Reg/-Mdl ONLY]\n");
			return FALSE;
		}
	}
	else {
		*PoolType = REGULAR_NONPAGED_POOL;
	}
	printf("[+] Mapping driver from path %s, allocation type is 0x%x\n", argv[1], *PoolType);
	return TRUE;
}