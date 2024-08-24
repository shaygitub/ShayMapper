#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <memory>
#include <stdint.h>

#include "utils.hpp"

typedef struct _RTL_BALANCED_LINKS {
	struct _RTL_BALANCED_LINKS* Parent;
	struct _RTL_BALANCED_LINKS* LeftChild;
	struct _RTL_BALANCED_LINKS* RightChild;
	CHAR Balance;
	UCHAR Reserved[3];
} RTL_BALANCED_LINKS;
typedef RTL_BALANCED_LINKS* PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE {
	RTL_BALANCED_LINKS BalancedRoot;
	PVOID OrderedPointer;
	ULONG WhichOrderedElement;
	ULONG NumberGenericTableElements;
	ULONG DepthOfTree;
	PVOID RestartKey;
	ULONG DeleteCount;
	PVOID CompareRoutine;
	PVOID AllocateRoutine;
	PVOID FreeRoutine;
	PVOID TableContext;
} RTL_AVL_TABLE, * PRTL_AVL_TABLE;

typedef struct _PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
} PiDDBCacheEntry, * PPiDDBCacheEntry;

typedef struct _HashBucketEntry
{
	struct _HashBucketEntry* Next;
	UNICODE_STRING DriverName;
	ULONG CertHash[5];
} HashBucketEntry, * PHashBucketEntry;

namespace stealth_functions {
	bool ClearMmUnloadedDrivers();
	bool ClearKernelHashBucketList();
	bool ClearWdFilterDriverList();
	bool ClearPiDDBCacheTable(uintptr_t* PiDDBLockPtr, uintptr_t* PiDDBCacheTablePtr, ULONG DriverTimestamp);

	PiDDBCacheEntry* LookupEntry(RTL_AVL_TABLE* PiDDBCacheTable, ULONG timestamp, const wchar_t* name);
	BOOLEAN RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(RTL_AVL_TABLE* Table, PVOID Buffer);
}