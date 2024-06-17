#pragma once

#include "pch.h"
#include "IrpHookDetectorCommon.h"
#include "WindowsTypes.hpp"

#define FreeMemory(ptr) \
	if (ptr) { \
		ExFreePoolWithTag(ptr, DRIVER_TAG); \
		ptr = NULL; \
	}

/*
* Description:
* AllocateMemory is responsible for allocating memory with the right function depends on the windows version.
*
* Parameters:
* @size [_In_ SIZE_T] -- Size to allocate.
* @paged [_In_ bool]  -- Whether to allocate paged or non-paged memory.
*
* Returns:
* @ptr  [PVOID]  -- Allocated pointer on success else NULL.
*/
inline PVOID AllocateMemory(_In_ SIZE_T size, _In_ bool paged = true) {
	if (AllocatePool2 && WindowsBuildNumber >= WIN_2004) {
		return paged ? ((tExAllocatePool2)AllocatePool2)(POOL_FLAG_PAGED, size, DRIVER_TAG) :
			((tExAllocatePool2)AllocatePool2)(POOL_FLAG_NON_PAGED_EXECUTE, size, DRIVER_TAG);
	}

#pragma warning( push )
#pragma warning( disable : 4996)
	return paged ? ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG) :
		ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
#pragma warning( pop )
}