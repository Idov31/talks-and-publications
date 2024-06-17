#include "pch.h"
#include "Detector.hpp"

_IRQL_requires_(PASSIVE_LEVEL)
Detector::Detector(_In_ ULONG interval) {
	OBJECT_ATTRIBUTES objectAttributes{};
	this->detectorThread = NULL;

	this->detectorContext = (DetectorContext*)AllocateMemory(sizeof(DetectorContext), false);

	if (!detectorContext)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	
	this->detectorContext->Interval = interval;
	this->detectorContext->Running = true;
	this->detectorContext->Lock.Init();

	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	NTSTATUS status = PsCreateSystemThread(&this->detectorThread, GENERIC_ALL, &objectAttributes, NULL, NULL, (PKSTART_ROUTINE)&Detect, detectorContext);

	if (!NT_SUCCESS(status))
		ExRaiseStatus(status);
	Print(DRIVER_PREFIX "Thread starting\n");
}

_IRQL_requires_(PASSIVE_LEVEL)
Detector::~Detector() {
	if (detectorContext->Running)
		StopThread();
	Print(DRIVER_PREFIX "Thread stopped\n");

	if (this->detectorThread) {
		NTSTATUS status = ZwWaitForSingleObject(this->detectorThread, FALSE, NULL);

		if (!NT_SUCCESS(status))
			Print(DRIVER_PREFIX "Failed to wait to the thread to terminate (0x%08X)\n", status);
		ZwClose(this->detectorThread);
	}

	if (this->detectorContext)
		ExFreePoolWithTag(this->detectorContext, DRIVER_TAG);
}

_IRQL_requires_(PASSIVE_LEVEL)
void Detector::StopThread() {
	AutoLock lock(this->detectorContext->Lock);
	detectorContext->Running = false;
}

/*
* Description:
* ScanIrps is responsible for iterating the driver objects and find irp hooking.
*
* Parameters:
* There are no parameters.
*
* Returns:
* There is no return value.
*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS Detector::ScanIrps() {
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE directoryHandle = NULL;
	OBJECT_ATTRIBUTES attributes{};
	UNICODE_STRING directory_name = { 0 };
	POBJECT_DIRECTORY directoryObject = NULL;
	PDRIVER_OBJECT currentDriverObject = NULL;
	PFULL_OBJECT_TYPE currentObjectType = NULL;
	PKLDR_DATA_TABLE_ENTRY currentDataTableEntry = NULL;
	PVOID currentModuleEnd = 0;
	PVOID currentIrpFunction = 0;

	RtlInitUnicodeString(&directory_name, L"\\Driver");
	InitializeObjectAttributes(&attributes, &directory_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenDirectoryObject(&directoryHandle, DIRECTORY_ALL_ACCESS, &attributes);

	if (!NT_SUCCESS(status))
		return status;

	status = ObReferenceObjectByHandle(directoryHandle, DIRECTORY_ALL_ACCESS, nullptr, KernelMode, (PVOID*)&directoryObject, nullptr);

	if (!NT_SUCCESS(status)) {
		ZwClose(directoryHandle);
		return status;
	}
	ExAcquirePushLockExclusiveEx((PULONG_PTR)&directoryObject->Lock, 0);

	for (POBJECT_DIRECTORY_ENTRY entry : directoryObject->HashBuckets) {
		if (!entry)
			continue;

		while (entry && entry->Object) {
			// Verifying that the object is a driver object.
			currentObjectType = (PFULL_OBJECT_TYPE)ObGetObjectType(entry->Object);

			if (currentObjectType) {
				if (_wcsicmp(currentObjectType->Name.Buffer, L"Driver") == 0) {
					currentDriverObject = (PDRIVER_OBJECT)entry->Object;
					currentDataTableEntry = (PKLDR_DATA_TABLE_ENTRY)currentDriverObject->DriverSection;

					if (currentDataTableEntry) {
						currentModuleEnd = (PVOID)((ULONGLONG)currentDataTableEntry->DllBase +
							currentDataTableEntry->SizeOfImage);

						for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
							currentIrpFunction = (PVOID)currentDriverObject->MajorFunction[i];

							if (currentIrpFunction <= 0)
								break;

							if (currentIrpFunction < currentDataTableEntry->DllBase || currentIrpFunction > currentModuleEnd) {
								CHAR driverName[MAX_DRIVER_PATH] = { 0 };
								status = MatchAddress((PVOID)currentDriverObject->MajorFunction[i], driverName);

								if (ShouldReport(driverName, currentDataTableEntry->BaseDllName)) {
									if (NT_SUCCESS(status))
										Print(DRIVER_PREFIX "Driver %s is hooking %ws IRP %d\n", driverName, currentDataTableEntry->BaseDllName.Buffer,
											i);
									else
										Print(DRIVER_PREFIX "Unknown driver is hooking %ws IRP %d\n", currentDataTableEntry->BaseDllName.Buffer, i);
								}
							}
						}
					}
				}
			}
			entry = entry->ChainLink;
		}
	}

	ExReleasePushLockExclusiveEx((PULONG_PTR)&directoryObject->Lock, 0);
	ObDereferenceObject(directoryObject);
	ZwClose(directoryHandle);
	return status;
}

/*
* Description:
* MatchAddress is responsible to match the address to its driver.
*
* Parameters:
* @address	  [_In_ PVOID]       -- Address to search.
* @driverName [_Inout_ PCHAR]    -- Pointer to the driver name if found, else null.
*
* Returns:
* @status	  [NTSTATUS]		 -- Whether successfuly matched or not.
*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS Detector::MatchAddress(_In_ PVOID address, _Inout_ CHAR driverName[MAX_DRIVER_PATH]) {
	NTSTATUS status = STATUS_SUCCESS;
	PRTL_PROCESS_MODULES info = NULL;
	ULONG infoSize;
	errno_t err = 0;

	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (info)
			ExFreePoolWithTag(info, DRIVER_TAG);
		info = (PRTL_PROCESS_MODULES)AllocateMemory(infoSize);

		if (!info) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		status = ZwQuerySystemInformation(SystemModuleInformation, info, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !info)
		return status;

	PRTL_PROCESS_MODULE_INFORMATION modules = info->Modules;

	for (ULONG i = 0; i < info->NumberOfModules; i++) {
		if (address >= modules[i].ImageBase && address < (PVOID)((PUCHAR)modules[i].ImageBase + modules[i].ImageSize)) {
			if (modules[i].FullPathName) {
				SIZE_T fullPathNameSize = strlen((const char*)modules[i].FullPathName);

				if (fullPathNameSize <= MAX_DRIVER_PATH) {
					err = strcpy_s(driverName, MAX_DRIVER_PATH, (const char*)modules[i].FullPathName);

					if (err != 0)
						status = STATUS_UNSUCCESSFUL;
				}
			}
			else
				status = STATUS_UNSUCCESSFUL;
			break;
		}
	}

	FreeMemory(info);
	return status;
}

/*
* Description:
* ShouldReport is responsible for determine if to report the hooking or not.
* 
* NOTE: This function can be implemented better and check for every driver the specific hook that is expected.
* For POC reasons, I've implemented a more robust check.
*
* Parameters:
* @hookingDriverName [_In_ CHAR[MAX_DRIVER_PATH]] -- The driver name that is hooking.
* @hookedDriverName  [_In_ UNICODE_STRING]		  -- The driver name that is hooked.
*
* Returns:
* @status			 [bool]						  -- Whether to report or not.
*/
_IRQL_requires_(PASSIVE_LEVEL)
bool Detector::ShouldReport(_In_ CHAR hookingDriverName[MAX_DRIVER_PATH], _In_ UNICODE_STRING hookedDriverName) {
	if (_stricmp(hookingDriverName, NTOSKRNL_PATH) == 0 || _stricmp(hookingDriverName, WDF_PATH) == 0 ||
		_stricmp(hookingDriverName, NDIS_PATH) == 0 || _stricmp(hookingDriverName, USBPORT_PATH) == 0 ||
		_stricmp(hookingDriverName, STORPORT_PATH) == 0 || _stricmp(hookingDriverName, DXGKRNL_PATH) == 0 ||
		_stricmp(hookingDriverName, CLASSPNP_PATH) == 0 || _stricmp(hookingDriverName, HIDCLASS_PATH) == 0 ||
		_stricmp(hookingDriverName, BTHPORT_PATH) == 0 || _stricmp(hookingDriverName, KS_PATH) == 0 ||
		_stricmp(hookingDriverName, PORTCLS_PATH) == 0 || _stricmp(hookingDriverName, ATAPORT_PATH) == 0 || 
		_stricmp(hookingDriverName, PCIIDEX_PATH) == 0)
		return false;
	return true;
}

/*
* Description:
* Detect is responsible for periodically scan for IRP hooking.
*
* Parameters:
* @StartContext [_In_ PVOID] -- The context that holds the lock, if suppose to continue to run and interval.
*
* Returns:
* There is no return value.
*/
_IRQL_requires_(PASSIVE_LEVEL)
void Detect(_In_ PVOID StartContext) {
	LARGE_INTEGER interval{};
	DetectorContext* detectorContext = (DetectorContext*)StartContext;
	Print(DRIVER_PREFIX "Thread started\n");

	if (!detectorContext)
		PsTerminateSystemThread(STATUS_INSUFFICIENT_RESOURCES);
	detectorContext->Lock.Lock();

	while (detectorContext->Running) {
		detectorContext->Lock.Unlock();
		interval.QuadPart = -100ll * 10 * detectorContext->Interval;
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
		Print(DRIVER_PREFIX "Scanning for IRP hooking...\n");
		IrpDetector->ScanIrps();
		Print(DRIVER_PREFIX "Scan finished...\n");
		detectorContext->Lock.Lock();
	}

	detectorContext->Lock.Unlock();
	Print(DRIVER_PREFIX "Thread is stopping\n");
	PsTerminateSystemThread(STATUS_SUCCESS);
}
