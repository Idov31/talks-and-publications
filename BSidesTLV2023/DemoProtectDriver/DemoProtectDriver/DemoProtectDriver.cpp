#include <ntddk.h>


void BlockNotepadRoutine(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	if (CreateInfo) {
		if (CreateInfo->CommandLine->Length > 0) {
			if (_wcsnicmp(CreateInfo->CommandLine->Buffer, L"\"C:\\Windows\\System32\\notepad.exe\"", 32) == 0) {
				CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
			}
		}
	}
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {
	PsSetCreateProcessNotifyRoutineEx(BlockNotepadRoutine, TRUE);
	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\DemoProtectDriver");
	IoDeleteSymbolicLink(&symbolicLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) { 
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\DemoProtectDriver");
	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\DemoProtectDriver");

	// Creating device and symbolic link.
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&symbolicLink, &deviceName);

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
		return status;
	}
	
	status = PsSetCreateProcessNotifyRoutineEx(BlockNotepadRoutine, FALSE);
	DriverObject->DriverUnload = DriverUnload;
	return status;
}
