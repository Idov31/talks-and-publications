#include "pch.h"
#include "IrpHookDetector.h"

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = IrpHookDetectorUnload;
	IrpDetector = NULL;

	__try {
		IrpDetector = new Detector();
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Print(DRIVER_PREFIX "Failed to create detector object (0x%08X)\n", GetExceptionCode());
		return GetExceptionCode();
	}
	Print(DRIVER_PREFIX "Driver loaded, driver object @ %p\n", (PVOID)DriverObject);
	return STATUS_SUCCESS;
}

void IrpHookDetectorUnload(DRIVER_OBJECT* DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	if (IrpDetector)
		delete IrpDetector;
}