#pragma once

#include "pch.h"
#include "MemoryHelper.hpp"
#include "StringHelper.hpp"

constexpr ULONG DEFAULT_INTERVAL = 60000;
constexpr CHAR NTOSKRNL_PATH[] = "\\SystemRoot\\system32\\ntoskrnl.exe";
constexpr CHAR WDF_PATH[] = "\\SystemRoot\\system32\\drivers\\Wdf01000.sys";
constexpr CHAR NDIS_PATH[] = "\\SystemRoot\\system32\\drivers\\ndis.sys";
constexpr CHAR USBPORT_PATH[] = "\\SystemRoot\\System32\\drivers\\USBPORT.SYS";
constexpr CHAR STORPORT_PATH[] = "\\SystemRoot\\System32\\drivers\\storport.sys";
constexpr CHAR DXGKRNL_PATH[] = "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys";
constexpr CHAR CLASSPNP_PATH[] = "\\SystemRoot\\System32\\drivers\\CLASSPNP.SYS";
constexpr CHAR HIDCLASS_PATH[] = "\\SystemRoot\\System32\\drivers\\HIDCLASS.SYS";
constexpr CHAR BTHPORT_PATH[] = "\\SystemRoot\\System32\\drivers\\bthport.sys";
constexpr CHAR KS_PATH[] = "\\SystemRoot\\System32\\drivers\\ks.sys";
constexpr CHAR PORTCLS_PATH[] = "\\SystemRoot\\System32\\drivers\\portcls.sys";
constexpr CHAR ATAPORT_PATH[] = "\\SystemRoot\\System32\\drivers\\ataport.SYS";
constexpr CHAR PCIIDEX_PATH[] = "\\SystemRoot\\System32\\drivers\\PCIIDEX.SYS";

typedef struct _DetectorContext {
	FastMutex Lock;
	ULONG Interval;
	bool Running;
} DetectorContext;

class Detector
{
private:
	DetectorContext* detectorContext;
	HANDLE detectorThread;

	_IRQL_requires_(PASSIVE_LEVEL)
	bool ShouldReport(_In_ CHAR hookingDriverName[MAX_DRIVER_PATH], _In_ UNICODE_STRING hookedDriverName);

	_IRQL_requires_(PASSIVE_LEVEL)
	void StopThread();

	_IRQL_requires_(PASSIVE_LEVEL)
	NTSTATUS MatchAddress(_In_ PVOID address, _Inout_ CHAR driverName[MAX_DRIVER_PATH]);

public:
	void* operator new(size_t size) {
		return AllocateMemory(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	_IRQL_requires_(PASSIVE_LEVEL)
	Detector(_In_ ULONG interval);

	_IRQL_requires_(PASSIVE_LEVEL)
	Detector() : Detector(DEFAULT_INTERVAL) { }

	_IRQL_requires_(PASSIVE_LEVEL)
	~Detector();

	_IRQL_requires_(PASSIVE_LEVEL)
	NTSTATUS ScanIrps();
};
inline Detector* IrpDetector;

_IRQL_requires_(PASSIVE_LEVEL)
void Detect(_In_ PVOID StartContext);