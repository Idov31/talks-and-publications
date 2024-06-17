#pragma once

#include "pch.h"

#define DRIVER_TAG 'tceD'
#define DRIVER_PREFIX "[IrpHookDetector] :: "

#define PRINTS
#ifdef PRINTS
typedef ULONG(NTAPI* tDbgPrint)(PCSTR Format, ...);
constexpr tDbgPrint Print = DbgPrint;
#else
constexpr VOID Print(...) {};
#endif
