#pragma once
#include "pch.h"
#include "MemoryHelper.hpp"

/*
* Description:
* ConvertAnsiToUnicode is responsible for converting ANSI string to UNICODE.
*
* Parameters:
* @ansiString [_In_ PCHAR]				-- Source string to convert.
* @outString  [_Inout_ PUNICODE_STRING] -- Output unicode string.
*
* Returns:
* @status	  [NTSTATUS]				-- Whether successfuly converted or not.
*/
_IRQL_requires_(PASSIVE_LEVEL)
inline NTSTATUS ConvertAnsiToUnicode(_In_ PCHAR ansiString, _Inout_ PUNICODE_STRING outString) {
	ANSI_STRING aFunctionName = { 0 };
	RtlInitAnsiString(&aFunctionName, ansiString);
	return RtlAnsiStringToUnicodeString(outString, &aFunctionName, TRUE);
}

/*
* Description:
* FreeUnicodeString is responsible for freeing a unicode string.
*
* Parameters:
* @str [_Inout_ PUNICODE_STRING] -- String to free.
*
* Returns:
* There is no return value.
*/
_IRQL_requires_(PASSIVE_LEVEL)
inline void FreeUnicodeString(_Inout_ PUNICODE_STRING str) {
	FreeMemory(str->Buffer);
	str->Length = 0;
	str->MaximumLength = 0;
}