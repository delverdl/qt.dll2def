#ifndef __DLL_EXPORTED_SYMBOLS_H__
#define __DLL_EXPORTED_SYMBOLS_H__

#ifdef MSC_VER
#pragma once
#endif

enum ECfesResult
{
  eCfesOK,
  eCfesMissingFunctions,
  eCfesErrorOpeningFile,
  eCfesErrorReadingFile,
  eCfesInvalidDosHeader,
  eCfesInvalidNTHeader,
  eCfesNotADll,
  eCfesDllStructureError,
};

// Checks if the specified file is a real DLL that exports all
// the specified functions.
ECfesResult dllCheckExports(const char *dllPath, const char* symbols[], int symbolCount);

// Enumerate exported funcions in a DLL
ECfesResult dllEnumExports(const char *dllPath, void (*callback)(const char*));

// Release memory for internal class instance
ECfesResult dllReleaseMemory();

#endif //__DLL_EXPORTED_SYMBOLS_H__
