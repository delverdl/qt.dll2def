#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "DllExportedSymbols.h"

void showName(const char* n)
{ printf("%s\n", n); }

int main(int argc, char* argv[])
{
  (void) argc;
  (void) argv;

  dllEnumExports(
        "/opt/qt/projects/dll2def/egl32.dll"
//        "/opt/qt/projects/dll2def/egl64.dll"
        , showName);

  dllReleaseMemory(); //Internal instance is invalidated
  return 0;
}

