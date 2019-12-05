# qt.dll2def
This is a simple application which uses basic reading of Microsoft Windows executable files to get exports section of DLLs so as to properly create DEF files. They are useful for generating LIB files from DLLs to be used, for instance, with Visual Studio projects. That's the case of MinGW DLLs; for them to be used in Visual Studio projects you need the LIB and header files of those libraries. And this is when my tool comes to play a key role.

The project was created, configured, built and tested using Qt Creator, however, it could be easily integrated to another IDE, because it essentially consists of three files: main.cpp, DllExportedSymbols.cpp and DllExportedSymbols.h

The idea of this project was taken from pasztorpisti on his post in https://www.codeproject.com/tips/133747/checking-for-exported-symbols-functions-in-a-dll-w.

**Features**
- Windows binaries analizer
- OS independent project
- C++
- Qt project
