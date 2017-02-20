TEMPLATE    =   app
TARGET      =   dll2def
INCLUDEPATH +=  .

CONFIG      +=  console
CONFIG      -=  qt

# Input
SOURCES     +=  main.cpp \
    DllExportedSymbols.cpp

HEADERS += \
    DllExportedSymbols.h
