#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>

#include "DllExportedSymbols.h"

void processFunction(const char *n, void *user)
{
  std::ostream *os = (std::ostream *) user;

  (*os) << "  " << n << std::endl;
}

void showHelp()
{
  std::cout << "Usage: dll2def <dll-file>" << std::endl;
  exit(-1);
}

std::string getOutputFile(const std::string& sInput)
{
  std::size_t  iPos = std::string::npos;
  std::string sTemp;

#ifdef _WIN32
  iPos =  sInput.rfind('\\');
#endif

  if (iPos == std::string::npos)
    iPos =  sInput.rfind('/');

  //Get filename only
  if (iPos != std::string::npos) sTemp = sInput.substr(iPos + 1);
  else sTemp = sInput;

  //Change file extension
  iPos = sTemp.rfind('.');
  if (iPos == std::string::npos) sTemp += ".def";
  else sTemp.replace(sTemp.begin() + iPos, sTemp.end(), ".def");

  return sTemp;
}

const char *cszMessages[] =
{
  "OK",
  "Missing functions",
  "Error opening file",
  "Error reading file",
  "Invalid DOS Header",
  "Invalid NT Header",
  "File is not a DLL",
  "DLL structure error",
};

int main(int argc, char *argv[])
{
  std::string sInput;
  ECfesResult r;

  if (argc <= 1)
  {
    std::cerr << "You must provide a filename!" << std::endl;
    showHelp();
  }
  sInput = argv[1];
  if (sInput == "-h" || sInput == "--help" || sInput == "/?") showHelp();
  else
  {
    std::string   sFileName = getOutputFile(sInput);
    std::filebuf  fb;
    std::ostream  os(&fb);

    if (!fb.open(sFileName, std::ios::out))
    {
      std::cerr << "Couldn't open output file: " << sFileName << "!" << std::endl;
      return -1;
    }

    os << "LIBRARY " << sFileName.substr(0, sFileName.length() - 4) << std::endl
       << "EXPORTS" << std::endl;

    r = dllEnumExports(sInput.c_str(), processFunction, &os);
    dllReleaseMemory(); //Internal instance is invalidated
    if (r != eCfesOK)
    {
      std::cerr << "Error processing " << sInput << ": "
                << cszMessages[r] << std::endl;
      return -1;
    }
  }
  return 0;
}

