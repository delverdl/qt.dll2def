#include "DllExportedSymbols.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <list>
#include <string>
#include <vector>

#ifndef _min
#define _min(a,b) ((a < b) ? a : b)
#endif

#ifndef _max
#define _max(a,b) ((a < b) ? a : b)
#endif

#if !(defined(lint) || defined(RC_INVOKED))
#pragma pack(push,2)
#endif

typedef struct _idh {
  uint16_t                e_magic;
  uint16_t                e_cblp;
  uint16_t                e_cp;
  uint16_t                e_crlc;
  uint16_t                e_cparhdr;
  uint16_t                e_minalloc;
  uint16_t                e_maxalloc;
  uint16_t                e_ss;
  uint16_t                e_sp;
  uint16_t                e_csum;
  uint16_t                e_ip;
  uint16_t                e_cs;
  uint16_t                e_lfarlc;
  uint16_t                e_ovno;
  uint16_t                e_res[4];
  uint16_t                e_oemid;
  uint16_t                e_oeminfo;
  uint16_t                e_res2[10];
  long                    e_lfanew;
} SBinaryDosHeader, *PSBinaryDosHeader;

#if !(defined(lint) || defined(RC_INVOKED))
#pragma pack(push,4)
#endif

#define BINARY_MAX_FUNC_NAME    4096

#define BINARY_IS_DOS           0x5A4D
#define BINARY_IS_NT            0x00004550

#if !(defined(lint) || defined(RC_INVOKED))
#pragma pack(pop)
#endif

#define BINARY_IS_DLL           0x2000
#define BINARY_SHORT_SIZE       8
#define BINARY_MAX_DIRENTRIES   16
#define BINARY_IS_32BITS        0x10b
#define BINARY_IS_64BITS        0x20b
#define BINARY_DIRENTRIES_LIST  0

typedef struct _idd {
  uint32_t                virtualAddress;
  uint32_t                size;
} SBinaryDataDir,*PSDataDir;

typedef struct _ifh {
  uint16_t                machine;
  uint16_t                numberOfSections;
  uint32_t                timeDateStamp;
  uint32_t                pointerToSymbolTable;
  uint32_t                numberOfSymbols;
  uint16_t                sizeOfOptionalHeader;
  uint16_t                characteristics;
} SFileHeader,            *PSFileHeader;

typedef struct _ioh32 {

  uint16_t                magic;
  uint8_t                 majorLinkerVersion;
  uint8_t                 minorLinkerVersion;
  uint32_t                sizeOfCode;
  uint32_t                sizeOfInitializedData;
  uint32_t                sizeOfUninitializedData;
  uint32_t                addressOfEntryPoint;
  uint32_t                baseOfCode;
  uint32_t                baseOfData;
  uint32_t                imageBase;
  uint32_t                sectionAlignment;
  uint32_t                fileAlignment;
  uint16_t                majorOperatingSystemVersion;
  uint16_t                minorOperatingSystemVersion;
  uint16_t                majorImageVersion;
  uint16_t                minorImageVersion;
  uint16_t                majorSubsystemVersion;
  uint16_t                minorSubsystemVersion;
  uint32_t                win32VersionValue;
  uint32_t                sizeOfImage;
  uint32_t                sizeOfHeaders;
  uint32_t                checkSum;
  uint16_t                subsystem;
  uint16_t                dllCharacteristics;
  uint32_t                sizeOfStackReserve;
  uint32_t                sizeOfStackCommit;
  uint32_t                sizeOfHeapReserve;
  uint32_t                sizeOfHeapCommit;
  uint32_t                loaderFlags;
  uint32_t                numberOfRvaAndSizes;
  SBinaryDataDir          dataDirectory[BINARY_MAX_DIRENTRIES];
} SOptionalHeader32,      *PSOptionalHeader32;

typedef struct _ioh64 {
  uint16_t                magic;
  uint8_t                 majorLinkerVersion;
  uint8_t                 minorLinkerVersion;
  uint32_t                sizeOfCode;
  uint32_t                sizeOfInitializedData;
  uint32_t                sizeOfUninitializedData;
  uint32_t                addressOfEntryPoint;
  uint32_t                baseOfCode;
  uint64_t                imageBase;
  uint32_t                sectionAlignment;
  uint32_t                fileAlignment;
  uint16_t                majorOperatingSystemVersion;
  uint16_t                minorOperatingSystemVersion;
  uint16_t                majorImageVersion;
  uint16_t                minorImageVersion;
  uint16_t                majorSubsystemVersion;
  uint16_t                minorSubsystemVersion;
  uint32_t                win32VersionValue;
  uint32_t                sizeOfImage;
  uint32_t                sizeOfHeaders;
  uint32_t                checkSum;
  uint16_t                subsystem;
  uint16_t                dllCharacteristics;
  uint64_t                sizeOfStackReserve;
  uint64_t                sizeOfStackCommit;
  uint64_t                sizeOfHeapReserve;
  uint64_t                sizeOfHeapCommit;
  uint32_t                loaderFlags;
  uint32_t                numberOfRvaAndSizes;
  SBinaryDataDir          dataDirectory[BINARY_MAX_DIRENTRIES];
} SOptionalHeader64,      *PSOptionalHeader64;

typedef struct _inh32 {
  uint32_t                signature;
  SFileHeader             fileHeader;
  SOptionalHeader32       optionalHeader;
} SBinaryNtHeaders32,     *PSBinaryNtHeaders32;

typedef struct _inh64 {
  uint32_t                signature;
  SFileHeader             fileHeader;
  SOptionalHeader64       optionalHeader;
} SBinaryNtHeaders64,     *PSBinaryNtHeaders64;

typedef struct _isd
{
  uint8_t                 name[BINARY_SHORT_SIZE];
  union
  {
    uint32_t              physicalAddress;
    uint32_t              virtualSize;
  } misc;
  uint32_t                virtualAddress;
  uint32_t                sizeOfRawData;
  uint32_t                pointerToRawData;
  uint32_t                pointerToRelocations;
  uint32_t                pointerToLinenumbers;
  uint16_t                numberOfRelocations;
  uint16_t                numberOfLinenumbers;
  uint32_t                characteristics;
} SBinarySectionHeader,   *PSImageSectionHeader;

typedef struct _ied {
  uint32_t                characteristics;
  uint32_t                timeDateStamp;
  uint16_t                majorVersion;
  uint16_t                minorVersion;
  uint32_t                name;
  uint32_t                base;
  uint32_t                numberOfFunctions;
  uint32_t                numberOfNames;
  uint32_t                addressOfFunctions;
  uint32_t                addressOfNames;
  uint32_t                addressOfNameOrdinals;
} SBinaryExportDir,       *PSExportDir;

struct SRvaToFileOffset : public std::vector<SBinarySectionHeader>
{
  uint32_t operator()(uint32_t rva) const
  {
    for (const_iterator it=begin(), eit = end(); it != eit; ++it)
    {
      if (rva >= it->virtualAddress && rva < it->virtualAddress + it->misc.virtualSize)
        return rva - it->virtualAddress + it->pointerToRawData;
    }
    return rva;
  }
};

//-----------------------------------------------------------------------------

class CCfesFile
{
  public:
    CCfesFile() : m_file(0) {}

    ~CCfesFile() { close(); }

    bool openForRead(const char *filePath)
    {
      close();
      m_file = fopen(filePath, "r");
      return m_file != 0;
    }

    void close()
    { if (m_file != 0) { fclose(m_file); m_file = 0; } }

    bool read(void *buffer, uint32_t nuint8_ts, uint32_t nOffset = 0xFFFFFFFF,
              uint32_t *nRead = 0)
    {
      assert(m_file != 0);
      if (m_file == 0) return false;
      if (nOffset < 0xFFFFFFFF && fseek(m_file, (long) nOffset, SEEK_SET) < 0)
        return false;

      size_t ixRead = fread(buffer, 1, nuint8_ts, m_file);

      if (!nRead) return ((uint32_t) ixRead == nuint8_ts);
      *nRead = (uint32_t) ixRead;
      return true;
    }

    bool readString(void *buffer, uint32_t nOffset = 0xFFFFFFFF, uint32_t *nRead = 0)
    {
      assert(m_file != 0);

      int   nCount = 0;
      char  *szOut = (char *)buffer;
      char  letter;

      if (m_file == 0) return false;
      if (nOffset < 0xFFFFFFFF && fseek(m_file, (long) nOffset, SEEK_SET) < 0)
        return false;

      while ((letter = fgetc(m_file)) != 0)
      {
        *szOut = letter;
        szOut++;
        if (++nCount > 4096) return false; //Cannot have such a long name
      }
      *szOut = 0;
      if (feof(m_file)) return false; //Must have a valid null terminated string
      if (nRead) *nRead = nCount;
      return true;
    }

    bool isOpened() { return m_file != 0; }

  private:
    FILE* m_file;
};

//-----------------------------------------------------------------------------

class CDllExportedSymbols
{
  public:

    ~                           CDllExportedSymbols();

    static CDllExportedSymbols* instance();

    ECfesResult                 test(const char *path, const char *lSymbols[], int nSymbol);
    ECfesResult                 list(const char *path, std::list<std::string> &sSymbols);

  private:
    bool                        listSymbols(const char *path);

    bool                        readHeaders();
    bool                        checkSymbols(const char *symbols[], int symbolCount);
    bool                        setError(ECfesResult res);
    bool                        read(void *buf, uint32_t count, uint32_t offset = 0xFFFFFFFF);

  private:
    ECfesResult                 m_result;
    CCfesFile                   m_file;
    SBinaryDataDir              m_exportDirLocation; // RVA and size
    SRvaToFileOffset            m_rvaToFileOffset;
    std::list<std::string>      m_symbols;

    explicit                    CDllExportedSymbols();

    static CDllExportedSymbols* m_instance;
};

CDllExportedSymbols* CDllExportedSymbols::m_instance = 0;

CDllExportedSymbols::~CDllExportedSymbols()
{ m_instance = 0; }

CDllExportedSymbols *CDllExportedSymbols::instance()
{
  if (!m_instance) m_instance = new CDllExportedSymbols;
  return m_instance;
}

ECfesResult CDllExportedSymbols::test(const char *path, const char *lSymbols[], int nSymbol)
{
  if (nSymbol <= 0) setError(eCfesOK);
  else if (listSymbols(path)) checkSymbols(lSymbols, nSymbol);
  return m_result;
}

ECfesResult CDllExportedSymbols::list(const char *path, std::list<std::__cxx11::string> &sSymbols)
{
  listSymbols(path); //This method guaranties symbols listing once per instance
  sSymbols = m_symbols;
  return m_result;
}

bool CDllExportedSymbols::listSymbols(const char *path)
{
  if (m_file.isOpened()) return m_result == eCfesOK; //Result for last operation
  m_result = eCfesErrorOpeningFile;
  if (!m_file.openForRead(path)) return false;
  if (readHeaders())
  {
    //Make symbols set
    // reading the export directory
    assert(m_exportDirLocation.size >= sizeof(SBinaryExportDir));

    // Collecting the function names exported by the DLL.
    std::vector<uint32_t>   vecExportedSymbolRvas;
    SBinaryExportDir        edExportDir;
    char*                   szName;

    if (!read(&edExportDir, sizeof(edExportDir), m_rvaToFileOffset(
                m_exportDirLocation.virtualAddress))) return false;
    vecExportedSymbolRvas.resize(edExportDir.numberOfNames);
    if (!read(&vecExportedSymbolRvas[0], sizeof(uint32_t) * edExportDir.numberOfNames,
        m_rvaToFileOffset(edExportDir.addressOfNames))) return false;

    szName = new char[4097];
    szName[4095] = szName[4096] = 0;
    for (std::vector<uint32_t>::const_iterator it = vecExportedSymbolRvas.begin(),
         eit = vecExportedSymbolRvas.end(); it != eit; ++it)
    {
      uint32_t nRead;

      if (!m_file.readString(szName, m_rvaToFileOffset(*it), &nRead))
        return setError(eCfesErrorReadingFile);
      m_symbols.push_back(szName);
    }
    delete szName;
    return setError(eCfesOK);
  }
  return m_result == eCfesOK;
}

bool CDllExportedSymbols::readHeaders()
{
  SBinaryDosHeader    dosHdr;
  SBinaryNtHeaders64  hdr;
  uint32_t            uOptHeaderSize;

  if (!read(&dosHdr, sizeof(dosHdr))) return false;
  if (dosHdr.e_magic != BINARY_IS_DOS) return setError(eCfesInvalidDosHeader);
  if (!read(&hdr, sizeof(hdr) - sizeof(hdr.optionalHeader) +
            sizeof(uint16_t), dosHdr.e_lfanew)) return false;
  if (hdr.signature != BINARY_IS_NT) return setError(eCfesInvalidNTHeader);
  if (hdr.optionalHeader.magic != BINARY_IS_32BITS &&
      hdr.optionalHeader.magic != BINARY_IS_64BITS)
    return setError(eCfesInvalidNTHeader);
  if ((hdr.fileHeader.characteristics & BINARY_IS_DLL) == 0) return setError(eCfesNotADll);
  // In case of zero function names we only check for the validity of the DLL
  uOptHeaderSize = _min((uint32_t)sizeof(hdr.optionalHeader),
                        (uint32_t)hdr.fileHeader.sizeOfOptionalHeader);
  if (hdr.optionalHeader.magic == BINARY_IS_32BITS)
  {
    // 32 bit binary
    if (uOptHeaderSize < offsetof(SOptionalHeader32,
                                  dataDirectory[BINARY_DIRENTRIES_LIST+1]))
      return setError(eCfesMissingFunctions);
    if (!read((uint16_t*)&hdr.optionalHeader.magic + 1, uOptHeaderSize - sizeof(uint16_t)))
      return false;

    SBinaryNtHeaders32 &hdr32 = *(SBinaryNtHeaders32*) & hdr;

    if (hdr32.optionalHeader.numberOfRvaAndSizes < BINARY_DIRENTRIES_LIST + 1)
      return setError(eCfesMissingFunctions);
    m_exportDirLocation = hdr32.optionalHeader.dataDirectory[BINARY_DIRENTRIES_LIST];
  }
  else
  {
    // 64 bit binary
    if (uOptHeaderSize < offsetof(SOptionalHeader64,
                                  dataDirectory[BINARY_DIRENTRIES_LIST+1]))
      return setError(eCfesMissingFunctions);
    if (!read((uint16_t*)&hdr.optionalHeader.magic + 1, uOptHeaderSize - sizeof(uint16_t)))
      return false;
    if (hdr.optionalHeader.numberOfRvaAndSizes < BINARY_DIRENTRIES_LIST + 1)
      return setError(eCfesMissingFunctions);
    m_exportDirLocation = hdr.optionalHeader.dataDirectory[BINARY_DIRENTRIES_LIST];
  }
  // Reading the section headers in order to be able to calculate file offsets from RVAs
  if (hdr.fileHeader.numberOfSections)
  {
    m_rvaToFileOffset.resize(hdr.fileHeader.numberOfSections);

    uint32_t nSectionHeaderFileOffset = dosHdr.e_lfanew + sizeof(
                                          hdr.signature) + sizeof(hdr.fileHeader) +
                                        hdr.fileHeader.sizeOfOptionalHeader;

    if (!read(&m_rvaToFileOffset[0], hdr.fileHeader.numberOfSections *
              sizeof(SBinarySectionHeader), nSectionHeaderFileOffset))
      return false;
  }
  return true;
}

class CFinder
{
    std::string s;

  public:
    CFinder(const std::string& what): s(what) {}

    bool operator() (const std::string& s1)
    { return s1 == s; }
};

bool CDllExportedSymbols::checkSymbols(const char* symbols[], int symbolCount)
{
  std::list<std::string>::const_iterator it, end = m_symbols.end();

  if ((int)m_symbols.size() < symbolCount) return setError(eCfesMissingFunctions);
  for (int i = 0; i < symbolCount; ++i)
  {
    it = std::find_if(m_symbols.cbegin(), end, CFinder(symbols[i]));
    if (it == end) return setError(eCfesMissingFunctions);
  }
  return true;
}

bool CDllExportedSymbols::setError(ECfesResult res)
{ m_result = res; return false; }

bool CDllExportedSymbols::read(void *buf, uint32_t count, uint32_t offset)
{
  uint32_t read;

  if (!m_file.read(buf, count, offset, &read)) return setError(eCfesErrorReadingFile);
  if (read != count) return setError(eCfesDllStructureError);
  return true;
}

CDllExportedSymbols::CDllExportedSymbols()
: m_result(eCfesOK)
{ memset(&m_exportDirLocation, 0, sizeof(m_exportDirLocation)); }


//-----------------------------------------------------------------------------
// External functions

ECfesResult dllCheckExports(const char *dllPath, const char *symbols[], int symbolCount)
{
  CDllExportedSymbols *cfes = CDllExportedSymbols::instance();

  assert(cfes != 0);
  return cfes->test(dllPath, symbols, symbolCount);
}

ECfesResult dllEnumExports(const char *dllPath, void (*callback)(const char*))
{
  CDllExportedSymbols       *cfes = CDllExportedSymbols::instance();
  std::list<std::string>    sSymbols;
  ECfesResult               result;

  assert(cfes != 0);
  result = cfes->list(dllPath, sSymbols);
  if (result == eCfesOK)
  {
    for (std::list<std::string>::const_iterator i = sSymbols.cbegin();
         i != sSymbols.cend() ; ++i)
    {
      const std::string s = *i;

      callback(s.c_str());
    }
  }
  return result;
}

ECfesResult dllReleaseMemory()
{
  CDllExportedSymbols *cfes = CDllExportedSymbols::instance();

  delete cfes; //This will null static member to tell instace's freed
  return eCfesOK;
}
