#pragma warning(disable : 4005)	// macro redefinition (in windows headers)
#pragma warning(disable : 4091)	// 'typedef ': ignored on left of '' when no variable is declared
#pragma warning(disable : 4996)	// 'fopen': This function or variable may be unsafe.

#include <unordered_map>
#include <string>
#include <algorithm>
#include <iostream>

#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#include <winternl.h>

typedef std::unordered_map<std::string, const char*> SymbolMap;

const char* getSymbolAddressInCurrentProcess(const SymbolMap& inSituMap, const std::string& name) {
	auto it = inSituMap.find(name);
	if (it != inSituMap.end()) {
		// Use the binary map by default so that if a symbol exists in the binary, we will use it
		return it->second;
	} else {
		// Otherwise fall back to DbgHelp. This may get us symbols in loaded DLLs, such as msvcrt.dll.
		// Those won't necessarily lie within a 32bit offset from our module, but we generate thunks
		// to call them with absolute addresses if needed.

		SYMBOL_INFO symbol;
		symbol.SizeOfStruct = sizeof(SYMBOL_INFO);
		symbol.MaxNameLen = 1;

		if (SymFromName(GetCurrentProcess(), name.c_str(), &symbol)) {
			return (const char*)symbol.Address;
		} else {
			static const char* dllList[] = {
				"msvcp140d.dll",
				"msvcrt.dll",
			};

			for (const char* dll : dllList) {
				if (auto sym = GetProcAddress(GetModuleHandleA(dll), name.c_str())) {
					return (const char*)sym;
				}
			}

			printf("Could not resolve symbol: %s\n", name.c_str());
			abort();
			return nullptr;
		}
	}
}

#pragma pack(push)
#pragma pack(1)
struct CoffBinary
{
	enum ImageFileMachine : uint16_t {
		ImageFileMachineUnknown = 0x0,
		ImageFileMachineAm33 = 0x1d3,
		ImageFileMachineAmd64 = 0x8664,
		ImageFileMachineArm = 0x1c0,
		ImageFileMachineArm64 = 0xaa64,
		ImageFileMachineArmnt = 0x1c4,
		ImageFileMachineEbc = 0xebc,
		ImageFileMachineI386 = 0x14c,
		ImageFileMachineIa64 = 0x200,
		ImageFileMachineM32r = 0x9041,
		ImageFileMachineMips16 = 0x266,
		ImageFileMachineMipsfpu = 0x366,
		ImageFileMachineMipsfpu16 = 0x466,
		ImageFileMachinePowerpc = 0x1f0,
		ImageFileMachinePowerpcfp = 0x1f1,
		ImageFileMachineR4000 = 0x166,
		ImageFileMachineRiscv32 = 0x5032,
		ImageFileMachineRiscv64 = 0x5064,
		ImageFileMachineRiscv128 = 0x5128,
		ImageFileMachineSh3 = 0x1a2,
		ImageFileMachineSh3dsp = 0x1a3,
		ImageFileMachineSh4 = 0x1a6,
		ImageFileMachineSh5 = 0x1a8,
		ImageFileMachineThumb = 0x1c2,
		ImageFileMachineWcemipsv2 = 0x169,
	};

	enum ImageFileCharacteristics : uint16_t {
		ImageFileRelocsStripped = 0x0001,
		ImageFileExecutableImage = 0x0002,
		ImageFileLineNumsStripped = 0x0004,
		ImageFileLocalSymsStripped = 0x0008,
		ImageFileAggressiveWsTrim = 0x0010,
		ImageFileLargeAddressAware = 0x0020,
		ImageFileBytesReversedLo = 0x0080,
		ImageFile32bitMachine = 0x0100,
		ImageFileDebugStripped = 0x0200,
		ImageFileRemovableRunFromSwap = 0x0400,
		ImageFileNetRunFromSwap = 0x0800,
		ImageFileSystem = 0x1000,
		ImageFileDll = 0x2000,
		ImageFileUpSystemOnly = 0x4000,
		ImageFileBytesReversedHi = 0x8000,
	};

	struct ImageHeader
	{
		ImageFileMachine Machine;
		uint16_t NumberOfSections;
		uint32_t TimeDateStamp;
		uint32_t PointerToSymbolTable;
		uint32_t NumberOfSymbols;
		uint16_t SizeOfOptionalHeader;
		ImageFileCharacteristics Characteristics;
	};

	// PE32+ Windows
	struct OptionalHeader
	{
		uint16_t Magic;
		uint8_t MajorLinkerVersion;
		uint8_t MinorLinkerVersion;
		uint32_t SizeOfCode;
		uint32_t SizeOfInitializedData;
		uint32_t SizeOfUninitializedData;
		uint32_t AddressOfEntryPoint;
		uint32_t BaseOfCode;

		uint64_t ImageBase;
		uint32_t SectionAlignment;
		uint32_t FileAlignment;
		uint16_t MajorOperatingSystemVersion;
		uint16_t MinorOperatingSystemVersion;
		uint16_t MajorImageVersion;
		uint16_t MinorImageVersion;
		uint16_t MajorSubsystemVersion;
		uint16_t MinorSubsystemVersion;
		uint32_t Win32VersionValue;
		uint32_t SizeOfImage;
		uint32_t SizeOfHeaders;
		uint32_t CheckSum;
		uint16_t Subsystem;
		uint16_t DllCharacteristics;
		uint64_t SizeOfStackReserve;
		uint64_t SizeOfStackCommit;
		uint64_t SizeOfHeapReserve;
		uint64_t SizeOfHeapCommit;
		uint32_t LoaderFlags;
		uint32_t NumberOfRvaAndSizes;
	};

	struct CoffString
	{
		char data[8];
	};

	struct SectionHeader
	{
		CoffString Name;
		uint32_t VirtualSize;
		uint32_t VirtualAddress;
		uint32_t SizeOfRawData;
		uint32_t PointerToRawData;
		uint32_t PointerToRelocations;
		uint32_t PointerToLinenumbers;
		uint16_t NumberOfRelocations;
		uint16_t NumberOfLinenumbers;
		uint32_t Characteristics;
	};

	struct Relocation
	{
		uint32_t VirtualAddress;
		uint32_t SymbolTableIndex;
		uint16_t Type;
	};

	enum SymClass : uint8_t
	{
		SymClassEndOfFunction = (uint8_t)-1,
		SymClassNull = 0,
		SymClassAutomatic = 1,
		SymClassExternal = 2,
		SymClassStatic = 3,
		SymClassRegister = 4,
		SymClassExternalDef = 5,
		SymClassLabel = 6,
		SymClassUndefinedLabel = 7,
		SymClassMemberOfStruct = 8,
		SymClassArgument = 9,
		SymClassStructTag = 10,
		SymClassMemberOfUnion = 11,
		SymClassUnionTag = 12,
		SymClassTypeDefinition = 13,
		SymClassUndefinedStatic = 14,
		SymClassEnumTag = 15,
		SymClassMemberOfEnum = 16,
		SymClassRegisterParam = 17,
		SymClassBitField = 18,
		SymClassBlock = 100,
		SymClassFunction = 101,
		SymClassEndOfStruct = 102,
		SymClassFile = 103,
		SymClassSection = 104,
		SymClassWeakExternal = 105,
		SymClassClrToken = 107,
	};

	struct Symbol
	{
		CoffString Name;
		uint32_t Value;
		int16_t SectionNumber;
		uint16_t Type;
		SymClass StorageClass;
		uint8_t NumberOfAuxSymbols;
	};

	template <typename T>
	struct Slice
	{
		T* beginPtr = nullptr;
		T* endPtr = nullptr;

		T& operator[](uint32_t i) {
			return beginPtr[i];
		}
		const T& operator[](uint32_t i) const {
			return beginPtr[i];
		}

		T* begin() const { return beginPtr; }
		T* end() const { return endPtr; }
	};

	char* rawData;
	uint32_t rawDataSize = 0;

	char* coffData = nullptr;
	ImageHeader* imageHeader = nullptr;
	OptionalHeader* optionalHeader = nullptr;
	Slice<Symbol> symbols;
	Slice<SectionHeader> sections;
	char* stringTable = nullptr;

	std::string decodeString(const CoffString& name) const
	{
		if (name.data[0] == '\0') {
			return stringTable + ((uint32_t*)name.data)[1];
		} else {
			return std::string(&name.data[0], std::find(&name.data[0], &name.data[0] + 8, '\0'));
		}
	}

	std::string getSymbolName(uint32_t symbolIdx) const
	{
		return decodeString(symbols[symbolIdx].Name);
	}

	Slice<Relocation> getSectionRelocations(const SectionHeader& section)
	{
		Slice<Relocation> res;
		res.beginPtr = (Relocation*)(coffData + section.PointerToRelocations);
		res.endPtr = res.beginPtr + section.NumberOfRelocations;
		return res;
	}

	Slice<const Relocation> getSectionRelocations(const SectionHeader& section) const
	{
		Slice<const Relocation> res;
		res.beginPtr = (const Relocation*)(coffData + section.PointerToRelocations);
		res.endPtr = res.beginPtr + section.NumberOfRelocations;
		return res;
	}

	void parse()
	{
		coffData = rawData;
		parseCoff();
	}

	void parsePe()
	{
		coffData = rawData + ((uint32_t*)rawData)[0x3c / 4u] + 4;
		parseCoff();
	}

	void debugDump() const
	{
		for (uint32_t i = 0; i < imageHeader->NumberOfSymbols; ++i) {
			puts(getSymbolName(i).c_str());
		}
	}

private:
	void parseCoff()
	{
		imageHeader = (ImageHeader*)coffData;
		optionalHeader = (OptionalHeader*)(imageHeader + 1);
		symbols.beginPtr = (Symbol*)(coffData + imageHeader->PointerToSymbolTable);
		symbols.endPtr = symbols.beginPtr + imageHeader->NumberOfSymbols;
		sections.beginPtr = (SectionHeader*)(coffData + sizeof(ImageHeader) + imageHeader->SizeOfOptionalHeader);
		sections.endPtr = sections.beginPtr + imageHeader->NumberOfSections;
		stringTable = (char*)symbols.endPtr;
	}
};
#pragma pack(pop)

bool readCoff(const char* const filePath, CoffBinary *const output)
{
	FILE* f = fopen(filePath, "rb");

	if (!f) {
		return false;
	}

	fseek(f, 0, SEEK_END);
	const long fileSize = ftell(f);
	fseek(f, 0, SEEK_SET);

	output->rawData = new char[fileSize];
	output->rawDataSize = fileSize;

	fread(output->rawData, 1, fileSize, f);
	fclose(f);

	return true;
}

bool writeCoff(const char* const filePath, const CoffBinary& coff)
{
	FILE* f = fopen(filePath, "wb");
	if (!f) {
		return false;
	}

	fwrite(coff.rawData, 1, coff.rawDataSize, f);
	fclose(f);
	return true;
}

const char* makeFunctionThunk(const char* dstPtr)
{
	static char* lastAllocAddress = nullptr;
	char* targetAddress = lastAllocAddress;
	if (targetAddress) {
		targetAddress += 0x10000u;
	}
	else {
		// This is bork. Should find a sure way of allocating pages for sections
		targetAddress = (char*)((reinterpret_cast<size_t>(GetModuleHandle(nullptr)) & ~0xffffll) + 0x2000000u);
	}

	lastAllocAddress = (char*)VirtualAlloc(targetAddress, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	unsigned char* data = (unsigned char*)lastAllocAddress;

	// mov rax, dstPtr
	// jmp rax

	*data++ = 0x48;
	*data++ = 0xB8;
	*(const char**)data = dstPtr;
	data += 8;
	*data++ = 0xff;
	*data++ = 0xe0;

	DWORD oldProtect;
	VirtualProtect(lastAllocAddress, 12, PAGE_EXECUTE, &oldProtect);

	return lastAllocAddress;
}

SymbolMap parseMapFile(const char* filePath, const char* const modBase)
{
	FILE* f = fopen(filePath, "rb");
	if (!f) abort();
	fseek(f, 0, SEEK_END);
	const long fileSize = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *const fileContents = new char[fileSize];

	fread(fileContents, 1, fileSize, f);
	fclose(f);

	char* str = fileContents;

	auto skipLine = [&]() {
		while (*str++ != '\n') {}
	};

	for (int ln = 0; ln < 4; ++ln) {
		skipLine();
	}

	auto readHex = [&]() {
		size_t val = 0;
		for (int i = 0; i < 16; ++i) {
			val <<= 4;
			char ch = *str++;
			val += ch <= '9' ? (ch - '0') : (ch - 'a' + 10);
		}
		return val;
	};

	str += strlen(" Preferred load address is ");
	const size_t loadAddress = readHex();
	
	for (int ln = 0; ln < 3; ++ln) {
		skipLine();
	}

	// Skip to "  Address         Publics by Value              Rva+Base               Lib:Object"
	while (str[1] != ' ' || str[2] != 'A') skipLine();

	skipLine();
	skipLine();

	SymbolMap result;

	while (str < fileContents + fileSize) {
		str += 21;
		const char *const nameBegin = str;
		while (*str != ' ') { ++str; }
		const char* const nameEnd = str;

		while (*str == ' ') { ++str; }
		size_t addr = readHex();
		addr -= loadAddress;

		std::string name(nameBegin, nameEnd);
		result[name] = modBase + addr;

		skipLine();
	}

	delete[] fileContents;
	return result;
}

typedef NTSTATUS(NTAPI *PFN_NT_QUERY_INFORMATION_PROCESS) (
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

// https://github.com/dotnet/coreclr/blob/master/src/ToolBox/SOS/Strike/dllsext.cpp
typedef struct _PRIVATE_LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union _LDR_DATA_TABLE_ENTRY_UNION1 {    //DevDiv LKG RC Changes: Added union name to avoid warning C4408
		LIST_ENTRY HashLinks;
		struct _LDR_DATA_TABLE_ENTRY_STRUCT1 {  //DevDiv LKG RC Changes: Added struct name to avoid warning C4201
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union _LDR_DATA_TABLE_ENTRY_UNION2 {    //DevDiv LKG RC Changes: Added union name to avoid warning C4408
		struct _LDR_DATA_TABLE_ENTRY_STRUCT2 {  //DevDiv LKG RC Changes: Added struct name to avoid warning C4201
			ULONG TimeDateStamp;
		};
		struct _LDR_DATA_TABLE_ENTRY_STRUCT3 {  //DevDiv LKG RC Changes: Added struct name to avoid warning C4201
			PVOID LoadedImports;
		};
	};
	struct _ACTIVATION_CONTEXT * EntryPointActivationContext;

	PVOID PatchInformation;

} PRIVATE_LDR_DATA_TABLE_ENTRY, *PRIVATE_PLDR_DATA_TABLE_ENTRY;

struct Relocation
{
	enum class Type {
		Rel32,
		Abs64
	};

	std::string writeSymbol;
	uint32_t writeOffset;
	std::string readSymbol;
	uint32_t readOffset;
	Type type;
};

typedef std::vector<Relocation> RelocationTable;

void createRelocationTable(const CoffBinary& coff, RelocationTable *const result)
{
	struct SymbolAddr {
		std::string name;
		uint32_t addr;
	};

	struct SectionInfo {
		std::vector<SymbolAddr> symbols;
		uint32_t sectionSize;
	};

	std::vector<SectionInfo> sections(coff.imageHeader->NumberOfSections);

	for (auto& sym : coff.symbols) {
		const bool isValidStatic = sym.StorageClass == CoffBinary::SymClassStatic && sym.SectionNumber > 0 && sym.Value > 0;
		const bool isValidExtern = sym.StorageClass == CoffBinary::SymClassExternal && sym.SectionNumber > 0;

		if (isValidStatic || isValidExtern) {
			sections[sym.SectionNumber - 1].symbols.push_back({
				coff.decodeString(sym.Name), sym.Value
			});
		}
	}

	for (auto& section : sections) {
		const auto& srcSection = coff.sections[uint32_t(&section - &sections[0])];
		const uint32_t sectionSize = srcSection.SizeOfRawData;

		std::sort(section.symbols.begin(), section.symbols.end(), [&](const SymbolAddr& a, const SymbolAddr& b) {
			return a.addr < b.addr;
		});

		for (const auto& srcReloc : coff.getSectionRelocations(srcSection)) {
			if (srcReloc.Type == 11) continue;	// TODO
			if (srcReloc.Type == 10) continue;	// TODO
			if (srcReloc.Type == 3) continue;	// TODO

			// 4: The 32-bit relative address from the byte following the relocation
			// 5..9: similar to 4, with an extra offset from the relocation
			// 1: The 64-bit VA of the relocation target.
			if (!(srcReloc.Type == 1 || (4 <= srcReloc.Type && srcReloc.Type <= 9))) {
				abort();
			}

			uint32_t symAddr = srcReloc.VirtualAddress;
			std::string relocDstSymName;

			uint32_t readOffset = 0;
			if (srcReloc.Type > 4 && srcReloc.Type <= 9) {
				readOffset = srcReloc.Type - 4;
			}

			{
				auto relocDstSym = std::upper_bound(section.symbols.begin(), section.symbols.end(), srcReloc.VirtualAddress, [&](const uint32_t a, const SymbolAddr& b) {
					return a < b.addr;
				});

				if (relocDstSym > section.symbols.begin()) {
					--relocDstSym;
					symAddr -= relocDstSym->addr;
				}

				relocDstSymName = relocDstSym->name;
			}

			const CoffBinary::Symbol& srcSym = coff.symbols[srcReloc.SymbolTableIndex];

			if (symAddr < sectionSize && srcSym.StorageClass != CoffBinary::SymClassStatic && 0 == srcSym.SectionNumber) {
				std::string srcSymName = coff.getSymbolName(srcReloc.SymbolTableIndex);
				if (srcSym.StorageClass == CoffBinary::SymClassWeakExternal && srcSym.SectionNumber == 0 && srcSym.Value == 0 && srcSym.NumberOfAuxSymbols > 0) {
					// Weak symbol (COMDAT). Resolve with the default implementation pointed at by aux data following the symbol.
					srcSymName = coff.getSymbolName(*(uint32_t*)(&srcSym + 1));
				}

				result->push_back({
					relocDstSymName,
					symAddr,
					srcSymName,
					readOffset,
					srcReloc.Type == 1 ? Relocation::Type::Abs64 : Relocation::Type::Rel32
				});
			}
		}
	}
}

HMODULE loadAndRelocatePlugin(const std::string& modName, const SymbolMap& inSituMap)
{
	std::string dllPath = modName + ".dll";
	std::string mapPath = modName + ".map";
	std::string objPath = modName + ".obj";

	size_t dllSize = 0;
	{
		CoffBinary coff;
		readCoff(dllPath.c_str(), &coff);
		coff.parsePe();
		coff.optionalHeader->ImageBase = uint64_t(GetModuleHandle(nullptr)) + 0x100000;
		coff.optionalHeader->DllCharacteristics = 0x120;	// disable address randomization
		writeCoff(dllPath.c_str(), coff);

		dllSize = coff.optionalHeader->SizeOfImage;
	}

	CoffBinary objCoff;
	readCoff(objPath.c_str(), &objCoff);
	objCoff.parse();

	RelocationTable relocTable;
	createRelocationTable(objCoff, &relocTable);

	size_t sizeOfCodeSections = 0;
	for (auto& section : objCoff.sections) {
		if (section.Characteristics & 0x20) {
			sizeOfCodeSections += section.SizeOfRawData;
		}
	}

	HMODULE dll = LoadLibraryA(dllPath.c_str());
	{
		DWORD oldProtect;
		BOOL res = VirtualProtect(dll, dllSize, PAGE_EXECUTE_READWRITE, &oldProtect);
		if (!res) abort();
	}

	const SymbolMap dllMap = parseMapFile(mapPath.c_str(), (const char*)dll);

	for (auto& reloc : relocTable) {
		size_t relocLocation = reloc.writeOffset + (size_t)dllMap.at(reloc.writeSymbol);
		size_t dstAddr = (size_t)getSymbolAddressInCurrentProcess(inSituMap, reloc.readSymbol);

		auto applyRel32 = [&]() {
			ptrdiff_t offset = dstAddr - (relocLocation + 4 + reloc.readOffset);
			if (int32_t(offset) != offset) {
				offset = (size_t)makeFunctionThunk((const char*)dstAddr) - (relocLocation + 4);

				if (int32_t(offset) != offset) {
					abort();
				}
			}
			*(int32_t*)relocLocation = int32_t(offset);
		};

		if (reloc.type == Relocation::Type::Rel32) {
			applyRel32();
		}
		else if (reloc.type == Relocation::Type::Abs64) {
			*(size_t*)relocLocation = dstAddr;
		}
		else {
			abort();
		}
	}

	{
		DWORD oldProtect;
		BOOL res = VirtualProtect(dll, dllSize, PAGE_EXECUTE_READ, &oldProtect);
		if (!res) abort();
	}

	return dll;
}

int main()
{
	// Make references to symbols used in the plugin
	std::cout << "" << std::endl;
	// ----

	const SymbolMap inSituMap = parseMapFile("relocdll.map", (const char*)GetModuleHandle(nullptr));

	HMODULE dll = loadAndRelocatePlugin("test", inSituMap);

	auto foo = (int(*)(int, int))GetProcAddress(dll, "foo");
	auto bar = (void(*)())GetProcAddress(dll, "bar");
	auto baz = (int*(*)())GetProcAddress(dll, "baz");

	int x = foo(2, 3);
	printf("foo returned %d\n", x);

	bar();

	int* z = baz();
	printf("baz returned a pointer at %d\n", *z);
	delete z;

	printf("Hit ENTER to exit.\n");
	getchar();

	return 0;
}
