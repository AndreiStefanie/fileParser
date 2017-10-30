#pragma once
#include "stdafx.h"

const char *characteristicsDescription[16] = {
	"Relocation info stripped from file.",
	"File is executable  (i.e. no unresolved externel references).",
	"Line nunbers stripped from file.",
	"Local symbols stripped from file.",
	"Agressively trim working set",
	"App can handle >2gb addresses",
	"Bytes of machine word are reversed.",
	"????????",
	"32 bit word machine.",
	"Debugging info stripped from file in .DBG file",
	"If Image is on removable media, copy and run from the swap file.",
	"If Image is on Net, copy and run from the swap file.",
	"System File.",
	"File is a DLL.",
	"File should only be run on a UP machine"
	"Bytes of machine word are reversed."
};

void PE_parser::openFile(std::string & filePath)
{
	hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		throw std::invalid_argument("Could not open the file.");

	hMapping = CreateFileMappingA(hFile, 0, PAGE_READONLY, 0, 0, 0);
	if (hMapping == 0)
		throw std::invalid_argument("Could not create the map of the file.");

	fileBegin = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (fileBegin == 0)
		throw std::invalid_argument("Could not map the file.");

	//lib = LoadLibraryEx((LPCWSTR)filePath.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);

	pDos = (IMAGE_DOS_HEADER*)fileBegin;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
		throw std::invalid_argument("MSDOS signature missing.");

	pHeader = (PIMAGE_NT_HEADERS)(fileBegin + pDos->e_lfanew);
	if (pHeader->Signature != IMAGE_NT_SIGNATURE)
		throw std::invalid_argument("PE signature missing.");

	sections = IMAGE_FIRST_SECTION(pHeader);
}

void PE_parser::printCharacteristics(std::ostream& stream)
{
	int i, mask;

	printTabs(1, stream);
	stream << "Characteristics: " << std::endl;
	for (i = 0, mask = 1; i < 16; i++, mask <<= 1)
		if (mask & pHeader->FileHeader.Characteristics)
		{
			printTabs(2, stream);
			stream << characteristicsDescription[i] << std::endl;
		}
}

void PE_parser::printHeaderInfo(std::ostream& stream)
{
	stream << "Header:" << std::endl;
	PE_parser::printMachine(stream);
	PE_parser::printCharacteristics(stream);
	PE_parser::printExports(stream);
	//PE_parser::printImports(stream);
	//DumpExportsSection((DWORD)fileBegin, pHeader);
}

void PE_parser::printMachine(std::ostream& stream)
{
	std::string machine;
	switch (pHeader->FileHeader.Machine)
	{
	case IMAGE_FILE_MACHINE_UNKNOWN:
		machine.append("Unknown");
		break;
	case IMAGE_FILE_MACHINE_I386:
		machine.append("Intel 386");
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		machine.append("AMD64");
		break;
	default:
		machine.append("Unknown");
	}
	printTabs(1, stream);
	stream << "Machine: " << machine << std::endl;
}

void PE_parser::printExports(std::ostream& stream)
{
	if (pHeader->OptionalHeader.NumberOfRvaAndSizes < 1)
		return;

	PIMAGE_EXPORT_DIRECTORY expDescriptor;
	PDWORD *name_table;

	expDescriptor = (PIMAGE_EXPORT_DIRECTORY)(fileBegin + rva2Offset(pHeader->
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	name_table = (PDWORD *)(fileBegin + rva2Offset(expDescriptor->AddressOfNames));

	printTabs(1, stream);
	stream << "Exports:" << std::endl;
	printTabs(2, stream);
	stream << "Names (" << expDescriptor->NumberOfNames << "): " << std::endl;
	for (unsigned int i = 0; i < expDescriptor->NumberOfNames; i++)
	{
		printTabs(3, stream);
		stream << (BYTE *)(fileBegin + rva2Offset((unsigned int)name_table[i])) << std::endl;
		if (i == DISPLAY_LIMIT)
		{
			printTabs(3, stream);
			stream << "... " << expDescriptor->NumberOfNames - DISPLAY_LIMIT << " more" << std::endl;
			break;
		}
	}
}

void PE_parser::printImports(std::ostream& stream)
{
	if (pHeader->OptionalHeader.NumberOfRvaAndSizes < 2)
		return;

	PIMAGE_IMPORT_DESCRIPTOR impDescriptor;

	impDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(fileBegin + rva2Offset(
		pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

	printTabs(1, stream);
	stream << "Imports:" << std::endl;
	printTabs(2, stream);
	//PIMAGE_IMPORT_DESCRIPTOR impDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)
	//(pHeader->OptionalHeader.ImageBase + imports.VirtualAddress);
	//for (int i = 0; i < impDescriptor->FirstThunk; i++)
	//{
	/*printTabs(3);

	printf("\n");*/
	//}
}

DWORD PE_parser::rva2Offset(unsigned int rva)
{
	for (int i = 0; i < pHeader->FileHeader.NumberOfSections; i++) 
	{
		if ((rva >= sections[i].VirtualAddress) && 
			(rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize))
			return sections[i].PointerToRawData + rva - sections[i].VirtualAddress;
	}

	return -1;
}
