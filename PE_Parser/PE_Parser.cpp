#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include "defines.h"
#include <Dbghelp.h>

void parseCharacteristics(DWORD caract) 
{
	int i, mask;

	for (i = 0, mask = 1; i < 16; i++, mask <<= 1)
	{
		if (mask & caract)
			printf("\t\t%s\n", characteristics[i]);
	}
}

void printTabs(int tabs = 0)
{
	for (int i = 0; i < tabs; i++)
	{
		printf("\t");
	}
}

int main(int argc, char* argv[])
{
	char *filePath;
	HANDLE hFile = 0, hMapping = 0;
	IMAGE_DOS_HEADER *pDos;
	IMAGE_NT_HEADERS *pHeader;
	IMAGE_SECTION_HEADER *sectionHeader;
	DWORD dimensiuneFisier;
	BYTE *inceputFisier = 0;

	if (argc > 1)
	{
		filePath = argv[1];
	}
	else
	{
		printf("Usage: PE_parser.exe <target file>");
		getchar();
		exit(1);
	}

	hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		ABORT("Fisierul un a putut fi deschis");
	hMapping = CreateFileMappingA(hFile, 0, PAGE_READONLY, 0, 0, 0);
	if (hMapping == 0)
		ABORT("Fiserul nu s-a putut mapa");
	inceputFisier = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (inceputFisier == 0)
		ABORT("Eroare la crearea vederii");
	dimensiuneFisier = GetFileSize(hFile, 0);

	pDos = (IMAGE_DOS_HEADER*)inceputFisier;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
		ABORT("Nu are semnatura unui fisier MSDOS");

	MAP(IMAGE_NT_HEADERS*, pDos->e_lfanew, "pDos->e_lfanew > dimensiunea fisierului", pHeader);
	if (pHeader->Signature != IMAGE_NT_SIGNATURE)
		ABORT("Nu e executabil PE");

	printf("File Header:\n");
	printf("\tMachine = ");
	switch (pHeader->FileHeader.Machine)
	{
	case IMAGE_FILE_MACHINE_UNKNOWN:
		printf("unknown\n");
		break;
	case IMAGE_FILE_MACHINE_I386:
		printf("Intel 386\n");
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		printf("AMD64\n");
		ABORT("");
		break;
	default:
		printf("netratat\n");
	}
	parseCharacteristics(pHeader->FileHeader.Characteristics);

	printTabs(2);
	printf("Image base: %d\n", pHeader->OptionalHeader.ImageBase);

	// Exports
	if (pHeader->OptionalHeader.NumberOfRvaAndSizes >= 1)
	{
		IMAGE_DATA_DIRECTORY exports = pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		printTabs(2);
		printf("Exports (%d):\n", exports.Size);
		PIMAGE_EXPORT_DIRECTORY expDescriptor = (PIMAGE_EXPORT_DIRECTORY) (pHeader->OptionalHeader.ImageBase + exports.VirtualAddress);
		//PDWORD name_table = (PDWORD)(pHeader->OptionalHeader.ImageBase + expDescriptor->AddressOfNames);
		//ImageRvaToVa(pHeader, pHeader->OptionalHeader.ImageBase, expDescriptor->NumberOfNames, NULL);
		//printf("%d\n", expDescriptor->NumberOfNames);
		/*for (unsigned int i = 0; i < expDescriptor->NumberOfNames; i++)
		{
			printTabs(3);
			printf("%s", (char *) (name_table[i]));
			printf("\n");
		}*/
	}

	// Imports
	if (pHeader->OptionalHeader.NumberOfRvaAndSizes >= 2)
	{
		printf("\n");
		IMAGE_DATA_DIRECTORY imports = pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		printTabs(2);
		printf("Imports (%d):\n", imports.Size);
		//PIMAGE_IMPORT_DESCRIPTOR impDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)
			//(pHeader->OptionalHeader.ImageBase + imports.VirtualAddress);
		//for (int i = 0; i < impDescriptor->FirstThunk; i++)
		//{
			/*printTabs(3);

			printf("\n");*/
		//}
	}

	printf("Section Header\n");
	ABORT("Done\n");
}

