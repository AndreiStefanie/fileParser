#pragma once
#include "stdafx.h"
#define DISPLAY_LIMIT 30

class PE_parser : public BaseParser
{
public:
	PE_parser() {};
	PE_parser(std::string& filePath)
	{
		openFile(filePath);
	};
	~PE_parser() 
	{
		if (hFile)
			CloseHandle(hFile);
		if (hMapping)
			CloseHandle(hMapping);
		if (fileBegin)
			UnmapViewOfFile(fileBegin);
	};
	void openFile(std::string& filePath);
	void printCharacteristics(std::ostream& stream = std::cout);
	void printHeaderInfo(std::ostream& stream = std::cout);

private:
	HANDLE hFile = 0;
	HANDLE hMapping = 0;
	HMODULE lib;
	IMAGE_DOS_HEADER *pDos;
	IMAGE_NT_HEADERS *pHeader;
	IMAGE_SECTION_HEADER *sections;
	BYTE *fileBegin = 0;

	void printMachine(std::ostream& stream = std::cout);
	void printExports(std::ostream& stream = std::cout);
	void printImports(std::ostream& stream = std::cout);
	DWORD rva2Offset(unsigned int rva);
};
