#include "stdafx.h"

int main(int argc, char* argv[])
{
	std::string filePath;
	
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

	try
	{
		PE_parser peParser(filePath);
		peParser.printHeaderInfo();
	}
	catch (const std::exception& e)
	{
		std::cout << e.what();
	}
}