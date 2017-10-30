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
		std::unique_ptr<BaseParser> parser = std::make_unique<PE_parser>(filePath);
		parser->printHeaderInfo();
	}
	catch (const std::exception& e)
	{
		std::cout << e.what();
	}
	getchar();
}