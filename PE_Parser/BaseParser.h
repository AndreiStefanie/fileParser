#pragma once
#include "stdafx.h"

class BaseParser
{
public:
	BaseParser() {};
	~BaseParser() {};
	void printTabs(unsigned int tabs = 1, std::ostream& stream = std::cout);

private:

};

inline void BaseParser::printTabs(unsigned int tabs, std::ostream& stream)
{
	std::string sTabs(tabs, '\t');
	stream << sTabs;
}
