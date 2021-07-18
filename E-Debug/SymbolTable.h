#pragma once
#include <map>
#include <string>


class SymbolTable
{
public:
	static void InitSymbolTable();
	static std::string FindSymbolName(unsigned int);
public:
	static std::map<unsigned int, std::string> g_SymbolMap;
};