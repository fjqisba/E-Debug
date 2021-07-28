#include "SymbolTable.h"
#include "pluginsdk/bridgemain.h"
#include "pluginsdk/_scriptapi_symbol.h"
#include "pluginsdk/_scriptapi_module.h"

std::map<unsigned int, std::string> SymbolTable::g_SymbolMap;

void SymbolTable::InitSymbolTable()
{
	g_SymbolMap.clear();

	BridgeList<Script::Symbol::SymbolInfo> symbolList;
	Script::Symbol::GetList(&symbolList);

	for (unsigned int n = 0; n < symbolList.Count(); ++n) {
		duint modBase = DbgModBaseFromName(symbolList[n].mod);
		g_SymbolMap[modBase + symbolList[n].rva] = symbolList[n].name;
	}
	return;
}

std::string SymbolTable::FindSymbolName(unsigned int addr)
{
	return g_SymbolMap[addr];
}