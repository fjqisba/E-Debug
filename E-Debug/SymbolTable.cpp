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

	unsigned int baseStart = Script::Module::GetMainModuleBase();
	for (unsigned int n = 0; n < symbolList.Count(); ++n) {
		g_SymbolMap[baseStart + symbolList[n].rva] = symbolList[n].name;
	}
}

std::string SymbolTable::FindSymbolName(unsigned int addr)
{
	return g_SymbolMap[addr];
}