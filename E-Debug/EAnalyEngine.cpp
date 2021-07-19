#include "EAnalyEngine.h"
#include <QPlainTextEdit>
#include "pluginsdk/_scriptapi_memory.h"
#include "pluginsdk/_scriptapi_pattern.h"
#include "SymbolTable.h"
#include "public.h"

struct EStaticHead
{
	duint dwMagic;  //未知,值固定为3
	duint szNone2;  //未知,值固定为0
	duint szNone3;  //未知,好像是个随机数,修改不影响程序
	duint lpStartCode;   //起始用户代码地址,不可修改
	duint lpEString;     //字符串资源,如果没有字符串资源,则为0
	duint dwEStringSize; //字符串资源大小,如果没有字符串资源,则为0
	duint lpEWindow;     //创建组件信息
	duint dwEWindowSize; //创建组件信息大小
	duint dwLibNum;      //支持库数量
	duint lpLibEntry;    //支持库信息入口
	duint dwApiCount;    //Api数量
	duint lpModuleName;  //指向模块名称
	duint lpApiName;     //指向Api名称
};

EAnalyEngine::EAnalyEngine()
{

}

EAnalyEngine::~EAnalyEngine()
{

}

bool EAnalyEngine::InitEAnalyEngine(unsigned int anyAddr, QPlainTextEdit* outMsg)
{
	m_outMsg = outMsg;
	bool bRet = false;
	if (!InitSectionManager(anyAddr,outMsg)) {
		return false;
	}
	
	duint codeBase = Script::Memory::GetBase(anyAddr);
	duint codeSize = Script::Memory::GetSize(anyAddr);

	duint eMagicHead = Script::Pattern::FindMem(codeBase, codeSize, "50 64 89 25 00 00 00 00 81 EC AC 01 00 00 53 56 57");
	if (eMagicHead != 0) {
		m_AnalysisMode = 1;
		outMsg->appendPlainText(QStringLiteral("->检测到易语言静态编译程序"));
		duint dwHeadAddr = Script::Memory::ReadDword(eMagicHead + 0x26);
		m_bAnalySuccess = Parse_EStatic(dwHeadAddr);
		bRet = true;
	}

	//To do...
	//支持更多模式

	SymbolTable::InitSymbolTable();
	return bRet;
}

bool EAnalyEngine::ParseLibInfomation(duint lpLibStartAddr, duint dwLibCount)
{
	for (unsigned int nLibIndex = 0; nLibIndex < dwLibCount; ++nLibIndex) {

		LIB_INFO tmpLibInfo;
		Script::Memory::Read(Script::Memory::ReadDword(lpLibStartAddr), &tmpLibInfo, sizeof(LIB_INFO), 0);
		lpLibStartAddr = lpLibStartAddr + 4;

		//判断是否符合支持库格式
		if (tmpLibInfo.m_dwLibFormatVer != 0x1312D65) {
			continue;
		}

		mid_ELibInfo eLibInfo;
		eLibInfo.m_Name = get_shortstring(tmpLibInfo.m_lpName);
		eLibInfo.m_Guid = get_shortstring(tmpLibInfo.m_lpGuid);
		eLibInfo.m_nMajorVersion = tmpLibInfo.m_nMajorVersion;
		eLibInfo.m_nMinorVersion = tmpLibInfo.m_nMinorVersion;

		//解析出全部的库函数数据
		LibFuncMap eLibFuncMap;
		eLibFuncMap.libName = get_shortstring(tmpLibInfo.m_lpName);
		eLibFuncMap.libGuid = get_shortstring(tmpLibInfo.m_lpGuid);
		if (tmpLibInfo.m_nCmdCount && tmpLibInfo.m_lpCmdsFunc) {
			duint* pFuncBuf = (duint*)BridgeAlloc(tmpLibInfo.m_nCmdCount * 4);
			Script::Memory::Read(tmpLibInfo.m_lpCmdsFunc, pFuncBuf, tmpLibInfo.m_nCmdCount * 4, 0);
			for (unsigned int nFuncIndex = 0; nFuncIndex < tmpLibInfo.m_nCmdCount; ++nFuncIndex) {
				LibFuncMap::FuncInfo tmpFunc;
				tmpFunc.addr = pFuncBuf[nFuncIndex];
				eLibFuncMap.vec_Funcs.push_back(tmpFunc);
			}
			BridgeFree(pFuncBuf);
		}

		mVec_LibFunc.push_back(eLibFuncMap);
	}

	return true;
}

bool EAnalyEngine::Parse_EStatic(duint eHeadAddr)
{
	EStaticHead eHead;

	Script::Memory::Read(eHeadAddr, &eHead, sizeof(EStaticHead), 0);
	if (eHead.dwMagic != 0x3) {
		return false;
	}

	if (!ParseLibInfomation(eHead.lpLibEntry, eHead.dwLibNum)) {
		return false;
	}

	duint dwKrnlEntry = eHead.lpEString;
	if (dwKrnlEntry == 0) {
		dwKrnlEntry = eHead.lpEWindow;
	}
	m_UserCodeStartAddr= eHead.lpStartCode;


	return true;
}