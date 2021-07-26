#include "EAnalyEngine.h"
#include <QPlainTextEdit>
#include "pluginsdk/_scriptapi_memory.h"
#include "pluginsdk/_scriptapi_pattern.h"
#include "pluginsdk/_scriptapi_comment.h"
#include "pluginsdk/_scriptapi_label.h"
#include "SymbolTable.h"
#include ".\EAppControl\EAppControlFactory.h"
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

unsigned int krnln_GetIDSubType(unsigned int ID)
{
	return ID & 0xF0000000;
}

unsigned int krnln_GetIDGroupType(unsigned int ID)
{
	return ID & 0xF000000;
}

bool krnln_IsMenuItemID(unsigned int ID)
{
	return krnln_GetIDGroupType(ID) == 0x6000000 && krnln_GetIDSubType(ID) == 0x20000000;
}

unsigned int GetDataTypeType(unsigned int typeID)
{
	unsigned int result = typeID;
	if (typeID)
	{
		if ((typeID & 0xC0000000) == 0x80000000) {
			result = 1;
		}
		else {
			result = ((typeID & 0xC0000000) != 0x40000000) + 2;
		}
	}
	return result;
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

void EAnalyEngine::ParseKrnlInterface(duint lpKrnlEntry)
{
	lpKrnlEntry -= sizeof(mid_KrnlApp);
	Script::Memory::Read(lpKrnlEntry, &m_KrnlApp, sizeof(mid_KrnlApp), 0);

	Script::Label::Set(m_KrnlApp.krnl_MReportError, StringUtils::LocalCpToUtf8("错误回调").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MCallDllCmd, StringUtils::LocalCpToUtf8("DLL命令").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MCallLibCmd, StringUtils::LocalCpToUtf8("三方支持库命令").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MCallKrnlLibCmd, StringUtils::LocalCpToUtf8("核心支持库命令").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MReadProperty, StringUtils::LocalCpToUtf8("读取组件属性").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MWriteProperty, StringUtils::LocalCpToUtf8("设置组件属性").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MMalloc, StringUtils::LocalCpToUtf8("分配内存").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MRealloc, StringUtils::LocalCpToUtf8("重新分配内存").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MFree, StringUtils::LocalCpToUtf8("释放内存").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MExitProcess, StringUtils::LocalCpToUtf8("结束").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MMessageLoop, StringUtils::LocalCpToUtf8("窗口消息循环").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MLoadBeginWin, StringUtils::LocalCpToUtf8("载入启动窗口").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MOtherHelp, StringUtils::LocalCpToUtf8("辅助函数").c_str());
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

	
		//解析出全部的库函数数据
		ElibInfo eLibInfo;
		eLibInfo.libName = get_shortstring(tmpLibInfo.m_lpName);
		eLibInfo.libGuid = get_shortstring(tmpLibInfo.m_lpGuid);
		eLibInfo.nMajorVersion = tmpLibInfo.m_nMajorVersion;
		eLibInfo.nMinorVersion = tmpLibInfo.m_nMinorVersion;
		if (tmpLibInfo.m_nCmdCount && tmpLibInfo.m_lpCmdsFunc) {
			duint* pFuncBuf = (duint*)BridgeAlloc(tmpLibInfo.m_nCmdCount * 4);
			Script::Memory::Read(tmpLibInfo.m_lpCmdsFunc, pFuncBuf, tmpLibInfo.m_nCmdCount * 4, 0);
			for (unsigned int nFuncIndex = 0; nFuncIndex < tmpLibInfo.m_nCmdCount; ++nFuncIndex) {
				ElibInfo::FuncInfo tmpFunc;
				tmpFunc.addr = pFuncBuf[nFuncIndex];
				eLibInfo.vec_Funcs.push_back(tmpFunc);
			}
			BridgeFree(pFuncBuf);
		}

		//解析支持库中的数据类型
		duint lpFirstDataType = tmpLibInfo.m_lpDataType;
		for (int nDataTypeIndex = 0; nDataTypeIndex < tmpLibInfo.m_nDataTypeCount; ++nDataTypeIndex) {
			LIB_DATA_TYPE_INFO tmpDataTypeInfo;
			memcpy(&tmpDataTypeInfo,LinearAddrToVirtualAddr(lpFirstDataType), sizeof(LIB_DATA_TYPE_INFO));
			lpFirstDataType += sizeof(LIB_DATA_TYPE_INFO);

			EDataTypeInfo eDataType;
			if (tmpDataTypeInfo.m_lpszName) {
				unsigned int controlTypeId = (nLibIndex + 1) << 0x10;
				controlTypeId = controlTypeId + (nDataTypeIndex + 1);
				eDataType.dataTypeName = get_shortstring(tmpDataTypeInfo.m_lpszName);
			}
			eLibInfo.vec_DataTypeInfo.push_back(eDataType);
		}

		mVec_LibInfo.push_back(eLibInfo);
	}

	return true;
}

bool EAnalyEngine::ParseUserImports(duint dwApiCount, duint lpModuleName, duint lpApiName)
{
	unsigned char* pszLibnameAddr = SectionManager::LinearAddrToVirtualAddr(lpModuleName);
	unsigned char* pszApinameAddr = SectionManager::LinearAddrToVirtualAddr(lpApiName);

	for (unsigned int n = 0; n < dwApiCount; ++n) {
		char* pszLibname = (char*)SectionManager::LinearAddrToVirtualAddr(ReadUInt(pszLibnameAddr));
		char* pszApiname = (char*)SectionManager::LinearAddrToVirtualAddr(ReadUInt(pszApinameAddr));

		ImportsApi eImportsApi = {};
		eImportsApi.LibName = pszLibname;
		eImportsApi.ApiName = pszApiname;

		mVec_ImportsApi.push_back(eImportsApi);
		pszLibnameAddr += 4;
		pszApinameAddr += 4;
	}
	return true;
}

duint EAnalyEngine::GetUserCodeEndAddr()
{
	//首先尝试通过特征码来定位用户代码结束地址
	duint codeEndAddr = SeachUserCodeEndAddr();
	if (codeEndAddr) {
		codeEndAddr = codeEndAddr + 1;
		codeEndAddr = codeEndAddr + ReadInt(LinearAddrToVirtualAddr(codeEndAddr + 1)) + 5;

		QString outMsg;
		outMsg.sprintf("->%s: %08X", StringUtils::LocalCpToUtf8("易语言程序入口").c_str(), codeEndAddr);
		m_outMsg->appendPlainText(outMsg);
		Script::Comment::Set(codeEndAddr, StringUtils::LocalCpToUtf8("易语言程序入口").c_str());
		return codeEndAddr;
	}

	//系统支持库函数中的最小地址函数作为结束地址
	if (mVec_LibInfo[0].vec_Funcs.size()) {
		unsigned int nMinAddress = 0xFFFFFFFF;
		for (unsigned int n = 0; n < mVec_LibInfo[0].vec_Funcs.size(); ++n) {
			if (mVec_LibInfo[0].vec_Funcs[n].addr < nMinAddress) {
				nMinAddress = mVec_LibInfo[0].vec_Funcs[n].addr;
			}
		}
		return nMinAddress;
	}

	return mVec_segInfo[0].m_segStart + mVec_segInfo[0].m_segSize - 1;
}



std::string EAnalyEngine::GetControlTypeName(duint typeId)
{
	std::string ret;
	if (GetDataTypeType(typeId) != 3) {
		return ret;
	}

	int libIndex = (typeId >> 0x10) - 1;
	if (libIndex >= mVec_LibInfo.size()) {
		return ret;
	}
	int typeIndex = (unsigned short)typeId - 1;
	if (typeIndex >= mVec_LibInfo[libIndex].vec_DataTypeInfo.size()) {
		return ret;
	}
	ret = mVec_LibInfo[libIndex].vec_DataTypeInfo[typeIndex].dataTypeName;
	return ret;
}

void EAnalyEngine::ParseControlBasciProperty(unsigned char* lpControlInfo, mid_ControlInfo& out_Property)
{
	//无用字符串1?
	ReadStr(lpControlInfo);
	lpControlInfo += strlen((char*)lpControlInfo) + 1;

	//存储数据?
	ReadUInt(lpControlInfo);
	lpControlInfo += 4;

	unsigned int m_left = ReadUInt(lpControlInfo);
	lpControlInfo += 4;

	unsigned int m_top = ReadUInt(lpControlInfo);
	lpControlInfo += 4;

	unsigned int m_width = ReadUInt(lpControlInfo);
	lpControlInfo += 4;

	unsigned int m_height = ReadUInt(lpControlInfo);
	lpControlInfo += 4;

	//值为0,用来存储LoadCursorA返回的句柄值的
	unsigned int hCURSOR = ReadUInt(lpControlInfo);
	lpControlInfo += 4;

	//父控件ID
	unsigned int fatherControlId = ReadUInt(lpControlInfo);
	lpControlInfo += 4;

	//子控件数目
	unsigned int childControlCount = ReadUInt(lpControlInfo);
	lpControlInfo += 4;

	for (unsigned int n = 0; n < childControlCount; ++n) {
		unsigned int tmpChildControlId = ReadUInt(lpControlInfo);
		lpControlInfo += 4;
		//out_Property.mVec_childControl.push_back(tmpChildControlId);
	}

	//未知偏移
	unsigned int offset2 = ReadUInt(lpControlInfo);
	lpControlInfo += offset2 + 4;

	//标记
	std::string m_tag = ReadStr(lpControlInfo);
	lpControlInfo += strlen((char*)lpControlInfo) + 1;

	//未知的值
	lpControlInfo += 12;

	int dwEventCount = ReadInt(lpControlInfo);
	lpControlInfo += 4;
	
	for (int nIndexEvent = 0; nIndexEvent < dwEventCount; ++nIndexEvent) {
		mid_EventInfo tmpEvent;
		tmpEvent.nEventIndex = ReadInt(lpControlInfo);
		lpControlInfo += 4;
		tmpEvent.eventAddr = ReadUInt(lpControlInfo) + m_UserCodeStartAddr;
		lpControlInfo += 4;
		out_Property.vec_eventInfo.push_back(tmpEvent);
	}
	return;
}

bool EAnalyEngine::ParseGUIResource(duint lpGUIStart, duint infoSize)
{
	std::vector<unsigned char> tmpGuiBuf;
	tmpGuiBuf.resize(infoSize);
	if (!Script::Memory::Read(lpGUIStart, &tmpGuiBuf[0], infoSize, 0)) {
		return false;
	}

	//当前解析地址
	unsigned char* lpCurrentParseAddr = &tmpGuiBuf[0];
	std::vector<unsigned int> vec_WindowId;
	unsigned int dwTotalWindowCount = ReadUInt(&tmpGuiBuf[0]) >> 3;
	lpCurrentParseAddr += 4;

	for (unsigned int n = 0; n < dwTotalWindowCount; ++n) {
		vec_WindowId.push_back(ReadUInt(lpCurrentParseAddr));
		lpCurrentParseAddr += 4;
	}

	//编译器遗留值?
	for (unsigned int n = 0; n < dwTotalWindowCount; ++n) {
		//uint32 unknowId = ReadUInt(lpCurrentParseAddr);
		lpCurrentParseAddr += 4;
	}

	for (unsigned int nIndexWindow = 0; nIndexWindow < dwTotalWindowCount; ++nIndexWindow) {
		unsigned char* lpWindowInfo = lpCurrentParseAddr;

		mid_GuiInfo eGuiInfo;
		eGuiInfo.windowId = vec_WindowId[nIndexWindow];

		//暂时未知
		unsigned int unKnownFieldA = ReadUInt(lpWindowInfo);
		lpWindowInfo += 4;
		unsigned int unKnownFieldB = ReadUInt(lpWindowInfo);
		lpWindowInfo += 4;

		//接下来跟着两个CString,都为空
		lpWindowInfo += 8;

		//单个窗口中的控件总个数
		unsigned int dwTotalControlCount = ReadUInt(lpWindowInfo);
		lpWindowInfo += 4;

		//单个窗口中的控件总占用大小
		unsigned int dwTotalControlSize = ReadUInt(lpWindowInfo);
		lpWindowInfo += 4;

		//开始解析控件
		unsigned char* lpControlArray = lpWindowInfo;
		{
			//解析控件ID,例如0x160612BC
			std::vector<unsigned int> vec_ControlId;
			for (unsigned int j = 0; j < dwTotalControlCount; ++j) {
				vec_ControlId.push_back(ReadUInt(lpControlArray));
				lpControlArray += 4;
			}

			//解析控件偏移
			std::vector<unsigned int> vec_ControlOffset;
			for (unsigned int j = 0; j < dwTotalControlCount; ++j) {
				vec_ControlOffset.push_back(ReadUInt(lpControlArray));
				lpControlArray += 4;
			}

			//解析控件属性
			for (unsigned int nIndexControl = 0; nIndexControl < dwTotalControlCount; ++nIndexControl) {
				unsigned char* lpControlInfo = lpControlArray + vec_ControlOffset[nIndexControl];

				mid_ControlInfo eControlInfo;

				//控件占用的大小
				int dwControlSize = ReadInt(lpControlInfo);
				lpControlInfo += 4;

				eControlInfo.propertyAddr = lpGUIStart + (lpControlInfo - &tmpGuiBuf[0]);
				eControlInfo.propertySize = dwControlSize;

				//控件类型ID
				unsigned int dwControlTypeId = ReadUInt(lpControlInfo);
				lpControlInfo += 4;

				//固定的20个空字节,保留使用?
				lpControlInfo += 20;

				if (dwControlTypeId == 0x10001) {
					lpControlInfo += strlen((char*)lpControlInfo)+1;
					ParseControlBasciProperty(lpControlInfo, eControlInfo);
					eControlInfo.controlName = StringUtils::sprintf("窗口0x%08X", eGuiInfo.windowId);
				}
				else if (krnln_IsMenuItemID(vec_ControlId[nIndexControl])) {
					lpControlInfo += 14;
					eControlInfo.controlName = ReadStr(lpControlInfo);
				}
				else {
					eControlInfo.controlName = ReadStr(lpControlInfo);
					lpControlInfo += strlen((char*)lpControlInfo) + 1;
					ParseControlBasciProperty(lpControlInfo, eControlInfo);
				}

				eControlInfo.controlId = vec_ControlId[nIndexControl];
				eControlInfo.controlTypeId = dwControlTypeId;
				eControlInfo.controlTypeName = GetControlTypeName(dwControlTypeId);
				eControlInfo.controlType = EAppControlFactory::GetControlType(eControlInfo.controlTypeName);
				eGuiInfo.vec_ControlInfo.push_back(eControlInfo);
			}
		}

		mVec_GuiInfo.push_back(eGuiInfo);
		lpCurrentParseAddr = lpWindowInfo + dwTotalControlSize;
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
	ParseKrnlInterface(dwKrnlEntry);
	m_UserCodeStartAddr = eHead.lpStartCode;
	m_UserCodeEndAddr = GetUserCodeEndAddr();

	if (eHead.dwApiCount) {
		ParseUserImports(eHead.dwApiCount, eHead.lpModuleName, eHead.lpApiName);
	}

	if (eHead.lpEWindow != 0 && eHead.dwEWindowSize > 4) {
		ParseGUIResource(eHead.lpEWindow, eHead.dwEWindowSize);
	}

	return true;
}