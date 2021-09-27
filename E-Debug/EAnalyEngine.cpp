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
	duint dwMagic;  //δ֪,ֵ�̶�Ϊ3
	duint szNone2;  //δ֪,ֵ�̶�Ϊ0
	duint szNone3;  //δ֪,�����Ǹ������,�޸Ĳ�Ӱ�����
	duint lpStartCode;   //��ʼ�û������ַ,�����޸�
	duint lpEString;     //�ַ�����Դ,���û���ַ�����Դ,��Ϊ0
	duint dwEStringSize; //�ַ�����Դ��С,���û���ַ�����Դ,��Ϊ0
	duint lpEWindow;     //���������Ϣ
	duint dwEWindowSize; //���������Ϣ��С
	duint dwLibNum;      //֧�ֿ�����
	duint lpLibEntry;    //֧�ֿ���Ϣ���
	duint dwApiCount;    //Api����
	duint lpModuleName;  //ָ��ģ������
	duint lpApiName;     //ָ��Api����
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
		outMsg->appendPlainText(QStringLiteral("->��⵽�����Ծ�̬�������"));
		duint dwHeadAddr = Script::Memory::ReadDword(eMagicHead + 0x26);
		if (m_bAnalySuccess = Parse_EStatic(dwHeadAddr)) {
			return true;
		}
	}

	//ǿ�����������Ծ�̬��������
	std::string pattern_eMgData = "0300000000000000??????????";
	pattern_eMgData.append(UCharToStr(codeBase >> 0x8));
	pattern_eMgData.append(UCharToStr(codeBase >> 0x10));
	pattern_eMgData.append(UCharToStr(codeBase >> 0x18));
	for (unsigned int n = 0; n < mVec_segInfo.size(); ++n) {
		duint eMagicDataOffset = Script::Pattern::Find(mVec_segInfo[n].m_segData.data(), mVec_segInfo[n].m_segSize, pattern_eMgData.c_str());
		if (eMagicDataOffset == -1) {
			continue;
		}
		unsigned char* eMagicDataHead = &mVec_segInfo[n].m_segData[eMagicDataOffset];
		unsigned int dwLibEntry = ReadUInt(eMagicDataHead + 0x24);
		unsigned char* lpLibEntry = SectionManager::LinearAddrToVirtualAddr(dwLibEntry);
		if (!lpLibEntry) {
			continue;
		}
		unsigned int dwFirstLibAddr = ReadUInt(lpLibEntry);
		unsigned char* lpFirstLibAddr = SectionManager::LinearAddrToVirtualAddr(dwFirstLibAddr);
		if (!lpFirstLibAddr) {
			continue;
		}
		if (ReadUInt(lpFirstLibAddr) == 0x1312D65) {
			m_AnalysisMode = 1;
			outMsg->appendPlainText(QStringLiteral("->��⵽�����Ծ�̬�������"));
			m_bAnalySuccess = Parse_EStatic(SectionManager::VirtualAddrToLinearAddr(eMagicDataHead));
			bRet = true;
			break;
		}
	}

	//To do...
	//֧�ָ���ģʽ

	SymbolTable::InitSymbolTable();
	return bRet;
}

void EAnalyEngine::ParseKrnlInterface(duint lpKrnlEntry)
{
	lpKrnlEntry -= sizeof(mid_KrnlApp);
	Script::Memory::Read(lpKrnlEntry, &m_KrnlApp, sizeof(mid_KrnlApp), 0);

	Script::Label::Set(m_KrnlApp.krnl_MReportError, StringUtils::LocalCpToUtf8("����ص�").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MCallDllCmd, StringUtils::LocalCpToUtf8("DLL����").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MCallLibCmd, StringUtils::LocalCpToUtf8("����֧�ֿ�����").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MCallKrnlLibCmd, StringUtils::LocalCpToUtf8("����֧�ֿ�����").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MReadProperty, StringUtils::LocalCpToUtf8("��ȡ�������").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MWriteProperty, StringUtils::LocalCpToUtf8("�����������").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MMalloc, StringUtils::LocalCpToUtf8("�����ڴ�").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MRealloc, StringUtils::LocalCpToUtf8("���·����ڴ�").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MFree, StringUtils::LocalCpToUtf8("�ͷ��ڴ�").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MExitProcess, StringUtils::LocalCpToUtf8("����").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MMessageLoop, StringUtils::LocalCpToUtf8("������Ϣѭ��").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MLoadBeginWin, StringUtils::LocalCpToUtf8("������������").c_str());
	Script::Label::Set(m_KrnlApp.krnl_MOtherHelp, StringUtils::LocalCpToUtf8("��������").c_str());
}

bool EAnalyEngine::ParseLibInfomation(duint lpLibStartAddr, duint dwLibCount)
{
	for (unsigned int nLibIndex = 0; nLibIndex < dwLibCount; ++nLibIndex) {

		LIB_INFO tmpLibInfo;
		Script::Memory::Read(Script::Memory::ReadDword(lpLibStartAddr), &tmpLibInfo, sizeof(LIB_INFO), 0);
		lpLibStartAddr = lpLibStartAddr + 4;

		//�ж��Ƿ����֧�ֿ��ʽ
		if (tmpLibInfo.m_dwLibFormatVer != 0x1312D65) {
			continue;
		}

	
		//������ȫ���Ŀ⺯������
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

		//����֧�ֿ��е���������
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
	//���ȳ���ͨ������������λ�û����������ַ
	duint codeEndAddr = SeachUserCodeEndAddr();
	if (codeEndAddr) {
		codeEndAddr = codeEndAddr + 1;
		codeEndAddr = codeEndAddr + ReadInt(LinearAddrToVirtualAddr(codeEndAddr + 1)) + 5;

		QString outMsg;
		outMsg.sprintf("->%s: %08X", StringUtils::LocalCpToUtf8("�����Գ������").c_str(), codeEndAddr);
		m_outMsg->appendPlainText(outMsg);
		Script::Comment::Set(codeEndAddr, StringUtils::LocalCpToUtf8("�����Գ������").c_str());
		return codeEndAddr;
	}

	//ϵͳ֧�ֿ⺯���е���С��ַ������Ϊ������ַ
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
	//�����ַ���1?
	ReadStr(lpControlInfo);
	lpControlInfo += strlen((char*)lpControlInfo) + 1;

	//�洢����?
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

	//ֵΪ0,�����洢LoadCursorA���صľ��ֵ��
	unsigned int hCURSOR = ReadUInt(lpControlInfo);
	lpControlInfo += 4;

	//���ؼ�ID
	unsigned int fatherControlId = ReadUInt(lpControlInfo);
	lpControlInfo += 4;

	//�ӿؼ���Ŀ
	unsigned int childControlCount = ReadUInt(lpControlInfo);
	lpControlInfo += 4;

	for (unsigned int n = 0; n < childControlCount; ++n) {
		unsigned int tmpChildControlId = ReadUInt(lpControlInfo);
		lpControlInfo += 4;
		//out_Property.mVec_childControl.push_back(tmpChildControlId);
	}

	//δ֪ƫ��
	unsigned int offset2 = ReadUInt(lpControlInfo);
	lpControlInfo += offset2 + 4;

	//���
	std::string m_tag = ReadStr(lpControlInfo);
	lpControlInfo += strlen((char*)lpControlInfo) + 1;

	//δ֪��ֵ
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

	//��ǰ������ַ
	unsigned char* lpCurrentParseAddr = &tmpGuiBuf[0];
	std::vector<unsigned int> vec_WindowId;
	unsigned int dwTotalWindowCount = ReadUInt(&tmpGuiBuf[0]) >> 3;
	lpCurrentParseAddr += 4;

	for (unsigned int n = 0; n < dwTotalWindowCount; ++n) {
		vec_WindowId.push_back(ReadUInt(lpCurrentParseAddr));
		lpCurrentParseAddr += 4;
	}

	//����������ֵ?
	for (unsigned int n = 0; n < dwTotalWindowCount; ++n) {
		//uint32 unknowId = ReadUInt(lpCurrentParseAddr);
		lpCurrentParseAddr += 4;
	}

	for (unsigned int nIndexWindow = 0; nIndexWindow < dwTotalWindowCount; ++nIndexWindow) {
		unsigned char* lpWindowInfo = lpCurrentParseAddr;

		mid_GuiInfo eGuiInfo;
		eGuiInfo.windowId = vec_WindowId[nIndexWindow];

		//��ʱδ֪
		unsigned int unKnownFieldA = ReadUInt(lpWindowInfo);
		lpWindowInfo += 4;
		unsigned int unKnownFieldB = ReadUInt(lpWindowInfo);
		lpWindowInfo += 4;

		//��������������CString,��Ϊ��
		lpWindowInfo += 8;

		//���������еĿؼ��ܸ���
		unsigned int dwTotalControlCount = ReadUInt(lpWindowInfo);
		lpWindowInfo += 4;

		//���������еĿؼ���ռ�ô�С
		unsigned int dwTotalControlSize = ReadUInt(lpWindowInfo);
		lpWindowInfo += 4;

		//��ʼ�����ؼ�
		unsigned char* lpControlArray = lpWindowInfo;
		{
			//�����ؼ�ID,����0x160612BC
			std::vector<unsigned int> vec_ControlId;
			for (unsigned int j = 0; j < dwTotalControlCount; ++j) {
				vec_ControlId.push_back(ReadUInt(lpControlArray));
				lpControlArray += 4;
			}

			//�����ؼ�ƫ��
			std::vector<unsigned int> vec_ControlOffset;
			for (unsigned int j = 0; j < dwTotalControlCount; ++j) {
				vec_ControlOffset.push_back(ReadUInt(lpControlArray));
				lpControlArray += 4;
			}

			//�����ؼ�����
			for (unsigned int nIndexControl = 0; nIndexControl < dwTotalControlCount; ++nIndexControl) {
				unsigned char* lpControlInfo = lpControlArray + vec_ControlOffset[nIndexControl];

				mid_ControlInfo eControlInfo;

				//�ؼ�ռ�õĴ�С
				int dwControlSize = ReadInt(lpControlInfo);
				lpControlInfo += 4;

				eControlInfo.propertyAddr = lpGUIStart + (lpControlInfo - &tmpGuiBuf[0]);
				eControlInfo.propertySize = dwControlSize;

				//�ؼ�����ID
				unsigned int dwControlTypeId = ReadUInt(lpControlInfo);
				lpControlInfo += 4;

				//�̶���20�����ֽ�,����ʹ��?
				lpControlInfo += 20;

				if (dwControlTypeId == 0x10001) {
					lpControlInfo += strlen((char*)lpControlInfo)+1;
					ParseControlBasciProperty(lpControlInfo, eControlInfo);
					eControlInfo.controlName = StringUtils::sprintf("����0x%08X", eGuiInfo.windowId);
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