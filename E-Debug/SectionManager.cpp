#include "SectionManager.h"
#include "pluginsdk/bridgemain.h"
#include <QPlainTextEdit>
#include "pluginsdk/_scriptapi_memory.h"
#include "pluginsdk/_scriptapi_gui.h"
#include "pluginsdk/_scriptapi_module.h"
#include "pluginsdk/_scriptapi_pattern.h"
#include "public.h"

unsigned int AlignByMemory(unsigned int originValue)
{
	unsigned int Alignment = 0x1000;
	DWORD reminder = originValue / Alignment;
	DWORD mod = originValue % Alignment;

	if (mod != 0) {
		reminder += 1;
	}
	return reminder * Alignment;
}

bool SectionManager::InitSectionManager(unsigned int anyAddr, QPlainTextEdit* outMsg)
{
	m_outMsg = outMsg;
	BridgeList<Script::Module::ModuleSectionInfo> moduleList;
	if (!Script::Module::SectionListFromAddr(anyAddr, &moduleList)) {
		outMsg->appendPlainText(QStringLiteral("[InitSectionManager]获取程序区段失败"));
		return false;;
	}

	for (unsigned int n = 0; n < moduleList.Count(); ++n) {

		SegmentInfomation tmpInfo;
		tmpInfo.m_segStart = moduleList[n].addr;
		tmpInfo.m_segSize = AlignByMemory(moduleList[n].size);
		tmpInfo.m_segName = moduleList[n].name;

		QString logMsg;
		logMsg.sprintf("->[%s]  %s:%08X,%s:%08X", StringUtils::LocalCpToUtf8("添加分析区段").c_str(), StringUtils::LocalCpToUtf8("地址").c_str(), tmpInfo.m_segStart, StringUtils::LocalCpToUtf8("大小").c_str(), tmpInfo.m_segSize);
		outMsg->appendPlainText(logMsg);

		tmpInfo.m_segData.resize(tmpInfo.m_segSize);
		Script::Memory::Read(tmpInfo.m_segStart, &tmpInfo.m_segData[0], tmpInfo.m_segSize, 0);

		mVec_segInfo.push_back(tmpInfo);
	}
	return true;
}

unsigned char* SectionManager::LinearAddrToVirtualAddr(unsigned int LinerAddr)
{
	//存储上一次命中的索引,用于加速访问
	static unsigned int saveIndex = 0;

	unsigned int index = saveIndex;

	for (unsigned int n = 0; n < mVec_segInfo.size(); ++n) {
		unsigned int endAddr = mVec_segInfo[index].m_segStart + mVec_segInfo[index].m_segSize;
		if (LinerAddr >= mVec_segInfo[index].m_segStart && LinerAddr < endAddr) {
			unsigned int offset = LinerAddr - mVec_segInfo[index].m_segStart;
			saveIndex = index;
			return &mVec_segInfo[index].m_segData[offset];
		}
		++index;
		if (index == mVec_segInfo.size()) {
			index = 0;
		}
	}
	return 0;
}


unsigned int SectionManager::VirtualAddrToLinearAddr(unsigned char* pVirtualAddr)
{
	for (unsigned int n = 0; n < mVec_segInfo.size(); ++n) {
		unsigned char* pEndAddr = &mVec_segInfo[n].m_segData[0] + mVec_segInfo[n].m_segSize;
		if (pVirtualAddr >= &mVec_segInfo[n].m_segData[0] && pVirtualAddr < pEndAddr) {
			unsigned int offset = pVirtualAddr - &mVec_segInfo[n].m_segData[0];
			return mVec_segInfo[n].m_segStart + offset;
		}
	}
	return -1;
}

unsigned int SectionManager::SeachUserCodeEndAddr()
{
	if (!mVec_segInfo.size()) {
		return -1;
	}
	unsigned int memSize = 0;
	for (unsigned int n = 0; n < mVec_segInfo.size(); ++n) {
		memSize += mVec_segInfo[n].m_segSize;
	}

	const char pattern[] = "60E8????????8945FC618B45FC5F5E5B8BE55DC3";
	return Script::Pattern::FindMem(mVec_segInfo[0].m_segStart, memSize, pattern);
}

unsigned int SectionManager::ReadCallAddr(unsigned int addr)
{
	return addr + ReadUInt(LinearAddrToVirtualAddr(addr + 1)) + 5;
}