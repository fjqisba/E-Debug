#pragma once
#include <vector>
#include <string>


struct SegmentInfomation
{
	unsigned int m_segStart;                   //区段起始地址
	unsigned int m_segSize;                  //区段大小
	std::string m_segName;                 //区段名称
	std::vector<unsigned char> m_segData;  //区段数据
};

class QPlainTextEdit;
class SectionManager
{
public:
	bool InitSectionManager(unsigned int anyAddr, QPlainTextEdit* outMsg);

	//线性地址转换为虚拟地址
	unsigned char* LinearAddrToVirtualAddr(unsigned int LinerAddr);
	//虚拟地址转换为线性地址
	unsigned int VirtualAddrToLinearAddr(unsigned char* pVirtualAddr);

	//模糊搜索
	unsigned int SeachUserCodeEndAddr();
	//参数为call指令所在的实际地址,返回跳转得到的实际地址
	unsigned int ReadCallAddr(unsigned int addr);
public:
	std::vector<SegmentInfomation> mVec_segInfo;
private:
	QPlainTextEdit* m_outMsg = nullptr;
};
