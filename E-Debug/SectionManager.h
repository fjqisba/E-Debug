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

class SectionManager
{
public:
	bool InitSectionManager(unsigned int anyAddr);

	//线性地址转换为虚拟地址
	unsigned char* LinearAddrToVirtualAddr(unsigned int LinerAddr);
	//虚拟地址转换为线性地址
	unsigned int VirtualAddrToLinearAddr(unsigned char* pVirtualAddr);
private:
	std::vector<SegmentInfomation> mVec_segInfo;
};
