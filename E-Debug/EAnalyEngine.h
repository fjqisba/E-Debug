#pragma once
#include "pluginsdk/bridgemain.h"
#include "SectionManager.h"
#include <map>

struct LIB_INFO
{
	duint m_dwLibFormatVer;    //支持库格式版本号,应该为0x1312D65
	duint m_lpGuid;            //对应支持库的GUID指针。
	dsint  m_nMajorVersion;     //支持库的主版本号，必须大于0。
	dsint  m_nMinorVersion;     //支持库的次版本号。
	dsint  m_nBuildNumber;      //构建版本号
	dsint  m_nRqSysMajorVer;    //所需要易语言系统的主版本号
	dsint  m_nRqSysMinorVer;    //所需要易语言系统的次版本号
	dsint  m_nRqSysKrnlLibMajorVer;   //所需要的系统核心支持库的主版本号
	dsint  m_nRqSysKrnlLibMinorVer;   //所需要的系统核心支持库的次版本号
	duint  m_lpName;            //支持库名称指针
	dsint  m_nLanguage;         //支持库所支持的语言,应该是1
	duint m_lpExplain;         //支持库解释内容指针,可为空
	duint m_dwState;           //支持库特殊状态说明
	duint m_lpszAuthor;        //作者相关信息
	duint m_lpszZipCode;       //作者相关信息
	duint m_lpszAddress;       //作者相关信息
	duint m_lpszPhone;         //作者相关信息
	duint m_lpszFax;           //作者相关信息
	duint m_lpszEmail;         //作者相关信息
	duint m_lpszHomePage;      //作者相关信息
	duint m_lpszOther;         //作者相关信息

//////////////////
	dsint m_nDataTypeCount;     //支持库全部的数据类型个数
	duint m_lpDataType;        //指向程序用到的数据类型信息的指针,LIB_DATA_TYPE_INFO

	dsint m_nCategoryCount;     //全局命令类别数目
	duint m_lpszzCategory;     //全局命令类别说明表，每项为一字符串，前四位数字表示图象索引号（从1开始，0表示无）。
								// 减一后的值为指向支持库中名为"LIB_BITMAP"的BITMAP资源中某一部分16X13位图的索引

	dsint m_nCmdCount;          //本库中提供的所有命令(全局命令及对象方法)的数目(如无则为0)。
	duint m_lpBeginCmdInfo;    //指向所有命令及方法的定义信息数组(如m_nCmdCount为0,则为NULL),CMD_INFO
	duint m_lpCmdsFunc;        //指向每个命令的实现代码首地址，(如m_nCmdCount为0, 则为NULL)。

	duint m_lpfnRunAddInFn;    //可为NULL，用作为易语言IDE提供附加功能
	duint m_szzAddInFnInfo;    //有关AddIn功能的说明，两个字符串说明一个功能

	duint m_lpfnNotify;        //不能为NULL，提供接收来自易语言IDE或运行环境通知信息的函数。

	// 超级模板暂时保留不用。
	duint m_lpfnSuperTemplate;       //为空
	duint m_lpszzSuperTemplateInfo;  //为空

	// 本库定义的所有常量。
	dsint m_nLibConstCount;   //常量数据
	duint m_lpLibConst;      //指向常量定义数组的指针

	duint m_lpszzDependFiles; //本库正常运行所需要依赖的其他文件，在制作安装软件时将会自动带上这些文件,可为空
};

struct mid_EDataTypeInfo
{
	std::string m_Name;     //数据类型名称
};

struct mid_ELibInfo
{
	std::string m_Name;          //支持库名称
	std::string m_Guid;          //支持库的GUID
	int  m_nMajorVersion;  //支持库的主版本号，必须大于0。
	int  m_nMinorVersion;  //支持库的次版本号。

	std::vector<mid_EDataTypeInfo> mVec_DataTypeInfo;      //数据类型信息
};

struct LibFuncMap
{
	std::string libName;
	std::string libGuid;
	struct FuncInfo
	{
		duint addr;
		//ascii
		std::string name;
	};
	std::vector<FuncInfo> vec_Funcs;
};

class EAnalyEngine:public SectionManager
{
public:
	EAnalyEngine();
	~EAnalyEngine();
public:
	bool InitEAnalyEngine(unsigned int anyAddr);
private:
	bool Parse_EStatic(duint eHeadAddr);

	bool ParseLibInfomation(duint lpLibStartAddr, duint dwLibCount);
public:
	//0是失败,1是静态编译,2是动态编译,3是独立编译,4是黑月编译
	unsigned int m_AnalysisMode = 0;
	//是否分析成功
	bool m_bAnalySuccess = false;
	//用户代码起始地址
	duint m_UserCodeStartAddr = 0;
public:
	//库函数表
	std::vector<LibFuncMap> mVec_LibFunc;
};