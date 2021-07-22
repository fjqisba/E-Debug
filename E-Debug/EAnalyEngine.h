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

struct LIB_DATA_TYPE_INFO   //库定义数据类型结构
{
	duint m_lpszName;     //名称
	duint m_lpszEGName;   //英文名称,可为空
	duint m_szExplain;    //详细解释,可为空
	dsint  m_nCmdCount;    //本数据类型成员方法的数目(可为0)
	duint m_lpnCmdsIndex; //指向所有成员方法命令在支持库命令表中的索引值指针,编译后数据被抹除
	duint m_dwState;      //数据类型的特殊属性

	 ////////////////////////////////////////////
	// 以下成员只有在为窗口单元、菜单时才有效。

	duint m_dwUnitBmpID;     //指定在支持库中的单元图像资源ID
	dsint  m_nEventCount;     //本单元的事件数目
	duint m_lpEventBegin;    //指向单元的所有事件的指针,EVENT_INFO,编译后数据被抹除
	dsint m_nPropertyCount;   //本单元的属性数目
	duint m_lpPropertyBegin; //指向单元的所有属性的指针,UNIT_PROPERTY

	duint m_lpfnGetInterface; //用作提供本窗口单元的所有接口。

	////////////////////////////////////////////
	// 以下成员只有在不为窗口单元、菜单时才有效。

	dsint m_nElementCount;    //本数据类型中子成员的数目(可为0)
	duint m_lpElementBegin;   //指向子成员数组的首地址,LIB_DATA_TYPE_ELEMENT
};


struct EDataTypeInfo
{
	std::string dataTypeName;   //数据类型名称
};

struct ElibInfo
{
	std::string libName;
	std::string libGuid;
	int nMajorVersion;  //支持库的主版本号，必须大于0。
	int nMinorVersion;  //支持库的次版本号。
	struct FuncInfo
	{
		duint addr;
		//ascii
		std::string name;
	};
	std::vector<FuncInfo> vec_Funcs;
	std::vector<EDataTypeInfo> vec_DataTypeInfo;      //数据类型信息
};

struct ImportsApi
{
	std::string LibName;
	std::string ApiName;
	int refCount;
};


enum controlType_t
{
	UnknownControl = 0,
	krnl_window,     //窗口
	krnl_menu,       //菜单
	krnl_EditBox,    //编辑框
	krnl_PicBox,     //图片框
	krnl_ShapeBox,   //外形框
	krnl_DrawPanel,  //画板
	krnl_GroupBox,   //分组框
	krnl_Label,      //标签
	krnl_Button,     //按钮
	krnl_CheckBox,   //选择框
	krnl_RadioBox,   //单选框
	krnl_ComboBox,   //组合框
	krnl_ListBox,    //列表框
	krnl_ChkListBox, //选择列表框
	krnl_HScrollBar, //横向滚动条
	krnl_VScrollBar, //纵向滚动条
	krnl_ProcessBar, //进度条
	krnl_SliderBar,  //滑块条
	krnl_Tab,        //选择夹
	krnl_AnimateBox, //影像框
	krnl_DatePicker, //日期框
	krnl_MonthCalendar,  //月历
	krnl_DriverBox,  //驱动器框
	krnl_DirBox,     //目录框
	krnl_FileBox,    //文件框
	krnl_ColorPicker, //颜色选择器
	krnl_HyperLinker, //超级链接器
	krnl_Spin,        //调节器
	krnl_CommonDlg,   //通用对话框
	krnl_Timer,       //时钟
	krnl_printer,     //打印机
	krnl_UDP,         //数据报
	krnl_Client,      //客户
	krnl_Server,      //服务器
	krnl_SerialPort,  //端口
	krnl_Grid,        //表格
	krnl_DataSrc,     //数据源
	krnl_NProvider,   //通用提供者
	krnl_DBProvider,  //数据库提供者
	krnl_PicBtn,      //图形按钮
	krnl_ODBCDB,      //外部数据库
	krnl_ODBCProvider,//外部数据提供者
	krnl_DropTarget,  //拖放对象
};

struct ControlProperty
{
	std::string controlName;
	
};

struct mid_EventInfo
{
	int  nEventIndex;       //事件索引
	duint eventAddr;        //事件地址
};

struct mid_ControlInfo
{
	controlType_t controlType;            //控件类型
	duint controlId;                      //控件自身ID
	duint controlTypeId;                  //控件类型ID
	std::string controlTypeName;          //控件类型名称
	std::string controlName;              //控件名称
	duint propertyAddr;                   //属性地址
	dsint propertySize;                   //属性大小
	std::vector<mid_EventInfo> vec_eventInfo;   //事件处理
};

struct mid_GuiInfo
{
	unsigned int windowId;                        //控件所属窗口ID
	std::vector<mid_ControlInfo> vec_ControlInfo;
};

struct mid_KrnlApp
{
	duint krnl_MReportError;               //错误回调
	duint krnl_MCallDllCmd;                //DLL命令
	duint krnl_MCallLibCmd;                //三方支持库命令
	duint krnl_MCallKrnlLibCmd;            //核心支持库命令
	duint krnl_MReadProperty;              //读取组件属性
	duint krnl_MWriteProperty;             //设置组件属性
	duint krnl_MMalloc;                    //分配内存
	duint krnl_MRealloc;                   //重新分配内存
	duint krnl_MFree;                      //释放内存
	duint krnl_MExitProcess;               //结束
	duint krnl_MMessageLoop;               //窗口消息循环
	duint krnl_MLoadBeginWin;              //载入启动窗口
	duint krnl_MOtherHelp;                 //辅助功能
};

class QPlainTextEdit;
class EAnalyEngine:public SectionManager
{
public:
	EAnalyEngine();
	~EAnalyEngine();
public:
	bool InitEAnalyEngine(unsigned int anyAddr, QPlainTextEdit* outMsg);
private:
	bool Parse_EStatic(duint eHeadAddr);
	void ParseKrnlInterface(duint lpKrnlEntry);
	bool ParseLibInfomation(duint lpLibStartAddr, duint dwLibCount);
	bool ParseUserImports(duint dwApiCount, duint lpModuleName, duint lpApiName);
	bool ParseGUIResource(duint lpGUIStart, duint infoSize);
	//获取用户代码结束地址
	duint GetUserCodeEndAddr();

	void ParseControlBasciProperty(unsigned char* lpControlInfo, mid_ControlInfo& out_Property);
	std::string GetControlTypeName(duint typeId);
public:
	//0是失败,1是静态编译,2是动态编译,3是独立编译,4是黑月编译
	unsigned int m_AnalysisMode = 0;
	//是否分析成功
	bool m_bAnalySuccess = false;
	//用户代码起始地址
	duint m_UserCodeStartAddr = 0;
	//用户代码结束地址
	duint m_UserCodeEndAddr = 0;

	mid_KrnlApp m_KrnlApp;
public:
	//库函数表
	std::vector<ElibInfo> mVec_LibInfo;
	//导入函数表
	std::vector<ImportsApi> mVec_ImportsApi;
	//窗口控件信息
	std::vector<mid_GuiInfo> mVec_GuiInfo;
	//日志打印输出
	QPlainTextEdit* m_outMsg = nullptr;
};