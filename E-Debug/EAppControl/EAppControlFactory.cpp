#include "EAppControlFactory.h"
#include "krnl_window.h"
#include "krnl_EditBox.h"
#include "krnl_Label.h"
#include "krnl_Button.h"
#include "krnl_Timer.h"
#include "krnl_PicBox.h"
#include "krnl_ShapeBox.h"
#include "krnl_DrawPanel.h"
#include "krnl_GroupBox.h"
#include "krnl_CheckBox.h"
#include "krnl_RadioBox.h"
#include "krnl_ComboBox.h"
#include "krnl_ListBox.h"
#include "krnl_ChkListBox.h"
#include "krnl_HScrollBar.h"
#include "krnl_VScrollBar.h"
#include "krnl_ProcessBar.h"
#include "krnl_SliderBar.h"
#include "krnl_Tab.h"
#include "krnl_AnimateBox.h"

class krnl_window gkrnl_window;
class krnl_EditBox gkrnl_EditBox;
class krnl_PicBox gkrnl_PicBox;
class krnl_Label gkrnl_Label;
class krnl_Button gkrnl_Button;
class krnl_Timer gkrnl_Timer;
class krnl_ShapeBox gkrnl_ShapeBox;
class krnl_DrawPanel gkrnl_DrawPanel;
class krnl_GroupBox gkrnl_GroupBox;
class krnl_CheckBox gkrnl_CheckBox;
class krnl_RadioBox gkrnl_RadioBox;
class krnl_ComboBox gkrnl_ComboBox;
class krnl_ListBox gkrnl_ListBox;
class krnl_ChkListBox gkrnl_ChkListBox;
class krnl_HScrollBar gkrnl_HScrollBar;
class krnl_VScrollBar gkrnl_VScrollBar;
class krnl_ProcessBar gkrnl_ProcessBar;
class krnl_SliderBar gkrnl_SliderBar;
class krnl_Tab gkrnl_Tab;
class krnl_AnimateBox gkrnl_AnimateBox;

std::map<controlType_t, EAppControl*> g_EControlClassMap =
{
	{krnl_window, &gkrnl_window},
	{krnl_EditBox,&gkrnl_EditBox},
	{krnl_PicBox,&gkrnl_PicBox},
	{krnl_Label,&gkrnl_Label},
	{krnl_Button,&gkrnl_Button},
	{krnl_Timer,&gkrnl_Timer},
	{krnl_ShapeBox,&gkrnl_ShapeBox},
	{krnl_DrawPanel,&gkrnl_DrawPanel},
	{krnl_GroupBox,&gkrnl_GroupBox},
	{krnl_CheckBox,&gkrnl_CheckBox},
	{krnl_RadioBox,&gkrnl_RadioBox},
	{krnl_ComboBox,&gkrnl_ComboBox},
	{krnl_ListBox,&gkrnl_ListBox},
	{krnl_ChkListBox,&gkrnl_ChkListBox},
	{krnl_HScrollBar,&gkrnl_HScrollBar},
	{krnl_VScrollBar,&gkrnl_VScrollBar},
	{krnl_ProcessBar,&gkrnl_ProcessBar},
	{krnl_SliderBar,&gkrnl_SliderBar},
	{krnl_Tab,&gkrnl_Tab},
	{krnl_AnimateBox,&gkrnl_AnimateBox}
};

std::map<std::string, controlType_t> g_ControlTypeMap
{
	{"窗口",krnl_window},
	{"菜单",krnl_menu},
	{"编辑框",krnl_EditBox},
	{"图片框",  krnl_PicBox},
	{"外形框", krnl_ShapeBox},
	{"画板"  ,krnl_DrawPanel},
	{"分组框", krnl_GroupBox},
	{"标签", krnl_Label},
	{"按钮", krnl_Button},
	{"选择框", krnl_CheckBox},
	{"单选框", krnl_RadioBox},
	{"组合框", krnl_ComboBox},
	{"列表框", krnl_ListBox},
	{"选择列表框", krnl_ChkListBox},
	{"横向滚动条", krnl_HScrollBar},
	{"纵向滚动条", krnl_VScrollBar},
	{"进度条", krnl_ProcessBar},
	{"滑块条", krnl_SliderBar},
	{"选择夹", krnl_Tab},
	{"影像框", krnl_AnimateBox},
	{"日期框", krnl_DatePicker},
	{"月历", krnl_MonthCalendar},
	{"驱动器框",krnl_DriverBox},
	{"目录框", krnl_DirBox},
	{"文件框", krnl_FileBox},
	{"颜色选择器", krnl_ColorPicker},
	{"超级链接器", krnl_HyperLinker},
	{"调节器",krnl_Spin},
	{"通用对话框", krnl_CommonDlg},
	{"时钟", krnl_Timer},
	{"打印机", krnl_printer},
	{"数据报", krnl_UDP},
	{"客户", krnl_Client},
	{"服务器", krnl_Server},
	{"端口",krnl_SerialPort},
	{"表格", krnl_Grid},
	{"数据源", krnl_DataSrc},
	{"通用提供者", krnl_NProvider},
	{"数据库提供者", krnl_DBProvider},
	{"图形按钮", krnl_PicBtn},
	{"外部数据库", krnl_ODBCDB},
	{"外部数据提供者", krnl_ODBCProvider},
	{"拖放对象", krnl_DropTarget}
};

EAppControl* EAppControlFactory::GetEAppControl(controlType_t type)
{
	return g_EControlClassMap[type];
}

controlType_t EAppControlFactory::GetControlType(std::string controlTypeName)
{
	std::map<std::string, controlType_t>::iterator it = g_ControlTypeMap.find(controlTypeName);
	if (it == g_ControlTypeMap.end()) {
		return UnknownControl;
	}
	return it->second;
}