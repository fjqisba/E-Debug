#include "MainWindow.h"
#include <QMessageBox>
#include <QTextCodec>
#include <QString>
#include <QMenu>
#include "pluginsdk/_scriptapi_label.h"
#include "pluginsdk/_scriptapi_gui.h"
#include "pluginsdk/_scriptapi_pattern.h"
#include "pluginsdk/_scriptapi_comment.h"
#include "pluginsdk/_scriptapi_memory.h"
#include "pluginsdk/_scriptapi_function.h"
#include "pluginsdk/_scriptapi_module.h"
#include "TrieTree.h"
#include ".\EAppControl\EAppControlFactory.h"
#include ".\EAppControl\EAppControl.h"
#include "public.h"

MainWindow::MainWindow(unsigned int dwBase, QWidget* parent) : QWidget(parent)
{
	ui.setupUi(this);
	
	ui.tabWidget->clear();
	
	//设置版本号
	this->setWindowTitle(QStringLiteral("E-Debug 4.0"));
	//禁止最大化按钮
	//this->setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);
	//设置窗体图标
	this->setWindowIcon(QIcon(":/ico/ico.png"));
	//设置窗体自动析构
	this->setAttribute(Qt::WA_DeleteOnClose);
	ui.table_Func->setColumnCount(2);
	ui.table_Func->setColumnWidth(0, 100);   //设置第一列宽度
	
	ui.table_Func->horizontalHeader()->setStretchLastSection(true);
	
	ui.table_Func->setHorizontalHeaderLabels(QStringList() << QStringLiteral("地址") << QStringLiteral("命令名称"));
	ui.table_Func->setEditTriggers(QAbstractItemView::NoEditTriggers);

	ui.table_Func->setItem(0, 1, new QTableWidgetItem("func"));

	connect(ui.list_LibInfo, SIGNAL(currentTextChanged(const QString&)), SLOT(on_LibNameSelected(const QString&)));
	connect(ui.table_Func,SIGNAL(itemDoubleClicked(QTableWidgetItem*)),SLOT(on_FuncDoubleClicked(QTableWidgetItem*)));
	connect(ui.outMsg, SIGNAL(selectionChanged()), SLOT(on_MsgSelected()));
	connect(ui.button_ForcePush, SIGNAL(clicked(bool)), SLOT(on_ForcePushWindow(bool)));

	
	if (!eAnalyEngine.InitEAnalyEngine(dwBase, ui.outMsg)) {
		QMessageBox::critical(0, QStringLiteral("抱歉"), QStringLiteral("初始化失败"));
		return;
	}

	//静态编译程序
	if (eAnalyEngine.m_AnalysisMode == 1) {
		InitWindow_EStatic(dwBase);
		return;
	}
}

MainWindow::~MainWindow()
{
	
}


bool isValidAddress(QString& src)
{
	std::string asciiStr = src.toStdString();
	const char* s = asciiStr.c_str();
	while (*s && *s >= '0' && *s <= 'F') s++;
	if (*s)
	{
		return false;
	}
	return true;
}

void MainWindow::on_ForcePushWindow(bool checked)
{
	if (eAnalyEngine.m_AnalysisMode != 1) {
		ui.outMsg->appendPlainText(QStringLiteral("暂时不支持其它模式"));
		return;
	}

	std::vector<unsigned char> ShellCode = {
	0xC8,0x00,0x00,0x00,                //enter 0x0,0x0		
	};
	for (unsigned int nWindowIndex = 0; nWindowIndex < eAnalyEngine.mVec_GuiInfo.size(); ++nWindowIndex) {
		std::vector<mid_EventInfo>& vec_Events = eAnalyEngine.mVec_GuiInfo[nWindowIndex].vec_ControlInfo[0].vec_eventInfo;
		for (unsigned int nEventIndex = 0; nEventIndex < vec_Events.size(); ++nEventIndex) {
			//窗口创建完毕,窗口首次激活
			if (vec_Events[nEventIndex].nEventIndex == 0 || vec_Events[nEventIndex].nEventIndex == 8) {
				Script::Memory::WriteByte(vec_Events[nEventIndex].eventAddr, 0xC3);
				QString outMsg;
				outMsg.sprintf("%s:\t%08X", StringUtils::LocalCpToUtf8("修改字节为0xC3").c_str(), vec_Events[nEventIndex].eventAddr);
				ui.outMsg->appendPlainText(outMsg);
			}
		}

		std::vector<unsigned char> windowShell = {
			0x68,0x00,0x00,0x00,0x00,       //push windowId
			0xBB,0x00,0x00,0x00,0x00,       //mov ebx,LoadWindow
			0xFF,0xD3,                      //call ebx
			0x83,0xC4,0x4,                  //add esp,0x4
			0x6A,0x00,                      //push 0x0
			0x6A,0x01,                      //push 0x1
			0x6A,0xFF,                      //push -0x1
			0x6A,0x5,                       //push 0x5
			0x68,0x00,0x00,0x00,0x00,       //push ControlId
			0x68,0x00,0x00,0x00,0x00,       //push WindowId
			0xBB,0x00,0x00,0x00,0x00,       //mov ebx,SetWindowProperty
			0xFF,0xD3,                      //call ebx
			0x83,0xC4,0x18,                 //add esp,0x18
			0x6A,0x00,                      //push 0x0
			0x6A,0x00,                      //push 0x0
			0x6A,0xFF,                      //push -0x1
			0x6A,0x6,                       //push 0x6
			0x68,0x00,0x00,0x00,0x00,       //push ControlId
			0x68,0x00,0x00,0x00,0x00,       //push WindowId
			0xBB,0x00,0x00,0x00,0x00,       //mov ebx,SetWindowProperty
			0xFF,0xD3,                      //call ebx
			0x83,0xC4,0x18,                 //add esp,0x18
		};
		mid_GuiInfo* pGuiInfo = &eAnalyEngine.mVec_GuiInfo[nWindowIndex];
		WriteUInt(&windowShell[1], pGuiInfo->windowId);
		WriteUInt(&windowShell[6], eAnalyEngine.m_KrnlApp.krnl_MLoadBeginWin);
		WriteUInt(&windowShell[24], pGuiInfo->vec_ControlInfo[0].controlId);
		WriteUInt(&windowShell[29], pGuiInfo->windowId);
		WriteUInt(&windowShell[34], eAnalyEngine.m_KrnlApp.krnl_MWriteProperty);
		WriteUInt(&windowShell[52], pGuiInfo->vec_ControlInfo[0].controlId);
		WriteUInt(&windowShell[57], pGuiInfo->windowId);
		WriteUInt(&windowShell[62], eAnalyEngine.m_KrnlApp.krnl_MWriteProperty);
		ShellCode.insert(ShellCode.end(), windowShell.begin(), windowShell.end());
	}

	std::vector<unsigned char> endLoop = {
		0xBB,0x00,0x00,0x00,0x00,       //mov ebx,MessageLoop
		0xFF,0xD3,                      //call ebx
		0xC9,                           //leave
		0xC3                            //ret
	};
	WriteUInt(&endLoop[1], eAnalyEngine.m_KrnlApp.krnl_MMessageLoop);
	ShellCode.insert(ShellCode.end(), endLoop.begin(), endLoop.end());

	duint shellCodeBuf = Script::Memory::RemoteAlloc(0, 0x1000);
	QString outMsg;
	outMsg.sprintf("%s%08X", StringUtils::LocalCpToUtf8("申请内存成功:\t").c_str(), shellCodeBuf);
	ui.outMsg->appendPlainText(outMsg);
	duint recvLen = 0;
	Script::Memory::Write(shellCodeBuf, ShellCode.data(), ShellCode.size(), &recvLen);

	HANDLE hThread = CreateRemoteThread(DbgGetProcessHandle(), 0, 0, (LPTHREAD_START_ROUTINE)shellCodeBuf, 0, 0, 0);
	if (hThread == 0) {
		return;
	}
	CloseHandle(hThread);
	return;
}

void MainWindow::on_WindowSelected(int index)
{
	ui.table_Control->setRowCount(0);
	mid_GuiInfo& eGuiInfo = eAnalyEngine.mVec_GuiInfo[index];

	QTextCodec* codec = QTextCodec::codecForName("GB2312");

	ui.table_Control->setSortingEnabled(false);
	for (unsigned int n = 0; n < eGuiInfo.vec_ControlInfo.size(); ++n) {
		mid_ControlInfo& eControlInfo = eGuiInfo.vec_ControlInfo[n];
		int insertRow = ui.table_Control->rowCount();
		ui.table_Control->insertRow(insertRow);
		//设置每行高度
		ui.table_Control->setRowHeight(insertRow, 30);

		QString strControlId;
		strControlId.sprintf("0x%08X", eControlInfo.controlId);
		QTableWidgetItem* pItemControlId = new QTableWidgetItem(strControlId);
		pItemControlId->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
		ui.table_Control->setItem(insertRow, 0, pItemControlId);

		QTableWidgetItem* pItemControlType = new QTableWidgetItem(codec->toUnicode(eControlInfo.controlTypeName.c_str()));
		pItemControlType->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
		ui.table_Control->setItem(insertRow, 1, pItemControlType);

		QTableWidgetItem* pItemControlName = new QTableWidgetItem(codec->toUnicode(eControlInfo.controlName.c_str()));
		pItemControlName->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
		ui.table_Control->setItem(insertRow, 2, pItemControlName);
	}
	ui.table_Control->setSortingEnabled(true);
}

void MainWindow::on_MsgSelected()
{
	QString selectedTxt = ui.outMsg->textCursor().selectedText();
	if (selectedTxt.isEmpty()) {
		return;
	}

	if (isValidAddress(selectedTxt) && selectedTxt.length() == 0x8) {
		unsigned int goAddr = selectedTxt.toUInt(nullptr, 16);
		if (Script::Memory::IsValidPtr(goAddr)) {
			GuiDisasmAt(goAddr, 0);
		}
	}
}

void MainWindow::on_ApiMenu(const QPoint& point)
{
	QTableWidgetItem* currentItem = ui.table_Api->itemAt(point);
	if (!currentItem) {
		return;
	}

	QMenu* popMenu = new QMenu(ui.table_Api);
	QAction* findAction = popMenu->addAction(QStringLiteral("查找引用"));

	if (popMenu->exec(QCursor::pos()) == findAction) {
		ui.outMsg->clear();
		ui.outMsg->appendPlainText(QStringLiteral("->执行命令 --==查找引用==--"));
		duint scanStartAddr = eAnalyEngine.m_UserCodeStartAddr;
		unsigned char apiCode[] = { 0xB8,0x00,0x00,0x00,0x00,0xE8 };
		int apiIndex = ui.table_Api->item(currentItem->row(), 0)->text().toUInt();

		WriteUInt(apiCode + 1, apiIndex);
		std::string strApiCode = 十到十六(apiCode, sizeof(apiCode));
		do
		{	
			scanStartAddr = Script::Pattern::FindMem(scanStartAddr + 1, eAnalyEngine.m_UserCodeEndAddr - scanStartAddr, strApiCode.c_str());
			if (!scanStartAddr) {
				break;
			}
			unsigned int callAddr = eAnalyEngine.ReadCallAddr(scanStartAddr + 5);
			if (ReadUShort(eAnalyEngine.LinearAddrToVirtualAddr(callAddr)) != 0x25FF) {
				continue;
			}
			callAddr = ReadUInt(eAnalyEngine.LinearAddrToVirtualAddr(callAddr + 2));
			callAddr = ReadUInt(eAnalyEngine.LinearAddrToVirtualAddr(callAddr));
			if (callAddr == eAnalyEngine.m_KrnlApp.krnl_MCallDllCmd) {
				QString outMsg;
				outMsg.sprintf("%08X    mov eax,%08X     %s", scanStartAddr, apiIndex, StringUtils::LocalCpToUtf8(eAnalyEngine.mVec_ImportsApi[apiIndex].ApiName.c_str()).c_str());
				ui.outMsg->appendPlainText(outMsg);
			}
		} while (true);

	}
}

void MainWindow::on_FuncDoubleClicked(QTableWidgetItem* pItem)
{
	if (!pItem) {
		return;
	}

	QString funcAddr = ui.table_Func->item(pItem->row(), 0)->text();
	duint addr = funcAddr.toUInt(nullptr, 16);
	
	GuiDisasmAt(addr,0);	
}

void MainWindow::on_LibNameSelected(const QString& currentText)
{
	ui.table_Func->setRowCount(0);
	
	for (unsigned int nLibIndex = 0; nLibIndex < eAnalyEngine.mVec_LibInfo.size(); ++nLibIndex) {
		ElibInfo& eLibInfo = eAnalyEngine.mVec_LibInfo[nLibIndex];

		std::string uLibName = StringUtils::LocalCpToUtf8(eLibInfo.libName.c_str());
		int index = currentText.indexOf(uLibName.c_str());
		if (index == -1) {
			continue;
		}

		//关闭排序功能
		ui.table_Func->setSortingEnabled(false);
		QTextCodec* codec = QTextCodec::codecForName("GB2312");
		for (unsigned int nFuncIndex = 0; nFuncIndex < eLibInfo.vec_Funcs.size(); ++nFuncIndex) {
			int insertRow = ui.table_Func->rowCount();
			ui.table_Func->insertRow(insertRow);
			//设置每行高度
			ui.table_Func->setRowHeight(insertRow, 20);

			QString strAddr;
			strAddr.sprintf("%08X", eLibInfo.vec_Funcs[nFuncIndex].addr);
			QTableWidgetItem* pAddrItem = new QTableWidgetItem(strAddr);
			pAddrItem->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
			ui.table_Func->setItem(insertRow, 0, pAddrItem);

			QString strName = codec->toUnicode(eLibInfo.vec_Funcs[nFuncIndex].name.c_str());
			QTableWidgetItem* pNameItem = new QTableWidgetItem(strName);
			pNameItem->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
			ui.table_Func->setItem(insertRow, 1, pNameItem);
		}
		//开启排序功能
		ui.table_Func->setSortingEnabled(true);	
	}
}

bool MainWindow::InitWindow_EStatic(duint codeAddr)
{
	//控制流分析
	DbgCmdExecDirect("cfanalyze");

	//ui.outMsg->appendPlainText(QStringLiteral("->开始识别易语言支持库函数..."));

	ui.tabWidget->addTab(ui.tab_Func, QStringLiteral("函数识别"));
	QTextCodec* codec = QTextCodec::codecForName("GB2312");
	for (unsigned int nLibIndex = 0; nLibIndex < eAnalyEngine.mVec_LibInfo.size(); ++nLibIndex) {

		ElibInfo& eLibInfo = eAnalyEngine.mVec_LibInfo[nLibIndex];
		std::string libPath = GetApplicationDirA() + "\\plugins\\esig\\" + eLibInfo.libName + ".esig";

		//函数识别
		TrieTree esigTree(&eAnalyEngine);
		if (esigTree.LoadSig(libPath.c_str())) {
			for (unsigned int nFuncIndex = 0; nFuncIndex < eLibInfo.vec_Funcs.size(); ++nFuncIndex) {
				double score = 0;
				const char* pFuncName = esigTree.MatchFunc(eAnalyEngine.LinearAddrToVirtualAddr(eLibInfo.vec_Funcs[nFuncIndex].addr));
				if (pFuncName) {
					eLibInfo.vec_Funcs[nFuncIndex].name = pFuncName;
					std::string u16FuncName = StringUtils::LocalCpToUtf8(pFuncName);
					SetX64DbgLabel(eLibInfo.vec_Funcs[nFuncIndex].addr, u16FuncName.c_str());
				}
				else if ((pFuncName = esigTree.MatchFunc_Fuzzy(eAnalyEngine.LinearAddrToVirtualAddr(eLibInfo.vec_Funcs[nFuncIndex].addr), score))) {
					eLibInfo.vec_Funcs[nFuncIndex].name = std::string(pFuncName) + "_模糊";
					std::string u16FuncName = StringUtils::LocalCpToUtf8(eLibInfo.vec_Funcs[nFuncIndex].name.c_str());
					SetX64DbgLabel(eLibInfo.vec_Funcs[nFuncIndex].addr, u16FuncName.c_str());
#ifdef _DEBUG
					QString logMsg; logMsg.sprintf("%s	%08X:%lf", StringUtils::LocalCpToUtf8("模糊匹配成功").c_str(), eLibInfo.vec_Funcs[nFuncIndex].addr,score);
					ui.outMsg->appendPlainText(logMsg);
#endif	
				}
				else {
#ifdef _DEBUG
					QString logMsg; logMsg.sprintf("%s	%08X", StringUtils::LocalCpToUtf8("识别函数失败").c_str(), eLibInfo.vec_Funcs[nFuncIndex].addr);
					ui.outMsg->appendPlainText(logMsg);
#endif
				}
			}
		}
		else {
			QString logMsg = QStringLiteral("->加载特征文件失败:") + codec->toUnicode(libPath.c_str());
			ui.outMsg->appendPlainText(logMsg);
		}

		
		//更新界面
		QString LibNameLine = codec->toUnicode(eLibInfo.libName.c_str());
		LibNameLine.append(QString::number(eLibInfo.nMajorVersion) + QStringLiteral(".") + QString::number(eLibInfo.nMinorVersion));
		LibNameLine.append(QStringLiteral("(命令总数:"));
		LibNameLine.append(QString::number(eLibInfo.vec_Funcs.size()));
		LibNameLine.append(QStringLiteral(")"));
		ui.list_LibInfo->insertItem(ui.list_LibInfo->count(), new QListWidgetItem(LibNameLine));

		QString LibGuidLine = "   " + QString::fromLocal8Bit(eLibInfo.libGuid.c_str());
		QListWidgetItem* pGuidItem = new QListWidgetItem(LibGuidLine);
		pGuidItem->setTextColor(QColor(150, 150, 150));
		ui.list_LibInfo->insertItem(ui.list_LibInfo->count(), pGuidItem);
		ui.list_LibInfo->insertItem(ui.list_LibInfo->count(), new QListWidgetItem(QStringLiteral("——————————————————————————————")));
	}

	//基础命令识别
	std::string basicLibPath = GetApplicationDirA() + "\\plugins\\esig\\易语言基础命令.esig";
	TrieTree basicEsigTree(&eAnalyEngine);
	if (basicEsigTree.LoadSig(basicLibPath.c_str())) {
		BridgeList<Script::Function::FunctionInfo> vec_Funcs;
		Script::Function::GetList(&vec_Funcs);
		duint codeBaseAddr = Script::Module::BaseFromAddr(codeAddr);
		for (unsigned int n = 0; n < vec_Funcs.Count(); ++n) {
			duint funcAddr = codeBaseAddr + vec_Funcs[n].rvaStart;
			char* pFuncName = basicEsigTree.MatchFunc(eAnalyEngine.LinearAddrToVirtualAddr(funcAddr));
			if (pFuncName) {
				SetX64DbgLabel(funcAddr, StringUtils::LocalCpToUtf8(pFuncName).c_str());
			}
		}
	}
	else {
		QString logMsg = QStringLiteral("->加载易语言基础命令特征文件失败");
		ui.outMsg->appendPlainText(logMsg);
	}


	//开始生成DLL命令表
	if (eAnalyEngine.mVec_ImportsApi.size()) {

		ui.tabWidget->addTab(ui.tab_Api, QStringLiteral("Api命令"));
		//设置列数
		ui.table_Api->setColumnCount(4);
		ui.table_Api->setColumnWidth(0, 60);   //设置第1列宽度
		ui.table_Api->setColumnWidth(1, 120);   //设置第2列宽度
		ui.table_Api->setColumnWidth(2, 340);   //设置第3列宽度
		ui.table_Api->setHorizontalHeaderLabels(QStringList() << QStringLiteral("序号") << QStringLiteral("DLL库") << QStringLiteral("命令名称") << QStringLiteral("引用次数"));

		connect(ui.table_Api, SIGNAL(customContextMenuRequested(const QPoint&)), SLOT(on_ApiMenu(const QPoint&)));
		duint scanStartAddr = eAnalyEngine.m_UserCodeStartAddr;
		do
		{
			scanStartAddr = Script::Pattern::FindMem(scanStartAddr + 1, eAnalyEngine.m_UserCodeEndAddr - scanStartAddr, "B8????0000E8");
			if (!scanStartAddr) {
				break;
			}
			unsigned int callAddr = eAnalyEngine.ReadCallAddr(scanStartAddr + 5);
			if (ReadUShort(eAnalyEngine.LinearAddrToVirtualAddr(callAddr)) != 0x25FF) {
				continue;
			}
			callAddr = ReadUInt(eAnalyEngine.LinearAddrToVirtualAddr(callAddr + 2));
			callAddr = ReadUInt(eAnalyEngine.LinearAddrToVirtualAddr(callAddr));
			if (callAddr == eAnalyEngine.m_KrnlApp.krnl_MCallDllCmd) {
				int index = ReadUInt(eAnalyEngine.LinearAddrToVirtualAddr(scanStartAddr + 1));
				Script::Comment::Set(scanStartAddr, StringUtils::LocalCpToUtf8(eAnalyEngine.mVec_ImportsApi[index].ApiName.c_str()).c_str());
				eAnalyEngine.mVec_ImportsApi[index].refCount++;
			}
		} while (true);

		for (unsigned int n = 0; n < eAnalyEngine.mVec_ImportsApi.size(); ++n) {
			int insertRow = ui.table_Api->rowCount();
			ui.table_Api->insertRow(insertRow);
			//设置每行高度
			ui.table_Api->setRowHeight(insertRow, 20);

			QTableWidgetItem* pItemIndex = new QTableWidgetItem(QString::number(n));
			pItemIndex->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
			ui.table_Api->setItem(insertRow, 0, pItemIndex);

			QTableWidgetItem* pItemLib = nullptr;
			if (eAnalyEngine.mVec_ImportsApi[n].LibName.empty()) {
				pItemLib = new QTableWidgetItem(QStringLiteral("NULL"));
			}
			else {
				pItemLib = new QTableWidgetItem(codec->toUnicode(eAnalyEngine.mVec_ImportsApi[n].LibName.c_str()));
			}
			pItemLib->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
			ui.table_Api->setItem(insertRow, 1, pItemLib);

			QTableWidgetItem* pItemFunc = new QTableWidgetItem(codec->toUnicode(eAnalyEngine.mVec_ImportsApi[n].ApiName.c_str()));
			pItemFunc->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
			ui.table_Api->setItem(insertRow, 2, pItemFunc);

			QTableWidgetItem* pItemCount = new QTableWidgetItem(QString::number(eAnalyEngine.mVec_ImportsApi[n].refCount));
			pItemCount->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
			ui.table_Api->setItem(insertRow, 3, pItemCount);
		}
	}

	//开始生成窗口控件信息
	if (eAnalyEngine.mVec_GuiInfo.size()) {
		ui.tabWidget->addTab(ui.tab_Control, QStringLiteral("窗口控件"));
		ui.table_Control->setColumnCount(3);
		ui.table_Control->setColumnWidth(0, 110);   //设置第1列宽度
		ui.table_Control->setColumnWidth(1, 120);   //设置第2列宽度
		ui.table_Control->horizontalHeader()->setStretchLastSection(true);
		ui.table_Control->setHorizontalHeaderLabels(QStringList() << QStringLiteral("控件ID") << QStringLiteral("控件类型") << QStringLiteral("控件名称"));
		connect(ui.combo_Window, SIGNAL(currentIndexChanged(int)), SLOT(on_WindowSelected(int)));

		for (unsigned int nIndexWindow = 0; nIndexWindow < eAnalyEngine.mVec_GuiInfo.size(); ++nIndexWindow) {
			mid_GuiInfo& eGuiInfo = eAnalyEngine.mVec_GuiInfo[nIndexWindow];
			QString windowName;
			windowName.sprintf("%s_0x%08X(%d)", StringUtils::LocalCpToUtf8("窗口").c_str(), eGuiInfo.windowId, eGuiInfo.vec_ControlInfo.size());
			ui.combo_Window->addItem(windowName);
			for (unsigned int nIndexControl = 0; nIndexControl < eGuiInfo.vec_ControlInfo.size(); ++nIndexControl) {
				mid_ControlInfo& eControlInfo = eGuiInfo.vec_ControlInfo[nIndexControl];
				EAppControl* pControlClass = EAppControlFactory::GetEAppControl(eControlInfo.controlType);
				if (pControlClass) {
					for (unsigned int nIndexEvent = 0; nIndexEvent < eControlInfo.vec_eventInfo.size(); ++nIndexEvent) {
						std::string strEventName;
						strEventName = "_" + eControlInfo.controlName + "_" + pControlClass->取事件名称(eControlInfo.vec_eventInfo[nIndexEvent].nEventIndex);
						SetX64DbgLabel(eControlInfo.vec_eventInfo[nIndexEvent].eventAddr, StringUtils::LocalCpToUtf8(strEventName.c_str()).c_str());
					}
				}
			}
		}
		on_WindowSelected(0);
	}
	
	
	return true;
}