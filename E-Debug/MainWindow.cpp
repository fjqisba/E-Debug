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
#include "TrieTree.h"
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


	if (!eAnalyEngine.InitEAnalyEngine(dwBase, ui.outMsg)) {
		QMessageBox::critical(0, QStringLiteral("抱歉"), QStringLiteral("初始化失败"));
		return;
	}

	//静态编译程序
	if (eAnalyEngine.m_AnalysisMode == 1) {
		InitWindow_EStatic();
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
			callAddr = ReadUInt(eAnalyEngine.LinearAddrToVirtualAddr(callAddr + 2));
			callAddr = ReadUInt(eAnalyEngine.LinearAddrToVirtualAddr(callAddr));
			if (callAddr == eAnalyEngine.m_KrnlApp.krnl_MCallDllCmd) {
				QString outMsg;
				outMsg.sprintf("%08X    mov eax,%08X     %s", scanStartAddr, apiIndex, LocalCpToUtf8(eAnalyEngine.mVec_ImportsApi[apiIndex].ApiName.c_str()).c_str());
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

		std::string uLibName = LocalCpToUtf8(eLibInfo.libName.c_str());
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

bool MainWindow::InitWindow_EStatic()
{
	//ui.outMsg->appendPlainText(QStringLiteral("->开始识别易语言支持库函数..."));

	ui.tabWidget->addTab(ui.tab_Func, QStringLiteral("函数识别"));
	QTextCodec* codec = QTextCodec::codecForName("GB2312");
	for (unsigned int nLibIndex = 0; nLibIndex < eAnalyEngine.mVec_LibInfo.size(); ++nLibIndex) {

		ElibInfo& eLibInfo = eAnalyEngine.mVec_LibInfo[nLibIndex];
		std::string libPath = GetCurrentDirA() + "\\plugins\\esig\\" + eLibInfo.libName + ".esig";

		//函数识别
		TrieTree esigTree(&eAnalyEngine);
		if (esigTree.LoadSig(libPath.c_str())) {
			for (unsigned int nFuncIndex = 0; nFuncIndex < eLibInfo.vec_Funcs.size(); ++nFuncIndex) {
				char* pFuncName = esigTree.MatchFunc(eAnalyEngine.LinearAddrToVirtualAddr(eLibInfo.vec_Funcs[nFuncIndex].addr));
				if (pFuncName) {
					eLibInfo.vec_Funcs[nFuncIndex].name = pFuncName;
					std::string u16FuncName = LocalCpToUtf8(pFuncName);
					Script::Label::Set(eLibInfo.vec_Funcs[nFuncIndex].addr, u16FuncName.c_str());
				}
				else {
					//To do...模糊匹配
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
			callAddr = ReadUInt(eAnalyEngine.LinearAddrToVirtualAddr(callAddr + 2));
			callAddr = ReadUInt(eAnalyEngine.LinearAddrToVirtualAddr(callAddr));
			if (callAddr == eAnalyEngine.m_KrnlApp.krnl_MCallDllCmd) {
				int index = ReadUInt(eAnalyEngine.LinearAddrToVirtualAddr(scanStartAddr + 1));
				Script::Comment::Set(scanStartAddr, LocalCpToUtf8(eAnalyEngine.mVec_ImportsApi[index].ApiName.c_str()).c_str());
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
			windowName.sprintf("%s_0x%08X(%d)", LocalCpToUtf8("窗口").c_str(), eGuiInfo.windowId, eGuiInfo.vec_ControlInfo.size());
			ui.combo_Window->addItem(windowName);
			for (unsigned int nIndexControl = 0; nIndexControl < eGuiInfo.vec_ControlInfo.size(); ++nIndexControl) {
				mid_ControlInfo& eControlInfo = eGuiInfo.vec_ControlInfo[nIndexControl];
				for (unsigned int nIndexEvent = 0; nIndexEvent < eControlInfo.vec_eventInfo.size(); ++nIndexEvent) {
					
				}
			}
		}
		on_WindowSelected(0);
	}
	
	return true;
}