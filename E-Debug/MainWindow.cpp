#include "MainWindow.h"
#include <QMessageBox>
#include <QTextCodec>
#include <QString>
#include "pluginsdk/_scriptapi_label.h"
#include "TrieTree.h"
#include "public.h"

MainWindow::MainWindow(unsigned int dwBase, QWidget* parent) : QWidget(parent)
{
	ui.setupUi(this);

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

	if (!eAnalyEngine.InitEAnalyEngine(dwBase)) {
		QMessageBox::critical(0, QStringLiteral("抱歉"), QStringLiteral("检测易语言程序失败"));
		this->close();
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

void MainWindow::on_LibNameSelected(const QString& currentText)
{
	ui.table_Func->setRowCount(0);
	
	for (unsigned int nLibIndex = 0; nLibIndex < eAnalyEngine.mVec_LibFunc.size(); ++nLibIndex) {
		LibFuncMap& eLibMap = eAnalyEngine.mVec_LibFunc[nLibIndex];

		std::string uLibName = LocalCpToUtf8(eLibMap.libName.c_str());
		int index = currentText.indexOf(uLibName.c_str());
		if (index == -1) {
			continue;
		}

		//关闭排序功能
		ui.table_Func->setSortingEnabled(false);
		QTextCodec* codec = QTextCodec::codecForName("GB2312");
		for (unsigned int nFuncIndex = 0; nFuncIndex < eLibMap.vec_Funcs.size(); ++nFuncIndex) {
			int insertRow = ui.table_Func->rowCount();
			ui.table_Func->insertRow(insertRow);

			QString strAddr;
			strAddr.sprintf("%08X", eLibMap.vec_Funcs[nFuncIndex].addr);
			QTableWidgetItem* pAddrItem = new QTableWidgetItem(strAddr);
			pAddrItem->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
			ui.table_Func->setItem(insertRow, 0, pAddrItem);

			QString strName = codec->toUnicode(eLibMap.vec_Funcs[nFuncIndex].name.c_str());
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
	ui.outMsg->appendPlainText(QStringLiteral("->识别易语言支持库函数..."));

	QTextCodec* codec = QTextCodec::codecForName("GB2312");
	for (unsigned int nLibIndex = 0; nLibIndex < eAnalyEngine.mVec_LibFunc.size(); ++nLibIndex) {

		LibFuncMap& eLibMap = eAnalyEngine.mVec_LibFunc[nLibIndex];
		std::string libPath = GetCurrentDirA() + "\\plugins\\esig\\" + eLibMap.libName + ".esig";

		//函数识别
		TrieTree esigTree(&eAnalyEngine);
		if (!esigTree.LoadSig(libPath.c_str())) {
			continue;
		}
		for (unsigned int nFuncIndex = 0; nFuncIndex < eLibMap.vec_Funcs.size(); ++nFuncIndex) {
			char* pFuncName = esigTree.MatchFunc(eAnalyEngine.LinearAddrToVirtualAddr(eLibMap.vec_Funcs[nFuncIndex].addr));
			if (pFuncName) {
				eLibMap.vec_Funcs[nFuncIndex].name = pFuncName;
				std::string u16FuncName = LocalCpToUtf8(pFuncName);
				Script::Label::Set(eLibMap.vec_Funcs[nFuncIndex].addr, u16FuncName.c_str());
			}
		}

		//更新界面
		QString LibNameLine = codec->toUnicode(eLibMap.libName.c_str());
		LibNameLine.append(QStringLiteral("(命令总数:"));
		LibNameLine.append(QString::number(eLibMap.vec_Funcs.size()));
		LibNameLine.append(QStringLiteral(")"));
		ui.list_LibInfo->insertItem(ui.list_LibInfo->count(), new QListWidgetItem(LibNameLine));

		QString LibGuidLine = "   " + QString::fromLocal8Bit(eLibMap.libGuid.c_str());
		QListWidgetItem* pGuidItem = new QListWidgetItem(LibGuidLine);
		pGuidItem->setTextColor(QColor(150, 150, 150));
		ui.list_LibInfo->insertItem(ui.list_LibInfo->count(), pGuidItem);
		ui.list_LibInfo->insertItem(ui.list_LibInfo->count(), new QListWidgetItem(QStringLiteral("——————————————————————————————")));
	}
	return true;
}