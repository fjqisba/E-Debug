#pragma once
#include <QtWidgets/QDialog>
#include "ui_MainWindow.h"
#include "EAnalyEngine.h"

class MainWindow :public QWidget
{
	Q_OBJECT
public:
	MainWindow(unsigned int dwBase, QWidget* parent = Q_NULLPTR);
	~MainWindow();
public:
	//准备易语言静态编译程序窗口
	bool InitWindow_EStatic(duint codeAddr);
private slots:
	void on_LibNameSelected(const QString& currentText);
	void on_FuncDoubleClicked(QTableWidgetItem* pItem);
	void on_ApiMenu(const QPoint&);
	void on_MsgSelected();
	void on_WindowSelected(int index);
	void on_ForcePushWindow(bool checked = false);
private:
	Ui::MainWindow ui;
	EAnalyEngine eAnalyEngine;
};