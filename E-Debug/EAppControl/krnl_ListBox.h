#pragma once
#include "EAppControl.h"

class krnl_ListBox:public EAppControl
{
protected:
	std::string 取事件名称(int eventIndex);
private:
};