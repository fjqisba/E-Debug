#pragma once
#include "EAppControl.h"

class krnl_Tab :public EAppControl
{
protected:
	std::string 取事件名称(int eventIndex);
private:
};