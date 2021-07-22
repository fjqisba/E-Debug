#pragma once
#include <string>

class EAppControl
{
public:
	virtual std::string 取事件名称(int eventIndex) = 0;
};