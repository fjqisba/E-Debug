#pragma once

enum controlType_t;
class EAppControl;
class EAppControlFactory
{
public:
	//根据type类型定位到类指针
	static EAppControl* getEAppControl(controlType_t type);
};