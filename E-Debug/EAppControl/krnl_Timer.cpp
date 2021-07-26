#include "krnl_Timer.h"

std::string krnl_Timer::取事件名称(int eventIndex)
{
	std::string ret;
	switch (eventIndex)
	{
	case 0:
		ret = "周期事件";
		break;
	default:
		ret = "未知事件";
		break;
	}
	return ret;
}