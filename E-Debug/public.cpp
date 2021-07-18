#include "public.h"
#include "pluginsdk/_scriptapi_memory.h"

unsigned char BinMap[256] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,		//123456789
		0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,	//ABCDEF
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,	//abcdef
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

unsigned char HexToBin(unsigned char HexCode)
{
	return BinMap[HexCode];
}

void HexToBin(std::string& HexCode, unsigned char* BinCode)
{
	for (unsigned int n = 0; n < HexCode.length() / 2; n++) {
		BinCode[n] = BinMap[HexCode[2 * n]] * 16 + BinMap[HexCode[2 * n + 1]];
	}
}


std::string get_shortstring(dsint addr)
{
	if (addr <= 0)
	{
		return "";
	}
	char buffer[255] = { 0 };
	if (!Script::Memory::Read(addr, buffer, 255, 0)) {
		return "";
	}
	std::string ret = buffer;
	return ret;
}

std::string GetCurrentDirA()
{
	char buffer[MAX_PATH] = { 0 };
	GetCurrentDirectoryA(MAX_PATH, buffer);
	return buffer;
}

std::wstring GetCurrentDirW()
{
	wchar_t buffer[MAX_PATH] = { 0 };
	GetCurrentDirectoryW(MAX_PATH, buffer);
	return buffer;
}

int ReadInt(unsigned char* pBuf)
{
	return *(int*)pBuf;
}


unsigned int ReadUInt(unsigned char* pBuf)
{
	return *(unsigned int*)pBuf;
}

unsigned char ReadUChar(unsigned char* pBuf)
{
	return *(unsigned char*)pBuf;
}

std::wstring LocalCpToUtf16(const char* str)
{
	std::wstring convertedString;
	if (!str || !*str)
		return convertedString;
	int requiredSize = MultiByteToWideChar(CP_ACP, 0, str, -1, nullptr, 0);
	if (requiredSize > 0)
	{
		convertedString.resize(requiredSize - 1);
		if (!MultiByteToWideChar(CP_ACP, 0, str, -1, (wchar_t*)convertedString.c_str(), requiredSize))
			convertedString.clear();
	}
	return convertedString;
}

std::string Utf16ToUtf8(const wchar_t* wstr)
{
	std::string convertedString;
	if (!wstr || !*wstr)
		return convertedString;
	auto requiredSize = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
	if (requiredSize > 0)
	{
		convertedString.resize(requiredSize - 1);
		if (!WideCharToMultiByte(CP_UTF8, 0, wstr, -1, (char*)convertedString.c_str(), requiredSize, nullptr, nullptr))
			convertedString.clear();
	}
	return convertedString;
}

std::string LocalCpToUtf8(const char* str)
{
	return Utf16ToUtf8(LocalCpToUtf16(str).c_str());
}