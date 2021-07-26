#pragma once
#include <string>
#include "pluginsdk/bridgemain.h"

//存放一些常用的函数


std::string get_shortstring(dsint addr);

//获取当前目录
std::string GetCurrentDirA();
std::wstring GetCurrentDirW();


//十六到十
unsigned char HexToBin(unsigned char HexCode);
void HexToBin(std::string& HexCode, unsigned char* BinCode);

std::string 十到十六(unsigned char* pBuf,unsigned int len);


//十到十六
const char* UCharToStr(unsigned char c);

int ReadInt(unsigned char* pBuf);
unsigned int ReadUInt(unsigned char* pBuf);
void WriteUInt(unsigned char* pBuf,unsigned int value);
unsigned char ReadUChar(unsigned char* pBuf);
unsigned short ReadUShort(unsigned char* pBuf);
std::string ReadStr(unsigned char* pBuf);

//只有标签不存在的时候，会进行设置
void SetX64DbgLabel(duint addr, const char* text);

//copy from source code of x64Dbg
class StringUtils
{
public:
	static std::wstring LocalCpToUtf16(const char* str);
	static std::string Utf16ToUtf8(const wchar_t* wstr);
	static std::string LocalCpToUtf8(const char* str);
	static std::string sprintf(_In_z_ _Printf_format_string_ const char* format, ...);
	static std::string vsprintf(_In_z_ _Printf_format_string_ const char* format, va_list args);
};