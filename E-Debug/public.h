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

//十到十六
const char* UCharToStr(unsigned char c);

int ReadInt(unsigned char* pBuf);
unsigned int ReadUInt(unsigned char* pBuf);
unsigned char ReadUChar(unsigned char* pBuf);
unsigned short ReadUShort(unsigned char* pBuf);

std::wstring LocalCpToUtf16(const char* str);

std::string Utf16ToUtf8(const wchar_t* wstr);

std::string LocalCpToUtf8(const char* str);

