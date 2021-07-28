#include "public.h"
#include "pluginsdk/_scriptapi_memory.h"
#include "pluginsdk/_scriptapi_label.h"

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

const char* ByteMap[256] = {
	"00","01","02","03","04","05","06","07","08","09","0A","0B","0C","0D","0E","0F",
	"10","11","12","13","14","15","16","17","18","19","1A","1B","1C","1D","1E","1F",
	"20","21","22","23","24","25","26","27","28","29","2A","2B","2C","2D","2E","2F",
	"30","31","32","33","34","35","36","37","38","39","3A","3B","3C","3D","3E","3F",
	"40","41","42","43","44","45","46","47","48","49","4A","4B","4C","4D","4E","4F",
	"50","51","52","53","54","55","56","57","58","59","5A","5B","5C","5D","5E","5F",
	"60","61","62","63","64","65","66","67","68","69","6A","6B","6C","6D","6E","6F",
	"70","71","72","73","74","75","76","77","78","79","7A","7B","7C","7D","7E","7F",
	"80","81","82","83","84","85","86","87","88","89","8A","8B","8C","8D","8E","8F",
	"90","91","92","93","94","95","96","97","98","99","9A","9B","9C","9D","9E","9F",
	"A0","A1","A2","A3","A4","A5","A6","A7","A8","A9","AA","AB","AC","AD","AE","AF",
	"B0","B1","B2","B3","B4","B5","B6","B7","B8","B9","BA","BB","BC","BD","BE","BF",
	"C0","C1","C2","C3","C4","C5","C6","C7","C8","C9","CA","CB","CC","CD","CE","CF",
	"D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","DA","DB","DC","DD","DE","DF",
	"E0","E1","E2","E3","E4","E5","E6","E7","E8","E9","EA","EB","EC","ED","EE","EF",
	"F0","F1","F2","F3","F4","F5","F6","F7","F8","F9","FA","FB","FC","FD","FE","FF"
};

unsigned char HexToBin(unsigned char HexCode)
{
	return BinMap[HexCode];
}



const char* UCharToStr(unsigned char c)
{
	return ByteMap[c];
}

std::string Ê®µ½Ê®Áù(unsigned char* pBuf, unsigned int len)
{
	std::string ret;
	ret.reserve(len << 1);
	for (unsigned int n = 0; n < len; ++n) {
		ret.append(UCharToStr(pBuf[n]));
	}
	return ret;
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

void WriteUInt(unsigned char* pBuf, unsigned int value)
{
	*(unsigned int*)pBuf = value;
}

unsigned short ReadUShort(unsigned char* pBuf)
{
	return *(unsigned short*)pBuf;
}

std::string ReadStr(unsigned char* pBuf)
{
	int Len = strlen((char*)pBuf);
	std::string ret((const char*)pBuf, Len);
	return ret;
}

unsigned char ReadUChar(unsigned char* pBuf)
{
	return *(unsigned char*)pBuf;
}

std::wstring StringUtils::LocalCpToUtf16(const char* str)
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

std::string StringUtils::Utf16ToUtf8(const wchar_t* wstr)
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

std::string StringUtils::LocalCpToUtf8(const char* str)
{
	return Utf16ToUtf8(LocalCpToUtf16(str).c_str());
}

std::string StringUtils::sprintf(_In_z_ _Printf_format_string_ const char* format, ...)
{
	va_list args;
	va_start(args, format);
	auto result = vsprintf(format, args);
	va_end(args);
	return result;
}

std::string StringUtils::vsprintf(_In_z_ _Printf_format_string_ const char* format, va_list args)
{
	char sbuffer[64] = "";
	if (_vsnprintf_s(sbuffer, _TRUNCATE, format, args) != -1)
		return sbuffer;

	std::vector<char> buffer(256, '\0');
	while (true)
	{
		int res = _vsnprintf_s(buffer.data(), buffer.size(), _TRUNCATE, format, args);
		if (res == -1)
		{
			buffer.resize(buffer.size() * 2);
			continue;
		}
		else
			break;
	}
	return std::string(buffer.data());
}

void SetX64DbgLabel(duint addr, const char* text)
{
	Script::Label::LabelInfo info = {};
	if (!Script::Label::GetInfo(addr, &info) || !info.manual) {
		Script::Label::Set(addr, text, true);
	}
}