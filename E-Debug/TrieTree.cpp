#include "TrieTree.h"
#include <stack>
#include "SectionManager.h"
#include "SymbolTable.h"
#include <math.h>
#include <QDebug>
#include "public.h"

std::string GetMidString(std::string& src, const char* left, const char* right, int offset) {
	int start = src.find(left, offset);
	if (start == -1) {
		return "";
	}

	int end = src.find(right, start);
	if (end == -1) {
		return "";
	}

	std::string ret = src.substr(start + strlen(left), end);
	return ret;
}

bool FastMatch_CmpApi(unsigned char* pSrc, std::string IATEAT)
{
	std::string IATCom;
	std::string EATCom;

	int EATpos = IATEAT.find("||");
	if (EATpos != -1) {            //存在自定义EAT
		IATCom = IATEAT.substr(0, EATpos);
		EATCom = IATEAT.substr(EATpos + 2);
	}
	else
	{
		IATCom = IATEAT;
		EATCom = IATEAT.substr(IATEAT.find('.') + 1);
	}

	size_t nDllPos = IATCom.find('.');
	if (nDllPos != std::string::npos) {
		IATCom = IATCom.substr(nDllPos + 1);
	}

	unsigned int oaddr = ReadUInt(pSrc);
	std::string funcName = SymbolTable::FindSymbolName(oaddr);

	if ((funcName == EATCom) || (funcName == IATCom)) {
		return true;
	}
	return false;
}

bool TrieTree::SimilarMatch_CmpCall(unsigned char* pSrc, std::string FuncName, double& out_RightLen, double& out_TotalLen)
{
	if (*pSrc != 0xE8) {
		return false;
	}
	unsigned int oaddr = m_SectionManager->VirtualAddrToLinearAddr(pSrc + ReadInt(pSrc + 1) + 5);
	if (m_RFunc[oaddr] == FuncName) {
		return true;
	}
	if (SimilarMatch(m_SectionManager->LinearAddrToVirtualAddr(oaddr), m_subFunc[FuncName], out_RightLen, out_TotalLen) == 100) {
		return true;
	}
	return false;
}

bool TrieTree::SlowMatch_CmpCall(unsigned char* pSrc, std::string FuncName)
{
	if (*pSrc != 0xE8) {
		return false;
	}
	unsigned int oaddr = m_SectionManager->VirtualAddrToLinearAddr(pSrc + ReadInt(pSrc + 1) + 5);
	if (m_RFunc[oaddr] == FuncName) {
		return true;
	}
	m_RFunc[oaddr] = FuncName;
	if (SlowMatch(m_SectionManager->LinearAddrToVirtualAddr(oaddr), m_subFunc[FuncName])) {
		return true;
	}
	m_RFunc[oaddr] = "";
	return false;
}

bool TrieTree::SlowMatch_CmpCallApi(unsigned char* pSrc, std::string IATEAT)
{
	if (*pSrc != 0xFF) {
		return false;
	}
	if ((*(pSrc + 1) != 0x15) && (*(pSrc + 1) != 0x25)) {
		return false;
	}
	std::string IATCom;
	std::string EATCom;

	int EATpos = IATEAT.find("||");
	if (EATpos != -1) {            //存在自定义EAT
		IATCom = IATEAT.substr(0, EATpos);
		EATCom = IATEAT.substr(EATpos + 2);
	}
	else
	{
		IATCom = IATEAT;
		EATCom = IATEAT.substr(IATEAT.find('.') + 1);
	}

	size_t nDllPos = IATCom.find('.');
	if (nDllPos != std::string::npos) {
		IATCom = IATCom.substr(nDllPos + 1);
	}

	unsigned int oaddr = ReadUInt(pSrc + 2);
	std::string funcName = SymbolTable::FindSymbolName(oaddr);

	if ((funcName == EATCom) || (funcName == IATCom)) {
		return true;
	}
	return false;
}

TrieTreeNode::TrieTreeNode() {
	ChildNodes = new TrieTreeNode * [256];
	for (int i = 0; i < 256; i++) {
		ChildNodes[i] = NULL;
	}
	EsigText = NULL;
	FuncName = NULL;
	IsMatched = false;
}

TrieTree::TrieTree(SectionManager* pSectionManager)
{
	root = new TrieTreeNode();
	root->SpecialType = NODE_NORMAL;

	m_SectionManager = pSectionManager;
	//默认配置
	m_IsAligned = false;
	m_IsSetName = true;
	m_MatchSubName = false;
}

TrieTreeNode* TrieTree::AddNode(TrieTreeNode* p, std::string Txt) {
	unsigned char index = 0;
	HexToBin(Txt, &index);
	if (p->ChildNodes[index]) {
		return p->ChildNodes[index];
	}

	TrieTreeNode* NewNode = new TrieTreeNode(); //如果所有的节点中都没有,则创建一个新节点
	p->ChildNodes[index] = NewNode;      //当前节点加入新子节点

	//赋值EsigTxt
	NewNode->EsigText = new char[Txt.length() + 1];
	strcpy_s(NewNode->EsigText, Txt.length() + 1, Txt.c_str());
	MemAllocSave.push_back(NewNode->EsigText);
	NewNode->SpecialType = NODE_NORMAL;
	return NewNode;
}

TrieTreeNode* TrieTree::AddSpecialNode(TrieTreeNode* p, unsigned int type, std::string Txt) {
	for (int i = 0; i < p->SpecialNodes.size(); i++) {		//遍历当前子节点
		if (p->SpecialNodes[i]->SpecialType == type && Txt == p->SpecialNodes[i]->EsigText) {
			return p->SpecialNodes[i];
		}
	}
	TrieTreeNode* NewNode = new TrieTreeNode(); //如果所有的节点中都没有,则创建一个新节点
	p->SpecialNodes.push_back(NewNode);      //当前节点加入新子节点
	NewNode->EsigText = new char[Txt.length() + 1]; 
	strcpy_s(NewNode->EsigText, Txt.length() + 1, Txt.c_str());//赋值EsigTxt
	MemAllocSave.push_back(NewNode->EsigText);
	NewNode->SpecialType = type;
	return NewNode;
}

bool TrieTree::Insert(std::string& FuncTxt, const std::string& FuncName) {		//参数一为函数的文本形式,参数二为函数的名称
	TrieTreeNode* p = root;		//将当前节点指针指向ROOT节点

	std::string BasicTxt;
	std::string SpecialTxt;

	MemAllocSave.clear();
	for (unsigned int n = 0; n < FuncTxt.length(); n++) {
		switch (FuncTxt[n])
		{
		case '-':	//Check 1次
			if (FuncTxt[n + 1] == '-' && FuncTxt[n + 2] == '>')
			{
				BasicTxt = "E9";
				p = AddNode(p, BasicTxt);
				p = AddSpecialNode(p, NODE_LONGJMP, "");
				n = n + 2;
				continue;		//此continue属于外部循环
			}
			return false;
		case '<':
			if (FuncTxt[n + 1] == '[') {						//CALLAPI
				int post = FuncTxt.find("]>", n);
				if (post == -1) {
					return false;
				}
				BasicTxt = "FF";
				p = AddNode(p, BasicTxt);
				BasicTxt = "15";
				p = AddNode(p, BasicTxt);
				SpecialTxt = FuncTxt.substr(n + 2, post - n - 2);   //得到文本中的IAT函数
				p = AddSpecialNode(p, NODE_CALLAPI, SpecialTxt);
				n = post + 1;
				continue;
			}
			else {											//普通的函数CALL
				int post = FuncTxt.find('>', n);
				if (post == -1) {
					return false;
				}
				SpecialTxt = FuncTxt.substr(n + 1, post - n - 1);
				BasicTxt = "E8";
				p = AddNode(p, BasicTxt);
				p = AddSpecialNode(p, NODE_CALL, SpecialTxt);
				n = post;
				continue;
			}
		case '[':
			if (FuncTxt[n + 1] == ']' && FuncTxt[n + 2] == '>') {
				//To Do
			}
			else
			{
				int post = FuncTxt.find(']', n);
				if (post == -1) {
					return false;
				}
				BasicTxt = "FF";
				p = AddNode(p, BasicTxt);
				BasicTxt = "25";
				p = AddNode(p, BasicTxt);
				SpecialTxt = FuncTxt.substr(n + 1, post - n - 1);
				p = AddSpecialNode(p, NODE_JMPAPI, SpecialTxt);
				n = post;
				continue;
			}
		case '?':
			if (FuncTxt[n + 1] == '?') {
				p = AddSpecialNode(p, NODE_ALLPASS, FuncTxt.substr(n, 2));	//全通配符
				n = n + 1;
				continue;
			}
			else
			{
				p = AddSpecialNode(p, NODE_LEFTPASS, FuncTxt.substr(n, 2));	//左通配符
				n = n + 1;
				continue;
			}
		case '!':
		{
			int post = FuncTxt.find('!', n + 1);	//从!的下一个字符开始寻找!
			if (post == -1) {
				return false;
			}
			SpecialTxt = FuncTxt.substr(n + 1, post - n - 1);
			p = AddSpecialNode(p, NODE_CONSTANT, SpecialTxt);
			n = post;	//将当前指针指向右边的!号
			continue;
		}
		default:
			if (FuncTxt[n + 1] == '?') {
				p = AddSpecialNode(p, NODE_RIGHTPASS, FuncTxt.substr(n, 2));	//右通配符
				n = n + 1;
				continue;
			}
			else {
				BasicTxt = FuncTxt.substr(n, 2);
				p = AddNode(p, BasicTxt);
				n = n + 1;
				continue;
			}
		}
	}

	if (p->FuncName) {		//确保函数名称唯一性！！！
		//msg("Find The same Function--%s", p->FuncName);
		for (unsigned int i = 0; i < MemAllocSave.size(); i++)
		{
			delete MemAllocSave[i];
		}
		return false;
	}

	p->FuncName = new char[FuncName.length() + 1]; strcpy_s(p->FuncName, FuncName.length() + 1, FuncName.c_str());
	return true;
}

TrieTree::~TrieTree()
{
	TrieTreeNode* p = root;
	if (!p)
	{
		return;
	}

	std::stack<TrieTreeNode*> StackNode;	//节点
	StackNode.push(p);

	while (!StackNode.empty()) {
		p = StackNode.top();
		StackNode.pop();
		//取回堆栈顶端节点
		if (p)
		{
			for (unsigned int i = 0; i < 256; i++)
			{
				StackNode.push(p->ChildNodes[i]);
			}
			for (unsigned int j = 0; j < p->SpecialNodes.size(); j++)
			{
				StackNode.push(p->SpecialNodes[j]);
			}
			if (p->EsigText)
			{
				delete p->EsigText;
				p->EsigText = NULL;
			}
			if (p->FuncName)
			{
				delete p->FuncName;
				p->FuncName = NULL;
			}
			if (p->ChildNodes)
			{
				delete p->ChildNodes;
				p->ChildNodes = NULL;
			}
			p->SpecialNodes.clear();
		}
		delete p;
		p = NULL;
	}
}

bool TrieTree::FastMatch(TrieTreeNode* p, unsigned char*& FuncSrc)
{
#ifdef _DEBUG
	if (p->SpecialType != NODE_NORMAL) {
		int a = 0;
	}
#endif
	switch (p->SpecialType)
	{
	case NODE_NORMAL:
	{
		return true;
	}
	case NODE_LONGJMP:
	{
		unsigned int oaddr = m_SectionManager->VirtualAddrToLinearAddr(FuncSrc - 1 + ReadInt(FuncSrc) + 5);
		FuncSrc = m_SectionManager->LinearAddrToVirtualAddr(oaddr);
		return true;
	}
	case NODE_CALL:
	{
		unsigned char* pCallSrc = FuncSrc - 1 + ReadInt(FuncSrc) + 5;
		unsigned int oaddr = m_SectionManager->VirtualAddrToLinearAddr(pCallSrc);
		if (m_RFunc[oaddr] == p->EsigText)	//此函数已经匹配过一次
		{
			FuncSrc = FuncSrc + 4;
			return true;
		}
		if (!SlowMatch(m_SectionManager->LinearAddrToVirtualAddr(oaddr), m_subFunc[p->EsigText])) {
			return false;
		}
		m_RFunc[oaddr] = p->EsigText;
		FuncSrc = FuncSrc + 4;
		return true;
	}
	case NODE_JMPAPI:
	case NODE_CALLAPI:
	{
		if (!FastMatch_CmpApi(FuncSrc, p->EsigText)) {
			return false;
		}
		FuncSrc = FuncSrc + 4;
		return true;
	}
	case NODE_CONSTANT:
	{
		unsigned int oaddr = ReadUInt(FuncSrc);
		if (m_RFunc[oaddr] == p->EsigText) {
			FuncSrc = FuncSrc + 4;
			return true;
		}
		if (!SlowMatch(m_SectionManager->LinearAddrToVirtualAddr(oaddr), m_subFunc[p->EsigText])) {
			return false;
		}
		m_RFunc[oaddr] = p->EsigText;
		FuncSrc = FuncSrc + 4;
		return true;
	}
	case NODE_LEFTPASS:
	{
		if ((ReadUChar(FuncSrc) & 0xF) == HexToBin(p->EsigText[1])) {
			FuncSrc = FuncSrc + 1;
			return true;
		}
		return false;
	}
	case NODE_RIGHTPASS:
	{
		if ((ReadUChar(FuncSrc) >> 4) == HexToBin(p->EsigText[0])) {
			FuncSrc = FuncSrc + 1;
			return true;
		}
		return false;
	}
	case NODE_ALLPASS:
	{
		FuncSrc = FuncSrc + 1;
		return true;
	}
	default:
		break;
	}

	return false;
}


int TrieTree::SimilarMatch(unsigned char* FuncSrc, std::string& FuncTxt, double& out_RightLen, double& out_TotalLen)
{
	unsigned char* pSrc = FuncSrc;  //初始化函数代码指针
	if (FuncTxt.empty() || !FuncSrc)
	{
		return 0;
	}

	unsigned int MaxLength = FuncTxt.length();
	unsigned int n = 0;

	while (n < MaxLength) {
		switch (FuncTxt[n]) {
		case '-':
		{
			out_TotalLen += 5;
			if (FuncTxt[n + 1] == '-' && FuncTxt[n + 2] == '>') {		//长跳转
				if (*pSrc != 0xE9) {
					out_RightLen = 0;
					goto label_end;
				}
				unsigned int oaddr = m_SectionManager->VirtualAddrToLinearAddr(pSrc + ReadInt(pSrc + 1) + 5);
				pSrc = m_SectionManager->LinearAddrToVirtualAddr(oaddr);
				if (!pSrc) {
					goto label_end;
				}
				n = n + 3;
				out_RightLen += 5;
				continue;
			}
			goto label_end;
		}
		case '<':
		{
			out_TotalLen += 6;
			if (FuncTxt[n + 1] == '[') {						//CALLAPI
				int post = FuncTxt.find("]>", n);
				if (post == -1) {
					goto label_end;
				}
				if (SlowMatch_CmpCallApi(pSrc, FuncTxt.substr(n + 2, post - n - 2))) {
					out_RightLen += 6;
				}
				pSrc = pSrc + 6;
				n = post + 2;
				continue;
			}
			else {
				out_TotalLen += 5;
				int post = FuncTxt.find('>', n);
				if (post == -1) {
					goto label_end;
				}
				double callRightLen = 0;
				double callTotalLen = 0;
				if (SimilarMatch_CmpCall(pSrc, FuncTxt.substr(n + 1, post - n - 1), callRightLen, callTotalLen)) {
					out_RightLen += 5;
					out_RightLen += callRightLen;
					out_TotalLen += callTotalLen;
				}
				pSrc = pSrc + 5;
				n = post + 1;
				continue;
			}
		}
		case '[':
		{
			out_TotalLen += 6;
			int post = FuncTxt.find(']', n);
			if (post == -1) {
				goto label_end;
			}
			if (SlowMatch_CmpCallApi(pSrc, FuncTxt.substr(n + 1, post - n - 1))) {
				out_RightLen += 6;
			}
			pSrc = pSrc + 6;
			n = post + 1;
			continue;
		}
		case '!':
		{
			out_TotalLen += 4;
			int post = FuncTxt.find('!', n + 1);
			if (post == -1) {
				goto label_end;
			}
			std::string constantName = FuncTxt.substr(n + 1, post - n - 1);
			unsigned int oaddr = ReadUInt(pSrc);
			if (m_RFunc[oaddr] != constantName) {
				double dwRightLen = 0;
				double dwTotalLen = 0;
				SimilarMatch(m_SectionManager->LinearAddrToVirtualAddr(oaddr), m_subFunc[constantName], dwRightLen, dwTotalLen);
			}
			out_RightLen += 4;
			pSrc = pSrc + 4;
			n = post + 1;
			continue;
		}
		case '?':
		{
			if (FuncTxt[n + 1] == '?') {	                                  //全通配符
				out_TotalLen += 0.25;
				out_RightLen += 0.25;
			}
			else if ((ReadUChar(pSrc) & 0xF) == HexToBin(FuncTxt[n + 1])) {   //左通配符
				out_TotalLen += 0.5;
				out_RightLen += 0.5;
			}
			else {
				out_TotalLen += 1;
			}
			pSrc = pSrc + 1;
			n = n + 2;
			continue;
		}
		default:
		{
			if (FuncTxt[n + 1] == '?') {                                      //右通配符
				if ((ReadUChar(pSrc) >> 4) == HexToBin(FuncTxt[n])) {
					out_RightLen += 0.5;
					out_TotalLen += 0.5;
				}
				else {
					out_TotalLen += 1;
				}
			}
			else {
				out_TotalLen += 1;
				unsigned char ByteCode;
				HexToBin(FuncTxt.substr(n, 2), &ByteCode);
				if (*pSrc == ByteCode) {
					out_RightLen += 1;
				}
			}
			pSrc = pSrc + 1;
			n = n + 2;
			continue;
		}
		}
	}

label_end:
	if (out_TotalLen) {
		return (out_RightLen * 100) / out_TotalLen;
	}
	return 0;
}

bool TrieTree::SlowMatch(unsigned char* FuncSrc, std::string& FuncTxt)
{
	unsigned char* pSrc = FuncSrc;  //初始化函数代码指针
	if (FuncTxt == "" || !FuncSrc)
	{
		return false;
	}

	unsigned int MaxLength = FuncTxt.length();
	unsigned int n = 0;
	while (n < MaxLength) {
		switch (FuncTxt[n]) {
		case '-':
		{
			if (FuncTxt[n + 1] == '-' && FuncTxt[n + 2] == '>') {		//长跳转
				if (*pSrc != 0xE9) {
					return false;
				}
				unsigned int oaddr = m_SectionManager->VirtualAddrToLinearAddr(pSrc + ReadInt(pSrc + 1) + 5);
				pSrc = m_SectionManager->LinearAddrToVirtualAddr(oaddr);
				n = n + 3;
				continue;
			}
			return false;
		}
		case '<':
		{
			if (FuncTxt[n + 1] == '[') {						//CALLAPI
				int post = FuncTxt.find("]>", n);
				if (post == -1) {
					return false;
				}
				if (!SlowMatch_CmpCallApi(pSrc, FuncTxt.substr(n + 2, post - n - 2))) {
					return false;
				}
				pSrc = pSrc + 6;
				n = post + 2;
				continue;
			}
			else {
				int post = FuncTxt.find('>', n);
				if (post == -1) {
					return false;
				}
				if (SlowMatch_CmpCall(pSrc, FuncTxt.substr(n + 1, post - n - 1))) {
					pSrc = pSrc + 5;
					n = post + 1;
					continue;
				}
				return false;
			}
		}
		case '[':
		{
			int post = FuncTxt.find(']', n);
			if (post == -1) {
				return false;
			}
			if (!SlowMatch_CmpCallApi(pSrc, FuncTxt.substr(n + 1, post - n - 1))) {
				return false;
			}
			pSrc = pSrc + 6;
			n = post + 1;
			continue;
		}
		case '!':
		{
			int post = FuncTxt.find('!', n + 1);
			if (post == -1) {
				return false;
			}
			std::string constantName = FuncTxt.substr(n + 1, post - n - 1);
			unsigned int oaddr = ReadUInt(pSrc);
			if (m_RFunc[oaddr] == constantName || SlowMatch(m_SectionManager->LinearAddrToVirtualAddr(oaddr), m_subFunc[constantName])) {
				pSrc = pSrc + 4;
				n = post + 1;
				continue;
			}
			return false;
		}
		case '?':
		{
			if (FuncTxt[n + 1] == '?') {	                                  //全通配符
				pSrc = pSrc + 1;
				n = n + 2;
				continue;
			}
			else if ((ReadUChar(pSrc) & 0xF) == HexToBin(FuncTxt[n + 1])) {   //左通配符
				pSrc = pSrc + 1;
				n = n + 2;
				continue;
			}
			return false;
		}
		default:
		{
			if (FuncTxt[n + 1] == '?') {                                      //右通配符
				if ((ReadUChar(pSrc) >> 4) == HexToBin(FuncTxt[n])) {
					pSrc = pSrc + 1;
					n = n + 2;
					continue;
				}
			}
			else {
				unsigned char ByteCode;
				HexToBin(FuncTxt.substr(n, 2), &ByteCode);
				if (*pSrc != ByteCode) {
					return false;
				}
				pSrc = pSrc + 1;
				n = n + 2;
				continue;
			}
		}
		}
	}
	return true;
}

const char* TrieTree::MatchFunc_Fuzzy(unsigned char* CodeSrc, double& out_score)
{
	unsigned int retIndex = 0;
	for (unsigned int n = 0; n < mVec_MainFunc.size(); ++n) {
		double dwRightLen = 0;
		double dwTotalLen = 0;
		if (!SimilarMatch(CodeSrc, mVec_MainFunc[n].second, dwRightLen, dwTotalLen)) {
			continue;
		}

		//计算出基础分数
		double Similarity = (dwRightLen * 100 / dwTotalLen);
		double WeightValue= std::sqrt((16 + dwRightLen) / 32);
		//进行匹配字节加权
		Similarity = Similarity * WeightValue;

		//40分是及格分数
		if (Similarity < 40) {
			continue;
		}
		if (Similarity > out_score) {
			out_score = Similarity;
			retIndex = n;
		}
#ifdef _DEBUG
		if (m_SectionManager->VirtualAddrToLinearAddr(CodeSrc) == 0x0048F430) {
			if (mVec_MainFunc[n].first == "处理事件") {
				int a = 0;
			}
			qDebug() << QString::fromLocal8Bit(mVec_MainFunc[n].first.c_str()) << "(" << dwRightLen << "/" << dwTotalLen << "):" << Similarity;
		}
#endif
	}

	if (out_score) {
		//禁止重复模糊匹配
		mVec_MainFunc[retIndex].second.clear();
		return mVec_MainFunc[retIndex].first.c_str();
	}
	return NULL;
}

char* TrieTree::MatchFunc(unsigned char* FuncSrc)
{
	TrieTreeNode* p = root;		                //当前指针指向root

	std::stack<TrieTreeNode*> StackNode;	        //节点
	std::stack<unsigned char*> StackFuncSrc;        //节点地址

	StackNode.push(p);
	StackFuncSrc.push(FuncSrc);
	//进入循环初始条件

	while (!StackNode.empty()) {
		p = StackNode.top();
		StackNode.pop();
		FuncSrc = StackFuncSrc.top();
		StackFuncSrc.pop();
		//取回堆栈顶端节点
		if (!FastMatch(p, FuncSrc)) {		//检查当前节点合法性优先级高于判断终节点
			continue;
		}
		if (p->FuncName) {
			return p->FuncName;
		}
		for (UINT i = 0; i < p->SpecialNodes.size(); i++) {
			StackNode.push(p->SpecialNodes[i]);
			StackFuncSrc.push(FuncSrc);
		}
		if (p->ChildNodes[*FuncSrc]) {
			StackNode.push(p->ChildNodes[*FuncSrc]);
			StackFuncSrc.push(FuncSrc + 1);
		}
	}

	return NULL;
}

bool TrieTree::LoadSig(const char* lpMapPath)
{
	HANDLE hFile = CreateFileA(lpMapPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	DWORD dwSize = GetFileSize(hFile, 0);
	char* pMapBuffer = (char*)BridgeAlloc(dwSize);

	bool bRet = true;
	do
	{
		unsigned int recvLen = 0;
		if (!ReadFile(hFile, pMapBuffer, dwSize, (LPDWORD)&recvLen, 0)) {
			bRet = false;
			break;
		}

		std::string str_Map = pMapBuffer;
		std::string SubFunc = GetMidString(str_Map, "*****SubFunc*****\r\n", "*****SubFunc_End*****", 0);

		int pos = SubFunc.find("\r\n");     //子函数
		while (pos != -1) {
			std::string temp = SubFunc.substr(0, pos);  //单个子函数
			if (temp == "")
			{
				SubFunc = SubFunc.substr(SubFunc.find("\r\n") + 2);
				pos = SubFunc.find("\r\n");
				continue;
			}
			int tempos = temp.find(':');
			if (tempos == -1) {
				break;
			}
			while (SubFunc[tempos + 1] == ':')
			{
				tempos = temp.find(':', tempos + 2);
			}
			m_subFunc[temp.substr(0, tempos)] = temp.substr(tempos + 1);
			SubFunc = SubFunc.substr(pos + 2);
			pos = SubFunc.find("\r\n");
		}

		std::string Func = GetMidString(str_Map, "***Func***\r\n", "***Func_End***", 0);

		pos = Func.find("\r\n");//分割文本
		while (pos != -1) {
			std::string temp = Func.substr(0, pos);    //取出单个函数文本
			if (temp == "")		//得到空行
			{
				Func = Func.substr(Func.find("\r\n") + 2);
				pos = Func.find("\r\n");
				continue;
			}
			int tempos = temp.find(':');
			if (tempos == -1) {
				break;
			}
			while (Func[tempos + 1] == ':')
			{
				tempos = temp.find(':', tempos + 2);
			}
			if (!Insert(temp.substr(tempos + 1), temp.substr(0, tempos))) {
				//"插入函数失败\r\n");
			}
			mVec_MainFunc.push_back(std::pair<std::string, std::string>(temp.substr(0, tempos), temp.substr(tempos + 1)));
			Func = Func.substr(pos + 2);
			pos = Func.find("\r\n");
		}
	} while (0);

	BridgeFree(pMapBuffer);
	CloseHandle(hFile);
	return bRet;
}

void TrieTree::Log_PrintSubFunc()
{
	
	//std::map<qstring, qstring>::iterator it;
	//for (it = m_subFunc.begin(); it != m_subFunc.end(); it++)
	//{
	//	msg("%s----%s\r\n", it->first.c_str(), it->second.c_str());
	//}
}