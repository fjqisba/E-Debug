#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <map>

class SectionManager;
class TrieTreeNode
{
public:
	TrieTreeNode();
	std::vector<TrieTreeNode*> SpecialNodes;
	TrieTreeNode** ChildNodes;

	unsigned int SpecialType;	//一个数字代表类型
	char* EsigText;		        //一段文字代表数据
	char* FuncName;		        //函数名称

	bool IsMatched;             //是否已经匹配过
};

class TrieTree
{
public:
	TrieTree(SectionManager*);
	~TrieTree();

	//日志,打印子函数结果
	void Log_PrintSubFunc();
	//加载特征码
	bool LoadSig(const char* lpMapPath);
	//执行函数匹配
	char* MatchFunc(unsigned char* CodeSrc);
	//执行模糊匹配,分数越高越好
	const char* MatchFunc_Fuzzy(unsigned char* CodeSrc, double& out_score);
private:
	//增加普通节点
	TrieTreeNode* AddNode(TrieTreeNode* p, std::string Txt);
	//增加特殊节点
	TrieTreeNode* AddSpecialNode(TrieTreeNode* p, unsigned int type, std::string Txt);

	//快速匹配特征码
	bool FastMatch(TrieTreeNode* p, unsigned char*& FuncSrc);
	//慢速匹配特征码
	bool SlowMatch(unsigned char* FuncSrc, std::string& FuncTxt);

	int SimilarMatch(unsigned char* FuncSrc, std::string& FuncTxt, double& out_RightLen, double& out_TotalLen);

	bool SlowMatch_CmpCallApi(unsigned char* pSrc, std::string IATEAT);
	bool SlowMatch_CmpCall(unsigned char* pSrc, std::string FuncName);
	bool SimilarMatch_CmpCall(unsigned char* pSrc, std::string FuncName, double& out_RightLen, double& out_TotalLen);
public:
	std::vector<char*>  MemAllocSave;
	SectionManager* m_SectionManager;

	//修改函数的名称
	bool m_IsSetName;
	bool m_IsAligned;
	bool m_IsAllMem;
	bool m_MatchSubName;
protected:
	bool Insert(std::string& FuncTxt, const std::string& FuncName);

private:
	enum NodeType_t
	{
		NODE_NORMAL = 0,
		NODE_LONGJMP = 1,	       //      -->
		NODE_CALL = 2,	           //      <>
		NODE_JMPAPI = 3,	       //      []
		NODE_CALLAPI = 4,	       //      <[]>
		NODE_CONSTANT = 6,	       //      !!
		NODE_LEFTPASS = 11,        //      ?
		NODE_RIGHTPASS = 12,       //       ?
		NODE_ALLPASS = 13          //      ??
	};
	//根节点
	TrieTreeNode* root;


	//子函数,函数名称和函数文本一一映射
	std::map<std::string, std::string> m_subFunc;
	
	//主函数,first函数名称,second函数特征
	std::vector<std::pair<std::string, std::string>> mVec_MainFunc;
	
	//R代表Runtime,运行时记录实际地址对应函数,不要试图一个地址多个函数名称 ,参数一为实际内存地址,参数二为对应名称
	std::map<unsigned int, std::string> m_RFunc;
};