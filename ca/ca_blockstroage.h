/*
 * @Author: lyw 15035612538@163.com
 * @Date: 2024-03-24 16:47:18
 * @LastEditors: lyw 15035612538@163.com
 * @LastEditTime: 2024-03-24 16:47:18
 * @FilePath: /don/ca/ca_blockstroage.h
 */
#ifndef _BLOCK_STROAGE_
#define _BLOCK_STROAGE_

#include "ca/ca_transtroage.h"
#include "ca/ca_blockmonitor.h"
#include "utils/MagicSingleton.h"
#include "utils/VRF.hpp"
#include <future>


using RetType = std::pair<std::string, uint16_t>;

class BlockStroage
{
public:
    BlockStroage(){ StartTimer(); };
    ~BlockStroage() = default;
    BlockStroage(BlockStroage &&) = delete;
    BlockStroage(const BlockStroage &) = delete;
    BlockStroage &operator=(BlockStroage&&) = delete;
    BlockStroage &operator=(const BlockStroage &) = delete;

public:
	void AddBlock(const BlockMsg &msg);
	int AddContractBlock(const ContractBlockMsg &msg);

	int UpdateBlock(const BlockMsg &msg);
	int UpdateContractBlock(const ContractBlockMsg &msg);

	void CommitSeekTask(uint64_t seekHeight);
	void CommitContractSeekTask(uint64_t seekHeight);

	bool IsSeekTask(uint64_t seekHeight);
	bool IsContractSeekTask(uint64_t seekHeight);

	void ForceCommitSeekTask(uint64_t seekHeight);
	//void ForceContractCommitSeekTask(uint64_t seekHeight);

	std::shared_future<RetType> GetPrehash(const uint64_t height);
	int VerifyBlockFlowSignNode(const ContractBlockMsg & blockMsg);
	void ClearPreHashMap();
private:

	void StartTimer();

	void BlockCheck();
	void BlockContractCheck();

	void composeEndBlockmsg(std::vector<BlockMsg> &msgvec);
	int  composeContractEndBlockmsg(const std::vector<ContractBlockMsg> &msgVec, ContractBlockMsg & outMsg , bool isVrf);

	void Remove(const std::string &blockhash);
	void RemoveContract(const std::string &blockhash);
	RetType _SeekPreHashThread(uint64_t seekHeight);
	RetType _SeekPreHashByNode(
		const std::vector<std::string> &sendNodeIds, uint64_t seekHeight, const uint64_t &selfNodeHeight, const uint64_t &chainHeight);

private:

	CTimer _block_timer;
	CTimer _contract_block_timer;
	std::mutex _block_mutex_;
	std::shared_mutex _block_mutex_contract_;

	
	mutable std::shared_mutex _prehashMutex;
	mutable std::shared_mutex _prehashMutex_contract;

	std::map<uint64_t, std::shared_future<RetType>> _preHashMap;

	std::map<std::string, std::vector<BlockMsg>> _BlockMap;
	std::map<std::string, std::vector<ContractBlockMsg>> _BlockMap_Contract;
};
int GetPrehashFindNode(uint32_t num, uint64_t selfNodeHeight, const std::vector<std::string> &pledgeAddr,
                            std::vector<std::string> &sendNodeIds);
//int DoProtoBlockStatus(const BlockStatus& blockStatus, const std::string destNode);

void SendSeekGetPreHashAck(SeekPreHashByHightAck& ack,const std::string &nodeId, const std::string &msgId, uint64_t seekHeight);
void SendSeekGetPreHashReq(const std::string &nodeId, const std::string &msgId, uint64_t seekHeight);
int HandleSeekGetPreHashReq(const std::shared_ptr<SeekPreHashByHightReq> &msg, const MsgData &msgdata);
int HandleSeekGetPreHashAck(const std::shared_ptr<SeekPreHashByHightAck> &msg, const MsgData &msgdata);

 int HandleBlockStatusMsg(const std::shared_ptr<BlockStatus> &msg, const MsgData &msgData);
#endif