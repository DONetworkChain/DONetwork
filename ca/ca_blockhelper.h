#ifndef _CA_BLOCKHELPER_H
#define _CA_BLOCKHELPER_H

#include <stack>
#include <mutex>
#include <string>
#include <map>
#include <thread>
#include <condition_variable>
#include <atomic>

#include "ca_sync_block.h"
#include "ca_global.h"

namespace compator
{
    struct BlockTimeAscending
    {
        bool operator()(const CBlock &a, const CBlock &b) const
        {
            if(a.height() == b.height()) return a.time() < b.time();
            else if(a.height() < b.height()) return true;
            return false;
        }
    };
}

enum ContractPreHashStatus {
    Normal,
    DbBlockException,
    MemBlockException,
    Waiting,
    Err
};

enum class doubleSpendType
{
    repeatenDoubleSpend,
    newDoubleSpend,
    oldDoubleSpend,
    invalidDoubleSpend,
    err
};
struct MissingBlock
{
	std::string hash_;
	uint64_t time_;
    std::shared_ptr<bool> tx_or_block_; // 0 is block hash  1 is utxo
    std::shared_ptr<uint64_t> trigger_count;
    
    MissingBlock(const std::string& hash, const uint64_t& time, const bool& tx_or_block)
    {
        hash_ = hash;
        time_ = time;
        tx_or_block_ = std::make_shared<bool>(tx_or_block);
        trigger_count = std::make_shared<uint64_t>(0);
    }
	bool operator<(const struct MissingBlock & right)const   //Overload<operator
	{
		if (this->hash_ == right.hash_)
		{
			return false;
		}
		else
		{
			return time_ < right.time_; //Small top reactor
		}
	}
};

class BlockHelper
{
    public:
        BlockHelper();

        int VerifyFlowedBlock(const CBlock& block);
        int SaveBlock(const CBlock& block, global::ca::SaveType saveType, global::ca::BlockObtainMean obtainMean);

        void SetMissingPrehash();
        void ResetMissingPrehash();
        void PushMissUTXO(const std::string& utxo);  
        void PopMissUTXO();

        static bool obtain_chain_height(uint64_t& chain_height);

        void Process();  
        void SeekBlockThread();
        void AddBroadcastBlock(const CBlock& block);
        void AddSyncBlock(const std::map<uint64_t, std::set<CBlock, CBlockCompare>> &sync_block_data, global::ca::SaveType type);
        void AddFastSyncBlock(const std::map<uint64_t, std::set<CBlock, CBlockCompare>> &sync_block_data, global::ca::SaveType type);
        void AddRollbackBlock(const std::map<uint64_t, std::set<CBlock, CBlockCompare>> &sync_block_data);
        void AddMissingBlock(const CBlock& block);
        void AddSeekBlock(std::vector<std::pair<CBlock,std::string>>& seek_blocks);
        void GetBroadcastBlock(std::set<CBlock, compator::BlockTimeAscending>& block);

        //deal double spend new type
        int DealDoubleSpend(const CBlock& block, const CTransaction& tx, const std::string& missing_utxo);
        bool GetwhetherRunSendBlockByUtxoReq() { return _whetherRunSendBlockByUtxoReq; };
        void SetwhetherRunSendBlockByUtxoReq(bool flag) {_whetherRunSendBlockByUtxoReq = flag;};
        void rollback_test();
        static bool ObtainChainHeight(uint64_t& chainHeight);
        int RollbackPreviousBlocks(const std::string utxo, uint64_t shelfHeight, const std::string blockHash);

        // void MakeTxStatusMsg(const CBlock &oldBlock, const CBlock &newBlock);
        //void CheckDoubleBlooming(const std::pair<doubleSpendType, CBlock>& doubleSpendInfo, const CBlock &block);
        void StopSaveBlock() { _stopBlocking = false; }
        int ContractVerifyFlowedBlock(const CBlock& block, BlockStatus* blockStatus = nullptr,ContractBlockMsg *msg = nullptr);
        void SetMissingBlock(const CBlock& block);
    private:
        bool VerifyHeight(const CBlock& block, uint64_t ownblockHeight);
        bool GetMissBlock();
        void PostMembershipCancellationProcess(const CBlock &block);
        void PostTransactionProcess(const CBlock &block);
        void  PostSaveProcess(const CBlock &block);
        int PreSaveProcess(const CBlock& block, global::ca::SaveType saveType, global::ca::BlockObtainMean obtainMean);
        int RollbackBlocks();
        int RollbackContractBlock();
        void AddPendingBlock(const CBlock& block);
        int checkContractBlock(const CBlock& block, std::string& contractTxPreHash);
        int checkContractBlockCache(const CBlock& block, const std::string& contractTxPreHash);
        void AddContractBlock(const CBlock& block, const std::string& contractTxPreHash);
        ContractPreHashStatus CheckContractPreHashStatus(const std::string& contractAddr, const std::string& MEMContractPreHash, const uint64_t blockTime, std::string& DBBlockHash);

        std::mutex helper_mutex;
        std::mutex helper_mutex_low1;
        std::atomic<bool> missing_prehash;
        std::mutex _missingUtxosMutex;
        std::stack<std::string> missing_utxos;
        

        std::set<CBlock, compator::BlockTimeAscending> broadcast_blocks; //Polling of blocks to be added after broadcasting
        std::set<CBlock, compator::BlockTimeAscending> sync_blocks; //Synchronized block polling
        std::set<CBlock, compator::BlockTimeAscending> fast_sync_blocks; //Quickly synchronize the block polling to be added
        std::map<uint64_t, std::set<CBlock, CBlockCompare>> rollback_blocks; //Polling of blocks to be rolled back
        std::map<uint64_t, std::multimap<std::string, CBlock>> pending_blocks; //Because there is no block trigger waiting to be added in the previous hash
        std::map<std::string, std::pair<uint64_t, CBlock>> hash_pending_blocks; //Polling for blocks found by the find block protocol and blocks not found by utxo
        std::vector<CBlock> utxo_missing_blocks; //Poll the block found by finding the protocol of utxo
        std::mutex seek_mutex_;
        std::set<MissingBlock> missing_blocks; //Wait for the hash polling to trigger the block finding protocols
        std::map<std::string,CBlock> DoubleSpend_blocks;
        std::unordered_map<std::string, CBlock> _contractBlocks;
        std::atomic<bool> _whetherRunSendBlockByUtxoReq = true;
        std::atomic<bool> _stopBlocking = true;
        const static int max_missing_block_size = 10;
        const static int max_missing_uxto_size = 10;
        const static int sync_save_fail_tolerance = 2;

        uint64_t postCommitCost = 0;
        uint64_t postCommitCount = 0;
};

static int GetUtxoFindNode(uint32_t num, uint64_t self_node_height, const std::vector<std::string> &pledge_addr,
                            std::vector<std::string> &send_node_ids);
int SendBlockByUtxoReq(const std::string &utxo);
int SendBlockByUtxoAck(const std::string &utxo, const std::string &addr, const std::string &msg_id);
int HandleBlockByUtxoReq(const std::shared_ptr<GetBlockByUtxoReq> &msg, const MsgData &msgdata);
int HandleBlockByUtxoAck(const std::shared_ptr<GetBlockByUtxoAck> &msg, const MsgData &msgdata);

int SendBlockByHashReq(const std::map<std::string, bool> &missingHashs);
int SendBlockByHashAck(const std::map<std::string, bool> &missingHashs, const std::string &addr, const std::string &msg_id);
int HandleBlockByHashReq(const std::shared_ptr<GetBlockByHashReq> &msg, const MsgData &msgdata);
int HandleBlockByHashAck(const std::shared_ptr<GetBlockByHashAck> &msg, const MsgData &msgdata);

#endif