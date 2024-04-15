#ifndef __CA_TRANSACTION_CACHE__
#define __CA_TRANSACTION_CACHE__

#include "../proto/transaction.pb.h"
#include "../proto/ca_protomsg.pb.h"
#include "utils/CTimer.hpp"
#include "ca/ca_transactionentity.h"


#include <map>
#include <list>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <vector>
#include <string>
#include "../proto/block.pb.h"
#include "net/msg_queue.h"
#include "utils/json.hpp"
#include "ca/ca_contract_transaction_entity.h"

//Transaction cache class. After the transaction flow ends, add the transaction to this class. Pack blocks every time a certain interval elapses or when the number of transactions reaches a certain number.
class CtransactionCache
{
    private:
    //Used to store statistical information
        struct StatisticEntity
        {
            //Pre-block hash
            std::string pre_block_hash_;
            //The hash of the transaction that owns the hash of that previous block
            std::vector<std::string> transaction_hashes_;
            //The hash is the percentage of all transactions
            double percentage_;
        };

        typedef std::list<TransactionEntity>::const_iterator tx_entities_iter;
        typedef std::map<uint64_t, std::list<TransactionEntity>>::iterator cache_iter;

        struct hash_comparator
        {
            bool operator()(const StatisticEntity& p_left, const std::string& p_right)
            {
                return p_left.pre_block_hash_ < p_right;
            }
            bool operator()(const std::string& p_left, const StatisticEntity& p_right)
            {
                return p_left < p_right.pre_block_hash_;
            }
        };

    private:
        //Transaction container
        std::map<uint64_t, std::list<TransactionEntity>> cache_;
        //The mutex of the transaction container
        std::mutex cache_mutex_;

        std::mutex contract_cache_mutex_;
        //Condition variables are used to package blocks
        std::condition_variable blockbuilder_;
        //Timers are used for packing at specific time intervals
        std::condition_variable _contractPreBlockWaiter;
        CTimer build_timer_;
        //Thread variables are used for packaging
        std::thread build_thread_;
        std::thread build_thread_contract_;

        // The mutex of the Contract transaction container
        std::mutex _contractCacheMutex;
        // The mutex of the  transaction container
        std::mutex _transactionCacheMutex;
        //Packing interval
        static const int build_interval_;
        //Transaction expiration interval
        static const time_t tx_expire_interval_;
        //Packaging threshold
        static const int build_threshold_;
        //Decision threshold (percentage) 
        static const double decision_threshold_; 
        //Transaction pending container
        std::map<uint64_t, std::list<TransactionEntity>> pending_cache_;
        //The transaction holds the mutex of the container
        std::mutex pending_cache_mutex_;

        std::mutex contract_pending_cache_mutex_;
        // The mutex of _contractInfoCache
        std::shared_mutex _contractInfoCacheMutex;

        std::map<std::string, std::pair<nlohmann::json, uint64_t>> _contractInfoCache;

        std::string _preContractBlockHash;
        std::map<std::string, std::pair<uint64_t, std::set<std::string> >> _dirtyContractMap;
        std::shared_mutex _dirtyContractMapMutex;
        std::atomic<bool> _threadRun = true;

        std::vector<ContractTransactionEntity> _contractCache;

        typedef std::map<uint64_t, std::list<TransactionEntity>>::iterator cacheIter;
        
        // Transaction container
        std::map<uint64_t ,std::list<CTransaction>> _transactionCache;

    public:
        CtransactionCache();
        ~CtransactionCache() = default;
        //Add a cache
        int contract_add_cache(const CTransaction& transaction,const uint64_t& height, const std::vector<std::string> dirtyContract);

        int add_cache(const CTransaction& transaction, const TxMsgReq& SendTxMsg);
        //Start the packaging block building thread 
        bool process();
        //Check for conflicting (overloaded) block pool calls
        bool check_conflict(const CTransaction& transaction, const TxMsgReq& SendTxMsg);

        //bool contract_check_conflict(const CTransaction& transaction, const ContractTempTxMsgReq& SendTxMsg);
        //Get the transaction cache
        void get_cache(std::map<uint64_t, std::list<TransactionEntity>>& cache); 
        //Query the cache for the existence of a transaction
        bool exist_in_cache(const std::string& hash);
        //Delete the pending transaction cache
        bool remove_pending_transaction(const std::string& tx_hash);
        std::string GetAndUpdateContractPreHash(const std::string &contractAddress, const std::string &transactionHash,
                                                std::map<std::string, std::string> &contractPreHashCache);
                                        
        void SetDirtyContractMap(const std::string& transactionHash, const std::set<std::string>& dirtyContract);
        bool GetDirtyContractMap(const std::string& transactionHash, std::set<std::string>& dirtyContract);
        static bool HasContractPackingPermission(const std::string& addr, uint64_t transactionHeight, uint64_t time);

        void ProcessContract(); 

        void removeExpiredEntriesFromDirtyContractMap();                                                                                                                                    

        int GetContractInfoCache(const std::string& transactionHash, nlohmann::json& jTxInfo);
        void ContractBlockNotify(const std::string& blockHash);
        void AddContractInfoCache(const std::string& transactionHash, const nlohmann::json& jTxInfo, const uint64_t& txtime);
    private:
        //Threading functions
        void processing_func();
        void contract_processing_func(); 
        //Generate hash statistics that meet the criteria
        void generate_statistic_info(const TransactionEntity&  tx_entity, std::list<StatisticEntity>& statistic_list);
        //Obtain the pre-hash statistics of the flow node
        std::list<StatisticEntity> get_statistic_info(const std::list<tx_entities_iter>& tx_entities);
        //Filter packaged transactions
        int filter_current_transaction(std::list<StatisticEntity>& static_info, 
                                                            std::list<tx_entities_iter>& tx_entities, 
                                                            std::string& pre_block_hash, 
                                                            bool& build_first);
        //Get the cache that needs to be blocked
        std::list<tx_entities_iter>  get_needed_cache(const std::list<TransactionEntity>& txs);
        //Delete the block building cache and expired cache
        //Return value: Whether there are still transactions at that height
        bool remove_processed_transaction(const  std::list<tx_entities_iter>& tx_entities_iter, const bool build_success, std::list<TransactionEntity>& tx_entities);
        //Check if a transaction is in a cache
        bool find_tx(const std::map<uint64_t, std::list<TransactionEntity>>& cache, const std::string& tx_hash);
        //Clean up functions
        void tear_down(const  std::list<tx_entities_iter>& tx_entities_iters, const bool build_success, std::vector<cache_iter>& empty_height_cache , cache_iter cache_entity);
        /**
         * @brief
         *
         */
        void _ExecuteContracts();

        int _AddContractInfoCache(const CTransaction &transaction,
                                  std::map<std::string, std::string> &contractPreHashCache);
        bool _VerifyDirtyContract(const std::string &transactionHash, const std::vector<std::string> &calledContract);
        int _GetContractTxPreHash(const std::list<CTransaction>& txs, std::list<std::pair<std::string, std::string>>& contractTxPreHashList);
};


int HandleContractPackagerMsg(const std::shared_ptr<ContractPackagerMsg> &msg, const MsgData &msgData);

// int _HandleSeekContractPreHashReq(const std::shared_ptr<newSeekContractPreHashReq> &msg, const MsgData &msgdata);
// int _HandleSeekContractPreHashAck(const std::shared_ptr<newSeekContractPreHashAck> &msg, const MsgData &msgdata);
int _newSeekContractPreHash(const std::list<std::pair<std::string, std::string>> &contractTxPreHashList);
int BuildBlockListForm(const std::list<CTransaction>& txs, const uint64_t& blockHeight, bool build_first);
int CreateBlockList(const std::list<CTransaction>& txs, const uint64_t& blockHeight, CBlock& cblock);
#endif
