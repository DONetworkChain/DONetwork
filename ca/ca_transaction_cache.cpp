#include <unordered_map>

#include "ca_transaction_cache.h"
#include "ca_transaction.h"
#include "utils/json.hpp"
#include "db/db_api.h"

#include "ca/ca_txhelper.h"
#include "utils/MagicSingleton.h"
#include "ca_algorithm.h"
#include "../utils/time_util.h"
#include "ca_tranmonitor.h"
#include "ca_blockhelper.h"
#include "utils/AccountManager.h"
#include "ca_checker.h"
#include "utils/DONbenchmark.h"
#include "common/time_report.h"
#include "utils/console.h"
#include "utils/tmp_log.h"
#include "common/task_pool.h"
#include "mpt/trie.h"
#include "include/ScopeGuard.h"
#include "utils/ContractUtils.h"
#include "ca/ca_DonHost.hpp"
#include "ca/ca_contract.h"
#include "common/global_data.h"
#include "ca/packager_dispatch.h"
const int CtransactionCache::build_interval_ = 3 * 1000;
const time_t CtransactionCache::tx_expire_interval_  = 10;
const int CtransactionCache::build_threshold_ = 1000000;
const double CtransactionCache::decision_threshold_ = 0.8; 

class ContractDataCache;
int CreateBlock(std::vector<TransactionEntity>& txs,const string& preblkhash,CBlock& cblock)
{
	cblock.Clear();

	// Fill version
	cblock.set_version(0);

	// Fill time
	uint64_t time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	cblock.set_time(time);

	// Fill preblockhash
	if(preblkhash.empty())
	{
		ERRORLOG("Preblkhash is empty!");
		return -1;
	}
	cblock.set_prevhash(preblkhash);

	// Fill height
	uint64_t prevBlockHeight = txs.front().get_txmsg().txmsginfo().height();
	uint64_t cblockHeight = ++prevBlockHeight;

	DBReader db_reader;
	uint64_t myTop = 0;
	db_reader.GetBlockTop(myTop);
	if ( (myTop  > global::ca::kUpperBlockHeight) && (myTop - global::ca::kUpperBlockHeight > cblockHeight))
	{
		ERRORLOG("CblockHeight is invalid!");
		return -2;
	}
	else if (myTop + global::ca::kLowerBlockHeight < cblockHeight)
	{
		ERRORLOG("CblockHeight is invalid!");
		return -3;
	}
	cblock.set_height(cblockHeight);

	// Fill tx
	for(auto& tx : txs)
	{
		// Add major transaction
		CTransaction * major_tx = cblock.add_txs();
		*major_tx = tx.get_transaction();

		auto tx_hash = major_tx->hash();
	}

	// Fill merkleroot
	cblock.set_merkleroot(ca_algorithm::CalcBlockMerkle(cblock));
	// Fill hash
	cblock.set_hash(getsha256hash(cblock.SerializeAsString()));

    MagicSingleton<DONbenchmark>::GetInstance()->AddBlockContainsTransactionAmountMap(cblock.hash(), txs.size());


	return 0;
}

int BuildBlock(std::vector<TransactionEntity>& txs,const string& preblkhash, bool build_first)
{
	if(txs.empty() || preblkhash.empty())
	{
		ERRORLOG("Txs or preblkhash is empty!");
		return -1;
	}

	CBlock cblock;
	int ret = CreateBlock(txs, preblkhash,cblock);
	if (cblock.hash().empty())
	{
		ERRORLOG("Create block failed!");
		return ret - 1000;
	}
	
	std::string serBlock = cblock.SerializeAsString();
	std::set<CBlock, compator::BlockTimeAscending> blocks;
	MagicSingleton<BlockHelper>::GetInstance()->GetBroadcastBlock(blocks);
	if(Checker::CheckConflict(cblock, blocks))
	{
		ERRORLOG("Block pool has conflict!");
		return -2;
	}

	ca_algorithm::PrintBlock(cblock);
    auto start_t4 = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    auto end_t4 = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    auto blockTime = cblock.time();
    auto t4 = end_t4 - start_t4;
    auto txSize = txs.size();
    auto BlockHight = cblock.height();
    MagicSingleton<DONbenchmark>::GetInstance()->SetByBlockHash(cblock.hash(), &blockTime, 1 , &t4, &txSize, &BlockHight);

    BlockMsg blockmsg;
    blockmsg.set_version(global::kVersion);
    blockmsg.set_time(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
    blockmsg.set_block(serBlock);


    for(auto &tx : cblock.txs())
    {
        if(GetTransactionType(tx) != kTransactionType_Tx)
        {
            continue;
        }
        uint64_t handleTxHeight =  cblock.height() - 1;
        TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);
        if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
        {
            continue;
        }

        std::pair<std::string,Vrf>  vrf;
        
        CTransaction copyTx = tx;
        copyTx.clear_hash();
        copyTx.clear_verifysign();
        std::string tx_hash = getsha256hash(copyTx.SerializeAsString());
        std::cout<<"buildBlock tx_hash:"<< tx_hash <<std::endl;
        MagicSingleton<DONbenchmark>::GetInstance()->SetTxHashByBlockHash(cblock.hash(), tx_hash);
        if(!MagicSingleton<VRF>::GetInstance()->getVrfInfo(tx_hash, vrf))
        {
            ERRORLOG("getVrfInfo failed!");
            return -3000;
        }
        Vrf *vrfinfo  = blockmsg.add_vrfinfo();
        vrfinfo ->CopyFrom(vrf.second);

    }

    auto msg = make_shared<BlockMsg>(blockmsg);
	ret = DoHandleBlock(msg);
    if(ret != 0)
    {
        ERRORLOG("DoHandleBlock failed The error code is {}",ret);
        return ret -4000;
    }
	return 0;
}

CtransactionCache::CtransactionCache()
{
    build_timer_.AsyncLoop(
        build_interval_, 
        [=](){ blockbuilder_.notify_one(); }
        );
}

int CtransactionCache::contract_add_cache(const CTransaction& transaction,const uint64_t& height, const std::vector<std::string> dirtyContract)
{
    auto txType = (global::ca::TxType)transaction.txtype();
    bool isContractTransaction = txType == global::ca::TxType::kTxTypeCallContract || txType == global::ca::TxType::kTxTypeDeployContract;
    if(isContractTransaction)
    {
        std::unique_lock<std::mutex> locker(_contractCacheMutex);
        if(Checker::CheckConflict(transaction, _contractCache))
        {
            DEBUGLOG("DoubleSpentTransactions, txHash:{}", transaction.hash());
            return -1;
        }
        _contractCache.push_back({transaction, height, false});
    }
    return 0;
}

int CtransactionCache::add_cache(const CTransaction& transaction, const TxMsgReq& sendTxMsg)
{
    std::unique_lock<mutex> locker(cache_mutex_);
    uint64_t height = sendTxMsg.txmsginfo().height() + 1;
    //Check for conflicts and verify
    if(check_conflict(transaction, sendTxMsg) )
    {
        TRACELOG("transaction {} hash conflict, maybe already exist in transaction cache", transaction.hash()); 
        return -1;
    }
    auto find = cache_.find(height); 
    if(find == cache_.end()) 
    {
        cache_[height] = std::list<TransactionEntity>{}; 
    }

    time_t add_time = time(NULL);
    cache_.at(height).push_back(TransactionEntity(transaction, sendTxMsg, add_time)) ;
    for(auto tx_entity: cache_)
    {
        if (tx_entity.second.size() >= build_threshold_)
        {
            blockbuilder_.notify_one();
        }
    }
    return 0;
}


bool CtransactionCache::process()
{
    build_thread_ = std::thread(std::bind(&CtransactionCache::processing_func, this));
    build_thread_.detach();
    // build_thread_contract_ = std::thread(std::bind(&CtransactionCache::contract_processing_func, this));
    // build_thread_contract_.detach();
    return true;
}

bool CtransactionCache::check_conflict(const CTransaction& transaction, const TxMsgReq& SendTxMsg)
{
    std::set<CBlock, compator::BlockTimeAscending> blocks;
    MagicSingleton<BlockHelper>::GetInstance()->GetBroadcastBlock(blocks);
                
    {
        std::lock_guard<mutex> locker(pending_cache_mutex_);
        if (Checker::CheckConflict(transaction, pending_cache_, SendTxMsg.txmsginfo().height() + 1))
        {
            return true;
        }
        
    }
    return Checker::CheckConflict(transaction, cache_, SendTxMsg.txmsginfo().height() + 1) 
                || Checker::CheckConflict(transaction, blocks);
}

// bool CtransactionCache::contract_check_conflict(const CTransaction& transaction, const ContractTempTxMsgReq& SendTxMsg)
// {
//     std::set<CBlock, compator::BlockTimeAscending> blocks;
//     MagicSingleton<BlockHelper>::GetInstance()->GetBroadcastBlock(blocks);
                
//     {
//        std::lock_guard<mutex> locker(contract_pending_cache_mutex_);
//        if (Checker::CheckConflict(transaction, pending_cache_, SendTxMsg.txmsginfo().height() + 1))
//        {
//            return true;
//        }
        
//     }
//    return Checker::CheckConflict(transaction, cache_, SendTxMsg.txmsginfo().height() + 1) 
//                || Checker::CheckConflict(transaction, blocks);
//     return true;
// }

// void CtransactionCache::contract_processing_func(){
//     while (true)
//     {
//         std::unique_lock<mutex> locker(contract_cache_mutex_);
//         blockbuilder_.wait(locker);
        
//         std::vector<cache_iter> empty_height_cache;
//         for(auto cache_entity = cache_.begin(); cache_entity != cache_.end(); ++cache_entity)
//         {
//             if(cache_entity == cache_.end())
//             {
//                 break;
//             }
//             std::list<tx_entities_iter> build_txs = get_needed_cache(cache_entity->second);
//             std::list<StatisticEntity> statistic_info = get_statistic_info(build_txs);
//             std::string pre_block_hash; 
//             bool build_first;
//             int res = filter_current_transaction(statistic_info, build_txs, pre_block_hash, build_first);
//             if(res != 0) 
//             {
//                 TRACELOG("{} build tx fail,no transaction match filter rule", res);
//                 tear_down(build_txs, false, empty_height_cache, cache_entity);
//                 continue;
//             }
//             std::vector<TransactionEntity> build_caches;
//             for(auto iter : build_txs)
//             {
//                 build_caches.push_back(*iter);
//             }
//             res = BuildBlock(build_caches, pre_block_hash, false);
//             if(res != 0)
//             {
//                 ERRORLOG("{} build block fail", res);
//                 tear_down(build_txs, false, empty_height_cache, cache_entity);
//                 continue;
//             }
//             std::lock_guard<mutex> locker(contract_pending_cache_mutex_);
//             auto find = pending_cache_.find(cache_entity->first); 
//             if(find == pending_cache_.end()) 
//             {
//                 pending_cache_[cache_entity->first] = std::list<TransactionEntity>{}; 
//             }
//             for(auto tx_iter : build_txs)
//             {
//                 pending_cache_[cache_entity->first].push_back(*tx_iter);
//             }
//             tear_down(build_txs, true, empty_height_cache, cache_entity);
//         }
//         for(auto cache: empty_height_cache)
//         {
//             cache_.erase(cache);
//         }
//         locker.unlock();
//     }
// }

void CtransactionCache::processing_func()
{
    while (true)
    {
        std::unique_lock<mutex> locker(cache_mutex_);
        blockbuilder_.wait(locker);
        
        std::vector<cache_iter> empty_height_cache;
        for(auto cache_entity = cache_.begin(); cache_entity != cache_.end(); ++cache_entity)
        {
            if(cache_entity == cache_.end())
            {
                break;
            }
            std::list<tx_entities_iter> build_txs = get_needed_cache(cache_entity->second);
            std::list<StatisticEntity> statistic_info = get_statistic_info(build_txs);
            std::string pre_block_hash; 
            bool build_first;
            int res = filter_current_transaction(statistic_info, build_txs, pre_block_hash, build_first);
            if(res != 0) 
            {
                TRACELOG("{} build tx fail,no transaction match filter rule", res);
                tear_down(build_txs, false, empty_height_cache, cache_entity);
                continue;
            }
            std::vector<TransactionEntity> build_caches;
            for(auto iter : build_txs)
            {
                build_caches.push_back(*iter);
            }
            res = BuildBlock(build_caches, pre_block_hash, false);
            if(res != 0)
            {
                ERRORLOG("{} build block fail", res);
                tear_down(build_txs, false, empty_height_cache, cache_entity);
                continue;
            }
            std::lock_guard<mutex> locker(pending_cache_mutex_);
            auto find = pending_cache_.find(cache_entity->first); 
            if(find == pending_cache_.end()) 
            {
                pending_cache_[cache_entity->first] = std::list<TransactionEntity>{}; 
            }
            for(auto tx_iter : build_txs)
            {
                pending_cache_[cache_entity->first].push_back(*tx_iter);
            }
            tear_down(build_txs, true, empty_height_cache, cache_entity);
        }
        for(auto cache: empty_height_cache)
        {
            cache_.erase(cache);
        }
        locker.unlock();
    }
}

void CtransactionCache::generate_statistic_info(const TransactionEntity& tx_entity, std::list<StatisticEntity>& statistic_list)
{
    std::unordered_map<std::string, int> hash_count;
    
    auto pre_hashes =  tx_entity.get_txmsg().prevblkhashs();//Get the pre-hash array from tx_entity get txmsg
    for(const auto& hash : pre_hashes)
    {
        auto find = hash_count.find(hash);
        if(find == hash_count.end())
        {
            hash_count[hash] = 0;
        }
        hash_count.at(hash) += 1;
    }
    
    uint32_t sign_count =  tx_entity.get_transaction().consensus() - 1;
    for(const auto& item : hash_count)
    {
        double percentage = item.second / sign_count; //Counts the percentage of signers who own the hash of the preceding block
        if(percentage >= decision_threshold_)
        {
            auto pre_hash = item.first;
            auto tx_hash = tx_entity.get_transaction().hash();
            auto find_result = find_if(statistic_list.begin(), statistic_list.end(), 
                                        [&pre_hash](const StatisticEntity& statistic_info)
                                        {
                                            return pre_hash == statistic_info.pre_block_hash_;
                                        } 
                                    );
            if(find_result == statistic_list.end())
            {
                statistic_list.push_back({pre_hash, {tx_hash}, 1});
            }
            else
            {
                find_result->transaction_hashes_.push_back(tx_hash);
                if(percentage < find_result->percentage_)
                {
                    find_result->percentage_ = percentage;
                } 
            }          
        }
    }
}

std::list<CtransactionCache::StatisticEntity> CtransactionCache::get_statistic_info(const std::list<tx_entities_iter>& tx_entities)
{
    std::list<StatisticEntity> statistic_info;
    for(const auto tx_entity : tx_entities)
    {
        generate_statistic_info(*tx_entity, statistic_info);
    }
    return statistic_info;
}

int CtransactionCache::filter_current_transaction(std::list<StatisticEntity>& statistic_info, 
                                                    std::list<tx_entities_iter>& tx_entities,  
                                                    std::string& pre_block_hash, 
                                                    bool& build_first  /*Do you want to build a block first*/)
{
    if(statistic_info.empty())
    {
        ERRORLOG("There are no eligible transactions");
        return -1;
    }

    //Gets the block hash locally at that height
    auto height = tx_entities.front()->get_txmsg().txmsginfo().height();
    std::vector<std::string> local_block_hashes;
    DBReader db_reader;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(height, local_block_hashes))
    {
        ERRORLOG("fail to get block hashes at height {}", height);
        return -2;
    }
    statistic_info.sort([](const StatisticEntity& e1, const StatisticEntity& e2) {return e1.pre_block_hash_ < e2.pre_block_hash_;});
    sort(local_block_hashes.begin(), local_block_hashes.end(), [](const std::string& e1, const std::string& e2){return e1 < e2;});

    //Get the pre-block hash that is present in StatisticEntity and locally available
    std::vector<StatisticEntity> intersect_hash;
    std::set_intersection(statistic_info.begin(), statistic_info.end()
                                        , local_block_hashes.begin(), local_block_hashes.end()
                                        ,back_inserter(intersect_hash), hash_comparator()
                                     );
    if(intersect_hash.empty())
    {
        
        ERRORLOG("There are no eligible transactions");
        return -3;
    }
    auto end = statistic_info.end();
    auto statistic_compator = [](decltype(statistic_info.begin()) iter)
    {
        return [iter](const StatisticEntity& statistic_info){ return iter->pre_block_hash_ == statistic_info.pre_block_hash_;}; 
    };

    statistic_info.sort([](const StatisticEntity& e1, const StatisticEntity& e2) {return e1.percentage_ > e2.percentage_;}); //Sort statistics for easy filtering 
    for(auto iter = statistic_info.begin(); iter != end; ++iter)
    {
        auto statistic_entity_percentage = iter->percentage_;
        if(statistic_entity_percentage == 1 
            && find_if(intersect_hash.begin(), intersect_hash.end(), statistic_compator(iter)) != intersect_hash.end()
            )
            //There are 100% of the cases in the local and StatisticEntity
        {
            build_first = true;
            pre_block_hash = iter->pre_block_hash_;
            return 0;
        }

        if(decision_threshold_ <= statistic_entity_percentage < (decision_threshold_ + 0.1)
            && find_if(intersect_hash.begin(), intersect_hash.end(), statistic_compator(iter)) == intersect_hash.end()
            )
            //There are no local cases but there are conditions in the StatisticEntity and the proportion is between the threshold and the threshold plus 10%.
        {
            statistic_info.erase(iter);
        }
    }

    if(statistic_info.empty())
    //If the cached value is not locally available but is present in the StatisticEntity and the proportion reaches between the threshold and the threshold plus 10%, the packaging fails
    {
        ERRORLOG("There are no eligible transactions");
        return -4;
    }
    
    build_first = false;
    auto first_statstic = statistic_info.begin();//Get the hash of the first statistic (with the highest percentage).
    pre_block_hash = first_statstic->pre_block_hash_;

    std::vector<std::string> tx_hashes = first_statstic->transaction_hashes_;
    for(auto iter = tx_entities.begin(); iter != tx_entities.end(); ++iter)
    {
        if(std::find(tx_hashes.begin(), tx_hashes.end(), (*iter)->get_transaction().hash()) == tx_hashes.end())
        {
            tx_entities.erase(iter);
        }
    }
    return 0;
}

std::list<CtransactionCache::tx_entities_iter> CtransactionCache::get_needed_cache(const std::list<TransactionEntity>& txs)
{
    std::list<tx_entities_iter> build_caches;

    if(txs.empty())
    {
        return build_caches;
    }

    tx_entities_iter iter = txs.begin();
    tx_entities_iter end = txs.end();
    for(int i = 0; i < build_threshold_ && iter != end; ++i, ++iter) 
    {
        build_caches.push_back(iter);
    }        
    return build_caches;
}

bool CtransactionCache::remove_processed_transaction(const  std::list<tx_entities_iter>& tx_entities_iter, const bool build_success, std::list<TransactionEntity>& tx_entities)
{
    //Delete successful or failed transactions for block building
    for(auto iter : tx_entities_iter)
    {
        std::string hash = iter->get_transaction().hash();
        tx_entities.erase(iter);
        std::string message;
        if(build_success)
        {
            message = " successfully packaged";
        }
        else
        {
            message = " packaging fail";
        }
        std::cout << "transaction " << hash << message << std::endl;
    }
    
    //Check for expired transactions
    for(auto tx_entity = tx_entities.begin(); tx_entity != tx_entities.end(); ++tx_entity)
    {
        time_t current_time = time(NULL);
        if((current_time - tx_entity->get_timestamp()) > tx_expire_interval_)
        {
            TRACELOG("transaction {} has expired", tx_entity->get_transaction().hash());
            std::cout << "transaction expired: " << tx_entity->get_transaction().hash() << std::endl;
        }
    }

    if(tx_entities.empty())
    {
        return false;
    }            
    return true;
}

bool CtransactionCache::remove_pending_transaction(const std::string& tx_hash)
{
    std::lock_guard<mutex> locker(pending_cache_mutex_);
    auto end = pending_cache_.end();
    for(auto pending_item = pending_cache_.begin();  pending_item != end; ++pending_item)
    {
        auto& cache_list = pending_item->second;
        auto end = cache_list.end();
        auto result = find_if(cache_list.begin(), end, 
                            [&tx_hash](const TransactionEntity& tx_entity)
                            {
                                return tx_entity.get_transaction().hash() == tx_hash;
                            });
        if(result != end)
        {
            cache_list.erase(result);
            if(cache_list.empty())
            {
                pending_cache_.erase(pending_item);
            }
            TRACELOG("success remove transaction cache {}", tx_hash);
            return true;             
        }
    }

    TRACELOG("fail to remove transaction cache {}，not exist or already been removed", tx_hash);
    return false;
}

void CtransactionCache::get_cache(std::map<uint64_t, std::list<TransactionEntity>>& cache)
{
    cache = cache_;
}

bool CtransactionCache::exist_in_cache(const std::string& hash)
{
    std::unique_lock<mutex> cache_locker(cache_mutex_);
    
    if(find_tx(cache_, hash))
    {
        return true;
    } 
    cache_locker.unlock();

    std::unique_lock<mutex> pending_cache_locker(pending_cache_mutex_);
    
    if(find_tx(pending_cache_, hash))
    {
        return true;
    } 
    pending_cache_locker.unlock();

    return false;
}

bool CtransactionCache::find_tx(const std::map<uint64_t, std::list<TransactionEntity>>& cache, const std::string& tx_hash)
{
    if(cache.empty())
    {
        return false;
    }
    for(auto item = cache.begin();  item != cache.end(); ++item)
    {
        auto cache_list = item->second;
        auto end = cache_list.end();
        auto result = find_if(cache_list.begin(), end, 
                            [&tx_hash](const TransactionEntity& tx_entity)
                            {
                                return tx_entity.get_transaction().hash() == tx_hash;
                            });
        if(result != end)
        {
            return true;             
        }
    }
    return false;
}
        
void CtransactionCache::tear_down(const  std::list<tx_entities_iter>& tx_entities_iters, const bool build_success, std::vector<cache_iter>& empty_height_cache , cache_iter cache_entity)
{
    if(!remove_processed_transaction(tx_entities_iters, build_success, cache_entity->second))
    {
        empty_height_cache.push_back(cache_entity);         
    }
}
std::string
CtransactionCache::GetAndUpdateContractPreHash(const std::string &contractAddress, const std::string &transactionHash,
                                              std::map<std::string, std::string> &contractPreHashCache)
{
    std::string strPrevTxHash;
    auto found = contractPreHashCache.find(contractAddress);
    if (found == contractPreHashCache.end())
    {
        DBReader dbReader;
        if (dbReader.GetLatestUtxoByContractAddr(contractAddress, strPrevTxHash) != DBStatus::DB_SUCCESS)
        {
            ERRORLOG("GetLatestUtxo of ContractAddr {} fail", contractAddress);
            return "";
        }
        if (strPrevTxHash.empty())
        {
            return "";
        }
    }
    else
    {
        strPrevTxHash = found->second;
    }
    contractPreHashCache[contractAddress] = transactionHash;

    return strPrevTxHash;
}

int HandleContractPackagerMsg(const std::shared_ptr<ContractPackagerMsg> &msg, const MsgData &msgData)
{
    //signature verification
    auto cSign = msg->sign();
    auto pub = cSign.pub();
    auto signature = cSign.sign();
    Account account;
    ContractPackagerMsg cp_msg = *msg;
    cp_msg.clear_sign();
	std::string message = getsha256hash(cp_msg.SerializeAsString());
    EVP_PKEY* eckey = nullptr;
    if(GetEDPubKeyByBytes(pub, eckey) == false){
        EVP_PKEY_free(eckey);
        ERRORLOG(RED " HandleContractPackagerMsg Get public key from bytes failed!" RESET);
        return -1;
    }
    if(ED25519VerifyMessage(message, eckey, signature) == false)
    {
        EVP_PKEY_free(eckey);
        ERRORLOG(RED "HandleBuildBlockBroadcastMsg Public key verify sign failed!" RESET);
        return -2;
    }
    //vrf verification
    NewVrf vrfInfo = msg->vrfinfo();
    std::string hash;
    int range;
    uint64_t verifyHeight;

    const VrfData& vrfData = vrfInfo.vrfdata();
	hash = vrfData.hash();
	range = vrfData.range();
    verifyHeight = vrfData.height();


	EVP_PKEY *pkey = nullptr;
	if (!GetEDPubKeyByBytes(vrfInfo.vrfsign().pub(), pkey))
	{
		ERRORLOG(RED "HandleBuildBlockBroadcastMsg Get public key from bytes failed!" RESET);
		return -4;
	}

    std::string contractHash;
    for (const ContractTempTxMsgReq& txMsg : msg->txmsgreq())
    {
        const TxMsgInfo& txMsgInfo = txMsg.txmsginfo();
        CTransaction transaction;
        if (!transaction.ParseFromString(txMsgInfo.tx()))
        {
            ERRORLOG("Failed to deserialize transaction body!");
            continue;
        }
        contractHash += transaction.hash();
    }
    std::string input = getsha256hash(contractHash);
    DEBUGLOG("HandleContractPackagerMsg input : {} , hash : {}", input,hash);
	std::string result = hash;
	std::string proof = vrfInfo.vrfsign().sign();
    DEBUGLOG("proof {}",proof);
	if (MagicSingleton<VRF>::GetInstance()->VerifyVRF(pkey, input, result, proof) != 0)
	{
		ERRORLOG(RED "HandleBuildBlockBroadcastMsg Verify VRF Info fail" RESET);
		return -5;
	}
    DEBUGLOG("HandleContractPackagerMsg 1");
    std::vector<Node> _vrfNodelist;
    for(auto & item : msg->vrfdatasource().vrfnodelist())
    {
        Node x;
        x.base58address = item;
        _vrfNodelist.push_back(x);
    }
    DEBUGLOG("HandleContractPackagerMsg 2");
    auto ret = verifyVrfDataSource(_vrfNodelist,verifyHeight);
    if(ret != 0)
    {
        ERRORLOG("verifyVrfDataSource fail ! ,ret:{}", ret);
        return -6;
    }
    DEBUGLOG("HandleContractPackagerMsg 3");
	
    Node node;
	if (!MagicSingleton<PeerNode>::GetInstance()->find_node_by_fd(msgData.fd, node))
	{
        ERRORLOG("find node error");
		return -7;
	}   
    DEBUGLOG("HandleContractPackagerMsg 4");

    double randNum = MagicSingleton<VRF>::GetInstance()->GetRandNum(result);
    std::string defaultAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    ret = VerifyContractPackNode(node.base58address, randNum, defaultAddr,_vrfNodelist);
    DEBUGLOG("HandleContractPackagerMsg 5");
    if(ret != 0)
    {
        ERRORLOG("VerifyContractPackNode ret  {}", ret);
        return -8;
    }

    for (const ContractTempTxMsgReq& txMsg : msg->txmsgreq())
    {
        const TxMsgInfo& txMsgInfo = txMsg.txmsginfo();
        CTransaction transaction;
        if (!transaction.ParseFromString(txMsgInfo.tx()))
        {
            ERRORLOG("Failed to deserialize transaction body!");
            continue;
        }
        
        //The packer collates the dependencies of the transactions received
        std::vector<std::string> dependentAddress(txMsgInfo.contractstoragelist().begin(), txMsgInfo.contractstoragelist().end());
        MagicSingleton<packDispatch>::GetInstance()->Add(transaction.hash(),dependentAddress);
	    MagicSingleton<packDispatch>::GetInstance()->AddTx(transaction.hash(),transaction);
    }


    std::map<std::string, std::future<int>> taskResults;
    for (const ContractTempTxMsgReq& txMsg : msg->txmsgreq())
    {
        const TxMsgInfo& txMsgInfo = txMsg.txmsginfo();
        CTransaction transaction;
        if (!transaction.ParseFromString(txMsgInfo.tx()))
        {
            ERRORLOG("Failed to deserialize transaction body!");
            continue;
        }
        auto task = std::make_shared<std::packaged_task<int()>>(
                [txMsg, txMsgInfo, transaction] {
                    std::string dispatcherAddr = transaction.identity();
                    if(!CtransactionCache::HasContractPackingPermission(dispatcherAddr, txMsgInfo.height(), transaction.time()))
                    {
                        ERRORLOG("HasContractPackingPermission fail!!!, txHash:{}", transaction.hash().substr(0,6));
                        return -1;
                    }

                    MagicSingleton<CtransactionCache>::GetInstance()->SetDirtyContractMap(transaction.hash(), {txMsgInfo.contractstoragelist().begin(), txMsgInfo.contractstoragelist().end()});



                    int ret = DoHandleContractTx(std::make_shared<ContractTempTxMsgReq>(txMsg), *std::make_unique<CTransaction>());
                    if (ret != 0)
                    {
                        ERRORLOG("DoHandleTx fail ret: {}, tx hash : {}", ret, transaction.hash());
                        return ret;
                    }
                    DEBUGLOG("finishi contract");
                    return 0;
                });
        try
        {
            taskResults[transaction.hash()] = task->get_future();
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
        }
        MagicSingleton<taskPool>::GetInstance()->commit_work_task([task](){(*task)();});
    }
    for (auto& res : taskResults)
    {
        res.second.get();
    }
    MagicSingleton<CtransactionCache>::GetInstance()->ProcessContract();
    return 0;
}

void CtransactionCache::SetDirtyContractMap(const std::string& transactionHash, const std::set<std::string>& dirtyContract)
{
    std::unique_lock locker(_dirtyContractMapMutex);
    uint64_t currentTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    _dirtyContractMap[transactionHash]= {currentTime, dirtyContract};

}

bool CtransactionCache::GetDirtyContractMap(const std::string& transactionHash, std::set<std::string>& dirtyContract)
{
    auto found = _dirtyContractMap.find(transactionHash);
    if(found != _dirtyContractMap.end())
    {
        dirtyContract = found->second.second;
        return true;
    }
    
    return false;
}
bool CtransactionCache::HasContractPackingPermission(const std::string& addr, uint64_t transactionHeight, uint64_t time)
{
    std::string packingAddr;
    if (CalculateThePackerByTime(time, transactionHeight, packingAddr, *std::make_unique<std::string>(), *std::make_unique<std::string>()) != 0)
    {
        return false;
    }
    DEBUGLOG("time: {}, height: {}, packer {}", time, transactionHeight, packingAddr);
    return packingAddr == addr;
}

void CtransactionCache::ProcessContract()
{
    DEBUGLOG("ProcessContract ++++++++ ");
    std::scoped_lock locker(_contractCacheMutex, _contractInfoCacheMutex, _dirtyContractMapMutex);
    MagicSingleton<ContractDataCache>::GetInstance()->lock();
    ON_SCOPE_EXIT{
        MagicSingleton<ContractDataCache>::GetInstance()->clear();
        MagicSingleton<ContractDataCache>::GetInstance()->unlock();
    };
    _ExecuteContracts();
    std::list<CTransaction> buildTxs;
    uint64_t topTransactionHeight = 0;
    for(const auto& txEntity : _contractCache)
    {
        buildTxs.push_back(txEntity.GetTransaction());
        if (txEntity.GetHeight() > topTransactionHeight)
        {
            topTransactionHeight = txEntity.GetHeight();
        }
    }
    DBReader dbReader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(top))
    {
        ERRORLOG("GetBlockTop error!");
        std::cout << "block packaging fail" << std::endl;
        return;
    }
    if (top > topTransactionHeight)
    {
        MagicSingleton<BlockStroage>::GetInstance()->CommitSeekTask(top);
        topTransactionHeight = top;
        DEBUGLOG("top:{} > topTransactionHeight:{}", top, topTransactionHeight);
    }
    if (buildTxs.empty())
    {
        DEBUGLOG("buildTxs.empty()");
        return;
    }

    ON_SCOPE_EXIT{
        removeExpiredEntriesFromDirtyContractMap();
        _contractCache.clear();
        _contractInfoCache.clear();
    };

    std::list<std::pair<std::string, std::string>> contractTxPreHashList;
    if(_GetContractTxPreHash(buildTxs,contractTxPreHashList) != 0)
    {
        ERRORLOG("_GetContractTxPreHash fail");
        return;
    }
    if(contractTxPreHashList.empty())
    {
        DEBUGLOG("contractTxPreHashList empty");
    }
    // else
    // {
    //     auto ret = _newSeekContractPreHash(contractTxPreHashList);
    //     if ( ret != 0)
    //     {
    //         ERRORLOG("{} _newSeekContractPreHash fail", ret);
    //         return;
    //     }
    // }

    auto ret = BuildBlockListForm(buildTxs, topTransactionHeight + 1, false);
    if(ret != 0)
    {
        ERRORLOG("{} build block fail", ret);
        std::cout << "block packaging fail" << std::endl;
    }
    else
    {
        std::cout << "block successfully packaged" << std::endl;
    }
    DEBUGLOG("FFF 555555555");
    return;
}

void CtransactionCache::_ExecuteContracts()
{
    uint64_t StartTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    DEBUGLOG("FFF _ExecuteContracts StartTime:{}", StartTime);
    std::map<std::string, std::string> contractPreHashCache;
    for (auto iter = _contractCache.begin(); iter != _contractCache.end();)
    {
        const auto& transaction = iter->GetTransaction();
        auto txType = (global::ca::TxType)transaction.txtype();
        if ( (txType != global::ca::TxType::kTxTypeCallContract && txType != global::ca::TxType::kTxTypeDeployContract)
            || _AddContractInfoCache(transaction, contractPreHashCache) != 0)
        {
            iter = _contractCache.erase(iter);
            continue;
        }
        DEBUGLOG("FFF _ExecuteContracts txHash:{}", transaction.hash().substr(0,6));
        ++iter;
    }
    uint64_t EndTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    DEBUGLOG("FFF _ExecuteContracts EndTime:{}", EndTime);
}

int CtransactionCache::_AddContractInfoCache(const CTransaction &transaction,
                                            std::map<std::string, std::string> &contractPreHashCache)
{
    auto txType = (global::ca::TxType)transaction.txtype();
    if (txType != global::ca::TxType::kTxTypeCallContract && txType != global::ca::TxType::kTxTypeDeployContract)
    {
        return 0;
    }

    bool isMultiSign = IsMultiSign(transaction);
    std::string fromAddr;
    int ret = ca_algorithm::GetCallContractFromAddr(transaction, isMultiSign, fromAddr);
    if (ret != 0)
    {
        ERRORLOG("GetCallContractFromAddr fail ret: {}", ret);
        return -1;
    }

    std::string OwnerEvmAddr;
    global::ca::VmType vmType;

    std::string code;

    std::string input;
    std::string deployerAddr;
    std::string deployHash;
    std::string destAddr;
    std::string contractFunName;
    uint64_t contractTransfer;
    try
    {
        nlohmann::json dataJson = nlohmann::json::parse(transaction.data());
        nlohmann::json txInfo = dataJson["TxInfo"].get<nlohmann::json>();

        if(txInfo.find("OwnerEvmAddr") != txInfo.end())
        {
            OwnerEvmAddr = txInfo["OwnerEvmAddr"].get<std::string>();
        }
        vmType = txInfo["VmType"].get<global::ca::VmType>();

        if (txType == global::ca::TxType::kTxTypeCallContract)
        {
            deployerAddr = txInfo["DeployerAddr"].get<std::string>();
            deployHash = txInfo["DeployHash"].get<std::string>();
            input = txInfo["Input"].get<std::string>();
            
            // if(vmType == global::ca::VmType::WASM)
            // {
            //     contractFunName = txInfo["contractFunName"].get<std::string>();
            // }
            //else
            if(vmType == global::ca::VmType::EVM)
            {
                contractTransfer = txInfo["contractTransfer"].get<uint64_t>();
            }
        }
        else if (txType == global::ca::TxType::kTxTypeDeployContract)
        {
            code = txInfo["Code"].get<std::string>();
        }

    }
    catch (...)
    {
        ERRORLOG("json parse fail");
        return -2;
    }
              
    int64_t gasCost = 0;
    nlohmann::json jTxInfo;
    std::string expectedOutput;
    std::vector<std::string> calledContract;
    if(vmType == global::ca::VmType::EVM)
    {
        destAddr = evm_utils::EvmAddrToBase58(OwnerEvmAddr);
        if(destAddr != fromAddr)
        {
            ERRORLOG("fromAddr {}  is not equal to detAddr {} ", fromAddr, destAddr);
            return -3;
        }
        DonHost host;
        if(txType == global::ca::TxType::kTxTypeDeployContract)
        {
            ret = Evmone::DeployContract(fromAddr, OwnerEvmAddr, code, expectedOutput,
                                        host, gasCost);
            if(ret != 0)
            {
                ERRORLOG("VM failed to deploy contract!, ret {}", ret);
                return ret - 100;
            }
        }
        else if(txType == global::ca::TxType::kTxTypeCallContract)
        {
            ret = Evmone::CallContract(fromAddr, OwnerEvmAddr, deployerAddr, deployHash, input, expectedOutput, host,
                                    gasCost, contractTransfer);
            if(ret != 0)
            {
                ERRORLOG("VM failed to call contract!, ret {}", ret);
                return ret - 200;
            }
        }

        ret = Evmone::ContractInfoAdd(host, transaction.hash(), txType, transaction.version(), jTxInfo,
                                    contractPreHashCache);
        if(ret != 0)
        {
            ERRORLOG("ContractInfoAdd fail ret: {}", ret);
            return -4;
        }

        Evmone::GetCalledContract(host, calledContract);
    }
    // else if(vmType == global::ca::VmType::WASM)
    // {
    //     destAddr = transaction.utxo().owner(0);
    //     if(destAddr != fromAddr)
    //     {
    //         ERRORLOG("fromAddr {}  is not equal to detAddr {} ", fromAddr, destAddr);
    //         return -5;
    //     }
    //     if(txType == global::ca::TxType::kTxTypeDeployContract)
    //     {
    //         std::string hexCode = Hex2Str(code);
    //         ret = Wasmtime::DeployWasmContract(fromAddr, hexCode, expectedOutput, gasCost);
    //         if(ret != 0)
    //         {
    //             ERRORLOG("WASM failed to deploy contract!");
    //             return ret - 300;
    //         }
    //     }
    //     else if(txType == global::ca::TxType::kTxTypeCallContract)
    //     {
    //         ret = Wasmtime::CallWasmContract(fromAddr, deployerAddr, deployHash, input, contractFunName, expectedOutput, gasCost);
    //         if(ret != 0)
    //         {
    //             ERRORLOG("WASM failed to call contract!");
    //             return ret - 400;
    //         }
    //     }
    //     ret = Wasmtime::ContractInfoAdd(transaction.hash(), jTxInfo, txType, transaction.version(), contractPreHashCache);
    //     if(ret != 0)
    //     {
    //         ERRORLOG("Wasmtime ContractInfoAdd fail! ret {}", ret);
    //         return -6;
    //     }
    //     Wasmtime::GetCalledContract(calledContract);
    // }

    if (!_VerifyDirtyContract(transaction.hash(), calledContract))
    {
        ERRORLOG("_VerifyDirtyContract fail");
        return -7;
    }
    jTxInfo["Output"] = expectedOutput;
    MagicSingleton<ContractDataCache>::GetInstance()->set(jTxInfo["Storage"]);
    _contractInfoCache[transaction.hash()] = {jTxInfo, transaction.time()};
    return 0;
}

bool CtransactionCache::_VerifyDirtyContract(const std::string &transactionHash, const std::vector<std::string> &calledContract)
{
    auto found = _dirtyContractMap.find(transactionHash);
    if (found == _dirtyContractMap.end())
    {
        ERRORLOG("dirty contract not found hash: {}", transactionHash);
        return false;
    }
    std::set<std::string> calledContractSet(calledContract.begin(), calledContract.end());
    std::vector<std::string> result;
    std::set_difference(calledContractSet.begin(), calledContractSet.end(),
                        found->second.second.begin(), found->second.second.end(),
                        std::back_inserter(result));
    if (!result.empty())
    {
        for (const auto& addr : calledContract)
        {
            ERRORLOG("executed {}", addr);
        }
        for (const auto& addr : found->second.second)
        {
            ERRORLOG("found {}", addr);
        }
        for (const auto& addr : result)
        {
            ERRORLOG("result {}", addr);
        }
        ERRORLOG("dirty contract doesn't match execute result, tx hash: {}", transactionHash);
        return false;
    }
    return true;
}

// int _newSeekContractPreHash(const std::list<std::pair<std::string, std::string>> &contractTxPreHashList)
// {
//     DEBUGLOG("_newSeekContractPreHash.............");
//     uint64_t chainHeight;
//     if(!MagicSingleton<BlockHelper>::GetInstance()->ObtainChainHeight(chainHeight))
//     {
//         DEBUGLOG("ObtainChainHeight fail!!!");
//     }
//     uint64_t selfNodeHeight = 0;
//     std::vector<std::string> pledgeAddr;
//     {
//         DBReader dbReader;
//         auto status = dbReader.GetBlockTop(selfNodeHeight);
//         if (DBStatus::DB_SUCCESS != status)
//         {
//             DEBUGLOG("GetBlockTop fail!!!");

//         }
//         std::vector<std::string> stakeAddr;
//         status = dbReader.GetStakeAddress(stakeAddr);
//         if (DBStatus::DB_SUCCESS != status && DBStatus::DB_NOT_FOUND != status)
//         {
//             DEBUGLOG("GetStakeAddress fail!!!");
//         }

//         for(const auto& addr : stakeAddr)
//         {
//             if(VerifyBonusAddr(addr) != 0)
//             {
//                 DEBUGLOG("{} doesn't get invested, skip", addr);
//                 continue;
//             }
//             pledgeAddr.push_back(addr);
//         }
//     }
//     std::vector<std::string> sendNodeIds;
//     if (GetPrehashFindNode(pledgeAddr.size(), chainHeight, pledgeAddr, sendNodeIds) != 0)
//     {
//         ERRORLOG("get sync node fail");
//     }

//     if(sendNodeIds.size() == 0)
//     {
//         DEBUGLOG("sendNodeIds {}",sendNodeIds.size());
//         return -2;
//     }

//     //send_size
//     std::string msgId;
//     if (!GLOBALDATAMGRPTR.CreateWait(3, sendNodeIds.size() * 0.8, msgId))
//     {
//         return -3;
//     }

//     newSeekContractPreHashReq req;
//     req.set_version(global::kVersion);
//     req.set_msg_id(msgId);

//     for(auto &item : contractTxPreHashList)
//     {
//         preHashPair * _hashPair = req.add_seekroothash();
//         _hashPair->set_contractaddr(item.first);
//         _hashPair->set_roothash(item.second);
//         DEBUGLOG("req contractAddr:{}, contractTxHash:{}", item.first, item.second);
//     }
    
//     for (auto &nodeBase58 : sendNodeIds)
//     {
//         if(!GLOBALDATAMGRPTR.AddResNode(msgId, nodeBase58))
//         {
//             return -4;
//         }
//         net_send_message<newSeekContractPreHashReq>(nodeBase58, req, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
//     }

//     std::vector<std::string> ret_datas;
//     if (!GLOBALDATAMGRPTR.WaitData(msgId, ret_datas))
//     {
//         return -5;
//     }

//     newSeekContractPreHashAck ack;
//     std::map<std::string, std::set<std::string>> blockHashMap;
//     std::map<std::string, std::pair<std::string, std::string>> testMap;
//     for (auto &ret_data : ret_datas)
//     {
//         ack.Clear();
//         if (!ack.ParseFromString(ret_data))
//         {
//             continue;
//         }
//         for(auto& iter : ack.seekcontractblock())
//         {
//             blockHashMap[ack.self_node_id()].insert(iter.blockraw());
//             testMap[iter.blockraw()] = {iter.contractaddr(), iter.roothash()};
//         }
//     }

//     std::unordered_map<std::string , int> countMap;
//     for (auto& iter : blockHashMap) 
//     {
//         for(auto& iter_second : iter.second)
//         {
//             countMap[iter_second]++;
//         }
        
//     }

//     DBReader dbReader;
//     std::vector<std::pair<CBlock,std::string>> seekBlocks;
//     for (const auto& iter : countMap) 
//     {
//         double rate = double(iter.second) / double(blockHashMap.size());
//         auto test_iter = testMap[iter.first];
//         if(rate < 0.66)
//         {
//             ERRORLOG("rate:({}) < 0.66, contractAddr:{}, contractTxHash:{}", rate, test_iter.first, test_iter.second);
//             continue;
//         }

//         CBlock block;
//         if(!block.ParseFromString(iter.first))
//         {
//             continue;
//         }
//         std::string blockStr;
//         if(dbReader.GetBlockByBlockHash(block.hash(), blockStr) != DBStatus::DB_SUCCESS)
//         {
//             seekBlocks.push_back({block, block.hash()});
//             DEBUGLOG("rate:({}) < 0.66, contractAddr:{}, contractTxHash:{}, blockHash:{}", rate, test_iter.first, test_iter.second, block.hash());
//             MagicSingleton<BlockHelper>::GetInstance()->AddSeekBlock(seekBlocks);
//         }
//     }

//     uint64_t timeOut = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp() + 2 * 1000000;
//     uint64_t currentTime;
//     bool flag;
//     do
//     {
//         flag = true;
//         for(auto& it : seekBlocks)
//         {
//             std::string blockRaw;
//             if(dbReader.GetBlockByBlockHash(it.second, blockRaw) != DBStatus::DB_SUCCESS)
//             {
//                 flag = false;
//                 break;
//             }
//         }
//         if(flag)
//         {
//             DEBUGLOG("find block successfuly ");
//             return 0;
//         }
//         sleep(1);
//         currentTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
//     }while(currentTime < timeOut && !flag);
//     return -6;
// }

void CtransactionCache::removeExpiredEntriesFromDirtyContractMap()
{
    uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    for(auto iter = _dirtyContractMap.begin(); iter != _dirtyContractMap.end();)
    {
        if(nowTime >= iter->second.first + 60 * 1000000ull)
        {
            _dirtyContractMap.erase(iter++);
        }
        else
        {
            ++iter;
        }
    }
}

int CtransactionCache::_GetContractTxPreHash(const std::list<CTransaction>& txs, std::list<std::pair<std::string, std::string>>& contractTxPreHashList)
{
    std::map<std::string, std::vector<std::pair<std::string, std::string>>> contractTxPreHashMap;
    for(auto& tx : txs)
	{
        if (global::ca::TxType::kTxTypeDeployContract == (global::ca::TxType)tx.txtype())
        {
            continue;
        }
        auto txHash = tx.hash();
        nlohmann::json txStorage;
        if (MagicSingleton<CtransactionCache>::GetInstance()->GetContractInfoCache(txHash, txStorage) != 0)
        {
            ERRORLOG("can't find storage of tx {}", txHash);
            return -1;
        }

        for(auto &it : txStorage["PrevHash"].items())
        {
            contractTxPreHashMap[txHash].push_back({it.key(), it.value()});
        }
	}
    DBReader dbReader;
    for(auto& iter : contractTxPreHashMap)
    {
        for(auto& preHashPair : iter.second)
        {
            if(contractTxPreHashMap.find(preHashPair.second) != contractTxPreHashMap.end())
            {
                continue;
            }
            std::string DBContractPreHash;
            if (DBStatus::DB_SUCCESS != dbReader.GetLatestUtxoByContractAddr(preHashPair.first, DBContractPreHash))
            {
                ERRORLOG("GetLatestUtxoByContractAddr fail !!! ContractAddr:{}", preHashPair.first);
                return -2;
            }
            if(DBContractPreHash != preHashPair.second)
            {
                ERRORLOG("DBContractPreHash:({}) != preHashPair.second:({})", DBContractPreHash, preHashPair.second);
                return -3;
            }
            contractTxPreHashList.push_back(preHashPair);
        }
    }
    return 0;
}

int CtransactionCache::GetContractInfoCache(const std::string& transactionHash, nlohmann::json& jTxInfo)
{
    auto found = _contractInfoCache.find(transactionHash);
    if (found == _contractInfoCache.end())
    {
        return -1;
    }
    
    jTxInfo = found->second.first;
    return 0;
}

// int _HandleSeekContractPreHashReq(const std::shared_ptr<newSeekContractPreHashReq> &msg, const MsgData &msgdata)
// {
//     newSeekContractPreHashAck ack;
//     ack.set_version(msg->version());
//     ack.set_msg_id(msg->msg_id());
//     ack.set_self_node_id(net_get_self_node_id());
//     Node node;
// 	if (!MagicSingleton<PeerNode>::GetInstance()->find_node_by_fd(msgdata.fd, node))
// 	{
//         ERRORLOG("FindNodeByFd fail !!!, seekId:{}", node.base58address);
// 		return -1;
// 	}

//     DBReader dbReader;
//     if(msg->seekroothash_size() >= 200)
//     {
//         ERRORLOG("msg->seekroothash_size:({}) >= 200", msg->seekroothash_size());
//         return -2;
//     }
//     for(auto& preHashPair : msg->seekroothash())
//     {
//         std::string DBContractPreHash;
//         if (DBStatus::DB_SUCCESS != dbReader.GetLatestUtxoByContractAddr(preHashPair.contractaddr(), DBContractPreHash))
//         {
//             ERRORLOG("GetLatestUtxoByContractAddr fail !!!");
//             return -3;
//         }
//         if(DBContractPreHash != preHashPair.roothash())
//         {
//             DEBUGLOG("DBContractPreHash:({}) != roothash:({}) seekId:{}", DBContractPreHash, preHashPair.roothash(), node.base58address);
//             std::string strPrevBlockHash;
//             if(dbReader.GetBlockHashByTransactionHash(DBContractPreHash, strPrevBlockHash) != DBStatus::DB_SUCCESS)
//             {
//                 ERRORLOG("GetBlockHashByTransactionHash failed!");
//                 return -4;
//             }
//             std::string blockRaw;
//             if(dbReader.GetBlockByBlockHash(strPrevBlockHash, blockRaw) != DBStatus::DB_SUCCESS)
//             {
//                 ERRORLOG("GetBlockByBlockHash failed!");
//                 return -5;
//             }
//             auto seekContractBlock = ack.add_seekcontractblock();
//             seekContractBlock->set_contractaddr(preHashPair.contractaddr());
//             seekContractBlock->set_roothash(strPrevBlockHash);
//             seekContractBlock->set_blockraw(blockRaw);
//         }
//     }
    
//     net_send_message<newSeekContractPreHashAck>(node.base58address, ack, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
//     return 0;
// }

int BuildBlockListForm(const std::list<CTransaction>& txs, const uint64_t& blockHeight, bool build_first)
{
	if(txs.empty())
	{
		ERRORLOG("Txs is empty!");
		return -1;
	}

	CBlock cblock;
	int ret = CreateBlockList(txs, blockHeight, cblock);
    if(ret != 0)
    {
        if(ret == -3 || ret == -4 || ret == -5)
        {
            MagicSingleton<BlockStroage>::GetInstance()->ForceCommitSeekTask(cblock.height() - 1);
        }
        auto tx_sum = cblock.txs_size();
        ERRORLOG("Create block failed! : {},  Total number of transactions : {} ", ret, tx_sum);
		return ret - 100;
    }
	std::string serBlock = cblock.SerializeAsString();
	ca_algorithm::PrintBlock(cblock);

    ContractBlockMsg blockmsg;
    blockmsg.set_version(global::kVersion);
    blockmsg.set_time(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
    blockmsg.set_block(serBlock);
    for(auto &tx : cblock.txs())
    {
        if(GetTransactionType(tx) != kTransactionType_Tx)
        {
            continue;
        }
        CTransaction copyTx = tx;
        copyTx.clear_hash();
        copyTx.clear_verifysign();
        std::string txHash = getsha256hash(copyTx.SerializeAsString());
        MagicSingleton<DONbenchmark>::GetInstance()->SetTxHashByBlockHash(cblock.hash(), txHash);
        uint64_t handleTxHeight =  cblock.height() - 1;
        TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);
        if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
        {
            continue;
        }
        std::pair<std::string,NewVrf>  vrf;
        if(!MagicSingleton<VRF>::GetInstance()->getNewVrfInfo(txHash, vrf))
        {
            ERRORLOG("getVrfInfo failed! tx hash {}", txHash);
            return -2;
        }
        NewVrf *vrfinfo  = blockmsg.add_vrfinfo();
        vrfinfo ->CopyFrom(vrf.second);

        if(!MagicSingleton<VRF>::GetInstance()->getTxNewVrfInfo(txHash, vrf))
        {
            ERRORLOG("getTxVrfInfo failed! tx hash {}", txHash);
            return -3;
        }

        NewVrf *txvrfinfo  = blockmsg.add_txvrfinfo();
        vrf.second.mutable_vrfdata()->set_txvrfinfohash(txHash);
        txvrfinfo ->CopyFrom(vrf.second);

    
    }

    ContractBlockMsg _cpMsg = blockmsg;
    _cpMsg.clear_block();

    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    std::string _cpMsgHash = getsha256hash(_cpMsg.SerializeAsString());
	std::string signature;
	std::string pub;

	if (TxHelper::Sign(defaultBase58Addr, _cpMsgHash, signature, pub) != 0)
	{
		return -4;
	}

	CSign * sign = blockmsg.mutable_sign();
	sign->set_sign(signature);
	sign->set_pub(pub);

    auto msg = std::make_shared<ContractBlockMsg>(blockmsg);

	ret = DoHandleContractBlock(msg);

    if(ret != 0)
    {
        ERRORLOG("DoHandleBlock failed The error code is {}",ret);
        CBlock cblock;
	    if (!cblock.ParseFromString(msg->block()))
	    {
		    ERRORLOG("fail to serialization!!");
		    return -5;
	    }
        return -6;
    }

	return 0;
}

int CreateBlockList(const std::list<CTransaction>& txs, const uint64_t& blockHeight, CBlock& cblock)
{
	cblock.Clear();

	// Fill version
	cblock.set_version(global::ca::kCurrentBlockVersion);

	// Fill time
	uint64_t time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	cblock.set_time(time);
    DEBUGLOG("block set time ======");

	// Fill height
	uint64_t prevBlockHeight = blockHeight - 1;
	cblock.set_height(blockHeight);

    nlohmann::json storage;
    bool isContractBlock = false;
	// Fill tx
	for(auto& tx : txs)
	{
		// Add major transaction
		CTransaction * majorTx = cblock.add_txs();
		*majorTx = tx;
		auto& txHash = tx.hash();
        auto txType = (global::ca::TxType)tx.txtype();
        if (txType == global::ca::TxType::kTxTypeCallContract || txType == global::ca::TxType::kTxTypeDeployContract)
        {
            isContractBlock = true;
            nlohmann::json txStorage;
            if (MagicSingleton<CtransactionCache>::GetInstance()->GetContractInfoCache(txHash, txStorage) != 0)
            {
                ERRORLOG("can't find storage of tx {}", txHash);
                return -1;
            }
            std::set<std::string> dirtyContractList;
            if(!MagicSingleton<CtransactionCache>::GetInstance()->GetDirtyContractMap(tx.hash(), dirtyContractList))
            {
                ERRORLOG("GetDirtyContractMap fail!!! txHash:{}", tx.hash());
                return -2;
            }
            txStorage["dependentCTx"] = dirtyContractList;
            DEBUGLOG("txHash {} ",txHash);
            for(auto it = txStorage.begin();it != txStorage.end();++it)
            {
                DEBUGLOG("dependentCTx {} ",it.key());
                for(auto i:it.value())
                {
                    DEBUGLOG("dirtyContractList", i);
                }
            }
            storage[txHash] = txStorage;
        }
	}

    cblock.set_data(storage.dump());
    // Fill preblockhash
    uint64_t seekPrehashTime = 0;
    std::future_status status;
    auto futurePrehash = MagicSingleton<BlockStroage>::GetInstance()->GetPrehash(prevBlockHeight);
    if(!futurePrehash.valid())
    {
        ERRORLOG("futurePrehash invalid,hight:{}",prevBlockHeight);
        return -2;
    }
    status = futurePrehash.wait_for(std::chrono::seconds(6));
    if (status == std::future_status::timeout) 
    {
        ERRORLOG("seek prehash timeout, hight:{}",prevBlockHeight);
        return -3;
    }
    else if(status == std::future_status::ready) 
    {
        std::string preBlockHash = futurePrehash.get().first;
        if(preBlockHash.empty())
        {
            ERRORLOG("seek prehash <fail>!!!,hight:{},prehash:{}",prevBlockHeight, preBlockHash);
            return -4;
        }
        DEBUGLOG("seek prehash <success>!!!,hight:{},prehash:{},blockHeight:{}",prevBlockHeight, preBlockHash, blockHeight);
        seekPrehashTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
        DEBUGLOG("preBlockHash {}",preBlockHash);
        cblock.set_prevhash(preBlockHash);
    }
    
	// Fill merkleroot
	cblock.set_merkleroot(ca_algorithm::CalcBlockMerkle(cblock));
	// Fill hash
	cblock.set_hash(getsha256hash(cblock.SerializeAsString()));
    DEBUGLOG("blockHash:{}, \n storage:{}", cblock.hash().substr(0,6), storage.dump(4));
    DEBUGLOG("block hash = {} set time ",cblock.hash());
	return 0;
}

// int _HandleSeekContractPreHashAck(const std::shared_ptr<newSeekContractPreHashAck> &msg, const MsgData &msgdata)
// {
//     std::cout << "this pre Hash Ack";
//     GLOBALDATAMGRPTR.NewAddWaitData(msg->msg_id(),msg->self_node_id(),msg->SerializeAsString());
//     return 0;
// }

void CtransactionCache::ContractBlockNotify(const std::string& blockHash)
{
    if (_preContractBlockHash.empty())
    {
        return;
    }
    if (blockHash == _preContractBlockHash)
    {
        _contractPreBlockWaiter.notify_one();
    }
}

void CtransactionCache::AddContractInfoCache(const std::string& transactionHash, const nlohmann::json& jTxInfo, const uint64_t& txtime)
{
    std::unique_lock<std::shared_mutex> locker(_contractInfoCacheMutex);
    _contractInfoCache[transactionHash] = {jTxInfo, txtime};
    return;
}