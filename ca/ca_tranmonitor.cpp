#include "ca/ca_tranmonitor.h"
#include "db/db_api.h"
#include "utils/MagicSingleton.h"
#include "utils/json.hpp"
#include "ca_transaction.h"
#include "ca_blockhelper.h"
#include "utils/AccountManager.h"

bool TranMonitor::isConfirmHash(const std::string& hash)
{
    if(hash_confirm_cache.find(hash) != hash_confirm_cache.end())
    {
        return true;
    }
    return false;
}

void TranMonitor::AddTxHash(const std::string& hash)
{
    std::unique_lock<std::mutex> lck(_Txhash_mutex_);
    hash_confirm_cache.insert(hash);
    DEBUGLOG("AddTxHash:{}", hash);
    return;
    
}

bool TranMonitor::RemoveByHash(const std::string& hash)
{
    std::unique_lock<std::mutex> lck(_Txhash_mutex_);
    if(hash_confirm_cache.find(hash) != hash_confirm_cache.end())
    {
        hash_confirm_cache.erase(hash);
        return true;
    }
    return false;
}

int TranMonitor::AddTranMonitor(const CTransaction& Tx)
{
	std::unique_lock<std::mutex> lck(_TranStatus_mutex_);
    if(_TranStatus.size() >= 10000)
    {
        _TranStatus.clear();
    }

    std::string TranMonitorKey;
    if(CalcTranMonitorKey(Tx,TranMonitorKey) != 0) 
    {
        return -1;
    }
    TranMonSt StatusSt;
    StatusSt.Tx = Tx;
    _TranStatus.insert(std::pair<std::string,TranMonSt>(TranMonitorKey,StatusSt));
    lck.unlock();

    return 0;
}

int TranMonitor::SetDoHandleTxStatus(const CTransaction& Tx, const int  ret)
{
	std::unique_lock<std::mutex> lck(_TranStatus_mutex_);

    std::string TranMonitorKey;
    if(CalcTranMonitorKey(Tx,TranMonitorKey) != 0)
    {
        return -1;
    }

    for(auto &tx : _TranStatus)//Update the status of a transaction
    {
        if(tx.first == TranMonitorKey)
        {           
            std::string time = MagicSingleton<TimeUtil>::GetInstance()->
                                    formatUTCTimestamp(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
           tx.second.LaunchTime.first = ret;
           tx.second.LaunchTime.second = time;

        }
    }
    lck.unlock();
    return 0;
}

int TranMonitor::SetBroadCastAck(const CBlock& block)
{
    std::unique_lock<std::mutex> lck(_TranStatus_mutex_);
    for(int i = 0; i < block.txs_size() ; i++)
    {
        CTransaction Tx = block.txs(i);

        std::string TranMonitorKey;
        if(CalcTranMonitorKey(Tx,TranMonitorKey) != 0)
        {
            return -1;
        }

        for(auto &i : _TranStatus)
        {
            if(i.first == TranMonitorKey)
            {
                std::string time = MagicSingleton<TimeUtil>::GetInstance()->
                                    formatUTCTimestamp(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
                i.second._BroadCastAck.first = time;
                i.second._BroadCastAck.second = 1;
            }
        }

    }
    lck.unlock();
    return 0;
}


void TranMonitor::AddFailureList(const CTransaction& Tx)
{
	std::unique_lock<std::mutex> lck(_FailureList_mutex_);
    std::cout << "AddFailureList" << std::endl;
    if(_FailureList.size() >= 10000)
    {
        _FailureList.clear();
    }
    _FailureList.push_back({Tx,MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp()});
    lck.unlock();
}

int TranMonitor::FindFailureList(const std::string & fromAddr, std::vector<FailureList> & txs)
{
    std::lock_guard<std::mutex> lck(_FailureList_mutex_);

    int result = -1;
    for (auto iter = _FailureList.begin(); iter != _FailureList.end(); ++iter)
    {
        std::map<std::string, std::vector<std::string>> txOwnerUtxo;
        for(int i = 0; i < iter->tx.utxo().owner_size(); ++i)
        {
            auto addr = iter->tx.utxo().owner().at(i);
            auto found = txOwnerUtxo.find(addr);
            if (found == txOwnerUtxo.end())
            {
                txOwnerUtxo[addr] = std::vector<std::string>{};
            }

            std::vector<std::string> utxos;
            for (int j = 0; j < iter->tx.utxo().vin_size(); ++j)
            {
                const CTxInput & txin = iter->tx.utxo().vin(j);
                for (auto & prevOut : txin.prevout())
                {
                    utxos.push_back(prevOut.hash());
                }
            }
            txOwnerUtxo[addr] = utxos;
        }


        auto found = txOwnerUtxo.find(fromAddr);
        if (found != txOwnerUtxo.end())
        {
            txs.push_back(*iter);
            result = 0;
        }
    }
    return result; 
}

void TranMonitor::PrintFailureList(std::ostream & stream)
{

    for (auto iter = _FailureList.begin(); iter != _FailureList.end(); ++iter)
    {
        stream << "-------------------------------------------------" << std::endl;
        stream << "Failure transaction: " << iter->tx.hash() << std::endl;

        std::map<std::string, std::vector<std::string>> txOwnerUtxo;
        for(int i = 0; i < iter->tx.utxo().owner_size(); ++i)
        {
            auto addr = iter->tx.utxo().owner().at(i);
            auto found = txOwnerUtxo.find(addr);
            if (found == txOwnerUtxo.end())
            {
                txOwnerUtxo[addr] = std::vector<std::string>{};
            }

            std::vector<std::string> utxos;
            for (int j = 0; j < iter->tx.utxo().vin_size(); ++j)
            {
                const CTxInput & txin = iter->tx.utxo().vin(j);
                for (auto & prevOut : txin.prevout())
                {
                    utxos.push_back(prevOut.hash());
                }
            }
            txOwnerUtxo[addr] = utxos;
        }

        stream << "from: ";
        for (const auto& item : txOwnerUtxo)
        {
            stream << item.first << " ";
        }
        stream << std::endl;

        uint64_t amount = 0;
        std::vector<std::string> toId;
        for (int i = 0; i < iter->tx.utxo().vout_size(); i++)
        {
            const CTxOutput & out = iter->tx.utxo().vout(i);
            auto found = txOwnerUtxo.find(out.addr());
            if (found == txOwnerUtxo.end())
            {
                toId.push_back(out.addr());
                amount += out.value();
            }
        }
        stream << "to: ";        
        for (const auto& id : toId)
        {
            stream << id << " ";
        }
        stream << std::endl;
        stream << "amount: " <<  amount << std::endl; 
        stream << "timestamp: " << MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp() << std::endl;
        stream << "-------------------------------------------------" << std::endl;
        stream << std::endl;
    }
    stream << "Failure transcation in Cache: " << _FailureList.size() << std::endl;
}


int TranMonitor::ReviceDoHandleAck(const TxMsgAck& ack )
{
    std::unique_lock<std::mutex> lck(_TranStatus_mutex_);
    static std::vector<int32_t> veclimt;
    CTransaction tx;
    if (!tx.ParseFromString(ack.tx()))
    {
        ERRORLOG("Failed to deserialize transaction body!");
        return -1;
    }
    std::string TranMonitorKey;
    if(CalcTranMonitorKey(tx,TranMonitorKey) != 0)
    {
        return -2;
    }
    for(auto& i : _TranStatus)
    {
        if(i.first == TranMonitorKey)
        {
            
            std::string time = MagicSingleton<TimeUtil>::GetInstance()->
                                              formatUTCTimestamp(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
            i.second._MonNodeDoHandleAck.insert(std::make_pair(ack.code(),time));  
        }
    }
    lck.unlock();
    return 0;

}

int TranMonitor::CalcTranMonitorKey(const CTransaction& Tx,std::string &key)
{
    std::string utxo_hash;
    std::set<std::string> OwnerBase58Addr;

    for(auto & owner : Tx.utxo().owner())
    {
        OwnerBase58Addr.insert(owner);
    }

    if(OwnerBase58Addr.size() != 1)
    {
        DEBUGLOG("Owner size is not 1 !");
        return -1;
    }

    for(auto & vin : Tx.utxo().vin())
    {
        for(auto & utxo : vin.prevout())
        {
             utxo_hash = utxo_hash + utxo.hash();
        }
    }
    auto iter = OwnerBase58Addr.begin();

    key = getsha256hash(utxo_hash + *iter + to_string(Tx.time()));
    return 0;
}

/****************************TxVinCache***********************************/
string TranMonitor::TxToString(const CTransaction& tx)
{
    std::vector<std::string> txOwnerVec(tx.utxo().owner().begin(), tx.utxo().owner().end());
    
    stringstream info;
    info << "hash: " << tx.hash();
    info << " from: ";

    for (const auto& id : txOwnerVec)
    {
        info << id << " ";
    }
    
    return info.str();
}

bool TranMonitor::IsExist(const CTransaction& tx)
{
    std::lock_guard<std::mutex> lck(VecTx_mutex_);
    for (auto iter = VecTx_.begin(); iter != VecTx_.end(); ++iter)
    {
        if (iter->tx.hash() == tx.hash())
        {
            return true;
        }
    }
    return false;
}

int TranMonitor::TxVinRemove(const CTransaction& tx)
{
    std::lock_guard<std::mutex> lck(VecTx_mutex_);

    if(VecTx_.empty())
    {
        return 1;
    }

    int result = -1;
    for (auto iter = VecTx_.begin(); iter != VecTx_.end();)
    {
        if (iter->tx.hash() == tx.hash())
        {
            iter = VecTx_.erase(iter);
            result = 0;       
        }
        else
        {
             ++iter;
        }
    }
    return result;
}

int TranMonitor::TxVinRemove(const std::string& txHash)
{
    CTransaction tx;
    tx.set_hash(txHash);
    return TxVinRemove(tx);
}


// int TranMonitor::Add(const CTransaction& tx,uint64_t BlockHeight)
// {

//     VinSt cacheVin;
//     cacheVin.tx = tx;
//     cacheVin.timestamp = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
//     cacheVin.prevBlkHeight = BlockHeight;

//     int result = Add(cacheVin);
//     std::string defaultbase58 =  MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
//     if (result == 0 && defaultbase58 == tx.identity())
//     {
//         BroadcastTxPending(tx, BlockHeight);
//     }

//     return result;
// }

int TranMonitor::Add(const VinSt& vinst)
{
    if (IsExist(vinst.tx))
    {
        DEBUGLOG("TX IsExist");
        return 1;
    }

    std::lock_guard<std::mutex> lck(VecTx_mutex_);
    VecTx_.push_back(vinst);
    return 0;
}

void TranMonitor::Print()
{

    for (const auto& item : VecTx_)
    {
        std::map<std::string, std::vector<std::string>> txOwnerUtxo;
        for(int i = 0; i < item.tx.utxo().owner_size(); ++i)
        {
            auto addr = item.tx.utxo().owner().at(i);
            auto found = txOwnerUtxo.find(addr);
            if (found == txOwnerUtxo.end())
            {
                txOwnerUtxo[addr] = std::vector<std::string>{};
            }

            std::vector<std::string> utxos;
            for (int j = 0; j < item.tx.utxo().vin_size(); ++j)
            {
                const CTxInput & txin = item.tx.utxo().vin(j);
                for (auto & prevOut : txin.prevout())
                {
                    utxos.push_back(prevOut.hash());
                }
            }
            txOwnerUtxo[addr] = utxos;
        }

        cout << "Transaction Hash: " << item.tx.hash() << " from: ";
        auto begin = txOwnerUtxo.begin();
        for ( ; begin != txOwnerUtxo.end(); ++begin)
        {
            cout << begin->first << " ";
        }
        cout << endl;
    }
    std::cout << "Pending transcation in Cache: " << VecTx_.size() << std::endl;
}

int TranMonitor::Find(const std::string & txHash, CTransaction & tx)
{
    std::lock_guard<std::mutex> lck(VecTx_mutex_);

    int result = -1;
    for (auto iter = VecTx_.begin(); iter != VecTx_.end(); ++iter)
    {
        if (iter->tx.hash() == txHash)
        {
            tx = iter->tx;
            result = 0;
            break;            
        }
    }
    return result;
}

int TranMonitor::Find(const std::string & fromAddr, std::vector<CTransaction> & txs)
{
    std::lock_guard<std::mutex> lck(VecTx_mutex_);

    int result = -1;
    for (auto iter = VecTx_.begin(); iter != VecTx_.end(); ++iter)
    {
        std::map<std::string, std::vector<std::string>> txOwnerUtxo;
        for(int i = 0; i < iter->tx.utxo().owner_size(); ++i)
        {
            auto addr = iter->tx.utxo().owner().at(i);
            auto found = txOwnerUtxo.find(addr);
            if (found == txOwnerUtxo.end())
            {
                txOwnerUtxo[addr] = std::vector<std::string>{};
            }

            std::vector<std::string> utxos;
            for (int j = 0; j < iter->tx.utxo().vin_size(); ++j)
            {
                const CTxInput & txin = iter->tx.utxo().vin(j);
                for (auto & prevOut : txin.prevout())
                {
                    utxos.push_back(prevOut.hash());
                }
            }
            txOwnerUtxo[addr] = utxos;
        }


        auto found = txOwnerUtxo.find(fromAddr);
        if (found != txOwnerUtxo.end())
        {
            txs.push_back(iter->tx);
            result = 0;
        }
    }
    return result;
}

int TranMonitor::Find(const std::string & fromAddr, std::vector<TranMonitor::VinSt> & txs)
{
    std::lock_guard<std::mutex> lck(VecTx_mutex_);

    int result = -1;
    for (auto iter = VecTx_.begin(); iter != VecTx_.end(); ++iter)
    {
        std::map<std::string, std::vector<std::string>> txOwnerUtxo;
        for(int i = 0; i < iter->tx.utxo().owner_size(); ++i)
        {
            auto addr = iter->tx.utxo().owner().at(i);
            auto found = txOwnerUtxo.find(addr);
            if (found == txOwnerUtxo.end())
            {
                txOwnerUtxo[addr] = std::vector<std::string>{};
            }

            std::vector<std::string> utxos;
            for (int j = 0; j < iter->tx.utxo().vin_size(); ++j)
            {
                const CTxInput & txin = iter->tx.utxo().vin(j);
                for (auto & prevOut : txin.prevout())
                {
                    utxos.push_back(prevOut.hash());
                }
            }
            txOwnerUtxo[addr] = utxos;
        }


        auto found = txOwnerUtxo.find(fromAddr);
        if (found != txOwnerUtxo.end())
        {
            txs.push_back(*iter);
            result = 0;
        }
    }
    return result; 
}

int TranMonitor::GetAllTx(std::vector<CTransaction> & txs)
{
    std::lock_guard<std::mutex> lck(VecTx_mutex_);
    for (const auto& iter : VecTx_ )
    {
        txs.push_back(iter.tx);
    }

    return 0;
}

int TranMonitor::GetAllTx(std::vector<TranMonitor::VinSt> & txs)
{
    txs = VecTx_;
    return 0;
}

int TranMonitor::Clear()
{
    std::lock_guard<std::mutex> lck(VecTx_mutex_);
    VecTx_.clear();
    
    return 0;
}

bool TranMonitor::IsConflict(const CTransaction& transaction)
{
    std::vector<std::string> vecFroms(transaction.utxo().owner().begin(), transaction.utxo().owner().end());
    std::sort(vecFroms.begin(), vecFroms.end());

    std::vector<std::string> vecUtxos;
	for (const auto& vin : transaction.utxo().vin())
	{
        for (const auto & prevout : vin.prevout())
        {
            if (!prevout.hash().empty())
            {
			    vecUtxos.push_back(prevout.hash());
            }
        }
	}
    std::sort(vecUtxos.begin(), vecUtxos.end());
    std::lock_guard<std::mutex> lck(VecTx_mutex_);
    for (auto cur_tx : VecTx_)
    {
        std::map<std::string, std::vector<std::string>> txOwnerUtxo;
        for(int i = 0; i < cur_tx.tx.utxo().owner_size(); ++i)
        {
            auto addr = cur_tx.tx.utxo().owner().at(i);
            auto found = txOwnerUtxo.find(addr);
            if (found == txOwnerUtxo.end())
            {
                txOwnerUtxo[addr] = std::vector<std::string>{};
            }

            std::vector<std::string> utxos;
            for (int j = 0; j < cur_tx.tx.utxo().vin_size(); ++j)
            {
                const CTxInput & txin = cur_tx.tx.utxo().vin(j);
                for (auto & prevOut : txin.prevout())
                {
                    utxos.push_back(prevOut.hash());
                }
            }
            txOwnerUtxo[addr] = utxos;
        }
        auto iter = txOwnerUtxo.begin();
        for(;iter != txOwnerUtxo.end(); ++iter)
        {
            for(auto owner : vecFroms)
            {
                if(iter->first == owner)
                {
                    for(auto &start : iter->second)
                    {
                        auto found = find(vecUtxos.begin(),vecUtxos.end(),start);
                        if(found != vecUtxos.end())
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

bool TranMonitor::IsConflict(const std::map<std::string, std::vector<std::string>> &identifies)
{
    std::lock_guard<std::mutex> lck(VecTx_mutex_);
    // Check from address
    for (auto iter = VecTx_.begin(); iter != VecTx_.end(); ++iter)
    {
        std::map<std::string, std::vector<std::string>> txOwnerUtxo;
        for(int i = 0; i < iter->tx.utxo().owner_size(); ++i)
        {
            auto addr = iter->tx.utxo().owner().at(i);
            auto found = txOwnerUtxo.find(addr);
            if (found == txOwnerUtxo.end())
            {
                txOwnerUtxo[addr] = std::vector<std::string>{};
            }
            std::vector<std::string> utxos;
            for (int j = 0; j < iter->tx.utxo().vin_size(); ++j)
            {
                const CTxInput & txin = iter->tx.utxo().vin(j);
                for (auto & prevOut : txin.prevout())
                {
                    utxos.push_back(prevOut.hash());
                }
            }
            txOwnerUtxo[addr] = utxos;
        }
        auto begin = identifies.begin();
        for( ;begin != identifies.end(); ++begin)
        {
            auto found = txOwnerUtxo.find(begin->first);
            if(found != txOwnerUtxo.end())
            {
                auto start = begin->second.begin();
                for( ;start != begin->second.end(); ++start)
                {
                    auto found_utxo = std::find(found->second.begin(), found->second.end(), *start);
                    if(found_utxo != found->second.end())
                    {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}


// void TranMonitor::BroadcastTxPending(const CTransaction& tx, uint64_t BlockHeight)
// {
//     string transactionRaw = tx.SerializeAsString();
//     TxPendingBroadcastMsg txPendingMsg;
//     txPendingMsg.set_version(global::kVersion);
//     txPendingMsg.set_txraw(transactionRaw);
//     txPendingMsg.set_prevblkheight(BlockHeight);

//     std::vector<Node> vnode = net_get_public_node();
//     for (auto & item : vnode)
//     {
//         net_send_message<TxPendingBroadcastMsg>(item.base58address, txPendingMsg, net_com::Priority::kPriority_Middle_1);
//     }
// }

void TranMonitor::Add ( uint64_t start_height , uint64_t end_height , std::string base , std::string block_hash) {
    if ( start_sync_height == 0 && end_sync_height == 0)
    {
        start_sync_height = start_height;
        end_sync_height = end_height;
    }
    if ( start_sync_height != start_height || end_sync_height != end_height)
    {
        m_base_block.clear();
        start_sync_height = start_height;
        end_sync_height = end_height;
    }
    m_base_block[base].insert(block_hash);
}

std::vector<std::string> get_Within_10_block_hashs()
{
    std::vector<std::string> block_hashes;
    uint64_t self_node_height = 0;
    DBReader data_reader;
    auto status = data_reader.GetBlockTop(self_node_height);
    if (DBStatus::DB_SUCCESS != status)
    {
        return block_hashes;
    }
    if (DBStatus::DB_SUCCESS != data_reader.GetBlockHashesByBlockHeight(self_node_height-10, self_node_height, block_hashes))
    {
        return block_hashes;
    }
    return block_hashes;
}

void TranMonitor::test_printf()
{
    std::vector<std::string> && block_hashes = get_Within_10_block_hashs();
    if(block_hashes.empty())
    {
        return;
    }

    std::vector<std::string> intersection_nodes;
    _m_base_s_block::iterator it = m_base_block.begin();
    for(;it != m_base_block.end();++it)
    {
        std::vector<std::string> exits_hashes;
        exits_hashes.assign(it->second.begin(),it->second.end());

        std::sort(block_hashes.begin(), block_hashes.end());
        std::sort(exits_hashes.begin(), exits_hashes.end());
        std::set_intersection(block_hashes.begin(), block_hashes.end(), exits_hashes.begin(), exits_hashes.end(), std::back_inserter(intersection_nodes));

        if(intersection_nodes.size() / exits_hashes.size() > 0.8 )
        {
            std::cout << "node: " << it->first << " intersection_nodes: " << intersection_nodes.size() << " my_hash: " << exits_hashes.size() << " proportion:" << double(intersection_nodes.size() / exits_hashes.size()) << std::endl;
        }
        intersection_nodes.clear();
    }
    std::cout << "start_sync_height: " << start_sync_height << " end_sync_height: " << end_sync_height << std::endl;
    /*
    _m_base_s_block::iterator it = m_base_block.begin();
    for(;it != m_base_block.end();++it)
    {
        std::string base64name = it->first;
        std::cout << "base64name: " << base64name << std::endl;

        std::set<std::string>::iterator it_2 = it->second.begin();
        for(;it_2 != it->second.end();++it_2)
        {
            std::cout << std::string( 8 * 4 , ' ') << " hash :" << it_2->c_str() << std::endl;
        }
    }
    std::cout << "start_sync_height: " << start_sync_height << " end_sync_height: " << end_sync_height << std::endl;
    */
}

std::vector<Node> TranMonitor::GetNodes()
{

    std::vector<Node> nodelist; 
    std::vector<std::string> && block_hashes = get_Within_10_block_hashs();
    if(block_hashes.empty())
    {
        return nodelist;
    }

    std::set<std::string> NodeIds;
    std::vector<std::string> intersection_nodes;
    _m_base_s_block::iterator it = m_base_block.begin();
    for(;it != m_base_block.end();++it)
    {
        std::vector<std::string> exits_hashes;
        exits_hashes.assign(it->second.begin(),it->second.end());

        std::sort(block_hashes.begin(), block_hashes.end());
        std::sort(exits_hashes.begin(), exits_hashes.end());
        std::set_intersection(block_hashes.begin(), block_hashes.end(), exits_hashes.begin(), exits_hashes.end(), std::back_inserter(intersection_nodes));
        double proportion = intersection_nodes.size() / exits_hashes.size();
        if(proportion > 0.8 )
        {
            NodeIds.insert(it->first);
        }
        intersection_nodes.clear();
    }

	std::vector<Node> nodelist1 = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
    for(std::vector<Node>::iterator it = nodelist1.begin(); it != nodelist1.end(); ++it )
    {
        if(NodeIds.end() != std::find(NodeIds.begin(),NodeIds.end(),it->base58address))
        {
            nodelist.emplace_back(*it);
        }
    }

    return nodelist;
}


int TranMonitor::Process()
{
    this->timer_.AsyncLoop(1000 * 10 * 1, TranMonitor::CheckExpire, this);

    return 0;
}

int TranMonitor::CheckExpire(TranMonitor * Tranmonitor)
{
    if (Tranmonitor == nullptr)
    {
        return -1;    
    }
    //The scheduled task queries whether the timestamp exceeds 5 minutes
    // If it is exceeded, it will be canceled from the list
    Tranmonitor->DoClearExpire();

    return 0;
}


void TranMonitor::DoClearExpire()
{
    std::lock_guard<std::mutex> lck(VecTx_mutex_);

    for (auto iter = VecTx_.begin(); iter != VecTx_.end();)
    {
        uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
        static const uint64_t WAIT_TIME = 1000000 * 60; // 1 minutes

        if (nowTime - iter->timestamp >= WAIT_TIME)
        {
            iter = VecTx_.erase(iter);
        }
        else
        {
            ++iter;
        }
    }
}


int TranMonitor::SetSelfAckDoHandle(const CTransaction& Tx,const int  ret)
{
	std::unique_lock<std::mutex> lck(_TranStatus_mutex_);

    std::string TranMonitorKey;
    if(CalcTranMonitorKey(Tx,TranMonitorKey) != 0)
    {
        return -1;
    }
    
    for(auto& i : _TranStatus)
    {
        if(i.first == TranMonitorKey)
        {
            std::string time = MagicSingleton<TimeUtil>::GetInstance()->
                                    formatUTCTimestamp(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
            i.second._SelfDohandleCount.insert(std::make_pair(ret,time));
        }
    }
    lck.unlock();

    return 0;

}

int TranMonitor::SetComposeStatus(const CTransaction& Tx)
{
	std::unique_lock<std::mutex> lck(_TranStatus_mutex_);
    DEBUGLOG("SetComposeStatus");
    std::string TranMonitorKey;
    if(CalcTranMonitorKey(Tx,TranMonitorKey) != 0)
    {
        return -1;
    }

    for(auto& i : _TranStatus)
    {
        if(i.first == TranMonitorKey)
        {
            std::string time = MagicSingleton<TimeUtil>::GetInstance()->
                                    formatUTCTimestamp(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
            i.second._ComposeStatusTime = time;
        }
    }

    lck.unlock();
    return 0;
}


int TranMonitor::SetRemoveTimeStatus(const CTransaction& Tx)
{
	std::unique_lock<std::mutex> lck(_TranStatus_mutex_);
    std::string TranMonitorKey;
    if(CalcTranMonitorKey(Tx,TranMonitorKey) != 0)
    {
        return -1;
    }

    for(auto& i : _TranStatus)
    {
        if(i.first == TranMonitorKey)
        {
            std::string time = MagicSingleton<TimeUtil>::GetInstance()->
                                    formatUTCTimestamp(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
            i.second._VinRemoveTime = time;
        }
    }
    lck.unlock();
    return 0;
}


int TranMonitor::UpdateTxHash(const CTransaction& tx)
{
    std::lock_guard<std::mutex> lck(VecTx_mutex_);
    DEBUGLOG("UpdateTxHash ");
    std::string TranMonitorKey;
    if(CalcTranMonitorKey(tx,TranMonitorKey) != 0) 
    {
        return -1;
    }

    for(auto &item : VecTx_)
    {
        std::string vinKey;
        if(CalcTranMonitorKey(item.tx,vinKey) != 0) 
        {
            return -2;
        }

        if(vinKey == TranMonitorKey)
        {
            item.DB_txhash = tx.hash();
        }

    }

    return 0;
}

void TranMonitor::t_VinSt::ConvertTx(const CTransaction& tx, uint64_t prevBlkHeight, t_VinSt& newTx,uint64_t timestamp)
{
    newTx.txHash = tx.hash();
    newTx.prevBlkHeight = prevBlkHeight;

    std::map<std::string, std::vector<std::string>> txOwnerUtxo;
    for(int i = 0; i < tx.utxo().owner_size(); ++i)
    {
        auto addr = tx.utxo().owner().at(i);
        auto found = txOwnerUtxo.find(addr);
        if (found == txOwnerUtxo.end())
        {
            txOwnerUtxo[addr] = std::vector<std::string>{};
        }

        std::vector<std::string> utxos;
        for (int j = 0; j < tx.utxo().vin_size(); ++j)
        {
            const CTxInput & txin = tx.utxo().vin(j);
            for (auto & prevOut : txin.prevout())
            {
                utxos.push_back(prevOut.hash());
            }
        }
        txOwnerUtxo[addr] = utxos;
    }
    newTx.identifies = txOwnerUtxo;


    uint64_t amount = 0;
    std::vector<std::string> toId;
    std::vector<uint64_t> toAmount;

    for (int i = 0; i < tx.utxo().vout_size(); i++)
    {
        const CTxOutput & out = tx.utxo().vout(i);
        auto found = txOwnerUtxo.find(out.addr());
        if (found == txOwnerUtxo.end())
        {
            toId.push_back(out.addr());
            toAmount.push_back(out.value());
            amount += out.value();
        }
    }	

    newTx.amount = amount;
    newTx.to = toId;
    newTx.toAmount = toAmount;
    newTx.timestamp = timestamp;

    //uint64_t gas = 0;               
    uint64_t needConsensus = tx.consensus();
   // uint64_t cost = 0;
    // gas = gas * (needConsensus - 1);


    bool isNeedAgent = TxHelper::IsNeedAgent(tx);

    // if(isNeedAgent)
    // {
    //     gas += cost; 
    // }
    
    // newTx.gas = gas;

    global::ca::TxType txType = (global::ca::TxType)tx.txtype();
    newTx.type = (int32_t)txType;

    if(txType != global::ca::TxType::kTxTypeTx)
    {
        nlohmann::json data = nlohmann::json::parse(tx.data());
        if (txType == global::ca::TxType::kTxTypeUnstake)
        {
            nlohmann::json txInfo = data["TxInfo"].get<nlohmann::json>();
            std::string utxoStr = txInfo["UnstakeUtxo"].get<std::string>();
            std::string strTxRaw;
            DBReader db_reader;
            if (DBStatus::DB_SUCCESS == db_reader.GetTransactionByHash(utxoStr, strTxRaw))
            {
                CTransaction utxoTx;
                utxoTx.ParseFromString(strTxRaw);
                for (int i = 0; i < utxoTx.utxo().vout_size(); i++)
                {
                    const CTxOutput & txout = utxoTx.utxo().vout(i);
                    if (txout.addr() == global::ca::kVirtualStakeAddr)
                    {
                        uint64_t outAmount = txout.value();
                        newTx.amount = outAmount;
                        //newTx.to = newTx.from;

                        auto iter = txOwnerUtxo.begin();
                        for( ; iter != txOwnerUtxo.end(); ++iter)
                        {
                            newTx.to.push_back(iter->first);
                        }

                        std::vector<uint64_t> currentToAmount = {newTx.amount};
                        newTx.toAmount = currentToAmount;
                        break ;
                    }
                }
            }
        }
        else if (txType == global::ca::TxType::kTxTypeDisinvest)
        {
            nlohmann::json txInfo = data["TxInfo"].get<nlohmann::json>();
            std::string utxoStr = txInfo["DisinvestUtxo"].get<std::string>();
            std::string strTxRaw;
            DBReader db_reader;
            if (DBStatus::DB_SUCCESS == db_reader.GetTransactionByHash(utxoStr, strTxRaw))
            {
                CTransaction utxoTx;
                utxoTx.ParseFromString(strTxRaw);
                for (int i = 0; i < utxoTx.utxo().vout_size(); i++)
                {
                    const CTxOutput & txout = utxoTx.utxo().vout(i);
                    if (txout.addr() == global::ca::kVirtualInvestAddr)
                    {
                        uint64_t outAmount = txout.value();
                        newTx.amount = outAmount;
                        //newTx.to = newTx.from;

                        auto iter = txOwnerUtxo.begin();
                        for( ; iter != txOwnerUtxo.end(); ++iter)
                        {
                            newTx.to.push_back(iter->first);
                        }

                        std::vector<uint64_t> currentToAmount = {newTx.amount};
                        newTx.toAmount = currentToAmount;
                        break ;
                    }
                }
            }
        }
        
    }           

}



string TranMonitor::t_VinSt::TxToString(const t_VinSt& tx)
{
    stringstream info;
    info << "hash: " << tx.txHash;
    info << " from: ";

 
    auto iter = tx.identifies.begin();
    for ( ; iter != tx.identifies.end(); ++iter)
    {
        info << iter->first << " ";
    }
    
    return info.str();
}

string TranMonitor::t_VinSt::TxToString(const CTransaction& tx)
{
    std::vector<std::string> txOwnerVec(tx.utxo().owner().begin(), tx.utxo().owner().end());
    
    stringstream info;
    info << "hash: " << tx.hash();
    info << " from: ";

    for (const auto& id : txOwnerVec)
    {
        info << id << " ";
    }
    
    return info.str();
}

std::map<std::string,TranMonitor::TranMonSt> TranMonitor::GetTranStatus()
{
    return _TranStatus;
}