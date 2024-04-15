#include "ca/ca_blockstroage.h"

#include "utils/VRF.hpp"
#include "utils/DONbenchmark.h"
#include "ca/ca_algorithm.h"
#include "ca/ca_sync_block.h"
#include "ca/ca_transaction.h"
#include "ca/ca_blockhelper.h"

#include "common/global.h"
#include "common/task_pool.h"
#include "common/global_data.h"

#include "proto/block.pb.h"
#include "net/peer_node.h"
void BlockStroage::StartTimer()
{
    //Notifications for inspections at regular intervals
	_block_timer.AsyncLoop(100, [this](){
		BlockCheck();
	});
    _contract_block_timer.AsyncLoop(100, [this](){
		BlockContractCheck();
	}); 
            
}


void BlockStroage::AddBlock(const BlockMsg &msg)
{
	std::unique_lock<std::mutex> lck(_block_mutex_);

    CBlock block;
    block.ParseFromString(msg.block());

	std::vector<BlockMsg> msgVec;
	msgVec.push_back(msg);
    //Self-add does not have its own signature on the block at this time
	_BlockMap.insert(std::pair<std::string,std::vector<BlockMsg>>(block.hash(),msgVec));
	DEBUGLOG("add TranStroage");
	lck.unlock();
}

int BlockStroage::AddContractBlock(const ContractBlockMsg &msg)
{
	std::unique_lock<std::shared_mutex> lck(_block_mutex_contract_);

    CBlock block;
    block.ParseFromString(msg.block());

	std::vector<ContractBlockMsg> msgVec;
	msgVec.push_back(msg);
    //Self-add does not have its own signature on the block at this time
	_BlockMap_Contract.insert(std::pair<std::string,std::vector<ContractBlockMsg>>(block.hash(),msgVec));
	DEBUGLOG("add TranStroage block hash : {}", block.hash().substr(0, 6));
	lck.unlock();
    
    return 0;
}

int BlockStroage::UpdateBlock(const BlockMsg &msg)
{
    std::unique_lock<std::mutex> lck(_block_mutex_);
    CBlock block;
    block.ParseFromString(msg.block());
    if(block.sign_size() != 2)
    {
		ERRORLOG("sign  size != 2");
        return -1;
    }
	for(auto &i : _BlockMap)
	{
		
		if(block.hash() != i.first || i.second.size() == global::ca::kConsensus)
		{
			continue;
		}
		i.second.push_back(msg);
		if(i.second.size() == global::ca::kConsensus)
		{
            //Combined into BlockMsg
			composeEndBlockmsg(i.second);	
		}
	}
	lck.unlock();
	return 0;
}


int BlockStroage::UpdateContractBlock(const ContractBlockMsg &msg)
{
    std::unique_lock<std::shared_mutex> lck(_block_mutex_contract_);
    CBlock block;
    block.ParseFromString(msg.block());
    INFOLOG("recv block sign addr = {},hash {}",GetBase58Addr(block.sign(1).pub()),block.hash());

    if(block.sign_size() != 2)
    {
		ERRORLOG("sign  size != 2");
        return -1;
    }
    
    auto it = _BlockMap_Contract.find(block.hash());
	if (it != _BlockMap_Contract.end())
    {
        _BlockMap_Contract[block.hash()].push_back(msg);
        DEBUGLOG("block map contract add {}",block.hash().substr(0,6));
    }
    
	lck.unlock();

	return 0;
}


void BlockStroage::BlockCheck()
{
    std::unique_lock<std::mutex> lck(_block_mutex_);

	std::vector<std::string> hashKey;
	for(auto &i : _BlockMap)
	{
        BlockMsg copyendmsg_ = i.second.at(0);
        CBlock block;
        block.ParseFromString(copyendmsg_.block());
        if(block.hash() != i.first)
        {
            hashKey.push_back(block.hash()); 
            continue;
        }
        int64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
        const int64_t kTenSecond = (int64_t)1000000 * 10; // TODO::10s

        DEBUGLOG("block.sign_size() =  {}",block.sign_size());
        if( abs(nowTime - (int64_t)block.time()) >= kTenSecond)
        {
            ERRORLOG("Add to failure list");
            hashKey.push_back(block.hash());
            copyendmsg_.Clear();

        }
        else if(block.sign_size() == global::ca::kConsensus)
        {
            DEBUGLOG("begin add cache block");
            //Verify Block flow verifies the signature of the node
            std::pair<std::string, std::vector<std::string>> nodes_pair;
            
            MagicSingleton<VRF>::GetInstance()->getVerifyNodes(block.hash(), nodes_pair);
            //Block signature node in cache
            std::vector<std::string> cache_nodes = nodes_pair.second;
            //The signature node in the block flow
            std::vector<std::string> verify_nodes;
            for(auto &item : block.sign())
            {
                verify_nodes.push_back(GetBase58Addr(item.pub()));
                
            }

            //Compare whether the nodes in the two containers are consistent
            for(auto & sign_node : verify_nodes)
            {
                if(std::find(cache_nodes.begin(), cache_nodes.end(), sign_node) == cache_nodes.end())
                {
                    DEBUGLOG(" The nodes in the two containers are inconsistent = {}",sign_node);
                    hashKey.push_back(block.hash());
                    continue;
                }
            }

            //After the verification is passed, the broadcast block is directly built
            if(block.version() >=0)
            {
                auto NowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
			    MagicSingleton<DONbenchmark>::GetInstance()->SetByBlockHash(block.hash(), &NowTime, 2);
                MagicSingleton<BlockMonitor>::GetInstance()->SendBroadcastAddBlock(copyendmsg_.block(),block.height());
                INFOLOG("Start to broadcast BuildBlockBroadcastMsg...");
            }
            else
            {
                std::cout << "The version is too low. Please update the version!" << std::endl;
            }
            
            hashKey.push_back(block.hash());
            copyendmsg_.Clear();
        }

	}
	if(!hashKey.empty())
	{
		for (auto &hash : hashKey)
		{
			Remove(hash);
		}
	}
	hashKey.clear();    
    
}

void BlockStroage::BlockContractCheck()
{
    std::unique_lock<std::shared_mutex> lck(_block_mutex_contract_);

    int64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    const int64_t kTenSecond = (int64_t)1000000 * 10;

	std::vector<std::string> hashKey;
	for(auto &item : _BlockMap_Contract)
	{
        CBlock temBlock;
        temBlock.ParseFromString(item.second.at(0).block());
        DEBUGLOG("temBlock hash : {}" , temBlock.hash());
        uint64_t lagTime = abs(nowTime - (int64_t)temBlock.time());
        uint32_t msgSize = item.second.size();
        
        DEBUGLOG("lagTime is {}",lagTime);
        if(msgSize >= global::ca::kConsensus && lagTime <= kTenSecond)
        {
            DEBUGLOG("Block hash : {} Recv block sign node size : {}" ,temBlock.hash(),msgSize);
            ContractBlockMsg outMsg;
            if(composeContractEndBlockmsg(item.second,outMsg,true) == 0){
                CBlock block;
                block.ParseFromString(outMsg.block());
                int ret = VerifyBlockFlowSignNode(outMsg);
                if(ret == 0){
                    //After the verification is passed, the broadcast block is directly built
                    if(block.version() >= global::ca::kInitBlockVersion){
                        auto NowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
                        MagicSingleton<DONbenchmark>::GetInstance()->SetByBlockHash(block.hash(), &NowTime, 2);
                        MagicSingleton<BlockMonitor>::GetInstance()->SendBroadcastContractAddBlock(outMsg.block(),block.height());
                        std::cout <<"block check send out msg";
                        DEBUGLOG("BuildBlockBroadcastMsg successful..., block hash : {}",block.hash());
                    }else{
                        std::cout << "The version is too low. Please update the version!" << std::endl;
                    }
                }else{
                    ERRORLOG("Verify Block Flow SignNode Failed! ret : {}",ret);
                }
            }else{
                ERRORLOG("Compose blockMsg failed!");
            }
            hashKey.push_back(temBlock.hash());
        }else if(lagTime > kTenSecond){
            hashKey.push_back(temBlock.hash());
            ERRORLOG("Block Flow Timeout! block hash : {}",temBlock.hash());
        }
    }
	
    if(!hashKey.empty())
	{
		for (auto &hash : hashKey)
		{
			RemoveContract(hash);
		}
	}
	hashKey.clear();    
}

void BlockStroage::composeEndBlockmsg(std::vector<BlockMsg> &msgvec)
{
	for(auto &msg : msgvec)
	{  
        CBlock block;
        block.ParseFromString(msg.block());

        if(block.sign_size() == 1)     //Exclude yourself
        {
            continue;
        }

        if(block.sign_size() != 2)
        {
            continue;
        }
        else
        {
            CBlock endBlock;
            endBlock.ParseFromString(msgvec[0].block()); 
            CSign * sign  = endBlock.add_sign();
            // sign->set_id(composeBlock.sign(1).id());
            sign->set_pub(block.sign(1).pub());
            sign->set_sign(block.sign(1).sign());
            msgvec[0].set_block(endBlock.SerializeAsString());

        }    
    }        
}

int  BlockStroage::composeContractEndBlockmsg(const std::vector<ContractBlockMsg> &msgVec, ContractBlockMsg & outMsg , bool isVrf)
{
    std::vector<ContractBlockMsg> _vrfMsgVec;
    if(isVrf)
    {
        CBlock temBlock;
        temBlock.ParseFromString(msgVec.at(0).block());
        Cycliclist<ContractBlockMsg> list;
        std::vector<ContractBlockMsg> secondMsg = msgVec;
        secondMsg.erase(secondMsg.begin());

        for(auto &msgBlock : secondMsg)
        {
            list.push_back(msgBlock);
        }

        std::string outPut , proof;
        Account defaultAccount;
        if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount) != 0)
        {
            ERRORLOG("Failed to get the default account");
            return -1;
        }

        int ret = MagicSingleton<VRF>::GetInstance()->CreateVRF(defaultAccount.pkey, temBlock.hash(), outPut, proof);
        if (ret != 0)
        {
            ERRORLOG("error create :{} generate VRF info fail",ret);
            return -2;
        }

        double randNum = MagicSingleton<VRF>::GetInstance()->GetRandNum(outPut);
        int randPos = list.size() * randNum;
        const int signMsgcnt = global::ca::kConsensus / 2;
        auto endMsgpos = randPos - signMsgcnt;

        std::vector<ContractBlockMsg> targetMsg;
        for (; targetMsg.size() < (global::ca::kConsensus - 1); endMsgpos++)
        {
            targetMsg.push_back(list[endMsgpos]);
        }

        if(targetMsg.size() != (global::ca::kConsensus - 1))
        {
            std::cout << "size" << targetMsg.size() << std::endl;
            ERRORLOG("target lazy weight, size = {}",targetMsg.size());
            return -3;
        }
    
        for(auto & msgTmg : targetMsg)
        {
            _vrfMsgVec.push_back(msgTmg);
        }
    }    

    CBlock endBlock;
    endBlock.ParseFromString(msgVec[0].block()); 
	for(auto &msg : _vrfMsgVec)
	{   
        CBlock block;
        block.ParseFromString(msg.block());

        if(block.sign_size() != 2)
        {
            continue;
        }
        else
        {

            CSign * sign  = endBlock.add_sign();
            sign->set_pub(block.sign(1).pub());
            sign->set_sign(block.sign(1).sign());
            INFOLOG("rand block sign = {}",GetBase58Addr(block.sign(1).pub()));

        }
    }
    std::string addr = GetBase58Addr(endBlock.sign(0).pub());
    outMsg.set_block(endBlock.SerializeAsString());
    return 0;       
}

void BlockStroage::Remove(const std::string &blockhash)
{
	for(auto iter = _BlockMap.begin(); iter != _BlockMap.end();)
	{
		if (iter->first == blockhash)
		{
			iter = _BlockMap.erase(iter);
			DEBUGLOG("BlockStroage::Remove");
		}
		else
		{
			iter++;
		}
	}
}

void BlockStroage::RemoveContract(const std::string &blockhash)
{
	for(auto iter = _BlockMap_Contract.begin(); iter != _BlockMap_Contract.end();)
	{
		if (iter->first == blockhash)
		{
			iter = _BlockMap_Contract.erase(iter);
			DEBUGLOG("BlockStroage::Remove");
		}
		else
		{
			iter++;
		}
	}
}

void BlockStroage::CommitSeekTask(uint64_t seekHeight)
{
    if(IsSeekTask(seekHeight))
    {
        return;
    }
    std::unique_lock<std::shared_mutex> lck(_prehashMutex);
    if(_preHashMap.size() > 100)
    {
        auto endHeight = _preHashMap.end()->first;
        std::map<uint64_t, std::shared_future<RetType>> PreHashTemp(_preHashMap.find(endHeight - 10), _preHashMap.end());
        _preHashMap.clear();
        _preHashMap.swap(PreHashTemp);
    }
    DEBUGLOG("CommitSeekTask, height:{}", seekHeight);
    auto task = std::make_shared<std::packaged_task<RetType()>>(std::bind(&BlockStroage::_SeekPreHashThread, this, seekHeight));
    try
    {
        _preHashMap[seekHeight] = task->get_future();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    MagicSingleton<taskPool>::GetInstance()->commit_syncBlock_task([task](){(*task)();});
    return;
}

bool BlockStroage::IsSeekTask(uint64_t seekHeight)
{
    std::shared_lock<std::shared_mutex> lck(_prehashMutex);
    if(_preHashMap.find(seekHeight) != _preHashMap.end())
    {
        DEBUGLOG("seek_prehash_task repeat");
        return true;
    }
    return false;
}

RetType BlockStroage::_SeekPreHashThread(uint64_t seekHeight)
{
    DEBUGLOG("_SeekPreHashThread Start");
    uint64_t chainHeight = 0;
    if(!MagicSingleton<BlockHelper>::GetInstance()->ObtainChainHeight(chainHeight))
    {
        DEBUGLOG("ObtainChainHeight fail!!!");
        return {"",0};
    }
    uint64_t selfNodeHeight = 0;
    std::vector<std::string> pledgeAddr; // stake and invested addr
    {
        DBReader dbReader;
        auto status = dbReader.GetBlockTop(selfNodeHeight);
        if (DBStatus::DB_SUCCESS != status)
        {
            DEBUGLOG("GetBlockTop fail!!!");
            return {"",0};
        }
        std::vector<std::string> stakeAddr;
        status = dbReader.GetStakeAddress(stakeAddr);
        if (DBStatus::DB_SUCCESS != status && DBStatus::DB_NOT_FOUND != status)
        {
            DEBUGLOG("GetStakeAddress fail!!!");
            return {"",0};
        }

        for(const auto& addr : stakeAddr)
        {
            if(VerifyBonusAddr(addr) != 0)
            {
                DEBUGLOG("{} doesn't get invested, skip", addr);
                continue;
            }
            pledgeAddr.push_back(addr);
        }
    }
    std::vector<std::string> sendNodeIds;
    if (GetPrehashFindNode(10, chainHeight, pledgeAddr, sendNodeIds) != 0)
    {
        ERRORLOG("get sync node fail");
        return {"",0};
    }
    if(seekHeight == 0 || seekHeight > selfNodeHeight)
    {
        DEBUGLOG("seekHeight:{}, selfNodeHeight:{}", seekHeight, selfNodeHeight);
    }
    return _SeekPreHashByNode(sendNodeIds, seekHeight, selfNodeHeight, chainHeight);
}

int GetPrehashFindNode(uint32_t num, uint64_t selfNodeHeight, const std::vector<std::string> &pledgeAddr,
                            std::vector<std::string> &sendNodeIds)
{
    int ret = 0;
    if ((ret = MagicSingleton<SyncBlock>::GetInstance()->GetFastSyncNode(num, selfNodeHeight, pledgeAddr, sendNodeIds)) != 0)
    {
        ERRORLOG("get seek node fail, ret:{}", ret);
        return -1;
    }
    return 0;
}
// int DoProtoBlockStatus(const BlockStatus& blockStatus, const std::string destNode)
// {
//     net_send_message<BlockStatus>(destNode, blockStatus, net_com::Priority::kPriority_High_1);
//     return 0;
// }



RetType BlockStroage::_SeekPreHashByNode(
		const std::vector<std::string> &sendNodeIds, uint64_t seekHeight, const uint64_t &selfNodeHeight, const uint64_t &chainHeight)
{
    std::string msgId;
    uint64_t succentCount = 0;
    if (!GLOBALDATAMGRPTR.CreateWait(10, sendNodeIds.size() * 0.8, msgId))
    {
        ERRORLOG("CreateWait fail!!!");
        return {"", 0};
    }
    for (auto &nodeId : sendNodeIds)
    {
        if(!GLOBALDATAMGRPTR.AddResNode(msgId, nodeId))
        {
            return {"", 0};
        }
        DEBUGLOG("new seek get block hash from {}", nodeId);
        SendSeekGetPreHashReq(nodeId, msgId, seekHeight);
    }
    std::vector<std::string> retDatas;
    if (!GLOBALDATAMGRPTR.WaitData(msgId, retDatas))
    {
        if(retDatas.size() < sendNodeIds.size() * 0.5)
        {
            ERRORLOG("wait seek block hash time out send:{} recv:{}", sendNodeIds.size(), retDatas.size());
            return {"", 0};
        }
    }

    std::map<std::string, bool> nodeAddrs;
    MagicSingleton<PeerNode>::GetInstance()->get_nodelist(nodeAddrs);
    
    SeekPreHashByHightAck ack;
    std::map<uint64_t, std::map<std::string, uint64_t>> seekPreHashes;
    for (auto &retData : retDatas)
    {
        ack.Clear();
        if (!ack.ParseFromString(retData))
        {
            continue;
        }
        succentCount++;
        uint64_t seekHeight = ack.seek_height();
        for(auto& prehash : ack.prehashes())
        {
            if(seekPreHashes[seekHeight].find(prehash) == seekPreHashes[seekHeight].end())
            {
                seekPreHashes[seekHeight][prehash] = 1;
            }
            else
            {
                seekPreHashes[seekHeight][prehash]++;
            }
        } 
    }

    std::set<std::string> verifyHashes;
    size_t verifyNum = succentCount / 5 * 3;

    for (auto &iter : seekPreHashes)
    {
        uint16_t maxPercentage = 0;
        std::string maxPercentagePrehash;
        for(auto &prehash : iter.second)
        {
            if (prehash.second >= verifyNum)
            {
                uint16_t percentage = prehash.second / (double)succentCount * 100;
                if(maxPercentage < percentage)
                {
                    maxPercentage = percentage;
                    maxPercentagePrehash = prehash.first;
                }
            }
        }
        if(maxPercentage >= 70)
        {
            DEBUGLOG("_SeekPreHashByNode <success> !!! ,seekHeight:{}, maxPercentage:{} > 70% , maxPercentagePrehash:{}", iter.first, maxPercentage, maxPercentagePrehash);
            return {maxPercentagePrehash, maxPercentage};
        }
        else
        {
            DEBUGLOG("_SeekPreHashByNode <fail> !!! ,seekHeight:{}, maxPercentage:{} < 70% , maxPercentagePrehash:{}", iter.first, maxPercentage, maxPercentagePrehash);
        }
    }
    return {"", 0};
}

void BlockStroage::ForceCommitSeekTask(uint64_t seekHeight)
{
    std::unique_lock<std::shared_mutex> lck(_prehashMutex);
    DEBUGLOG("ForceCommitSeekTask, height:{}", seekHeight);
    auto task = std::make_shared<std::packaged_task<RetType()>>(std::bind(&BlockStroage::_SeekPreHashThread, this, seekHeight));
    try
    {
        _preHashMap[seekHeight] = task->get_future();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    MagicSingleton<taskPool>::GetInstance()->commit_syncBlock_task([task](){(*task)();});
    return;
}

std::shared_future<RetType> BlockStroage::GetPrehash(const uint64_t height)
{
    std::shared_lock<std::shared_mutex> lck(_prehashMutex);
    auto result = _preHashMap.find(height);
    if(result != _preHashMap.end())
    {
       return result->second;
    }
    DEBUGLOG("_preHashMap[height] {},{},{}",height,result->first);
    return {};
}

void SendSeekGetPreHashReq(const std::string &nodeId, const std::string &msgId, uint64_t seekHeight)
{
    SeekPreHashByHightReq req;
    req.set_self_node_id(net_get_self_node_id());
    req.set_msg_id(msgId);
    req.set_seek_height(seekHeight);
    net_send_message<SeekPreHashByHightReq>(nodeId, req, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
    return;
}

// int HandleBlockStatusMsg(const std::shared_ptr<BlockStatus> &msg, const MsgData &msgData)
// {
//     if(!PeerNode::PeerNodeVerifyNodeId(msgData.fd, msg->id()))
//     {
//         return -1;
//     }

//     MagicSingleton<BlockStroage>::GetInstance()->AddBlockStatus(*msg);
//     return 0;
// }

int HandleSeekGetPreHashReq(const std::shared_ptr<SeekPreHashByHightReq> &msg, const MsgData &msgdata)
{
    DEBUGLOG("req");
    SeekPreHashByHightAck ack;
    SendSeekGetPreHashAck(ack,msg->self_node_id(), msg->msg_id(), msg->seek_height());
    net_send_message<SeekPreHashByHightAck>(msg->self_node_id(), ack, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
    return 0;
}
int HandleSeekGetPreHashAck(const std::shared_ptr<SeekPreHashByHightAck> &msg, const MsgData &msgdata)
{
    DEBUGLOG("ack");
    GLOBALDATAMGRPTR.AddWaitData(msg->msg_id(), msg->SerializeAsString());
    return 0;
}

void SendSeekGetPreHashAck(SeekPreHashByHightAck& ack,const std::string &nodeId, const std::string &msgId, uint64_t seekHeight)
{
    DEBUGLOG("SendSeekGetPreHashAck, id:{}, height:{}",  nodeId, seekHeight);
    ack.set_self_node_id(net_get_self_node_id());
    DBReader dbReader;
    uint64_t selfNodeHeight = 0;
    if (0 != dbReader.GetBlockTop(selfNodeHeight))
    {
        ERRORLOG("GetBlockTop(txn, top)");
        return;
    }
    ack.set_msg_id(msgId);
    std::vector<std::string> blockHashes;
    if(seekHeight > selfNodeHeight)
    {
        DEBUGLOG("seekHeight:{} > selfNodeHeight:{}", seekHeight, selfNodeHeight);
        return;
    }

    if (DBStatus::DB_SUCCESS != dbReader.GetBlockHashsByBlockHeight(seekHeight, blockHashes))
    {
        ERRORLOG("GetBlockHashsByBlockHeight fail !!!");
        return;
    }
    ack.set_seek_height(seekHeight);
    for(auto &hash : blockHashes)
    {
        ack.add_prehashes(hash);
    }
    
    return;
}

int BlockStroage::VerifyBlockFlowSignNode(const ContractBlockMsg & blockMsg)
{
    CBlock block;
    block.ParseFromString(blockMsg.block());

	// Verify Block flow verifies the signature of the node
    std::pair<std::string, std::vector<std::string>> nodesPair;
    
    MagicSingleton<VRF>::GetInstance()->getVerifyNodes(block.hash(), nodesPair);

    //Block signature node in cache
    std::vector<std::string> cacheNodes = nodesPair.second;

    //The signature node in the block flow
    std::vector<std::string> verifyNodes;
    std::string defaultBase58addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    for(auto &item : block.sign())
    {
        std::string addr = GetBase58Addr(item.pub());
        if(addr != defaultBase58addr)
        {
            verifyNodes.push_back(addr);
        }
    }
    
    
    //Compare whether the nodes in the two containers are consistent
    for(auto & signNode : verifyNodes)
    {
        if(std::find(cacheNodes.begin(), cacheNodes.end(), signNode) == cacheNodes.end())
        {
            ERRORLOG(" The nodes in the two containers are inconsistent = {}, blockHash:{}",signNode, block.hash());
            return -1;
        }
    }

    return 0;
}

void BlockStroage::ClearPreHashMap()
{
    std::unique_lock<std::shared_mutex> lck(_prehashMutex);
    _preHashMap.clear();
}