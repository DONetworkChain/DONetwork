#include "ca_blockmonitor.h"
#include "ca/ca_tranmonitor.h"
#include "ca_blockhelper.h"
#include "utils/VRF.hpp"

uint32_t BlockMonitor::MaxSendSize = 100;
uint64_t BlockMonitor::selfTime  = 0;

void BlockMonitor::checkTxSuccessRate()
{
	std::unique_lock<std::mutex> lck(mutex_);
	DBReader reader;
	int DropshippingTxVecFail = 0;
	std::vector<std::string> failTxhashVec;
	for(const auto& txHash : DropshippingTxVec)
	{
		std::string blockHash;
		reader.GetBlockHashByTransactionHash(txHash, blockHash);

		if (blockHash.empty())
		{
			failTxhashVec.push_back(txHash);
			DropshippingTxVecFail++;
			continue;
		}
	}
	
	std::ofstream outputFile("./failTxhash.txt");
	if (outputFile.is_open())
	{
		for(const auto& it : failTxhashVec)
		{
			outputFile << it << "\n";
		}
		outputFile.close();
	}
	double successRate = (1 - static_cast<double>(DropshippingTxVecFail) / DropshippingTxVec.size()) * 100;
	DEBUGLOG(GREEN "addDropshippingTxVec Txsize: {}, DropshippingTxVecFail size:{}, SuccessRate:{}%" RESET, DropshippingTxVec.size(), DropshippingTxVecFail, successRate );
	std::cout<< GREEN << "addDropshippingTxVec Txsize:" << DropshippingTxVec.size() << RESET << std::endl;
	std::cout<< GREEN <<"DropshippingTxVecFail size:" << DropshippingTxVecFail<< RESET << std::endl;
	std::cout<< GREEN <<"SuccessRate:" << successRate << "%" << RESET << std::endl;
	DropshippingTxVec.clear();

	int DoHandleTxVecFail = 0;
	for(const auto& txHash : DoHandleTxVec)
	{
		std::string blockHash;
		reader.GetBlockHashByTransactionHash(txHash, blockHash);

		if (blockHash.empty())
		{
			DoHandleTxVecFail++;
			continue;
		}
	}
	DEBUGLOG(GREEN "addDoHandleTxTxVec Txsize: {}, DoHandleTxVecFailFail size:{}" RESET, DoHandleTxVec.size(), DoHandleTxVecFail);
	DoHandleTxVec.clear();
}

void BlockMonitor::addDropshippingTxVec(const std::string& txHash)
{
	std::unique_lock<std::mutex> lck(mutex_);
	DropshippingTxVec.push_back(txHash);
}
void BlockMonitor::addDoHandleTxTxVec(const std::string& txHash)
{
	std::unique_lock<std::mutex> lck(mutex_);
	DoHandleTxVec.push_back(txHash);
}


int BlockMonitor::AddBlockMonitor(const std::string& blockhash , const std::string & id , const uint32_t& ackFlag)
{
    std::unique_lock<std::mutex> lck(_monitor_mutex_);
    {
		BlockAck ackmsg;
		ackmsg.id = id;
		ackmsg.is_response = ackFlag;
		_Respon.insert(std::make_pair(blockhash,ackmsg));
    }
    lck.unlock();
    return 0;
}

int BlockMonitor::SendBroadcastAddBlock(std::string strBlock, uint64_t blockHeight,uint64_t SendSize)
{
    std::vector<Node> list;
	list = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
	{
		// Filter nodes that meet the height
		std::vector<Node> tmpList;
		if (blockHeight != 0)
		{
			for (auto & item : list)
			{
				if (item.height >= blockHeight - 1)
				{
					tmpList.push_back(item);
				}
			}
			list = tmpList;
		}
	}

    BuildBlockBroadcastMsg buildBlockBroadcastMsg;
    buildBlockBroadcastMsg.set_version(global::kVersion);
	buildBlockBroadcastMsg.set_id(net_get_self_node_id());
	buildBlockBroadcastMsg.set_blockraw(strBlock);
	//VRF protocol for filling block flow
	CBlock block;
    block.ParseFromString(strBlock);
	std::pair<std::string,Vrf> vrf;
	MagicSingleton<VRF>::GetInstance()->getVrfInfo(block.hash(), vrf);
	Vrf *vrfinfo = buildBlockBroadcastMsg.mutable_vrfinfo();
	vrfinfo->CopyFrom(vrf.second);

	std::random_device device;
	std::mt19937 engine(device());
	int send_size = std::min(list.size(),(size_t)SendSize);
	MaxSendSize = send_size;
	int count = 0;
	while (count < send_size && !list.empty())
	{
		int index = engine() % list.size();
        buildBlockBroadcastMsg.set_flag(1);
		++count;
		
		list.erase(list.begin() + index);
	}
	
    bool isSucceed = net_com::BlockBroadcast_message(buildBlockBroadcastMsg);
	if(isSucceed == false)
	{
        ERRORLOG("Broadcast BuildBlockBroadcastMsg failed!");
        return -1;
	}

	DEBUGLOG("***********net broadcast time{}",MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
	std::map<std::string,std::string> temp;
	temp.insert(std::make_pair(net_get_self_node_id(),"true"));
	_Self.insert(std::make_pair(block.hash(),temp));
	blockCache.insert(std::make_pair(block.hash(),strBlock));

	selfTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	return 0;
}


int BlockMonitor::SendBroadcastContractAddBlock(std::string strBlock, uint64_t blockHeight,uint64_t SendSize)
{
	    std::vector<Node> list;
	list = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
	{
		// Filter nodes that meet the height
		std::vector<Node> tmpList;
		if (blockHeight != 0)
		{
			for (auto & item : list)
			{
				if (item.height >= blockHeight - 1)
				{
					tmpList.push_back(item);
				}
			}
			list = tmpList;
		}
	}

    BuildBlockBroadcastMsg buildBlockBroadcastMsg;
    buildBlockBroadcastMsg.set_version(global::kVersion);
	buildBlockBroadcastMsg.set_id(net_get_self_node_id());
	buildBlockBroadcastMsg.set_blockraw(strBlock);
	//VRF protocol for filling block flow
	CBlock block;
    block.ParseFromString(strBlock);
	std::pair<std::string,NewVrf> vrf;
	MagicSingleton<VRF>::GetInstance()->getNewVrfInfo(block.hash(), vrf);
	NewVrf *contractvrf = buildBlockBroadcastMsg.mutable_contractvrf();
	contractvrf->CopyFrom(vrf.second);

	std::random_device device;
	std::mt19937 engine(device());
	int send_size = std::min(list.size(),(size_t)SendSize);
	MaxSendSize = send_size;
	int count = 0;
	while (count < send_size && !list.empty())
	{
		int index = engine() % list.size();
        buildBlockBroadcastMsg.set_flag(1);
		++count;
		
		list.erase(list.begin() + index);
	}
	
    bool isSucceed = net_com::BlockBroadcast_message(buildBlockBroadcastMsg);
	if(isSucceed == false)
	{
        ERRORLOG("Broadcast BuildBlockBroadcastMsg failed!");
        return -1;
	}

	DEBUGLOG("***********net broadcast time{}",MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
	std::map<std::string,std::string> temp;
	temp.insert(std::make_pair(net_get_self_node_id(),"true"));
	_Self.insert(std::make_pair(block.hash(),temp));
	blockCache.insert(std::make_pair(block.hash(),strBlock));

	selfTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	return 0;
}

int BlockMonitor::HandleBroadcastAddBlockAck(const BuildBlockBroadcastMsgAck & msg)
{
	std::unique_lock<std::mutex> lck(_monitor_mutex_);
    uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	static const uint64_t WAIT_TIME = 1 * 5 * 1000000;
	std::map<std::string , std::string>::iterator iter;
	std::vector<std::string> NeedRemove;
	for(auto &item : _Self)
	{
		if(item.first == msg.blockhash())
		{
			item.second.insert(std::make_pair(msg.id(),msg.success()));
			for(iter = item.second.begin();iter!=item.second.end();iter++)
			{
				if(iter->first == net_get_self_node_id())
				{
					continue;
				}

				if(iter->second == "true")
				{
					success_id.push_back(msg.id());
				}
			}
			if( (nowTime - selfTime) <=  WAIT_TIME && success_id.size() >= 0.75 * 0.75 * MaxSendSize)
			{

				for(auto &bloche : blockCache)
				{
					if(bloche.first == item.first)
					{
						CBlock block;
                		block.ParseFromString(bloche.second);
						MagicSingleton<BlockHelper>::GetInstance()->AddBroadcastBlock(block);
						//MagicSingleton<TranMonitor>::GetInstance()->SetBroadCastAck(block);
						DEBUGLOG("-------->HandleBroadcastAddBlockAck loacl");
					}
				}
				success_id.clear();
				NeedRemove.push_back(item.first);
			}
			else if ( (nowTime - selfTime) > WAIT_TIME && success_id.size() < 0.75 * 0.75 * MaxSendSize)
			{
				success_id.clear();
				NeedRemove.push_back(item.first);
			}
		}
	}

	if( !NeedRemove.empty() )
	{
		for(auto & i : NeedRemove)
		{
			Remove(i);
		}
	}
    return 0;
}

 int BlockMonitor::SendSuccessBlockSituationAck(const CBlock &block)
 {
	BuildBlockBroadcastMsgAck  buildBlockBroadcastMsgAck;
	buildBlockBroadcastMsgAck.set_version(global::kVersion);
	buildBlockBroadcastMsgAck.set_id(net_get_self_node_id());
	
	for(auto &i : _Respon)
	{
		if(i.first ==  block.hash() && i.second.is_response == 1)
		{
			DEBUGLOG("Send SuccessBlock Ack");
			buildBlockBroadcastMsgAck.set_success("true");
			buildBlockBroadcastMsgAck.set_blockhash(block.hash());
			net_send_message<BuildBlockBroadcastMsgAck>( i.second.id ,buildBlockBroadcastMsgAck);
			DEBUGLOG("other node Send Success response time{}",MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());	
		}
	}
	return 0;
 }


 int BlockMonitor::SendFailedBlockSituationAck(const CBlock &block)
 {
	BuildBlockBroadcastMsgAck  buildBlockBroadcastMsgAck;
	buildBlockBroadcastMsgAck.set_version(global::kVersion);
	buildBlockBroadcastMsgAck.set_id(net_get_self_node_id());
	for(auto &i : _Respon)
	{
		if(i.first ==  block.hash() && i.second.is_response == 1)
		{
			std::cout << "SendFailedBlockSituationAck" << std::endl;
			buildBlockBroadcastMsgAck.set_success("false");
			buildBlockBroadcastMsgAck.set_blockhash(block.hash());
			net_send_message<BuildBlockBroadcastMsgAck>( i.second.id ,buildBlockBroadcastMsgAck);
			DEBUGLOG("other node Send  Failed response time{}",MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());	
		}
	}
	return 0;
 }


 void BlockMonitor::Remove(const std::string& bolckraw)
{
	for(auto iter = _Self.begin(); iter != _Self.end();)
	{
		if (iter->first == bolckraw)
		{
			iter = _Self.erase(iter);
			DEBUGLOG("BlockMonitor::Remove");
		}
		else
		{
			iter++;
		}
	}
}