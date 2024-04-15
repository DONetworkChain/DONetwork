
#include "unregister_node.h"
#include "net/peer_node.h"
#include "utils/MagicSingleton.h"
#include "common/global_data.h"
#include "common/config.h"
#include "net_api.h"
#include "net.pb.h"
#include "handle_event.h"
#include "ca/ca_algorithm.h"
#include "ca/ca_transaction.h"
#include "utils/AccountManager.h"
UnregisterNode::UnregisterNode()
{
}
UnregisterNode::~UnregisterNode()
{
}

int UnregisterNode::Add(const Node & node)
{
    std::unique_lock<std::shared_mutex> lck(_mutex_for_nodes);
    std::string key = std::to_string(node.public_ip) + std::to_string(node.public_port);

    if(key.size() == 0)
	{
		return -1;
	} 
	auto itr = _nodes.find(key);
	if (itr != _nodes.end())
	{
		return -2;
	}
	this->_nodes[key] = node;


    return 0;
}
    
int UnregisterNode::Register()
{
    std::unique_lock<std::shared_mutex> lck(_mutex_for_nodes);

    std::vector<Node> nodelist = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
    
    for (auto & unconnect_node : _nodes)
    {
        bool isFind = false;
        for (auto & node : nodelist)
        {
            if (unconnect_node.second.public_ip == node.public_ip && 
                unconnect_node.second.public_port == node.public_port)
            {
                isFind = true;
                break;
            }
        }
        
        if (isFind)
        {
            continue;
        }


        if (unconnect_node.second.fd > 0)
        {
            continue;
        }

        //net_com::SendRegisterNodeReq(unconnect_node.second, true);
    }

    _nodes.clear();

    return 0;
}

bool UnregisterNode::Register(std::map<uint32_t, Node> node_map)
{
    std::string msg_id;
    uint32 send_num = node_map.size();
    if (!GLOBALDATAMGRPTR2.CreateWait(5, send_num, msg_id))
    {
        return false;
    }

    std::vector<Node> nodelist = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
    
    for (auto & unconnect_node : node_map)
    {
        bool isFind = false;
        for (auto & node : nodelist)
        {
            if (unconnect_node.second.public_ip == node.public_ip)
            {
                isFind = true;
                break;
            }
        }
        
        if (isFind)
        {
            continue;
        }

        int ret = net_com::SendRegisterNodeReq(unconnect_node.second, msg_id, false);
        if(ret != 0)
        {
            ERRORLOG("SendRegisterNodeReq fail ret = {}", ret);
        }
    }

    std::vector<std::string> ret_datas;
    if (!GLOBALDATAMGRPTR2.WaitData(msg_id, ret_datas))//Wait for enough voting data to be received
    {
        if (ret_datas.empty())
        {
            ERRORLOG("wait Register time out send:{} recv:{}", send_num, ret_datas.size());
            return false;
        }
    }

    RegisterNodeAck registerNodeAck;
    for (auto &ret_data : ret_datas)
    {
        registerNodeAck.Clear();
        if (!registerNodeAck.ParseFromString(ret_data))
        {
            continue;
        }
        uint32_t ip = registerNodeAck.from_ip();
        uint32_t port = registerNodeAck.from_port();
        std::cout << "registerNodeAck.nodes_size(): " << registerNodeAck.nodes_size() <<std::endl;
        if(registerNodeAck.nodes_size() <= 1)
	    {
            const NodeInfo &nodeinfo = registerNodeAck.nodes(0);
            //Determine if TCP is connected
			if (MagicSingleton<BufferCrol>::GetInstance()->is_exists(ip, port) /* && node.is_established()*/)
			{
                DEBUGLOG("handleRegisterNodeAck--FALSE from.ip: {}", IpPort::ipsz(ip));
                auto ret = VerifyRegisterNode(nodeinfo, ip, port);
                if(ret < 0)
                {
                    DEBUGLOG("VerifyRegisterNode error ret:{}", ret);
                }
			}
        }
    }
    return true;
}
bool UnregisterNode::StartRegisterNode(std::map<std::string, int> &server_list)
{
    std::string msg_id;
    uint32 send_num = server_list.size();
    if (!GLOBALDATAMGRPTR2.CreateWait(5, send_num, msg_id))
    {
        return false;
    }
    Node selfNode = MagicSingleton<PeerNode>::GetInstance()->get_self_node();
    for (auto & item : server_list)
	{
        //The party actively establishing the connection
		Node node;
		node.public_ip = IpPort::ipnum(item.first);
		node.listen_ip = selfNode.listen_ip;
		node.listen_port = SERVERMAINPORT;

		if (item.first == global::local_ip)
		{
			continue;
		}

		int ret = net_com::SendRegisterNodeReq(node, msg_id, true);
        if(ret != 0)
        {
            ERRORLOG("StartRegisterNode error ret : {}", ret);
        }
	}

    std::vector<std::string> ret_datas;
    if (!GLOBALDATAMGRPTR2.WaitData(msg_id, ret_datas))//Wait for enough voting data to be received
    {
        if (ret_datas.empty())
        {
            ERRORLOG("wait StartRegisterNode time out send:{} recv:{}", send_num, ret_datas.size());
            return false;
        }
    }
    RegisterNodeAck registerNodeAck;
    std::map<uint32_t, Node> node_map;


    for (auto &ret_data : ret_datas)
    {
        registerNodeAck.Clear();
        if (!registerNodeAck.ParseFromString(ret_data))
        {
            continue;
        }

        uint32_t ip = registerNodeAck.from_ip();
        uint32_t port = registerNodeAck.from_port();
        uint32_t fd = registerNodeAck.fd();
        for (int i = 0; i < registerNodeAck.nodes_size(); i++)
	    {
            const NodeInfo &nodeinfo = registerNodeAck.nodes(i);
            {
                Node node;
                node.listen_ip = selfNode.listen_ip;
	            node.listen_port = SERVERMAINPORT;
                node.public_ip = nodeinfo.public_ip();
                node.base58address = nodeinfo.base58addr();
            }
            if(nodeinfo.base58addr() == selfNode.base58address)
            {
                continue;
            }
            if(i == 0)
            {
                //Determine if TCP is connected
                if (MagicSingleton<BufferCrol>::GetInstance()->is_exists(ip, port) /* && node.is_established()*/)
                {
                    DEBUGLOG("handleRegisterNodeAck--TRUE from.ip: {}", IpPort::ipsz(ip));
                    auto ret = VerifyRegisterNode(nodeinfo, ip, port);
                    if(ret < 0)
                    {
                        DEBUGLOG("VerifyRegisterNode error ret:{}", ret);
                        MagicSingleton<PeerNode>::GetInstance()->disconnect_node(ip, port, fd);
                        continue;
                    }
                }
            }
            else
            {
                Node node;
                node.listen_ip = selfNode.listen_ip;
	            node.listen_port = SERVERMAINPORT;
                node.public_ip = nodeinfo.public_ip();
                DEBUGLOG("Add NodeList--TRUE ip: {}", IpPort::ipsz(node.public_ip));
                if(node_map.find(node.public_ip) == node_map.end())
                {
                    node_map[nodeinfo.public_ip()] = node;
                }
            } 
        }
    }
    Register(node_map);
    return true;
}

bool UnregisterNode::StartSyncNode()
{
    std::string msg_id;
    std::vector<Node> node_list = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
    uint32 send_num = node_list.size();
    if (!GLOBALDATAMGRPTR3.CreateWait(5, send_num, msg_id))
    {
        ERRORLOG("StartSyncNode Error");
        return false;
    }
    Node selfNode = MagicSingleton<PeerNode>::GetInstance()->get_self_node();
    for (auto & node : node_list)
    {
        //Determine if TCP is connected
        if (MagicSingleton<BufferCrol>::GetInstance()->is_exists(node.public_ip, node.public_port) /* && node.is_established()*/)
        {
            net_com::SendSyncNodeReq(node, msg_id);
        }
        else
        {
            ERRORLOG("StartSyncNode error id:{} ip:{} port:{}", node.base58address, IpPort::ipsz(node.public_ip), node.public_port);
        }
    }
    std::vector<std::string> ret_datas;
    if (!GLOBALDATAMGRPTR3.WaitData(msg_id, ret_datas))//Wait for enough voting data to be received
    {
        if (ret_datas.empty())
        {
            ERRORLOG("wait StartSyncNode time out send:{} recv:{}", send_num, ret_datas.size());
            return false;
        }
    }
    SyncNodeAck syncNodeAck;
    std::map<uint32_t, Node> node_map;
    std::vector<Node> syncNodes;
    std::map<std::string,std::vector<Node>> _vrfNodelist;
    for (auto &ret_data : ret_datas)
    {
        syncNodeAck.Clear();
        if (!syncNodeAck.ParseFromString(ret_data))
        {
            continue;
        }
        auto copySyncNodeAck = syncNodeAck;
        copySyncNodeAck.clear_sign();
        std::string serVinHash = getsha256hash(copySyncNodeAck.SerializeAsString());
        DEBUGLOG("enter for StartSyncNode");
        int verifySignRet = ca_algorithm::VerifySign(syncNodeAck.sign(), serVinHash);
        if (verifySignRet != 0)
        {
            ERRORLOG("StartSyncNode targetNodelist VerifySign fail!!!");
            continue;
        }
        std::vector<Node> targetAddrList;
        for (int i = 0; i < syncNodeAck.nodes_size(); i++)
	    {
            const NodeInfo &nodeinfo = syncNodeAck.nodes(i);
            if(nodeinfo.base58addr() == selfNode.base58address)
            {
                continue;
            }
            Node node;
            node.listen_ip = selfNode.listen_ip;
            node.listen_port = SERVERMAINPORT;
            node.public_ip = nodeinfo.public_ip();
            node.base58address = nodeinfo.base58addr();
            node.time_stamp = nodeinfo.time_stamp();
            node.height = nodeinfo.height();
            if(node_map.find(node.public_ip) == node_map.end())
            {
                node_map[nodeinfo.public_ip()] = node;
            }
            targetAddrList.push_back(node);
        }
        DEBUGLOG("node_map size StartSyncNode :{}",node_map.size());
        DEBUGLOG("targetAddrList size StartSyncNode :{}",targetAddrList.size());
        _vrfNodelist[syncNodeAck.ids()] = targetAddrList;
    }
    DEBUGLOG("quit for StartSyncNode _vrfNodelist size is {}",_vrfNodelist.size());

    for(auto & item : _vrfNodelist)
    {
        std::sort(item.second.begin(), item.second.end(), compareStructs);
        auto last = std::unique(item.second.begin(), item.second.end(), compareStructs);
        item.second.erase(last, item.second.end());
        DEBUGLOG(" StartSyncNode sort and unique @@@@@@ ");
        for(auto & i : item.second)
        {
            syncNodes.push_back(i);
        }
    }

    //Count the number of IPs and the number of times they correspond to IPs
    {
        std::unique_lock<std::mutex> locker(_mutexStakelist);
        std::map<Node,int, NodeCompare> syncNodeCount;
        for(auto it = syncNodes.begin(); it != syncNodes.end(); ++it)
        {
            syncNodeCount[*it]++;
        }
        DEBUGLOG("StartSync syncNodeCount size {}",syncNodeCount.size());
        splitAndInsertData(syncNodeCount);
        syncNodes.clear();
        syncNodeCount.clear();
            //Only the latest elements are stored in the maintenance map map
    if(stakeNodelist.size() == 2 || unStakeNodelist.size() == 2)
    {
        DEBUGLOG(" StartSyncNode clearsplit  @@@@@@ ");
        ClearSplitNodeListData();
    }

    }

    if(node_map.empty())
    {
        auto configServerList = MagicSingleton<Config>::GetInstance()->GetServer();
        int port = MagicSingleton<Config>::GetInstance()->GetServerPort();
        
        std::map<std::string, int> serverList;
        for (auto & configServerIp: configServerList)
        {
            serverList.insert(std::make_pair(configServerIp, port));
        }

        MagicSingleton<UnregisterNode>::GetInstance()->StartRegisterNode(serverList);
    }
    else
    {
    Register(node_map);
    }
    return true;
}

 bool UnregisterNode::tool_connect(const std::string & ip,int port){
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (cfd == -1)
    {
        ERRORLOG("create socket err" );
        close(cfd);
        return false;
    }

    sockaddr_in server_addr;
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (connect(cfd, (sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        ERRORLOG("connection");
        close(cfd);
        return false;
    }
    close(cfd);
    return true;

 }
void UnregisterNode::GetConsensusStakeNodelist(std::map<std::string,int>& consensusStakeNodeMap)
{
    std::unique_lock<std::mutex> lck(_mutexStakelist);
    if(stakeNodelist.empty())
    {
        return;
    }
    consensusStakeNodeMap.insert(stakeNodelist.rbegin()->second.begin(), stakeNodelist.rbegin()->second.end());
    return;
}

void UnregisterNode::GetConsensusNodelist(std::map<std::string,int>& consensusNodeMap)
{
    std::unique_lock<std::mutex> lck(_mutexStakelist);
    if(stakeNodelist.empty() || unStakeNodelist.empty())
    {
        return;
    }
    consensusNodeMap.insert(stakeNodelist.rbegin()->second.begin(), stakeNodelist.rbegin()->second.end());
    
    for(const auto& it : unStakeNodelist.rbegin()->second)
    {
        consensusNodeMap[it.first] = it.second;
    }
    return;
}

void UnregisterNode::GetIpMap(std::map<uint64_t, std::map<std::string, int>> & m1,std::map<uint64_t, std::map<std::string, int>> & m2)
{
    std::unique_lock<std::mutex> locker(_mutexStakelist);
    m1 = stakeNodelist;
    m2 = unStakeNodelist;
}

void UnregisterNode::DeleteSpiltNodeList(const std::string & base58)
{
    std::unique_lock<std::mutex> locker(_mutexStakelist);
    if(stakeNodelist.empty() || unStakeNodelist.empty())
    {
        ERRORLOG("list is empty!");
        return;
    }

    for(auto & [_,iter] : stakeNodelist)
    {
        for(auto iter2 = iter.begin();iter2 != iter.end(); ++iter2)
        {
            if(iter2->first == base58)
            {
                iter2 = iter.erase(iter2);
                return;
            }
        }
    }


    for(auto & [_,iter] : unStakeNodelist)
    {
        for(auto iter2 = iter.begin();iter2 != iter.end(); ++iter2)
        {
            if(iter2->first == base58)
            {
                iter2 = iter.erase(iter2);
                return;
            }
        }
    }
}

void UnregisterNode::ClearSplitNodeListData()
{
    auto it = stakeNodelist.begin();
    stakeNodelist.erase(it);

    auto _it = unStakeNodelist.begin();
    unStakeNodelist.erase(_it);
    DEBUGLOG("ClearSplitNodeListData @@@@@ ");
}

void UnregisterNode::splitAndInsertData(const std::map<Node, int, NodeCompare>  syncNodeCount)
{
    std::map<std::string, int>  stakeSyncNodeCount;
    std::map<std::string, int>  UnstakeSyncNodeCount;
    DEBUGLOG("splitAndInsertData @@@@@ ");
    for(auto & item : syncNodeCount)
    {
        //Verification of investment and pledge
        int ret = VerifyBonusAddr(item.first.base58address);
        int64_t stakeTime = ca_algorithm::GetPledgeTimeByAddr(item.first.base58address, global::ca::StakeType::kStakeType_Node);
        if (stakeTime > 0 && ret == 0)
        {
            stakeSyncNodeCount.insert(std::make_pair(item.first.base58address,item.second));
        }
        else
        {
            UnstakeSyncNodeCount.insert(std::make_pair(item.first.base58address,item.second));
        }
    }

     DEBUGLOG("stakeNodelist size = {} , unStakeNodelist size = {}",stakeNodelist.size(),unStakeNodelist.size());
    DEBUGLOG("stakeSyncNodeCount size = {} , UnstakeSyncNodeCount size = {}",stakeSyncNodeCount.size(),UnstakeSyncNodeCount.size());
    uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    stakeNodelist[nowTime] = stakeSyncNodeCount;
    unStakeNodelist[nowTime] = UnstakeSyncNodeCount;
}

int UnregisterNode::verifyVrfDataSource(const std::vector<Node>& vrfNodelist, const uint64_t& vrfTxHeight)
{
    if(vrfNodelist.empty())
    {
        return -1;
    }
    std::set<std::string> vrfStakeNodelist;
    std::set<std::string> vrfUnStakeNodelist;
    for(const auto& node : vrfNodelist)
    {
        int ret = VerifyBonusAddr(node.base58address);
		int64_t stakeTime = ca_algorithm::GetPledgeTimeByAddr(node.base58address, global::ca::StakeType::kStakeType_Node);
		if (stakeTime > 0 && ret == 0)
		{
			vrfStakeNodelist.insert(node.base58address);
		}
        else
        {
            vrfUnStakeNodelist.insert(node.base58address);
        }
    }

    std::unique_lock<std::mutex> locker(_mutexStakelist);
    if(vrfStakeNodelist.size() >= global::ca::kNeed_node_threshold)
    {
        if(stakeNodelist.empty())
        {
            return -2;
        }
        std::set<std::string> consensusStakeNodelist;
        for(const auto& it : stakeNodelist.rbegin()->second)
        {
            Node node;
            if(MagicSingleton<PeerNode>::GetInstance()->find_node(it.first, node))
            {
                if(node.height >= vrfTxHeight)
                {
                    consensusStakeNodelist.insert(it.first);
                }
                continue;
            }
            consensusStakeNodelist.insert(it.first);
        }
        if(consensusStakeNodelist.empty())
        {
            ERRORLOG("consensusStakeNodelist.empty() == true");
            return -3;
        }
        std::set<std::string> difference;
        std::set_difference(consensusStakeNodelist.begin(), consensusStakeNodelist.end(),
                            vrfStakeNodelist.begin(), vrfStakeNodelist.end(),
                            std::inserter(difference, difference.begin()));

        for(auto& id : difference)
        {
            DEBUGLOG("difference, id:{}", id);
        }

        double differenceRatio = static_cast<double>(difference.size()) / consensusStakeNodelist.size();

        DEBUGLOG("difference size:{}, vrfStakeNodelist size:{}, consensusStakeNodelist size:{}, differenceRatio:{}", difference.size(), vrfStakeNodelist.size(), consensusStakeNodelist.size(), differenceRatio);
        if (differenceRatio <= 0.25)
        {
            return 0;
        }
        else
        {
            return -4;
        }

    }
    else if(!vrfUnStakeNodelist.empty())
    {
        if(unStakeNodelist.empty())
        {
            return -5;
        }
        std::set<std::string> consensusUnStakeNodelist;
        for(const auto& it : unStakeNodelist.rbegin()->second)
        {
            Node node;
            if(MagicSingleton<PeerNode>::GetInstance()->find_node(it.first, node))
            {
                if(node.height >= vrfTxHeight)
                {
                    consensusUnStakeNodelist.insert(it.first);
                }
                continue;
            }
            consensusUnStakeNodelist.insert(it.first);
        }

        if(consensusUnStakeNodelist.empty())
        {
            ERRORLOG("consensusUnStakeNodelist.empty() == true");
            return -6;
        }

        std::set<std::string> difference;
        std::set_difference(consensusUnStakeNodelist.begin(), consensusUnStakeNodelist.end(),
                            vrfUnStakeNodelist.begin(), vrfUnStakeNodelist.end(),
                            std::inserter(difference, difference.begin()));

        for(auto& id : difference)
        {
            DEBUGLOG("difference, id:{}", id);
        }

        double differenceRatio = static_cast<double>(difference.size()) / consensusUnStakeNodelist.size();

        DEBUGLOG("difference size:{}, vrfUnStakeNodelist size:{}, consensusUnStakeNodelist size:{}, differenceRatio:{}",difference.size(), vrfUnStakeNodelist.size(), consensusUnStakeNodelist.size(), differenceRatio);
        if (differenceRatio <= 0.25)
        {
            return 0;
        }
        else
        {
            return -7;
        }
    }
    return -8;
}