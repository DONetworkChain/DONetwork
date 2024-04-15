#ifndef _UnregisterNode_H_
#define _UnregisterNode_H_

#include <shared_mutex>
#include <map>
#include <set>
#include "utils/CTimer.hpp"
#include "node.hpp"
#include "utils/time_util.h"

class UnregisterNode
{
public:
    UnregisterNode();
    UnregisterNode(UnregisterNode &&) = delete;
    UnregisterNode(const UnregisterNode &) = delete;
    UnregisterNode &operator=(UnregisterNode &&) = delete;
    UnregisterNode &operator=(const UnregisterNode &) = delete;
    ~UnregisterNode();
public:
    int Add(const Node & node);
    int Find(const Node & node);

    bool tool_connect(const std::string & ip,int port);

    int Register();
    bool Register(std::map<uint32_t, Node> node_map);
    bool StartRegisterNode(std::map<std::string, int> &server_list);
    bool StartSyncNode();
    void GetConsensusStakeNodelist(std::map<std::string,int>& consensusStakeNodeMap);
    void GetConsensusNodelist(std::map<std::string,int>& consensusNodeMap);
    void GetIpMap(std::map<uint64_t, std::map<std::string, int>> & m1,std::map<uint64_t, std::map<std::string, int>> & m2);
    void DeleteSpiltNodeList(const std::string & base58);
    void ClearSplitNodeListData();

    int verifyVrfDataSource(const std::vector<Node>& vrfNodelist, const uint64_t& vrfTxHeight);
    static bool compareStructs(const Node& x1, const Node& x2) {
    return (x1.base58address == x2.base58address);
    }
    struct NodeCompare
    {
        bool operator()(const Node& n1, const Node& n2) const {
            return n1.base58address < n2.base58address;
        }
    };
    void splitAndInsertData(const std::map<Node, int, NodeCompare>  syncNodeCount);
private:
    std::shared_mutex _mutex_for_nodes;
    std::map<std::string, Node> _nodes;
    std::mutex _mutexStakelist;
    std::map<uint64_t,std::map<std::string,int>> stakeNodelist;
    std::map<uint64_t,std::map<std::string,int>> unStakeNodelist;
};

#endif 