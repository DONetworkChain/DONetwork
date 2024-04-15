/**
 * *****************************************************************************
 * @file        trie.h
 * @brief       
 * @author  ()
 * @date        2023-09-28
 * @copyright   tfsc
 * *****************************************************************************
 */
#ifndef TFS_MPT_TRIE_H_
#define TFS_MPT_TRIE_H_

#include <memory>
#include <iostream>
#include <map>
#include <string>
#include <unordered_map>
#include <shared_mutex>

#include <boost/algorithm/hex.hpp>
#include <boost/uuid/detail/sha1.hpp>

#include "node.h"
#include "Common.h"
#include "RLP.h"

#include "utils/json.hpp"
#include "utils/time_util.h"
#include "utils/MagicSingleton.h"
struct ReturnVal 
{
public:
    bool dirty;
    nodeptr node;
    int err;
};
struct ReturnNode 
{
public:
    nodeptr valueNode;
    nodeptr newNode;
};

class ContractDataCache
{
public:

    void lock()
    {
        Mutex.lock();
    }

    void unlock()
    {
        Mutex.unlock();
    }

    void set(const nlohmann::json& jStorage)
    {
        std::unique_lock<std::shared_mutex> lck(contractDataMapMutex);
        for (auto it = jStorage.begin(); it != jStorage.end(); ++it)
        {
            contractDataMap[it.key()] = it.value();
        }
        return;
    }

    bool get(const std::string& key, std::string& value)
    {
        std::shared_lock<std::shared_mutex> lck(contractDataMapMutex);
        auto it = contractDataMap.find(key);
        if (it != contractDataMap.end())
        {
            value = it->second;
            return true;
        }
        return false;
    }

    void clear()
    {
        std::unique_lock<std::shared_mutex> lck(contractDataMapMutex);
        contractDataMap.clear();
    }

private:
    std::unordered_map<std::string, std::string> contractDataMap;
    mutable std::shared_mutex contractDataMapMutex;
    std::mutex Mutex;
};

class Trie
{
public:
    Trie() 
    {
        root = NULL;
    }
    Trie(std::string ContractAddr) 
    {
        root = NULL;
        this->contractAddr = ContractAddr;
    }
    Trie(std::string roothash, std::string ContractAddr) 
    {
        this->contractAddr = ContractAddr;
        auto roothashnode = std::shared_ptr<packing<hashNode>>(
            new packing<hashNode>(hashNode{ roothash }));
        root = ResolveHash(roothashnode, "");
    }

    nodeFlag newFlag()
    {
        nodeFlag nf;
        nf.dirty = true;
        return nf;
    }
    nodeptr ResolveHash(nodeptr n, std::string prefix) const;
    std::string Get(std::string& key) const;
    ReturnNode Get(nodeptr n, std::string key, int pos) const;

    ReturnVal Insert(nodeptr n, std::string prefix, std::string key, nodeptr value);

    nodeptr Update(std::string key, std::string value);

    nodeptr DescendKey(std::string key) const;
    nodeptr DecodeShort(std::string hash, dev::RLP const& r) const;
    nodeptr DecodeFull(std::string hash, dev::RLP const& r) const;
    nodeptr DecodeRef(dev::RLP const& r) const;
    nodeptr DecodeNode(std::string hash, dev::RLP const& r) const;

    nodeptr hash(nodeptr n);
    nodeptr HashShortNodeChildren(nodeptr n);
    nodeptr HashFullNodeChildren(nodeptr n);
    nodeptr ToHash(nodeptr n);
    dev::RLPStream Encode(nodeptr n);

    nodeptr Store(nodeptr n);
    nodeptr Commit(nodeptr n);
    std::array<nodeptr, 17>commitChildren(nodeptr n);

    void Save();

    std::string WapperKey(std::string str) const;
    bool HasTerm(std::string& s) const;
    std::string HexToKeybytes(std::string hex);
    int PrefixLen(std::string a, std::string b);
    int Toint(char c) const;

    void GetBlockStorage(std::pair<std::string, std::string>& rootHash, std::map<std::string, std::string>& dirtyHash);
public:
    mutable nodeptr root;
    std::string contractAddr;
    std::map<std::string, std::string> dirtyHash;
};
#endif


