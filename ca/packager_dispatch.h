/*
 * @Author: lyw 15035612538@163.com
 * @Date: 2024-03-25 10:07:37
 * @LastEditors: lyw 15035612538@163.com
 * @LastEditTime: 2024-04-15 00:35:07
 * @FilePath: /don/ca/packager_dispatch.h
 */
#ifndef _PACKAGER_DISPATCH_
#define _PACKAGER_DISPATCH_

#include <map>
#include <list>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <vector>
#include <string>
#include <utils/json.hpp>
#include <shared_mutex>
#include "../proto/transaction.pb.h"
#include "../proto/ca_protomsg.pb.h"
#include "../proto/block.pb.h"
#include "utils/CTimer.hpp"
#include "utils/MagicSingleton.h"
#include "include/logging.h"
#include "ca/ca_dispatchtx.h"

class packDispatch
{
    /* data */
public:
    packDispatch(/* args */) = default;
    ~packDispatch() = default;
public:
    void Add(const std::string& contractHash, const std::vector<std::string>& dependentContracts);
    void AddTx(const std::string& contractHash, const CTransaction &msg);
    void GetDependentData(std::vector<std::pair<std::set<std::string>,std::vector<CTransaction>>> &Dependent ,std::vector<CTransaction> &nonDependent);
private:
    std::mutex _packDispatchMutex;
    std::unordered_map<std::string, std::vector<std::string>> _packDispatchDependent;
    std::mutex _packDispatchTxMsgReqMutex;
    std::unordered_map<std::string, CTransaction> _packDispatchTxCache; 
};

#endif
