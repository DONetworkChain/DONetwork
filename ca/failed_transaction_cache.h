/**
 * *****************************************************************************
 * @file        failed_transaction_cache.h
 * @brief       
 * @date        2023-09-27
 * @copyright   tfsc
 * *****************************************************************************
 */
#ifndef _DON_STROAGE_
#define _DON_STROAGE_

#include <net/if.h>
#include <unistd.h>

#include <shared_mutex>
#include <map>

#include "ca_txhelper.h"
#include "ca_global.h"
#include "proto/transaction.pb.h"
#include "proto/ca_protomsg.pb.h"
#include "net/msg_queue.h"
#include "utils/time_util.h"
#include "ca/ca_transaction_cache.h"

/**
 * @brief       
 */
class FailedTransactionCache
{
public:
    FailedTransactionCache(){ _StartTimer(); };
    ~FailedTransactionCache() = default;
    FailedTransactionCache(FailedTransactionCache &&) = delete;
    FailedTransactionCache(const FailedTransactionCache &) = delete;
    FailedTransactionCache &operator=(FailedTransactionCache &&) = delete;
    FailedTransactionCache &operator=(const FailedTransactionCache &) = delete;

public:
    /**
     * @brief       
     * 
     * @param       height: 
     * @param       msg: 
     * @return      int 
     */
	int Add(uint64_t height,const ContractTempTxMsgReq& msg);

    /**
     * @brief       
     * 
     */
    void StopTimer() { _timer.Cancel(); }
private:
    /**
     * @brief       
     * 
     */
	void _StartTimer();

    /**
     * @brief       
     * 
     * @return      true 
     * @return      false 
     */
    bool _IsEmpty();

    /**
     * @brief       
     * 
     */
	void _Check();
private:
//    friend std::string PrintCache(int where);
    mutable std::shared_mutex _txPendingMutex;
    std::map<uint64_t, std::vector<ContractTempTxMsgReq>> _txPending;
	CTimer _timer;
};

#endif