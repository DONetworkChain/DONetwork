#ifndef _TRAN_MONITOR_
#define _TRAN_MONITOR_

#include "ca_txhelper.h"
#include "ca_global.h"

#include "proto/transaction.pb.h"
#include "proto/ca_protomsg.pb.h"
#include "proto/block.pb.h"
#include "net/msg_queue.h"
#include "utils/time_util.h"
#include "ca/ca_transaction_cache.h"

#include <net/if.h>
#include <unistd.h>
#include <map>
#include <set>

typedef std::map<std::string, std::set<std::string>> _m_base_s_block;

class Node;
//Monitoring transaction status classes
class TranMonitor
{
public:

    TranMonitor() = default;
    ~TranMonitor() = default;
    TranMonitor(TranMonitor &&) = delete;
    TranMonitor(const TranMonitor &) = delete;
    TranMonitor &operator=(TranMonitor &&) = delete;
    TranMonitor &operator=(const TranMonitor &) = delete;

public:
    struct TranMonSt
    {
        CTransaction Tx;
        std::multimap<int32_t,std::string> _MonNodeDoHandleAck;  
        std::multimap<int32_t,std::string> _SelfDohandleCount;
        std::pair<std::string,int32_t> _BroadCastAck;
        std::pair<int32_t,std::string> LaunchTime;
        std::string _ComposeStatusTime;
        std::string _VinRemoveTime;

    };
    struct t_VinSt
    {
        std::string txHash;
        std::vector<std::string> to;
        std::map<std::string, std::vector<std::string>> identifies;
        uint64_t amount;
        uint64_t timestamp;
        uint64_t gas;
        std::vector<uint64_t> toAmount;
        uint32_t type;
        int isBroadcast = 0;
        uint64_t prevBlkHeight = 0;
        uint64_t txBroadcastTime = 0;

        //bool IsNeedAgent(const CTransaction & tx);
        static void ConvertTx(const CTransaction&, uint64_t, t_VinSt&,uint64_t);
        static std::string TxToString(const t_VinSt& tx);
        static std::string TxToString(const CTransaction& tx);
    };


    struct VinSt
    {
        CTransaction tx;
        uint64_t timestamp;
        uint64_t prevBlkHeight = 0;
        std::string DB_txhash ;
    };

    struct FailureList
    {
        CTransaction tx;
        uint64_t timestamp;
    };
    

public:

    /**********_TranStatus**********/
    int AddTranMonitor(const CTransaction& Tx); 
    int SetDoHandleTxStatus(const CTransaction& Tx,const int ret);
    int ReviceDoHandleAck(const TxMsgAck& ack);
    int SetBroadCastAck(const CBlock& block);
    int SetSelfAckDoHandle(const CTransaction& Tx,const int ret);
    int SetComposeStatus(const CTransaction& Tx);
    int SetRemoveTimeStatus(const CTransaction& Tx);
    int CalcTranMonitorKey(const CTransaction& Tx,std::string& key);

    std::map<std::string,TranMonSt> GetTranStatus();

    /**********TxhashCache**********/
    void AddTxHash(const std::string& hash);
    bool RemoveByHash(const std::string& hash);
    bool isConfirmHash(const std::string& hash);

    /**********_FailureList**********/
    void PrintFailureList(std::ostream & stream);
    void AddFailureList(const CTransaction& Tx);
    int  FindFailureList(const std::string & fromAddr, std::vector<FailureList> & txs);

    /**********TxVinCache*************/
    int Add(const CTransaction& tx,uint64_t BlockHeight);
    int Add(const VinSt& vinst);
    bool IsExist(const CTransaction& tx);
    int TxVinRemove(const CTransaction& tx);
    int TxVinRemove(const std::string& txHash);
    void Print();
    // void BroadcastTxPending(const CTransaction& tx, uint64_t BlockHeight);
    int Find(const std::string & txHash, CTransaction& tx);
    int Find(const std::string & fromAddr, std::vector<CTransaction> & txs);
    int Find(const std::string & fromAddr, std::vector<TranMonitor::VinSt> & txs);
    int GetAllTx(std::vector<CTransaction> & txs);
    int GetAllTx(std::vector<TranMonitor::VinSt> & txs);
    int Clear();
    std::string TxToString(const CTransaction& tx);
    bool IsConflict(const CTransaction& tx);
    bool IsConflict(const std::map<std::string, std::vector<std::string>> &identifies);
    int  UpdateTxHash(const CTransaction& tx);

    int Process();
    static int CheckExpire(TranMonitor * Tranmonitor);
    void DoClearExpire();

    /**Signature with sync nodes is preferred**/
    void Add ( uint64_t , uint64_t , std::string , std::string );
    std::vector<Node> GetNodes();
    void test_printf();

private:
    //Cache txHash
    std::mutex _Txhash_mutex_;
    std::set<std::string> hash_confirm_cache;
    
    /********Transaction status*********/
	std::mutex _TranStatus_mutex_;
    std::map<std::string,TranMonSt> _TranStatus;//Transaction status
    
    /********Failure list*********/
	std::mutex _FailureList_mutex_;
    std::vector<FailureList> _FailureList;//Failure list

    /********Transaction caching*********/
    std::vector<VinSt> VecTx_;//TxVin
    std::mutex VecTx_mutex_;
    CTimer timer_;
    
     /**Signature with sync nodes is preferred**/
private:
    _m_base_s_block m_base_block;
public:
    uint64_t start_sync_height = 0;
    uint64_t end_sync_height = 0;
    uint64_t kMaxSendSize = 100;
};  

#endif 