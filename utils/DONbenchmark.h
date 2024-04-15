
#ifndef __DONBENCHMARK_H_
#define __DONBENCHMARK_H_

#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <memory>
#include "proto/ca_protomsg.pb.h"

class DONbenchmark
{
public:
    DONbenchmark();
    void OpenBenchmark();
    void OpenBenchmark2();
    void Clear();

    void SetTransactionInitiateBatchSize(uint32_t amount);
    void AddTransactionInitiateMap(uint64_t start, uint64_t end);
    void ClearTransactionInitiateMap();
    void AddtransactionMemVerifyMap(const std::string& tx_hash, uint64_t cost_time);
    void AddtransactionDBVerifyMap(const std::string& tx_hash, uint64_t cost_time);
    void AddAgentTransactionReceiveMap(const std::shared_ptr<TxMsgReq> &msg);
    void AddTransactionSignReceiveMap(const std::string& tx_hash);
    void CalculateTransactionSignReceivePerSecond(const std::string& tx_hash, uint64_t compose_time);
    void AddBlockContainsTransactionAmountMap(const std::string& block_hash, int tx_amount);
    void AddBlockVerifyMap(const std::string& block_hash, uint64_t cost_time);
    void IncreaseTransactionInitiateAmount();
    void PrintTxCount();
    void AddBlockPoolSaveMapStart(const std::string& block_hash);
    void AddBlockPoolSaveMapEnd(const std::string& block_hash);

    void PrintBenchmarkSummary(bool export_to_file);


    ///////////DoHandleTx
    void SetByTxHash(const std::string& TxHash, void* arg, uint16_t type);
    void SetByBlockHash(const std::string& BlockHash, void* arg, uint16_t type, void* arg2 = nullptr, void* arg3 = nullptr, void* arg4 = nullptr);
    void SetTxHashByBlockHash(const std::string& BlockHash, const std::string& TxHash);
    void PrintBenchmarkSummary_DoHandleTx(bool export_to_file);

private:
    bool benchmarkSwitch;
    bool benchmarkSwitch2{false};
    std::mutex transactionInitiateMapMutex;
    uint32_t batchSize;
    std::vector<std::pair<uint64_t, uint64_t>> transactionInitiateMap;
    std::map<uint64_t, std::pair<double, double>> transactionInitiateCache;
    void CaculateTransactionInitiateAmountPerSecond();

    struct verify_time_record
    {
        verify_time_record() : mem_verify_time(0), db_verify_time(0){};
        uint64_t mem_verify_time;
        double mem_verify_amount_per_second;
        uint64_t db_verify_time;
        double db_verify_amount_per_second;
        uint64_t total_verify_time;
        double total_verify_amount_per_second;
    };
    std::mutex transactionVerifyMapMutex;
    std::map<std::string, verify_time_record> transactionVerifyMap;

    std::mutex agentTransactionReceiveMapMutex;
    std::map<std::string, uint64_t> agentTransactionReceiveMap;

    std::mutex transactionSignReceiveMapMutex;
    std::map<std::string, std::vector<uint64_t>> transactionSignReceiveMap;
    std::map<std::string, std::pair<uint64_t, double>> transactionSignReceiveCache;

    std::mutex blockContainsTransactionAmountMapMutex;
    std::map<std::string, int> blockContainsTransactionAmountMap;

    std::mutex blockVerifyMapMutex;
    std::map<std::string, std::pair<uint64_t, double>> blockVerifyMap;

    std::atomic_uint64_t transactionInitiateAmount;
    std::atomic_uint64_t transactionInitiateHeight;

    std::mutex blockPoolSaveMapMutex;
    std::map<std::string, std::pair<uint64_t, uint64_t>> blockPoolSaveMap;

    ///////////DoHandleTx
    struct TxVerify{
        TxVerify(): Verify_2(0), Verify_3(0){};

        uint64_t StartTime; // 1

        uint64_t Verify_2;// 2
        uint64_t Verify_3;// 3

        uint64_t EndTime; // 4
    };
    struct BlockVerify{
        BlockVerify(): Verify_4(0), Verify_5(0){};

        uint64_t Time;// 1
        uint64_t BroadcastTime;// 2

        uint64_t Verify_4;// 1
        uint64_t Verify_5;// 4

        uint64_t TxNumber;// 1
        uint64_t Hight;// 1
        
    };
    std::mutex DoHandleTxMutex;
    std::map<std::string,TxVerify> TV;
    std::multimap<std::string,std::string> BT;
    std::map<std::string,BlockVerify> BV;

};

#endif