#ifndef __CA_DISPATCHER_H_
#define __CA_DISPATCHER_H_
#include <mutex>
#include <thread>
#include <vector>
#include <functional>
#include <unordered_map>

#include "ca/ca_global.h"
#include "ca/ca_interface.h"
#include "ca/ca_transaction.h"
#include "ca/ca_transaction_cache.h"

class ContractDispatcher{

    public:
        ContractDispatcher() = default;
        ~ContractDispatcher() = default;
        /**
        * @brief       
        * 
        * @param       contractHash: 
        * @param       dependentContracts: 
        */
        void AddContractInfo(const std::string& contractHash, const std::vector<std::string>& dependentContracts);
        /**
        * @brief       
        * 
        * @param       contractHash: 
        * @param       msg: 
        */
        void AddContractMsgReq(const std::string& contractHash, const ContractTxMsgReq &msg);
        /**
        * @brief       
        */
        void Process();
        void setValue(const uint64_t& newValue);
        bool HasDuplicate(const std::vector<std::string>& v1, const std::vector<std::string>& v2);
    private:
        constexpr static int _contractWaitingTime = 3 * 1000000;

        struct msgInfo
        {
            std::vector<ContractTempTxMsgReq> txMsgReq;//Transaction information protocol
            std::set<std::string> nodelist;//A list of nodes when making a transaction
            NewVrf info; //vrf information
        };
        /**
        * @brief       
        */
        void _DispatcherProcessingFunc();
        /**
        * @brief       
        * 
        * @param       v1: 
        * @param       v2: 
        * @return      true
        * @return      false  
        */
        
        /**
        * @brief       
        * 
        * @return      std::vector<std::vector<ContractTempTxMsgReq>> 
        */
        std::vector<std::vector<ContractTempTxMsgReq>> GetDependentData();
        /**
        * @brief       
        * 
        * @param       txMsgVec:
        * @return      std::vector<std::vector<ContractTempTxMsgReq>>  
        */
        std::vector<std::vector<ContractTempTxMsgReq>> GroupDependentData(const std::vector<std::vector<ContractTempTxMsgReq>> & txMsgVec);
        /**
        * @brief       
        * 
        * @param       distribution:
        * @return      int 
        */
        int DistributionContractTx(std::multimap<std::string, msgInfo>& distribution);
        /**
        * @brief       Message the transaction information to the packer
        * 
        * @param       packager:
        * @param       info:
        * @param       txsMsg:
        * @param       nodeList:
        * @return      int 
        */
        int SendTxInfoToPackager(const std::string &packager, const NewVrf &info, std::vector<ContractTempTxMsgReq> &txsMsg, const std::set<std::string> nodeList);

    private:
        std::thread _dispatcherThread;
        std::mutex _contractInfoCacheMutex;
        std::mutex _contractMsgMutex;
        std::mutex _contractHandleMutex;

        std::unordered_map<std::string/*txHash*/, std::vector<std::string>/*Contract dependency address*/> _contractDependentCache; //The data received from the initiator is stored
        std::unordered_map<std::string, ContractTempTxMsgReq> _contractMsgReqCache; //hash TxMsgReq
        std::mutex _mtx;

        bool isFirst = false;
        uint64_t timeValue;

 

};

#endif