#ifndef _TXHELPER_H_
#define _TXHELPER_H_

#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <iostream>
#include <utils/json.hpp>
#include "../proto/ca_protomsg.pb.h"
#include "../proto/transaction.pb.h"
class VmInterface;
class TxHelper
{
public:

    struct Utxo
    {
        std::uint64_t value;
        std::string addr;
        std::string hash;
        std::uint32_t n;
    };

    class UtxoCompare
    {
    public:
        bool operator()(const Utxo& utxo1, const Utxo& utxo2) const
        {
            return utxo1.value < utxo2.value;
        }
    };

    typedef enum emPledgeType {
        kPledgeType_Unknown = -1,		// unknown
        kPledgeType_Node = 0,			// Node stake
    } PledgeType;

     typedef enum emInvestType {
        kInvestType_Unknown = -1,		// unknown
        kInvestType_NetLicence = 0,	    //NetLicence
    } InvestType;

    enum vrfAgentType
    {
        vrfAgentType_defalut = 0, 
        vrfAgentType_vrf ,
        vrfAgentType_local ,
        vrfAgentType_unknow,
    };

    static const uint32_t kMaxVinSize;

    TxHelper() = default;
    ~TxHelper() = default;

    static std::vector<std::string> GetTxOwner(const std::string tx_hash);
    static std::vector<std::string> GetTxOwner(const CTransaction& tx);
    static std::string GetTxOwnerStr(const std::string tx_hash);
    static std::string GetTxOwnerStr(const CTransaction& tx);
    static uint64_t GetUtxoAmount(std::string tx_hash, std::string address);
    static std::vector<std::string> GetUtxosByAddresses(std::vector<std::string> addresses);
    static std::vector<std::string> GetUtxosByTx(const CTransaction& tx);
    static int GetUtxos(const std::string & address, std::vector<TxHelper::Utxo>& utxos);

    static int Check(const std::vector<std::string>& fromAddr,
					uint64_t height
                    );

    static int FindUtxo(const std::vector<std::string>& fromAddr,
						const uint64_t need_utxo_amount,
						uint64_t& total,
						std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare>& setOutUtxos
    );

    static int CreateTxTransaction(const std::vector<std::string>& fromAddr,
									const std::map<std::string, int64_t> & toAddr,
									uint64_t height,
									CTransaction& outTx,
                                    TxHelper::vrfAgentType &type ,Vrf & info_);

    static int CreateStakeTransaction(const std::string & fromAddr,
                                        uint64_t stake_amount,
                                        uint64_t height,
                                        TxHelper::PledgeType pledgeType,
                                        CTransaction &outTx,
                                        std::vector<TxHelper::Utxo> & outVin
                                        ,TxHelper::vrfAgentType &type ,Vrf & info_);

    static int CreatUnstakeTransaction(const std::string& fromAddr,
                                        const std::string& utxo_hash,
                                        uint64_t height,
                                        CTransaction &outTx, 
                                        std::vector<TxHelper::Utxo> & outVin
                                        ,TxHelper::vrfAgentType &type ,Vrf & info_);

    static int CreateInvestTransaction(const std::string & fromAddr,
										const std::string& toAddr,
										uint64_t invest_amount,
										uint64_t height,
                                        TxHelper::InvestType investType,
										CTransaction & outTx,
										std::vector<TxHelper::Utxo> & outVin
                                        ,TxHelper::vrfAgentType &type,
                                        Vrf & info_);

    static int CreateDisinvestTransaction(const std::string& fromAddr,
										const std::string& toAddr,
										const std::string& utxo_hash,
										uint64_t height,
										CTransaction& outTx,
										std::vector<TxHelper::Utxo> & outVin
                                        ,TxHelper::vrfAgentType &type,
                                        Vrf & info_);

    static int CreateDeclareTransaction(const std::string & fromaddr,
                                        const std::string & toAddr,
                                        uint64_t amount, 
                                        const std::string & multiSignPub,
                                        const std::vector<std::string> & signAddrList,
                                        uint64_t signThreshold,
                                        uint64_t height,
                                        CTransaction& outTx
                                        ,TxHelper::vrfAgentType &type ,
                                        Vrf & info_);

    static int CreateBonusTransaction(const std::string& Addr,
										uint64_t height,
										CTransaction& outTx,
										std::vector<TxHelper::Utxo> & outVin,
                                        TxHelper::vrfAgentType &type,
                                        Vrf & info_);

    static int CreateEvmDeployContractTransaction(const std::string &fromAddr, const std::string &OwnerEvmAddr,
                                                  const std::string &code, uint64_t height,
                                                  CTransaction &outTx,
                                                  std::vector<std::string> &dirtyContract,
                                                  TxHelper::vrfAgentType &type, NewVrf &information);

    static int CreateEvmCallContractTransaction(const std::string &fromAddr, const std::string &toAddr,
                                                const std::string &txHash, const std::string &strInput,
                                                const std::string &OwnerEvmAddr, uint64_t height,
                                                CTransaction &outTx, TxHelper::vrfAgentType &type,
                                                NewVrf &information, const uint64_t contractTip,
                                                const uint64_t contractTransfer,
                                                std::vector<std::string> &dirtyContract);

    static int AddMutilSign(const std::string & addr, CTransaction &tx);

    static int AddVerifySign(const std::string & addr, CTransaction &tx);

    static int Sign(const std::string & addr, 
					const std::string & message, 
                    std::string & signature, 
					std::string & pub);

    static bool IsNeedAgent(const std::vector<std::string> & fromAddr);
    static bool IsNeedAgent(const CTransaction &tx);
    /// @brief Whether the time gap with the current highly recent block is within timeout
    /// @param txTime 
    /// @param timeout 
    /// @return 
    static bool checkTxTimeOut(const uint64_t & txTime, const uint64_t & timeout,const uint64_t & pre_height);

    static TxHelper::vrfAgentType GetVrfAgentType(const CTransaction &tx, uint64_t &pre_height);
    static void GetContractTxStartIdentity(const uint64_t &height,const uint64_t &current_time,TxHelper::vrfAgentType &type);
    static void GetTxStartIdentity(const std::vector<std::string> &fromaddr,const uint64_t &height,const uint64_t &current_time,TxHelper::vrfAgentType &type);
    static void GetInitiatorType(const std::vector<std::string> &fromaddr, TxHelper::vrfAgentType &type);


    static int sendMessage(CTransaction & outTx,int height,Vrf &info,TxHelper::vrfAgentType type);

    static std::string ReplaceCreateTxTransaction_test(const std::vector<std::string> & fromAddr,const std::map<std::string,int64_t> & toAddr,void * ack);

    static std::string ReplaceCreateStakeTransaction_test(const std::string & fromAddr, uint64_t stake_amount, 
     int32_t pledgeType,void * ack);

    //static std::string ReplaceCreateStakeTransaction(const std::string & fromAddr, uint64_t stake_amount,  int32_t pledgeType);

    static std::string ReplaceCreatUnstakeTransaction_test(const std::string& fromAddr, const std::string& utxo_hash,void * ack);

    static std::string ReplaceCreateInvestTransaction_test(const std::string & fromAddr,
                                    const std::string& toAddr,uint64_t invest_amount, int32_t investType,void * ack);

    static std::string ReplaceCreateDisinvestTransaction_test(const std::string& fromAddr,
                                    const std::string& toAddr, const std::string& utxo_hash,void * ack);

    static std::string ReplaceCreateDeclareTransaction_test(const std::string & fromaddr,
                                    const std::string & toAddr,
                                    uint64_t amount, 
                                    const std::string & multiSignPub,
                                    const std::vector<std::string> & signAddrList,
                                    uint64_t signThreshold,void * ack);
     
    static std::string ReplaceCreateBonusTransaction_test(const std::string& Addr,void *ack);


    static std::string GetEligibleNodes();

};



#endif



