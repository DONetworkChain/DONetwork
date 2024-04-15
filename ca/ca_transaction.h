#ifndef __CA_TRANSACTION__
#define __CA_TRANSACTION__

#include "ca_txhelper.h"
#include "utils/base58.h"
#include "utils/Cycliclist.hpp"
#include "ca_global.h"
#include "proto/block.pb.h"
#include "proto/transaction.pb.h"
#include "proto/block.pb.h"
#include "proto/ca_protomsg.pb.h"
#include "proto/interface.pb.h"
#include "net/msg_queue.h"

#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <map>
#include <memory>
#include <thread>
#include <vector>
#include <regex>
#include <shared_mutex>

#include "../include/net_interface.h"
#include "ca/ca_blockstroage.h"
#include "ca/ca_transtroage.h"
#include "ca_blockmonitor.h"
#include "ca/ca_txhelper.h"
#include "net/unregister_node.h"

int GetBalanceByUtxo(const std::string & address,uint64_t &balance);

typedef enum emTransactionType{
	kTransactionType_Unknown = -1,	//Unknown
	kTransactionType_Genesis = 0, 	//Genesis Deal
	kTransactionType_Tx,			//Normal trading
	kTransactionType_Gas,			//Fee transactions
	kTransactionType_Burn,			//Destroy transactions
} TransactionType;

TransactionType GetTransactionType(const CTransaction & tx);

int verifyVrfInfo(const std::shared_ptr<ContractBlockMsg> & msg, const std::map<std::string, CTransaction> & txMap);
//int verifyTxVrfInfo(const std::shared_ptr<ContractBlockMsg> & msg, const std::map<std::string, CTransaction> & txMap);

int HandleTx( const std::shared_ptr<TxMsgReq>& msg, const MsgData& msgdata );

int DoHandleTx( const std::shared_ptr<TxMsgReq>& msg, CTransaction & outTx);

int DoHandleContractTx( const std::shared_ptr<ContractTempTxMsgReq>& msg, CTransaction & outTx);


int HandleBlock(const std::shared_ptr<BlockMsg>& msg, const MsgData& msgdata);
int HandleContractBlock(const std::shared_ptr<ContractBlockMsg>& msg,const MsgData& msgdata);

bool AddBlockSign(CBlock &block);

int VerifyBlockSign(const CBlock &block);

int DoHandleBlock(const std::shared_ptr<BlockMsg>& msg);
int DoHandleContractBlock(const std::shared_ptr<ContractBlockMsg>& msg);

int HandleBuildBlockBroadcastMsg( const std::shared_ptr<BuildBlockBroadcastMsg>& msg, const MsgData& msgdata );
//int HandleBuildContractBlockBroadcastMsg(const std::shared_ptr<BuildContractBlockBroadcastMsg>& msg, const MsgData& msgdata );
int HandleDoHandleTxAck(const std::shared_ptr<TxMsgAck>& msg, const MsgData& msgdata);

int FindContractSignNode(const CTransaction & tx, const std::shared_ptr<ContractTempTxMsgReq> &msg,std::unordered_set<std::string> & nextNodes);
int FindSignNode(const CTransaction & tx, const std::shared_ptr<TxMsgReq> &msg,  const int nodeNumber, std::set<std::string> & nextNodes);

int GetBlockPackager(std::string &packager,const std::string & hash,Vrf & info);

int SearchStake(const std::string &address, uint64_t &stakeamount,  global::ca::StakeType stakeType);

int IsVrfVerifyContractNode(const std::string identity, const std::shared_ptr<ContractTempTxMsgReq> &msg);

int IsVrfVerifyNode(const std::string identity, const std::shared_ptr<TxMsgReq> &msg);
int IsVrfVerifyNode(const CTransaction& tx, const NewVrf& vrfInfo);
TxHelper::vrfAgentType IsNeedAgent(const CTransaction & tx);



int SendTxMsg(const CTransaction & tx, const std::shared_ptr<TxMsgReq>& msg);

int CheckVerifyNodeQualification(const std::string & base58);

int CheckVerifysign(const CTransaction & tx);

int IsQualifiedToUnstake(const std::string& fromAddr, 
						const std::string& utxo_hash, 
						uint64_t& staked_amount);

int CheckInvestQualification(const std::string& fromAddr, 
						const std::string& toAddr, 
						uint64_t invest_amount);

int IsQualifiedToDisinvest(const std::string& fromAddr, 
						const std::string& toAddr,
						const std::string& utxo_hash, 
						uint64_t& invested_amount);
						
int CheckBonusQualification(const std::string& BonusAddr, const uint64_t& txTime, bool verify_abnormal = true);

bool IsMoreThan30DaysForUnstake(const std::string& utxo);
bool IsMoreThan1DayForDivest(const std::string& utxo);
int VerifyBonusAddr(const std::string & BonusAddr);
int GetInvestmentAmountAndDuration(const std::string & bonusAddr,const uint64_t &cur_time,const uint64_t &zero_time,std::map<std::string, std::pair<uint64_t,uint64_t>> &mpInvestAddr2Amount);
int GetTotalCirculationYesterday(const uint64_t &cur_time, uint64_t &TotalCirculation);
int GetTotalInvestmentYesterday(const uint64_t &cur_time, uint64_t &Totalinvest);
int GetTotalBurnYesterday(const uint64_t &cur_time, uint64_t &TotalBrun);
void NotifyNodeHeightChange();

int HandleMultiSignTxReq(const std::shared_ptr<MultiSignTxReq>& msg, const MsgData &msgdata );

bool IsMultiSign(const CTransaction & tx);

int VerifyContractTxMsgReq(const ContractTempTxMsgReq & msg);
int VerifyTxMsgReq(const TxMsgReq & msg);

int VerifyContractTxFlowSignNode(const std::vector<Node>& vrfNodelist, const uint64_t& vrfTxHeight, const CTransaction &tx , const double & randNum, std::string & targetAddr);  
bool VerifyTxFlowSignNode(const CTransaction &tx , const double & rand_num, const int & range);
int VerifyTxTimeOut(const CTransaction &tx);

int HandleAddBlockAck(const std::shared_ptr<BuildBlockBroadcastMsgAck>& msg, const MsgData& msgdata);

int DropshippingTx(const std::shared_ptr<TxMsgReq> & txMsg,const CTransaction &tx);
//int DropCallShippingTx(const std::shared_ptr<ContractTxMsgReq> & txMsg,const CTransaction &tx);
int DropCallShippingTx(const std::shared_ptr<ContractTxMsgReq> & Msg,const CTransaction &tx);
int CalculateGas(const CTransaction &tx , uint64_t &gas );
int GenerateGas(const CTransaction &tx, const uint64_t voutSize, uint64_t &gas);
int PreCalcGas(CTransaction & tx);

void setVrf(Vrf & dest,const std::string & proof, const std::string & pub,const std::string & data);
void SetNewVrf(NewVrf & dest,const std::string & proof, const std::string & pub);
int getVrfdata(const Vrf & vrf,std::string & hash, int & range , double & percentage);
int getNewVrfdata(const NewVrf & vrf,std::string & hash, int & range , double & percentage);  

int getVrfdata(const Vrf & vrf,std::string & hash, int & range);
int getNewVrfdata(const NewVrf &vrf, std::string &hash, int &range);

static void filterNodeList(const CTransaction & tx, std::vector<Node> &outAddrs);
static int filterSendList(int & end_pos,Cycliclist<std::string> &list, std::vector<std::string> &target_addrs);
static int filterSendContractList(int & end_pos,Cycliclist<std::string> &list, std::vector<std::string> &target_addrs);

int GetContractRootHash(const std::string& contractAddress, std::string& rootHash);
int GetContractDistributionManager(const uint64_t& txTime, const uint64_t& txHeight, std::string& packager, NewVrf& info);



int HandleContractTx( const std::shared_ptr<ContractTxMsgReq>& msg, const MsgData& msgdata );
int VerifyContractDistributionManager(const CTransaction& tx, const uint64_t& height, const NewVrf& vrfInfo);
int CalculateThePackerByTime(const uint64_t& txTime, const uint64_t& txHeight, std::string& packager, std::string& proof, std::string &txHash);

int GetVrfDataSourceByTime(const uint64_t& txTime, const uint64_t& txHeight, std::string &txHash, std::vector<std::string>& targetAddrs);
int verifyVrfDataSource(const std::vector<Node>& vrfNodelist, const uint64_t& vrfTxHeight, bool txConsensusStatus = false);
int VerifyContractPackNode(const std::string& dispatchNodeAddr, const double& randNum, const std::string& targetAddr,const std::vector<Node> & _vrfNodelist);
int FindContractPackNode(const std::string & txHash, std::string &targetAddr, NewVrf& vrfInfo,std::set<std::string> & out_nodelist);

static int CalculatePackNode(const std::vector<Node> &nodes, const double &randNum, const bool& isVerify, std::vector<std::string>& targetAddrs);
static int filterVrfSignatureNodes(const CTransaction & tx, const std::shared_ptr<ContractTempTxMsgReq> &msg, const bool txConsensusStatus, std::unordered_set<std::string> & nextNodes);
static void FilterConsensusNodeList(const std::vector<Node>& vrfNodelist, const CTransaction & tx, std::vector<Node> &outAddrs);

int UpdateTxMsg(CTransaction & tx, const std::shared_ptr<ContractTempTxMsgReq> &msg);

bool CheckTxConsensusStatus(const CTransaction &tx);
bool IsContractBlock(const CBlock & block);
std::string GetContractAddr(const CTransaction & tx);
// void RandomSelectNode(const vector<Node> &nodes, size_t selectNumber, std::set<std::string> &outNodes);
// void RandomSelectNode(const std::vector<Node> &nodes, const double &rand_num, const int &sign_node_threshold, const bool &flag, std::set<std::string> &out_nodes, int &range , uint64_t & top);
// int GetContractDistributionManager(const uint64_t& txTime, const uint64_t& txHeight, std::string& packager, Vrf& info);
// int CalculateThePackerByTime(const uint64_t& txTime, const uint64_t& txHeight, std::string& packager, std::string& proof, std::string &txHash);
#endif
