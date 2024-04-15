/*
 * @Author: lyw 15035612538@163.com
 * @Date: 2024-03-24 17:55:35
 * @LastEditors: lyw 15035612538@163.com
 * @LastEditTime: 2024-04-15 00:28:41
 * @FilePath: /don/ca/ca_algorithm.h
 */
#ifndef DON_CA_ALGORITHM_H_
#define DON_CA_ALGORITHM_H_

#include <utils/json.hpp>
#include "ca_global.h"
#include "db/db_api.h"
#include "proto/block.pb.h"

namespace ca_algorithm
{
    
//Get the abnormal account number of the previous day
int GetAbnormalSignAddrListByPeriod(uint64_t &cur_time, std::vector<std::string> &abnormal_addr_list, std::unordered_map<std::string, uint64_t> & addr_sign_cnt);
int64_t GetPledgeTimeByAddr(const std::string &addr, global::ca::StakeType stakeType, DBReader *db_reader_ptr = nullptr);
std::string CalcTransactionHash(CTransaction tx);
std::string CalcBlockHash(CBlock block);
std::string CalcBlockMerkle(CBlock cblock);

int GetTxSignAddr(const CTransaction &tx, std::vector<std::string> &tx_sign_addr);
int DoubleSpendCheck(const CTransaction &tx, bool turn_on_missing_block_protocol, std::string* missing_utxo = nullptr);
//Verify transaction cache
int VerifyCacheTranscation(const CTransaction &tx);

//local Verification transaction
int MemVerifyTransactionTx(const CTransaction &tx);

//int MemVerifyContractTransactionTx(const CTransaction &tx);

//Verification transaction
int VerifyTransactionTx(const CTransaction &tx, uint64_t tx_height, bool turn_on_missing_block_protocol = false, bool verify_abnormal = true);

int VerifyContractTransactionTx(const CTransaction &tx, uint64_t txHeight, bool turnOnMissingBlockProtocol = false, bool verifyAbnormal = true);
//Check block
int MemVerifyBlock(const CBlock& block, bool isVerify = true);
int MemVerifyContractBlock(const CBlock& block, bool isVerify = true, BlockStatus* blockStat = nullptr);
int VerifyContractStorage(const nlohmann::json& txInfo, const nlohmann::json& expectedTxInfo);

int VerifyPreSaveBlock(const CBlock &block);

int VerifyContractBlock(const CBlock &block);

//Check block
int ContractVerifyBlock(const CBlock &block, bool turnOnMissingBlockProtocol = false, bool verifyAbnormal = true, bool isVerify = true, BlockStatus* blockStatus = nullptr);
int VerifyBlock(const CBlock &block, bool turn_on_missing_block_protocol = false, bool verify_abnormal = true, bool isVerify = true);
int SaveBlock(DBReadWriter &db_writer, const CBlock &block, global::ca::SaveType saveType, global::ca::BlockObtainMean obtainMean);
int DeleteBlock(DBReadWriter &db_writer, const std::string &block_hash);

int RollBackToHeight(uint64_t height);
int RollBackByHash(const std::string &block_hash);

void PrintTx(const CTransaction &tx);
void PrintBlock(const CBlock &block);

//Calculate the pledge rate and obtain the rate of return
int CalcBonusValue(uint64_t &cur_time, const std::string &bonusAddr,std::map<std::string, uint64_t> & vlaues);
int CalcBonusValue();

int GetInflationRate(const uint64_t &cur_time, const uint64_t &&StakeRate, double &InflationRate);    

uint64_t GetSumHashCeilingHeight(uint64_t height);
uint64_t GetSumHashFloorHeight(uint64_t height);
int CalcHeightsSumHash(uint64_t block_height, global::ca::SaveType saveType, global::ca::BlockObtainMean obtainMean, DBReadWriter &db_writer);
int CalcHeightsSumHash(uint64_t block_height, DBReadWriter &db_writer);
int Calc1000HeightsSumHash(uint64_t blockHeight, DBReadWriter &dbWriter, std::string& back_hask);

bool CalculateHeightSumHash(uint64_t start_height, uint64_t end_height, DBReadWriter &db_writer, std::string& sum_hash);
int VerifySign(const CSign & sign, const std::string & serHash);

int GetCommissionPercentage(const std::string& addr, double& retCommissionRate);
int GetCallContractFromAddr(const CTransaction& transaction, bool isMultiSign, std::string& fromAddr);
// namespace ca_algorithm
};

#endif
