/*
 * @Author: HaoXuDong 2848973813@qq.com
 * @Date: 2024-08-08 11:25:49
 * @LastEditors: HaoXuDong 2848973813@qq.com
 * @LastEditTime: 2024-08-08 11:29:30
 * @FilePath: /don/ca/evm/evm_environment.h
 * @Description:https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
//
// Created by root on 2024/4/24.
//

#ifndef DON_EVM_ENVIRONMENT_H
#define DON_EVM_ENVIRONMENT_H

#include <cstdint>
#include <evmc/evmc.h>
#include <transaction.pb.h>
#include "evm_host.h"

namespace evm_environment
{
//    int64_t GetChainId();

    int64_t GetBlockNumber();

    int64_t GetNonce(const std::string &address);

    int64_t GetNextNonce(const std::string &address);

    int MakeDeployMessage(const evmc_address &sender, const evmc_address &recipient, evmc_message &message);

    int MakeCallMessage(const evmc_address &sender, const evmc_address &recipient, const evmc::bytes &input,
                        const uint64_t &contractTransfer, evmc_message &message);
    int RPC_MakeCallMessage(const evmc_address &sender, const evmc_address &recipient, const evmc::bytes &input,
            const uint64_t &contractTransfer, evmc_message &message);

    int MakeDeployHost(const std::string &sender, const std::string &recipient, EvmHost &host,
                       int64_t blockTimestamp, int64_t blockPrevRandao, int64_t blockNumber,
                       uint64_t transferAmount);

    int MakeCallHost(const std::string &sender, const std::string &recipient, uint64_t transferAmount,
                     const evmc::bytes &code,
                     EvmHost &host, int64_t blockTimestamp, int64_t blockPrevRandao, int64_t blockNumber);

    int MakeTxContext(const std::string &from, evmc_tx_context &txContext, int64_t blockTimestamp,
                      int64_t blockPrevRandao, int64_t blockNumber);

    int64_t GetBlockTimestamp(const CTransaction &transaction);

    int64_t GetBlockPrevRandao(const CTransaction &transaction);

    //int64_t CalculateBlockTimestamp(int64_t time);
    int64_t CalculateBlockTimestamp(uint64_t txTime);
    
    int64_t CalculateBlockPrevRandao(const std::string &from);

    int64_t CalculateBlockPrevRandao(const CTransaction &transaction);

    int64_t VerifyEvmParameters(const CTransaction &transaction);

    int64_t VerifyEvmParametersPrevRandao(const CTransaction &transaction);
}


#endif //DON_EVM_ENVIRONMENT_H
