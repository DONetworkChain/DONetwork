#include <future>
#include <chrono>
#include <ostream>
#include <evmc/hex.hpp>
#include <evmone/evmone.h>

#include "ca/ca_global.h"
#include "ca/ca_contract.h"
#include "ca/ca_algorithm.h"
#include "ca/ca_transaction.h"
#include "ca/ca_wasmtime.h"
#include "ca/ca_transaction_cache.h"

#include "utils/json.hpp"
#include "utils/console.h"
#include "utils/ContractUtils.h"
#include "api/interface/rpc_error.h"

#include "mpt/trie.h"
#include "include/logging.h"
#include "api/interface/rpc_error.h"

#include "db/db_api.h"


namespace Evmone
{
    std::map<evmc_status_code, std::string> error_descriptions = 
    {
        {EVMC_SUCCESS, "Execution successful."},
        {EVMC_FAILURE, "Generic execution failure."},
        {EVMC_REVERT, "Execution terminated with REVERT opcode."},
        {EVMC_OUT_OF_GAS, "Execution ran out of gas."},
        {EVMC_INVALID_INSTRUCTION, "INVALID instruction hit."},
        {EVMC_UNDEFINED_INSTRUCTION, "Undefined instruction encountered."},
        {EVMC_STACK_OVERFLOW, "Stack overflow."},
        {EVMC_STACK_UNDERFLOW, "Stack underflow."},
        {EVMC_BAD_JUMP_DESTINATION, "Bad jump destination."},
        {EVMC_INVALID_MEMORY_ACCESS, "Read outside memory bounds."},
        {EVMC_CALL_DEPTH_EXCEEDED, "Call depth exceeded."},
        {EVMC_STATIC_MODE_VIOLATION, "Static mode violation."},
        {EVMC_PRECOMPILE_FAILURE, "Precompile failure."},
        {EVMC_CONTRACT_VALIDATION_FAILURE, "Contract validation failed."},
        {EVMC_ARGUMENT_OUT_OF_RANGE, "Argument out of range."},
        {EVMC_WASM_UNREACHABLE_INSTRUCTION, "Unreachable WASM instruction."},
        {EVMC_WASM_TRAP, "WASM trap hit."},
        {EVMC_INSUFFICIENT_BALANCE, "Insufficient balance."},
        {EVMC_INTERNAL_ERROR, "Internal error."},
        {EVMC_REJECTED, "Execution rejected."},
        {EVMC_OUT_OF_MEMORY, "Out of memory."}
    };
    std::map<int,std::string> printErrorMap = 
    {
        {0,"EVMC_SUCCESS" },
        {1,"EVMC_FAILURE" },
        {2,"EVMC_REVERT" },
        {3,"EVMC_OUT_OF_GAS" },
        {4,"EVMC_INVALID_INSTRUCTION", },
        {5,"EVMC_UNDEFINED_INSTRUCTION", },
        {6,"EVMC_STACK_OVERFLOW"},
        {7,"EVMC_STACK_UNDERFLOW"},
        {8,"EVMC_BAD_JUMP_DESTINATION"},
        {9,"EVMC_INVALID_MEMORY_ACCESS"},
        {10,"EVMC_CALL_DEPTH_EXCEEDED"},
        {11,"EVMC_STATIC_MODE_VIOLATION"},
        {12,"EVMC_PRECOMPILE_FAILURE"},
        {13,"EVMC_CONTRACT_VALIDATION_FAILURE"},
        {14,"EVMC_ARGUMENT_OUT_OF_RANGE"},
        {15,"EVMC_WASM_UNREACHABLE_INSTRUCTION"},
        {16,"EVMC_WASM_TRAP"},
        {17,"EVMC_INSUFFICIENT_BALANCE"},
        {18,"EVMC_INTERNAL_ERROR"},
        {19,"EVMC_REJECTED"},
        {20,"EVMC_OUT_OF_MEMORY"}
    };  
}
int ExecuteByEvmone(const evmc_message &msg, const evmc::bytes &code, DonHost &host, std::string &strOutput,
                    int64_t &gasCost)
{

    struct evmc_vm* pvm = evmc_create_evmone();
    if (!pvm)
    {
        return -1;
    }
    if (!evmc_is_abi_compatible(pvm))
    {
        return -2;
    }
    evmc::VM vm{pvm};

    auto async_execute = [&vm](Host& host, evmc_revision rev, const evmc_message& msg, const uint8_t* code, size_t code_size)
    {
        return vm.execute(host, rev, msg, code, code_size);
    };
    std::future<evmc::Result> futureResult = std::async(std::launch::async, async_execute, std::ref(host), EVMC_MAX_REVISION, std::ref(msg), code.data(), code.size());

    std::future_status status = futureResult.wait_for(std::chrono::seconds(10));
    if (status == std::future_status::timeout)
    {
        ERRORLOG(RED "Evmone execution failed timeout!" RESET); 
        std::cout<< RED << "contract execution failed timeout!" << RESET << std::endl;
        return -3;
    }
    evmc::Result result = futureResult.get();
    DEBUGLOG("Evmone execution Result: {}", Evmone::error_descriptions[result.status_code]);
    
    if (result.status_code != EVMC_SUCCESS)
	{	
        ERRORLOG(RED "Evmone execution failed! gas_left:{}" RESET, result.gas_left);  
        strOutput = Evmone::printErrorMap[result.status_code];
        strOutput = strOutput + Evmone::error_descriptions[result.status_code];
        strOutput = strOutput + "output: " + std::move(evmc::hex({result.output_data, result.output_size}));
		DEBUGLOG("Output: {}", strOutput);

        std::cout<< RED << "contract execution failed! Result:" << Evmone::error_descriptions[result.status_code] 
        << "gas_left:" << result.gas_left<< RESET << std::endl;

        return -4;
	}
    gasCost = msg.gas - result.gas_left;
	strOutput = std::move(evmc::hex({result.output_data, result.output_size}));
    if(gasCost < 0)
    {
        ERRORLOG("gasCost is{},msg.gas{},result.gas_left{}",gasCost,msg.gas,result.gas_left);
        return -5;
    }
    DEBUGLOG("gasCost is{},msg.gas{},result.gas_left{}",gasCost,msg.gas,result.gas_left);
	DEBUGLOG("Output: {}", strOutput);
    return 0;    
}

int Evmone::DeployContract(const std::string &fromAddr, const std::string &ownerEvmAddr, const std::string &code_str,
                           std::string &strOutput, DonHost &host, int64_t &gasCost)
{
    // code
    evmc::bytes code;
    try
    {
        auto convertResult = evmc::from_hex(code_str);
        if(convertResult.has_value())
        {
            code = convertResult.value();
        }
        else
        {
            ERRORLOG("fail to convert code to hex , code: {}", code_str);
            return -1;
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return -2;
    }
    

    // msg
    evmc_address&& evmAddr = evm_utils::stringToEvmAddr(ownerEvmAddr);
    evmc::address createAddress = {{0,1,2}};
    evmc_message createMsg{};
    createMsg.kind = EVMC_CREATE;
    createMsg.recipient = createAddress;
    createMsg.sender = evmAddr;
    uint64_t balance = 0;
    GetBalanceByUtxo(fromAddr, balance);
    if(balance <= 0)
    {
        std::cout<<RED << "Account balance is zero" << RESET << std::endl;
        return -3;
    }
    createMsg.gas = balance;

    struct evmc_tx_context txContext = {
        .tx_origin = evmAddr
    };
    host.tx_context = txContext;

    int ret = ExecuteByEvmone(createMsg, code, host, strOutput, gasCost);
    if(ret != 0)
    {
        ERRORLOG("evm execute ret: {}", ret);
        return -4;
    }
    
    return 0;
}

int Evmone::CallContract(const std::string &fromAddr, const std::string &ownerEvmAddr, const std::string &strDeployer, const std::string &strDeployHash,
                     const std::string &strInput, std::string &strOutput, DonHost &host, int64_t &gasCost, const uint64_t& contractTransfer)
{
    CTransaction deployTx;
    std::string contractAddress;
    int ret = ContractCommonInterface::GetDeployTxByDeployData(strDeployer, strDeployHash, contractAddress, deployTx);
    if(ret != 0)
    {
        ERRORLOG("GetDeployTxByDeployData error : {}", ret);
        return -1;
    }

    std::string strCode;
    evmc::bytes code;
    evmc::bytes input;
    try
    {
        nlohmann::json dataJson = nlohmann::json::parse(deployTx.data());
        nlohmann::json txInfo = dataJson["TxInfo"].get<nlohmann::json>();
        strCode = txInfo["Output"].get<std::string>();
        if(strCode.empty())
        {
            return -2;
        }
        auto codeConvertResult = evmc::from_hex(strCode);
        if(codeConvertResult.has_value())
        {
            code = codeConvertResult.value();
        }
        else
        {
            ERRORLOG("fail to convert code to hex , code: {}", strCode);
            return -3;
        }

        auto inputConvertResult = evmc::from_hex(strInput);
        if(inputConvertResult.has_value())
        {
            input = inputConvertResult.value();
        }
        else
        {
            ERRORLOG("fail to convert code to hex , code: {}", strCode);
            return -4;
        }

    }
    catch(const std::exception& e)
    {
        ERRORLOG("can't parse deploy contract transaction");
        return -5;
    }
    // msg
    evmc_address&& evmAddr = evm_utils::stringToEvmAddr(ownerEvmAddr);
    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.input_data = input.data();
    msg.input_size = input.size();
    msg.recipient = evm_utils::stringToEvmAddr(evm_utils::generateEvmAddr(strDeployer + strDeployHash));
    msg.sender = evmAddr;
    uint64_t balance = 0;
    GetBalanceByUtxo(fromAddr, balance);
    std::cout <<"balance" << balance;
    if(balance <= 0)
    {
        std::cout<<RED << "Account balance is zero" << RESET << std::endl;
        return -6;
    }
    msg.gas = balance;

    dev::u256 value = contractTransfer;
    if(value > 0)
    {
       dev::bytes by = dev::fromHex(dev::toCompactHex(value, 32));
       memcpy(msg.value.bytes, &by[0], by.size() * sizeof(uint8_t));
    }

    host.coin_transferrings.emplace_back(evm_utils::EvmAddrToBase58(msg.sender), evm_utils::EvmAddrToBase58(msg.recipient), contractTransfer);
    struct evmc_tx_context tx_context = {
        .tx_origin = evmAddr
    };
    host.tx_context = tx_context;

    std::string rootHash;
    int retVal = GetContractRootHash(contractAddress, rootHash);
    if (retVal != 0)
    {
        return retVal;
    }
    host.accounts[msg.recipient].CreateTrie(rootHash, contractAddress);
    host.accounts[msg.recipient].set_code(code);
    int res = ExecuteByEvmone(msg, code, host, strOutput, gasCost);
    DEBUGLOG("evm execute ret: {}", res);
    return res;
}

void Evmone::GetStorage(const DonHost &host, nlohmann::json &jStorage, std::set<address> &dirtyContract)
{
    for(const auto &account : host.accounts)
    {
        std::pair<std::string, std::string> rootHash;
        std::map<std::string, std::string> dirtyhash;
        std::shared_ptr<Trie> root = account.second.StorageRoot;
        root->Save();
        root->GetBlockStorage(rootHash, dirtyhash);

        if(!dirtyhash.empty())
        {
            dirtyContract.insert(account.first);
        }

        if(rootHash.first.empty())
        {
            continue;
        }
        jStorage[root->contractAddr + "_" + "rootHash"] = rootHash.first;
        if (!rootHash.second.empty())
        {
            dirtyContract.insert(account.first);
            jStorage[root->contractAddr + "_" + rootHash.first] = rootHash.second;
        }
        
        for(const auto& it : dirtyhash)
        {
            jStorage[root->contractAddr + "_" + it.first] = it.second;
        }
    }
}

void Evmone::GetCalledContract(const DonHost& host, std::vector<std::string>& calledContract)
{
    for(const auto &account : host.accounts)
    {
        calledContract.push_back(evm_utils::EvmAddrToBase58(account.first));
    }
}

void Evmone::GetSelfdestructs(const DonHost& host, nlohmann::json& jSelfdestructs)
{
    DBReader data_reader;
    for(auto &it : host.recorded_selfdestructs)
    {
        std::string contractAddress = evm_utils::EvmAddrToBase58(evmc::hex({it.selfdestructed.bytes,sizeof(it.selfdestructed.bytes)}));
        std::string deployHash;
        if(data_reader.GetContractDeployUtxoByContractAddr(contractAddress, deployHash) != DBStatus::DB_SUCCESS)
        {
            DEBUGLOG("GetContractDeployUtxoByContractAddr failed!, base58Addr:{}", contractAddress);
            return;
        }
        jSelfdestructs.push_back({contractAddress, deployHash});
    }
}

int Evmone::ContractInfoAdd(const DonHost &host, const std::string &txHash, global::ca::TxType TxType,
                            uint32_t transactionVersion,
                            nlohmann::json &jTxInfo, std::map<std::string, std::string> &contractPreHashCache)
{
    nlohmann::json jStorage;
    std::set<address> dirtyContract;
    GetStorage(host, jStorage, dirtyContract);
    jTxInfo["Storage"] = jStorage;

    DBReader data_reader;
    std::map<std::string,std::string> items;
    evmc::address createAddress = {{0,1,2}};
    for(auto &account : host.accounts)
    {
        if(TxType == global::ca::TxType::kTxTypeDeployContract && account.first == createAddress)
        {
            continue;
        }

        if(dirtyContract.find(account.first) == dirtyContract.end())
        {
            continue;
        }

        std::string callAddress = account.second.StorageRoot->contractAddr;
        std::string strPrevTxHash;
        if (transactionVersion == global::ca::kCurrentTransactionVersion)
        {
            strPrevTxHash = MagicSingleton<CtransactionCache>::GetInstance()->GetAndUpdateContractPreHash(
                    callAddress, txHash, contractPreHashCache);
        }

        items[callAddress] = strPrevTxHash;
    }
    jTxInfo["PrevHash"] = items;
    for(const auto& pair : items)
    {
        DEBUGLOG("Add it.callAddress() {} strPrevTxHash {}",pair.first,pair.second);
    }
    for(auto &it : host.recorded_logs)
    {
        nlohmann::json logmap;
        logmap["creator"] = evm_utils::EvmAddrToString(it.creator);
        logmap["data"] = evmc::hex({it.data.data(), it.data.size()});
        for(auto& topic : it.topics)
        {
            logmap["topics"].push_back(evmc::hex({topic.bytes, sizeof(topic.bytes)}));
        }
        jTxInfo["log"].push_back(logmap);
    }

    std::map<std::string,std::string> destructItems;
    for(auto &it : host.recorded_selfdestructs)
    {
        std::string contractAddress = evm_utils::EvmAddrToBase58(evmc::hex({it.selfdestructed.bytes,sizeof(it.selfdestructed.bytes)}));
        std::string deployHash;
        if(data_reader.GetContractDeployUtxoByContractAddr(contractAddress, deployHash) != DBStatus::DB_SUCCESS)
        {
            DEBUGLOG("GetContractDeployUtxoByContractAddr failed!, base58Addr:{}", contractAddress);
            return -1;
        }
        destructItems[contractAddress] = deployHash;

    }
    jTxInfo["selfdestructs"] = destructItems;
    return 0;
}

int ContractCommonInterface::GenVin(const std::vector<std::string>& fromAddr,CTxUtxo * txUtxo, std::vector<std::string>& utxoHashs, uint64_t& total, bool isSign)
{
    // Find utxo
    std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
    auto ret = TxHelper::FindUtxo(fromAddr, TxHelper::kMaxVinSize, total, setOutUtxos);
    if (ret != 0)
    {
        ERRORLOG(RED "FindUtxo failed! The error code is {}." RESET, ret);
        return -1;
    }
    if (setOutUtxos.empty())
    {
        ERRORLOG(RED "Utxo is empty!" RESET);
        return -2;
    }
    std::set<std::string> setTxowners;
    // Fill Vin
    for (auto & utxo : setOutUtxos)
    {
        setTxowners.insert(utxo.addr);
    }
    if (setTxowners.empty())
    {
        ERRORLOG(RED "Tx owner is empty!" RESET);
        return -3;
    }
    uint32_t n = txUtxo->vin_size();
    for (auto & owner : setTxowners)
    {
        txUtxo->add_owner(owner);
        
        CTxInput * vin = txUtxo->add_vin();
        for (auto & utxo : setOutUtxos)
        {
            if (owner == utxo.addr)
            {
                CTxPrevOutput * prevOutput = vin->add_prevout();
                prevOutput->set_hash(utxo.hash);
                prevOutput->set_n(utxo.n);
                DEBUGLOG("----- utxo.hash:{}, utxo.n:{} owner:{}", utxo.hash, utxo.n, owner);
                utxoHashs.push_back(utxo.hash);
            }
        }
        vin->set_sequence(n++);

        if(!isSign)
        {
            vin->set_contractaddr(owner);
        }

    }
    return 0;
}

int
FillOutTx(const std::string &fromAddr, const std::string &toAddr, global::ca::TxType txType,
          const std::vector<TransferInfo> &transferrings, const nlohmann::json &jTxInfo,
          uint64_t height, int64_t gasCost, CTransaction &outTx, TxHelper::vrfAgentType &type, NewVrf &info_, const uint64_t& contractTip)
{
    if(toAddr.empty())
    {
        return -1;
    }

    if(contractTip != 0 && fromAddr == toAddr)
    {
        return -2;
    }

    outTx.set_type(global::ca::kTxSign);
    nlohmann::json data;
    data["TxInfo"] = jTxInfo;
    std::string s = data.dump();
    outTx.set_data(s);
    
    std::vector<std::string> utxoHashs;
    int ret = Evmone::GenCallOutTx(fromAddr, toAddr, txType, transferrings, gasCost, outTx, contractTip, utxoHashs);
    if(ret < 0)
    {
        ERRORLOG("GenCallOutTx fail !!! ret:{}", ret);
        return -3;
    }

    ret = ContractCommonInterface::fillingTransactions(fromAddr, txType, height, outTx, type, info_);
    if(ret != 0)
    {
        ERRORLOG("fillingTransactions fail !!! ret:{}", ret);
        return -4;
    }

    return 0;
}

int Evmone::GenCallOutTx(const std::string &fromAddr, const std::string &toAddr, global::ca::TxType txType,
                  const std::vector<TransferInfo> &transferrings, int64_t gasCost, 
                  CTransaction& outTx, const uint64_t& contractTip, std::vector<std::string>& utxoHashs, bool isGenSign)

{
    DBReader db_reader;
    std::vector<std::string> vecDeployerAddrs;
    auto ret = db_reader.GetAllDeployerAddr(vecDeployerAddrs);
    if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
    {
        return -1;
    }

    std::map<std::string,std::map<std::string,uint64_t>> transfersMap;
    for(const auto& iter : transferrings)
    {
        DEBUGLOG("from:{}, to:{}, amount:{}", iter.from, iter.to, iter.amount); 
        if(iter.amount == 0) continue;
        transfersMap[iter.from][iter.to] += iter.amount;
    }

    int retValue = ContractCommonInterface::fillingTransactions(fromAddr, toAddr, txType, transfersMap, gasCost, outTx, contractTip, utxoHashs, isGenSign);
    if(retValue != 0)
    {
        ERRORLOG("fillingTransactions error : {} ", retValue);
        return -2;
    }

    return 0;
}

int Evmone::VerifyUtxo(const CTransaction& tx, const CTransaction& callOutTx)
{
    if(tx.utxo().vout_size() != callOutTx.utxo().vout_size())
    {
        return -1;
    }
    std::string srcStr;
    for(const auto& vout : tx.utxo().vout())
    {
        DEBUGLOG("----- vout.addr:{}, vout.amount:{}", vout.addr(), vout.value());
        srcStr += vout.SerializeAsString();
    }

    for (auto &vin : tx.utxo().vin())
    {
        DEBUGLOG("vin.sequence:",vin.sequence());
        for (auto & prevout : vin.prevout())
        {
            DEBUGLOG("prevout.hash:",prevout.hash());
            DEBUGLOG("prevout.n:",prevout.n());
        }
        auto &scriptSig = vin.vinsign();
        DEBUGLOG("scriptSig.addr:{}", GetBase58Addr(scriptSig.pub()));
    }
    std::string detStr;
    for(const auto& vout : callOutTx.utxo().vout())
    {
        DEBUGLOG("---- detStr.addr:{},vout.amount:{}",vout.addr(),vout.value());
        detStr += vout.SerializeAsString();
    }

    for (auto &vin : tx.utxo().vin())
    {
        DEBUGLOG("detvin.sequence:",vin.sequence());
        for (auto & prevout : vin.prevout())
        {
            DEBUGLOG("detprevout.hash:",prevout.hash());
            DEBUGLOG("prevout.n:",prevout.n());
        }
        auto &scriptSig = vin.vinsign();
        DEBUGLOG("detscriptSig.addr:{}", GetBase58Addr(scriptSig.pub()));
    }

    if(srcStr != detStr)
    {
        return -2;
    }
    return 0;
}

int Evmone::FillCallOutTx(const std::string &fromAddr, const std::string &toAddr,
                          const std::vector<TransferInfo> &transferrings,
                          const nlohmann::json &jTxInfo, uint64_t height, int64_t gasCost, CTransaction &outTx,
                          TxHelper::vrfAgentType &type, NewVrf &info_, const uint64_t& contractTip)
{
    if (!CheckBase58Addr(toAddr))
    {
        ERRORLOG("Fromaddr is a non base58 address!");
        return -1;
    }

    return FillOutTx(fromAddr, toAddr,
                     global::ca::TxType::kTxTypeCallContract, transferrings, jTxInfo, height, gasCost, outTx, type,
                     info_, contractTip);
}

int Evmone::FillDeployOutTx(const std::string &fromAddr, const std::string &toAddr,
                            const std::vector<TransferInfo> &transferrings,
                            const nlohmann::json &jTxInfo, int64_t gasCost, uint64_t height, CTransaction &outTx,
                            TxHelper::vrfAgentType &type, NewVrf &info_)
{
    return FillOutTx(fromAddr, toAddr,
                     global::ca::TxType::kTxTypeDeployContract, transferrings, jTxInfo, height, gasCost, outTx, type,
                     info_, 0);
}


int Wasmtime::DeployWasmContract(const std::string &fromAddr,  const std::string &code_str,  std::string &strOutput ,int64_t &gasCost)
{
    uint64_t balance = 0;
    GetBalanceByUtxo(fromAddr, balance);

    std::shared_ptr<TFSC::WasmtimeVMhost> hostFunctions = MagicSingleton<TFSC::WasmtimeVMhost>::GetInstance();
    TFSC::TfscWasmtimeVM vm(hostFunctions.get(), code_str);
    auto res = vm.Call("constructor", balance);
    if(!res.isOk())
    {
        return -1;
    }
    strOutput = res.GetResault();
    gasCost = vm.GetConsumedCost();

    return 0;
}   

int Wasmtime::CallWasmContract(const std::string &fromAddr, const std::string &strDeployer, const std::string &strDeployHash,
                            const std::string &strInput, const std::string &contractFunName, std::string &strOutput, int64_t &gasCost)
{
    CTransaction deployTx;
    std::string contractAddress;
    int ret = ContractCommonInterface::GetDeployTxByDeployData(strDeployer, strDeployHash, contractAddress, deployTx);
    if(ret != 0)
    {
        ERRORLOG("GetDeployTxByDeployData error : {}", ret);
        return -1;
    }

    std::string hexCode;
    try
    {
        nlohmann::json dataJson = nlohmann::json::parse(deployTx.data());
        nlohmann::json txInfo = dataJson["TxInfo"].get<nlohmann::json>();
        hexCode = txInfo["Code"].get<std::string>();
        if(hexCode.empty())
        {
            return -2;
        }
    }
    catch(const std::exception& e)
    {
        ERRORLOG("can't parse deploy contract transaction");
        return -3;
    }
    std::string strCode = Hex2Str(hexCode);

    std::string rootHash;
    int retVal = GetContractRootHash(contractAddress, rootHash);
    if (retVal != 0)
    {
        return retVal;
    }
    auto storage = MagicSingleton<TFSC::WasmStore>::GetInstance();
    storage->CreateTrie(rootHash, contractAddress);
    MagicSingleton<TFSC::StoreManager>::GetInstance()->InsertStore(contractAddress, storage);
    MagicSingleton<TFSC::StoreManager>::GetInstance()->setCurrentContractAddr(contractAddress);

    std::shared_ptr<TFSC::WasmtimeVMhost> Actuator =  MagicSingleton<TFSC::WasmtimeVMhost>::GetInstance();
    TFSC::TfscWasmtimeVM vm(Actuator.get(), strCode);

    uint64_t balance = 0;
    GetBalanceByUtxo(fromAddr, balance);
    
    if(strInput.empty())
    {
        auto res = vm.Call(contractFunName, balance);
        if(!res.isOk()){
            return -4;
        }
        strOutput = res.GetResault();
    }   
    else
    {
        std::string underline = "_";
        std::vector<std::string> args;
        if(strInput.find(underline) != std::string::npos)
        {
            StringUtil::SplitString(strInput, "_", args);
            auto ret = vm.Call(contractFunName, balance, args);
            if(!ret.isOk()){
                return -5;
            }
            strOutput = ret.GetResault();
        }
        else
        {
            args.push_back(strInput);
            auto ret = vm.Call(contractFunName, balance, args);
            if(!ret.isOk()){
                return -6;
            }
            strOutput = ret.GetResault();
        }
    }

    gasCost = vm.GetConsumedCost();

    nlohmann::json jStorage;
    std::set<std::string> dirtyContract;
    
    return 0;
}

int Wasmtime::GenCallWasmOutTx(const std::string &fromAddr, const std::string &toAddr, global::ca::TxType txType, int64_t gasCost, CTransaction& outTx, 
            const uint64_t& contractTip, std::vector<std::string>& utxoHashs, bool isGenSign)
{
    std::string contractAddr = MagicSingleton<TFSC::StoreManager>::GetInstance()->getCurrentContractAddr();
    auto tansationTargets = MagicSingleton<TFSC::StoreManager>::GetInstance()->GetTrasationTarget(contractAddr);
        
    std::map<std::string,std::map<std::string,uint64_t>> transfersMap;
    for(auto iter : tansationTargets)
    {
        if(std::stoi(iter.amount) == 0) continue;
        transfersMap[iter.from][iter.to] += std::stoi(iter.amount);
    }

    int result = ContractCommonInterface::fillingTransactions(fromAddr, toAddr, txType, transfersMap, gasCost, outTx, contractTip, utxoHashs, isGenSign);
    if(result != 0)
    {
        ERRORLOG("fillingTransactions error : {} ", result);
        return -1;
    }

    return 0;
}

// int Wasmtime::FillWasmOutTx(const std::string &fromAddr, const std::string &toAddr, global::ca::TxType txType,const nlohmann::json &jTxInfo,
//         uint64_t height, int64_t gasCost, CTransaction &outTx, TxHelper::vrfAgentType &type, Vrf &info_, const uint64_t& contractTip)
// {
//     if(toAddr.empty())
//     {
//         return -1;
//     }

//     if(contractTip != 0 && fromAddr == toAddr)
//     {
//         return -2;
//     }

//     outTx.set_type(global::ca::kTxSign);
//     nlohmann::json data;
//     data["TxInfo"] = jTxInfo;
//     std::string dataStr = data.dump();
//     outTx.set_data(dataStr);
    
//     std::vector<std::string> utxoHashs;
//     int ret = Wasmtime::GenCallWasmOutTx(fromAddr, toAddr, txType, gasCost, outTx, contractTip, utxoHashs, true);
//     if(ret < 0)
//     {
//         ERRORLOG("GenCallOutTx fail !!! ret:{}", ret);
//         return -3;
//     }

//     ret = ContractCommonInterface::fillingTransactions(fromAddr, txType, height, outTx, type, info_);
//     if(ret != 0)
//     {
//         ERRORLOG("fillingTransactions fail !!! ret:{}", ret);
//         return -4;
//     }

//     return 0;
// }
    
int Wasmtime::ContractInfoAdd(const std::string &txHash, nlohmann::json& jTxInfo, global::ca::TxType TxType, uint32_t transactionVersion, std::map<std::string, std::string> &contractPreHashCache)
{
    std::string contractAddr = MagicSingleton<TFSC::StoreManager>::GetInstance()->getCurrentContractAddr();
    auto tansationTarges = MagicSingleton<TFSC::StoreManager>::GetInstance()->GetTrasationTarget(contractAddr);

    std::map<std::string,std::map<std::string,uint64_t>> transfersMap;
    for(auto iter : tansationTarges)
    {
        if(std::stoi(iter.amount) == 0) continue;
        transfersMap[iter.from][iter.to] += std::stoi(iter.amount);
    }

    std::map<std::string, uint64_t> fromBalance;

    DBReader dataReader;
    nlohmann::json jStorage;
    std::set<std::string> dirtyContract;
    std::map<std::string,std::string> items;

    auto it = MagicSingleton<TFSC::StoreManager>::GetInstance();
    it->GetStorage(jStorage, dirtyContract);
    jTxInfo["Storage"] = jStorage;

    auto contractStores = it->GetAllStoreMap();
    for(auto &account : contractStores)
    {
        if(TxType == global::ca::TxType::kTxTypeDeployContract)
        {
            continue;
        }

        if(dirtyContract.find(account.first) == dirtyContract.end())
        {
            continue;
        }

        std::string callAddress = account.second->storeRoot->contractAddr;
        std::string strPrevTxHash;
        if (transactionVersion == global::ca::kInitTransactionVersion)
        {
            if (dataReader.GetLatestUtxoByContractAddr(callAddress, strPrevTxHash) != DBStatus::DB_SUCCESS)
            {
                ERRORLOG("GetLatestUtxo of ContractAddr {} fail", callAddress);
                return -1;
            }
        }
        else if (transactionVersion == global::ca::kCurrentTransactionVersion)
        {
            strPrevTxHash = MagicSingleton<CtransactionCache>::GetInstance()->GetAndUpdateContractPreHash(
                    callAddress, txHash, contractPreHashCache);
        }

        items[callAddress] = strPrevTxHash;
    }
    jTxInfo["PrevHash"] = items;
    for(const auto& pair : items)
    {
        DEBUGLOG("Add it.callAddress() {} strPrevTxHash {}",pair.first,pair.second);
    }
    auto destruction_data = MagicSingleton<TFSC::StoreManager>::GetInstance()->destruction_data;
    std::map<std::string,std::string> destructItems;
    for(auto &it : destruction_data)
    {
        std::string contractAddress = it.destoryAddr;

        std::string deployHash;
        if(dataReader.GetContractDeployUtxoByContractAddr(contractAddress, deployHash) != DBStatus::DB_SUCCESS)
        {
            DEBUGLOG("GetEvmContractDeployUtxoByContractAddr failed!, base58Addr:{}", it.destoryAddr);
            return -2;
        }
        destructItems[contractAddress] = deployHash;
    }
    jTxInfo["selfdestructs"] = destructItems;

    return 0;
}

void Wasmtime::GetCalledContract(std::vector<std::string>& calledContract)
{
    auto contractStores = MagicSingleton<TFSC::StoreManager>::GetInstance()->GetAllStoreMap();
    for(const auto &account : contractStores)
    {
        calledContract.push_back(account.first);
    }
}

int ContractCommonInterface::fillingTransactions(const std::string &fromAddr, const std::string &toAddr, global::ca::TxType txType,
                  const std::map<std::string,std::map<std::string,uint64_t>>& transfersMap, const int64_t gasCost, 
                  CTransaction& outTx, const uint64_t& contractTip, std::vector<std::string>& utxoHashs, bool isGenSign)
{ 
    std::map<std::string, uint64_t> fromBalance;
    DBReader db_reader;
    for(const auto& iter : transfersMap)
    {
        bool isSign = false;
        std::vector<std::string> vecfromAddr;
        vecfromAddr.push_back(iter.first);

        std::string utxo;
        if(db_reader.GetLatestUtxoByContractAddr(iter.first, utxo) != DBStatus::DB_SUCCESS)
        {
            isSign = true;
        }

        if(!isGenSign)
        {
            isSign = false;
        }

        uint64_t total = 0;
        auto ret = ContractCommonInterface::GenVin(vecfromAddr, outTx.mutable_utxo(), utxoHashs, total, isSign);
        if(ret < 0)
        {
            ERRORLOG("GenVin fail!!! ret:{}",ret);
            return -1;
        }
        fromBalance[iter.first] = total;
    }
    
    uint64_t expend =  gasCost + contractTip;
    auto found = fromBalance.find(fromAddr);
    if(found == fromBalance.end())
    {
        bool isSign = true;
        std::vector<std::string> vecfromAddr;
        vecfromAddr.push_back(fromAddr);

        if(!isGenSign)
        {
            isSign = false;
        }

        uint64_t total = 0;
        auto ret = ContractCommonInterface::GenVin(vecfromAddr, outTx.mutable_utxo(), utxoHashs, total, isSign);
        if(ret < 0)
        {
            ERRORLOG("GenVin fail!!! ret:{}",ret);
            return -2;
        }
        fromBalance[fromAddr] = total;
    }

    std::multimap<std::string, int64_t> targetAddrs;

    CTxUtxo * txUtxo = outTx.mutable_utxo();
    CTxOutput * vout = txUtxo->add_vout();
    std::string contractBurner;
    if (txType == global::ca::TxType::kTxTypeDeployContract)
    {
        contractBurner = global::ca::kVirtualDeployContractAddr;
    }
    else if (txType == global::ca::TxType::kTxTypeCallContract)
    {
        contractBurner = global::ca::kVirtualCallContractAddr;
    }
    else
    {
        return -3;
    }

    vout->set_addr(contractBurner);
    vout->set_value(gasCost);
    targetAddrs.insert({contractBurner, gasCost});

    if(contractTip != 0 && !toAddr.empty())
    {
        CTxOutput * voutToAddr = txUtxo->add_vout();
        voutToAddr->set_addr(toAddr);
        voutToAddr->set_value(contractTip);
        targetAddrs.insert({toAddr, contractTip});
    }

    for(auto & iter : transfersMap)
    {
        auto& balance = fromBalance[iter.first];
        for(const auto& toaddr : iter.second)
        {
            CTxOutput * vout = txUtxo->add_vout();
            vout->set_addr(toaddr.first);
            vout->set_value(toaddr.second);
            targetAddrs.insert({toaddr.first, toaddr.second});

            if(balance < toaddr.second)
            {
                return -4;
            }

            balance -= toaddr.second;
        }
        if(iter.first == fromAddr)
        {
            continue;
        } 
        CTxOutput * vout = txUtxo->add_vout();
        vout->set_addr(iter.first);
        vout->set_value(balance);
        targetAddrs.insert({iter.first, balance});
    }

    targetAddrs.insert({global::ca::kVirtualBurnGasAddr, 0});
    targetAddrs.insert({fromAddr, 0});
    uint64_t gas = 0;
    if(GenerateGas(outTx, targetAddrs.size(), gas) != 0)
    {
        ERRORLOG(" gas = 0 !");
        return -5;
    }

    if (contractTip != 0 && contractTip < gas)
    {
        SetRpcError("-72018",Sutil::Format("contractTip %s < gas %s",contractTip, gas));
        ERRORLOG("contractTip {} < gas {}" , contractTip, gas);
        return -6;
    }
    expend += gas;

    if(fromBalance[fromAddr] < expend)
    {
        ERRORLOG("The total cost = {} is less than the cost = {}", fromBalance[fromAddr], expend);
        SetRpcError("-72013", Sutil::Format("The total cost = %s is less than the cost = %s", fromBalance[fromAddr], expend));
        return -7;
    }

    fromBalance[fromAddr] -= expend;

    CTxOutput * voutFromAddr = txUtxo->add_vout();
    voutFromAddr->set_addr(fromAddr);
    voutFromAddr->set_value(fromBalance[fromAddr]);
    
    CTxOutput * vout_burn = txUtxo->add_vout();
    vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
    vout_burn->set_value(gas);

    return 0;
}

int ContractCommonInterface::GetDeployTxByDeployData(const std::string & strDeployer, const std::string & strDeployHash, std::string & contractAddress, CTransaction & deployTx)
{
    // check whether the addr has deployed the tx hash
    DBReader data_reader;
    std::vector<std::string> vecDeployHashs;
    auto ret = data_reader.GetDeployUtxoByDeployerAddr(strDeployer, vecDeployHashs);
    if(ret != DBStatus::DB_SUCCESS)
    {
        ERRORLOG("GetDeployUtxoByDeployerAddr failed!:{}",strDeployer);
        return -1;
    }
    auto iter = std::find(vecDeployHashs.cbegin(), vecDeployHashs.cend(), strDeployHash);
    if(iter == vecDeployHashs.cend())
    {
        ERRORLOG("Transaction has not been deployed at this address!");
        return -2;
    }
    contractAddress = evm_utils::GenerateContractAddr(strDeployer + strDeployHash);
    std::cout<<"contractAddress:" << contractAddress << std::endl;
    std::string deployHash;
    if(data_reader.GetContractDeployUtxoByContractAddr(contractAddress, deployHash) != DBStatus::DB_SUCCESS)
    {
        ERRORLOG("GetContractDeployUtxoByContractAddr failed!");
        return -3;
    }
    std::string txRaw;
    if(data_reader.GetTransactionByHash(deployHash, txRaw) != DBStatus::DB_SUCCESS)
    {
        ERRORLOG("GetTransactionByHash failed!");
        return -4;
    }

    if(!deployTx.ParseFromString(txRaw))
    {
        ERRORLOG("Transaction Parse failed!");
        return -5;
    }

    return 0;
}

int ContractCommonInterface::fillingTransactions(const std::string &fromAddr, global::ca::TxType txType, 
                                         uint64_t height, CTransaction &outTx, TxHelper::vrfAgentType &type, NewVrf &info_)
{
    
    auto currentTime=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    if(global::ca::TxType::kTxTypeCallContract == txType || global::ca::TxType::kTxTypeDeployContract == txType)
    {
        type = TxHelper::vrfAgentType_vrf;
    }

    outTx.set_time(currentTime);

    std::string identity;
    int ret = 0;
    ret = GetContractDistributionManager(outTx.time(), height - 1, identity, info_);
    if(ret != 0)
    {
        ERRORLOG("GetContractDistributionManager fail ret: {}", ret);
        return -1;
    }
    outTx.set_identity(identity);
    DEBUGLOG("@@@@@ owner = {} , packager = {} , txhash = {}",fromAddr, identity,outTx.hash());
    
    outTx.set_version(global::ca::kCurrentTransactionVersion);
    outTx.set_txtype((uint32_t)txType);
    outTx.set_consensus(global::ca::kConsensus);
    return 0;
}

// void TestAddressMapping()
// {
//     Account defaultAccount;
//     MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount);
//     std::cout<< "strFromAddr:" << defaultAccount._GetBase58Addr() <<std::endl;
//     std::cout<< "EvmAddress:" << evm_utils::getEvmAddr(defaultAccount._GetPubStr()) << std::endl;
// }