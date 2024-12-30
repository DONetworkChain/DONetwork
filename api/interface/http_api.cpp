#include "./http_api.h"
#include "./rpc_tx.h"
#include <netdb.h>
#include <dirent.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <sys/types.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <cctype>
#include <ctime>
#include <exception>
#include <functional>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <map>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "utils/base64.h"
#include "api/rpc_error.h"
#include "api/interface/rpc_tx.h"
#include <boost/math/constants/constants.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include "ca/ca.h"
#include "ca/advanced_menu.h"
#include "ca/global.h"
#include "ca/transaction.h"
#include "ca/txhelper.h"
#include "common/global.h"
#include "db/cache.h"
#include "db/db_api.h"
#include "interface.pb.h"
#include "logging.h"
#include "utils/account_manager.h"
#include "utils/magic_singleton.h"
#include "utils/tmp_log.h"
#include "net/test.hpp"
#include "ca/test.h"
#include <utils/contract_utils.h>
#include <google/protobuf/util/json_util.h>
#include "google/protobuf/stubs/status.h"
#include "include/scope_guard.h"
#include "net/interface.h"
#include "net/global.h"
#include "net/httplib.h"
#include "net/api.h"
#include "net/peer_node.h"
#include "utils/json.hpp"
#include "utils/string_util.h"
#include "net/unregister_node.h"
#include "ca/algorithm.h"
#include "./rpc_tx.h"
#include "block.pb.h"
#include "ca_protomsg.pb.h"
#include "transaction.pb.h"
#include "utils/envelop.h"
#include "ca/interface.h"
#include "rpc_create_transaction.h"

#define CHECK_PARSE_REQ\
    std::string PaseRet = req_t._paseFromJson(req.body);\
    if(PaseRet != "OK") {\
        errorL("bad error pase fail");\
        ack_t.code= 9090;\
        ack_t.message=Sutil::Format("pase fail:%s",PaseRet);\
        res.set_content(ack_t._paseToString(), "application/json");\
        return ;\
    }

#define CHECK_VALUE(value)\
        std::regex pattern("(^[1-9]\\d*\\.\\d+$|^0\\.\\d+$|^[1-9]\\d*$|^0$)");\
        if (!std::regex_match(value, pattern))\
        {\
            ack_t.code=-3004;\
            ack_t.message=Sutil::Format("input value error:",value);\
            res.set_content(ack_t._paseToString(), "application/json");\
            return;\
        }


void _CaRegisterHttpCallbacks() {
    HttpServer::RegisterCallback("/", _ApiJsonRpc);
    HttpServer::RegisterCallback("/GetPublicIp", _GetRequesterIP);
    HttpServer::RegisterCallback("/GetTxInfo", _ApiGetTxInfo);    
    HttpServer::RegisterCallback("/GetDisinvestUtxo", _GetDisinvestUtxo);
    HttpServer::RegisterCallback("/GetStakeUtxo", _GetStakeUtxo);


    HttpServer::RegisterCallback("/GetTransaction", _GetTransaction);
    HttpServer::RegisterCallback("/GetStakeTransaction", _GetStake);
    HttpServer::RegisterCallback("/GetUnStakeTransaction", _GetUnstake);
    HttpServer::RegisterCallback("/GetInvestTransaction", _GetInvest);
    HttpServer::RegisterCallback("/GetDisInvestTransaction", _GetDisinvest);
    HttpServer::RegisterCallback("/GetBounsTransaction", _GetBonus);
    HttpServer::RegisterCallback("/GetCallContractTransaction", _CallContract);
    HttpServer::RegisterCallback("/GetDeployContractTransaction", _DeployContract);
    HttpServer::RegisterCallback("/SendMessage", _ApiSendMessage);
    HttpServer::RegisterCallback("/SendContractMessage", _ApiSendContractMessage);
    HttpServer::RegisterCallback("/ConfirmTransaction",_ConfirmTransaction);


    HttpServer::RegisterCallback("/GetRatesInfo", _ApiGetRatesInfo);
    HttpServer::RegisterCallback("/GetAllStakeNodeList",_GetAllStakeNodeListnowledge);
    HttpServer::RegisterCallback("/GetBonusInfo",_ApiGetAllBonusInfo);
    HttpServer::RegisterCallback("/GetBlockNumber", _GetBlockNumber);
    HttpServer::RegisterCallback("/GetVersion", _GetVersion);
    HttpServer::RegisterCallback("/GetBalance", _GetBalance);
    HttpServer::RegisterCallback("/GetBlockTransactionCountByHash", _GetBlockTransactionCountByHash);
    HttpServer::RegisterCallback("/GetAccounts", _GetAccounts);
    HttpServer::RegisterCallback("/GetChainId", _GetChainId);
    HttpServer::RegisterCallback("/GetPeerList", _GetPeerList);

    HttpServer::RegisterCallback("/GetTransactionByHash", _ApiGetTransactionInfo);
    HttpServer::RegisterCallback("/GetBlockByTransactionHash", _APiGetBlockByTransactionHash);
    HttpServer::RegisterCallback("/GetBlockByHash", _ApiGetBlockByHash);
    HttpServer::RegisterCallback("/GetBlockByHeight", _ApiGetBlockByHeight);
    HttpServer::RegisterCallback("/GetDelegateInfo", _ApiGetDelegateInfoReq);
    
    HttpServer::RegisterCallback("/block", _ApiPrintBlock);
    HttpServer::RegisterCallback("/get_block", _ApiGetBlock);
    HttpServer::RegisterCallback("/pub", _ApiPub);

    // #if DEVCHAIN || TESTCHAIN
    HttpServer::RegisterCallback("/printCalcHash", ApiPrintCalc1000SumHash);
    HttpServer::RegisterCallback("/printhundredhash", ApiPrintHundredSumHash);
    HttpServer::RegisterCallback("/printblock", ApiPrintAllBlocks);
    HttpServer::RegisterCallback("/ComputeSumHash", ApiComputeSumHash);
    HttpServer::RegisterCallback("/SystemInfo", GetAllSystemInfo);
    // #endif

    HttpServer::Start();
}


void _ApiJsonRpc(const Request &req, Response &res) 
{
    nlohmann::json ret;
    ret["jsonrpc"] = "2.0";
    try {
        auto json = nlohmann::json::parse(req.body);

        std::string method = json["method"];

        auto p = HttpServer::rpcCbs.find(method);
        if (p == HttpServer::rpcCbs.end()) 
        {
            ret["error"]["code"] = -32601;
            ret["error"]["message"] = "Method not found";
            ret["id"] = "";
        } 
        else 
        {
            auto params = json["params"];
            ret = HttpServer::rpcCbs[method](params);
            try {
                ret["id"] = json["id"].get<int>();
            } 
            catch (const std::exception &e) 
            {
                ret["id"] = json["id"].get<std::string>();
            }
            ret["jsonrpc"] = "2.0";
        }
    } 
    catch (const std::exception &e) 
    {
        ret["error"]["code"] = -32700;
        ret["error"]["message"] = "Internal error";
        ret["id"] = "";
    }
    res.set_content(ret.dump(4), "application/json");
}


void _ApiGetTxInfo(const Request &req, Response &res) 
{
    
    get_tx_info_req req_t;
    get_tx_info_ack ack_t;
    CHECK_PARSE_REQ

    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "getTxInfo";
    DBReader dbReader;
    std::string BlockHash;
    std::string strHeader;
    unsigned int BlockHeight;
    if (DBStatus::DB_SUCCESS !=
        dbReader.GetTransactionByHash(req_t.txhash, strHeader)) 
    {
        ack_t.code = -2;
        ack_t.message = "txhash error";
        // ack_t.code = "-1";
        // ack_t.message = "txhash error";
        
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }

    if (DBStatus::DB_SUCCESS !=
        dbReader.GetBlockHashByTransactionHash(req_t.txhash, BlockHash)) 
    {
        ack_t.code = -3;
        ack_t.message = "Block error";
        
        // ack_t.code = "-2";
        // ack_t.message = "Block error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }

    if (DBStatus::DB_SUCCESS !=
        dbReader.GetBlockHeightByBlockHash(BlockHash, BlockHeight)) {
        ack_t.code = -4;
        ack_t.message = "Block error";
        
        // ack_t.code = "-3";
        // ack_t.message = "Block error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }

    CTransaction tx;
    if (!tx.ParseFromString(strHeader)) {
        ack_t.code = -5;
        ack_t.message = "tx ParseFromString error";
        
        // ack_t.code = "-4";
        // ack_t.message = "tx ParseFromString error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }

    ack_t.code = 0;
    ack_t.message = "success";
    ack_t.tx = TxInvet(tx);
    ack_t.blockhash = BlockHash;
    ack_t.blockheight = BlockHeight;
    res.set_content(ack_t._paseToString(), "application/json");
}

void _GetStake(const Request &req, Response &res) 
{
    getStakeReq req_t;
    txAck ack_t;

    CHECK_PARSE_REQ
    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetStakeTransaction";

    std::string fromAddr = req_t.fromAddr;
    if (fromAddr.substr(0, 2) == "0x") 
    {
        fromAddr = fromAddr.substr(2);
    }
    CHECK_VALUE(req_t.stakeAmount);
    uint64_t stake_amount =
        (std::stod(req_t.stakeAmount) + global::ca::kFixDoubleMinPrecision) *
        global::ca::kDecimalNum;
    int32_t pledgeType = std::stoll(req_t.PledgeType);

    std::regex bonus("^(5|6|7|8|9|1[0-9]|20)$"); // 5 - 20 
    if(!std::regex_match(req_t.commissionRate,bonus))
    {
        ack_t.code=-1;
        ack_t.message = "input pumping percentage error:" + req_t.commissionRate;
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }
    double commissionRate = std::stod(req_t.commissionRate) / 100;

    bool isFindUtxoFlag = req_t.isFindUtxo;
    std::string encodedInfo = Base64Encode(req_t.txInfo);

    ReplaceCreateStakeTransaction(fromAddr, stake_amount, pledgeType, &ack_t, commissionRate, isFindUtxoFlag, encodedInfo);

    res.set_content(ack_t._paseToString(), "application/json");
}

void _GetUnstake(const Request &req, Response &res) 
{
    getUnStakeReq req_t;
    txAck ack_t;
    CHECK_PARSE_REQ
    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetUnStakeTransaction";

    std::string fromAddr = req_t.fromAddr;
    if (fromAddr.substr(0, 2) == "0x") 
    {
        fromAddr = fromAddr.substr(2);
    }
    
    std::string utxoHash = req_t.utxoHash;

    bool isFindUtxoFlag = req_t.isFindUtxo;
    std::string encodedInfo = Base64Encode(req_t.txInfo);

    ReplaceCreatUnstakeTransaction(fromAddr, utxoHash, isFindUtxoFlag, encodedInfo, &ack_t);

    res.set_content(ack_t._paseToString(), "application/json");
}

void _GetInvest(const Request &req, Response &res) {
    getInvestReq req_t;
    txAck ack_t;

    CHECK_PARSE_REQ
    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetInvestTransaction";

   
    std::string fromAddr = req_t.fromAddr;
    if (fromAddr.substr(0, 2) == "0x") 
    {
        fromAddr = fromAddr.substr(2);
    }
    std::string toAddr = req_t.toAddr;
    if (toAddr.substr(0, 2) == "0x") 
    {
        toAddr = toAddr.substr(2);
    }
    CHECK_VALUE(req_t.investAmount);
    long double value = std::stold(req_t.investAmount) * 10000;
    value = value * 10000;
    uint64_t investAmout =
        (std::stod(req_t.investAmount) + global::ca::kFixDoubleMinPrecision) *
        global::ca::kDecimalNum;
    int32_t investType = std::stoll(req_t.investType);

    bool isFindUtxoFlag = req_t.isFindUtxo;
    std::string encodedInfo = Base64Encode(req_t.txInfo);

    ReplaceCreateInvestTransaction(
        fromAddr, toAddr, investAmout, investType, isFindUtxoFlag, encodedInfo, &ack_t);
   
    
    res.set_content(ack_t._paseToString(), "application/json");
}

void _GetDisinvest(const Request &req, Response &res) 
{
    getDisinvestreq req_t;
    txAck ack_t;

    CHECK_PARSE_REQ    
    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetDisInvestTransaction";


    std::string fromAddr = req_t.fromAddr;
    if (fromAddr.substr(0, 2) == "0x") 
    {
        fromAddr = fromAddr.substr(2);
    }
    std::string toAddr = req_t.toAddr;
    if (toAddr.substr(0, 2) == "0x") 
    {
        toAddr = toAddr.substr(2);
    }
    std::string utxoHash = req_t.utxoHash;
    if (utxoHash.substr(0, 2) == "0x") 
    {
        utxoHash = utxoHash.substr(2);
    }

    bool isFindUtxoFlag = req_t.isFindUtxo;
    std::string encodedInfo = Base64Encode(req_t.txInfo);

    ReplaceCreateDisinvestTransaction(
        fromAddr, toAddr, utxoHash, isFindUtxoFlag, encodedInfo, &ack_t);

    res.set_content(ack_t._paseToString(), "application/json");
}

std::map<int, std::string> ratesInfoErrorList = {
	{-101, "Failed to obtain the total flux"},
	{-102, "Failed to claim Utxo via periodic fetch"},
	{-103, "Failure to retrieve transaction via hash"},
	{-104, "Deserialization transaction failed"},
	{-201, "Failed to obtain the total burn amount"},
	{-202, "Failed to get the burn amount through the cycle"},
	{-203, "The amount destroyed on the day was greater than the total amount destroyed"},
	{-301, "Failure to obtain the total investment amount"},
    {-302, "Obtaining investment utxo through the cycle fails"},
	{-303, "Failure to retrieve transaction via hash"},
	{-304, "Deserialization transaction failed"},
};
void _ApiGetRatesInfo(const Request &req, Response &res) 
{
    GetRatesInfoReq req_t;
    GetRatesInfoAck ack_t;
    CHECK_PARSE_REQ
    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetRatesInfo";

    typedef boost::multiprecision::cpp_bin_float_50 cpp_bin_float;
    uint64_t curTime =
        MagicSingleton<TimeUtil>::GetInstance()->GetUTCTimestamp();
    uint64_t totalCirculationYesterday = 0;
    uint64_t totalInvestYesterday = 0;
    uint64_t totalCirculation = 0;
    DBReadWriter dbWriter;

    int ret = 0;

    do {
    ret = GetTotalCirculationYesterday(curTime, totalCirculationYesterday);
    if (ret < 0) {
		auto it = ratesInfoErrorList.find(ret);
		std::string errorMessage;
		if(it != ratesInfoErrorList.end()){
			errorMessage = it->second;
		}else{
			errorMessage = "GetTotalCirculationYesterday error";
		}

        ack_t.code = ret;
        ack_t.message = errorMessage;
        break;
    }

    uint64_t totalBrunYesterday = 0;
    ret = GetTotalBurnYesterday(curTime, totalBrunYesterday);
    if (ret < 0) {
		auto it = ratesInfoErrorList.find(ret);
		std::string errorMessage;
		if(it != ratesInfoErrorList.end()){
			errorMessage = it->second;
		}else{
			errorMessage = "GetTotalCirculationYesterday error";
		}

        ack_t.code = ret;
        ack_t.message = errorMessage;
        break;
    }

    totalCirculationYesterday = totalCirculationYesterday - totalBrunYesterday;
    ack_t.TotalCirculatingSupply = std::to_string(totalCirculationYesterday);
    ack_t.TotalBurn = std::to_string(totalBrunYesterday);
    ret = GetTotalInvestmentYesterday(curTime, totalInvestYesterday);
    if (ret < 0) {
		auto it = ratesInfoErrorList.find(ret);
		std::string errorMessage;
		if(it != ratesInfoErrorList.end()){
			errorMessage = it->second;
		}else{
			errorMessage = "GetTotalCirculationYesterday error";
		}

        ack_t.code = ret;
        ack_t.message = errorMessage;
        break;
    }
    ack_t.TotalStaked = std::to_string(totalInvestYesterday);

    uint64_t StakeRate =
        ((double)totalInvestYesterday / totalCirculationYesterday + 0.005) *
        100;
    if (StakeRate <= 25) 
    {
        StakeRate = 25;
    }
    else if (StakeRate >= 90) 
    {
        StakeRate = 90;
    }
    ack_t.StakingRate = std::to_string((double)totalInvestYesterday /
                                                totalCirculationYesterday);

    double inflationRate = .0f;
    ca_algorithm::GetInflationRate(curTime, StakeRate - 1, inflationRate);

    std::stringstream ss;
    ss << std::setprecision(8) << inflationRate;
    std::string inflationRateStr = ss.str();
    ss.str(std::string());
    ss.clear();
    ss << std::setprecision(2) << (StakeRate / 100.0);
    std::string stakeRateStr = ss.str();
    cpp_bin_float earningRate0 =
        static_cast<cpp_bin_float>(std::to_string(global::ca::kDecimalNum)) *
        (static_cast<cpp_bin_float>(inflationRateStr) /
            static_cast<cpp_bin_float>(stakeRateStr));
    ss.str(std::string());
    ss.clear();
    ss << std::setprecision(8) << earningRate0;

    uint64_t earningRate1 = std::stoi(ss.str());


    double earningRate2 = (double)earningRate1 / global::ca::kDecimalNum;
    if (earningRate2 > 0.34) 
    {
        ack_t.code = -1;
        ack_t.message = "The earning Rate is greater than the threshold";
        break;
    }
    ack_t.CurrentAPR = std::to_string(earningRate2);
    ack_t.code = 0;
    ack_t.message = "success";

    } while (0);

    res.set_content(ack_t._paseToString(), "application/json");
}

void _GetBonus(const Request &req, Response &res) 
{
    getBonusReq req_t;
    txAck ack_t;
    CHECK_PARSE_REQ
    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetBounsTransaction";

  
    std::string Addr = req_t.Addr;
    if (Addr.substr(0, 2) == "0x") 
    {
        Addr = Addr.substr(2);
    }

    bool isFindUtxoFlag = req_t.isFindUtxo;
    std::string encodedInfo = Base64Encode(req_t.txInfo);

    ReplaceCreateBonusTransaction(Addr, isFindUtxoFlag, encodedInfo, &ack_t);

    res.set_content(ack_t._paseToString(), "application/json");
}

void _GetDisinvestUtxo(const Request &req, Response &res) {
    get_disinvestutxo_ack ack_t;
    get_disinvestutxo_req req_t;

    CHECK_PARSE_REQ
    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetDisinvestUtxo";

    std::string toAddr = req_t.toAddr;
    if (toAddr.substr(0, 2) == "0x") 
    {
        toAddr = toAddr.substr(2);
    }

    std::string fromAddr = req_t.fromAddr;
    if (fromAddr.substr(0, 2) == "0x") 
    {
        fromAddr = fromAddr.substr(2);
    }

    DBReader dbReader;
    nlohmann::json resultJs;
    std::vector<std::string> vecUtxos;
    
    auto ret = dbReader.GetBonusAddrInvestUtxosByBonusAddr(toAddr, fromAddr,vecUtxos);
    if(ret!= DBStatus::DB_SUCCESS)
    {
        ack_t.code = -1;
        ack_t.message = "The address has no investment in anyone";
    }
    std::reverse(vecUtxos.begin(), vecUtxos.end());

    for(auto &utxo : vecUtxos)
    {
        resultJs["utxo"].push_back(addHexPrefix(utxo));
    }
    ack_t.code = 0;
    ack_t.message = "success";
    ack_t.utxos = resultJs;
    res.set_content(ack_t._paseToString(), "application/json");
    DEBUGLOG("http_api.cpp:GetDisinvestUtxo ack_T.paseToString{}",ack_t._paseToString());

}


void _GetStakeUtxo(const Request &req, Response &res) {
    get_stakeutxo_ack ack_t;
    get_stakeutxo_req req_t;

    CHECK_PARSE_REQ
    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetStakeUtxo";

    std::string strFromAddr = req_t.fromAddr;
    if (strFromAddr.substr(0, 2) == "0x") 
    {
        strFromAddr = strFromAddr.substr(2);
    }

    DBReader dbReader;
    std::vector<std::string> utxos;
    auto ret = dbReader.GetStakeAddressUtxo(strFromAddr, utxos);
    if(ret != DBStatus::DB_SUCCESS)
    {
        ack_t.code = -1;
        ack_t.message = "fromaddr not stake!";
    }

    std::reverse(utxos.begin(), utxos.end());
    nlohmann::json outPut;
    for (auto &utxo : utxos) {
        std::string txRaw;
        dbReader.GetTransactionByHash(utxo, txRaw);
        CTransaction tx;
        tx.ParseFromString(txRaw);
        uint64_t value = 0;
        for (auto &vout : tx.utxo().vout()) {
            if (vout.addr() == global::ca::kVirtualStakeAddr) {
                value = vout.value();
            }
            outPut[addHexPrefix(utxo)] = value;
        }
    }

    ack_t.code = 0;
    ack_t.message = "success";
    ack_t.utxos = outPut;
    res.set_content(ack_t._paseToString(), "application/json");
    DEBUGLOG("http_api.cpp:GetStakeUtxo ack_T.paseToString{}",ack_t._paseToString());
}


void _GetTransaction(const Request &req, Response &res) 
{
    txAck ack_t;
    tx_req req_t;

    CHECK_PARSE_REQ
    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetTransaction";
    std::map<std::string, int64_t> toAddr;

    for (auto iter = req_t.toAddr.begin(); iter != req_t.toAddr.end(); iter++) 
    {
        std::string address = iter->first;
        if (address.substr(0, 2) == "0x") 
        {
            address = address.substr(2);
        }

        std::string inputValue=iter->second;
        CHECK_VALUE(inputValue);
        toAddr[address] =
            (std::stod(iter->second) + global::ca::kFixDoubleMinPrecision) *
            global::ca::kDecimalNum;
    }

    std::vector<std::string> fromAddr;
    for (const auto& address : req_t.fromAddr)
    {
        if (address.substr(0, 2) == "0x") 
        {
            fromAddr.push_back(address.substr(2));
        }
        else
        {
            fromAddr.push_back(address);
        }
    }

    bool isFindUtxoFlag = req_t.isFindUtxo;
    std::string encodedInfo = Base64Encode(req_t.txInfo);

    ReplaceCreateTxTransaction(fromAddr, toAddr, isFindUtxoFlag, encodedInfo, &ack_t);
    
    res.set_content(ack_t._paseToString(), "application/json");
}



void _DeployContract(const Request &req, Response &res) {
    
    deploy_contract_req req_t;
    contractAck ack_t;
    CHECK_PARSE_REQ

    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetDeployContractTransaction";

    ack_t.code = 0;
    ack_t.message = "success";

    std::string ret = RpcDeployContract((void *)&req_t, &ack_t);

    if (ack_t.code == -2300)
    {
        auto rpcError=GetRpcError();
        ack_t.code = std::atoi(rpcError.first.c_str());
        ack_t.message = rpcError.second;
    }
    
    
    res.set_content(ack_t._paseToString(), "application/json");
}



void _CallContract(const Request &req, Response &res) 
{
    RpcErrorClear();
    call_contract_req req_t;
    contractAck ack_t;
    CHECK_PARSE_REQ;

    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetCallContractTransaction";

    ack_t.code = 0;
    ack_t.message = "success";

    std::string ret = RpcCallContract((void *)&req_t, &ack_t);

    if(ack_t.code == -2300)
    {
        auto rpcError=GetRpcError();
        ack_t.message = rpcError.second;
        ack_t.code = std::atoi(rpcError.first.c_str());
    }

    res.set_content(ack_t._paseToString(), "application/json");
}



void _ApiGetAllBonusInfo(const Request &req,Response &res)
{
    getAllbonusInfoReq req_t;
    getAllbonusInfoAck ack_t;
    CHECK_PARSE_REQ
    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetBonusInfo";

    nlohmann::json addr_conut_time;
    std::map<std::string, double> addr_percent;
    std::unordered_map<std::string, uint64_t> addrSignCnt;
    uint64_t curTime = MagicSingleton<TimeUtil>::GetInstance()->GetUTCTimestamp();
    uint64_t morningTime = MagicSingleton<TimeUtil>::GetInstance()->GetMorningTime(curTime)*1000000;

    auto ret = ca_algorithm::GetAbnormalSignAddrListByPeriod(curTime, addr_percent, addrSignCnt);
    if(ret < 0) 
    {   
        ack_t.code = -1;
        ack_t.message = "DB get sign addr failed!";
        ERRORLOG("DB get sign addr failed!");
    }   

    addr_conut_time["time"] = std::to_string(morningTime); 
    for(auto &it : addrSignCnt)
    {
        nlohmann::json addr_count;  
        addr_count["address"] = addHexPrefix(it.first);
        addr_count["count"] = it.second;
        addr_conut_time["addr_count"].push_back(addr_count);
    }

    ack_t.code = 0;
    ack_t.message = "message";
    ack_t.info = addr_conut_time;
    res.set_content(ack_t._paseToString(), "application/json");
}


void _GetAllStakeNodeListnowledge(const Request & req,Response & res){
 
    get_all_stake_node_list_req req_t;
    get_all_stake_node_list_ack ack_t;
    CHECK_PARSE_REQ
    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetAllStakeNodeList";

    std::shared_ptr<GetAllStakeNodeListReq> p_req;
    GetAllStakeNodeListAck  p_ack;
    int ret = GetAllStakeNodeListReqImpl(p_req, p_ack);
    if(ret!=0){
        p_ack.set_code(ret);
    }

    std::string jsonstr;
    google::protobuf::util::Status status =
        google::protobuf::util::MessageToJsonString(p_ack, &jsonstr);
       if(!status.ok()){
            errorL("protobuff to json fail");
            jsonstr="protobuff to json fail";
       }
    ack_t.code = p_ack.code();
    ack_t.message = p_ack.message();
    ack_t.list = nlohmann::json::parse(jsonstr);
    res.set_content(ack_t._paseToString(),"application/json");
}


void _ConfirmTransaction(const Request &req, Response &res) 
{
    confirm_transaction_req req_t;
    confirm_transaction_ack ack_t;
    CHECK_PARSE_REQ

    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "ConfirmTransaction";
    uint64_t height = std::stoll(req_t.height);
    ConfirmTransactionAck ack;
    std::shared_ptr<ConfirmTransactionReq> req_p = std::make_shared<ConfirmTransactionReq>();
    std::string txHash = req_t.txhash;
    if (txHash.substr(0, 2) == "0x") 
    {
        txHash = txHash.substr(2);
    }

    req_p->add_txhash(txHash);
    req_p->set_version(global::kVersion);
    req_p->set_height(height);
    auto currentTime = MagicSingleton<TimeUtil>::GetInstance()->GetUTCTimestamp();
    req_p->set_time(currentTime);

    int ret = 0;
    ret = SendConfirmTransactionReq(req_p, ack);
    ack_t.code = ret;
    ack_t.message = "success";
    if(ret != 0)
    {
        ERRORLOG("sussize is empty{}",ret);
        ack_t.code = ret;
        ack_t.message = ack.message();
        res.set_content(ack_t._paseToString(),"application/json");
        return;
    }
    std::string debugValue;
    google::protobuf::util::Status status =
        google::protobuf::util::MessageToJsonString(ack, &debugValue);
     DEBUGLOG("http_api.cpp:ConfirmTransaction ack_t.paseToString {}",debugValue);

   
    auto sus = ack.percentage();
    auto susSize = sus.size();
    if(susSize == 0)
    {
        ERRORLOG("sussize is empty{}",susSize);
        ack_t.message = "susSize node list is empty";
        ack_t.code = -6;
        res.set_content(ack_t._paseToString(),"application/json");
        return;
    }
    std::string received_size = std::to_string(ack.received_size());
    int receivedSizeNum = stoi(received_size);

    std::vector<Node> nodelist = MagicSingleton<PeerNode>::GetInstance()->GetNodelist();
    int sendsize = nodelist.size();
    if(receivedSizeNum < sendsize * 0.5)
    {
      ack_t.code = -7;
      ack_t.message = "The amount received was too small to verify transaction on-chain";
      res.set_content(ack_t._paseToString(),"application/json");
      return;
    }


    auto rate = sus.at(0);
    ack_t.txhash = addHexPrefix(rate.hash());
    ack_t.percent = std::to_string(rate.rate());
    ack_t.receivedsize = std::to_string(ack.received_size());
    ack_t.sendsize = std::to_string(ack.send_size());

    CTransaction tx;
    if (!tx.ParseFromString(ack.tx())) {
        ack_t.code = -8;
        ack_t.message = "tx ParseFromString error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }
    ack_t.tx = nlohmann::json::parse(TxInvet(tx));

    res.set_content(ack_t._paseToString(), "application/json");
}

void _GetBlockNumber(const Request &req, Response &res){
    getblocknumberReq req_t;
    getblocknumberAck ack_t;
    CHECK_PARSE_REQ
    ack_t.id=req_t.id;
    ack_t.method="GetBlockNumber";
    ack_t.jsonrpc=req_t.jsonrpc;
    DBReader dbReader;
    uint64_t top = 0;

    if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(top)) {
        ack_t.code = -1;
        ack_t.message = "GetBlockTop error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }

    ack_t.top = std::to_string(top);
    ack_t.code = 0;
    ack_t.message = "success";
    //ack_t.identity = "0x" + MagicSingleton<PeerNode>::GetInstance()->GetSelfId();
    res.set_content(ack_t._paseToString(), "application/json");
}

void _GetVersion(const Request &req, Response &res) {
    getversionReq req_t;
    getversionAck ack_t;
    CHECK_PARSE_REQ
	ack_t.id=req_t.id;
    ack_t.method="GetVersion";
    ack_t.jsonrpc=req_t.jsonrpc;

    ack_t.clientVersion =global::kVersion;
    ack_t.netVersion =global::kNetVersion;
    ack_t.configVersion= MagicSingleton<Config>::GetInstance()->GetVersion();
    ack_t.dbVersion=global::kVersion;
    ack_t.code = 0;
    ack_t.message = "success";
    res.set_content(ack_t._paseToString(), "application/json");
}

void _GetBalance(const Request &req, Response &res) {
    balanceReq req_t;
    balanceAck ack_t;
    CHECK_PARSE_REQ
	ack_t.id=req_t.id;
    ack_t.method="GetBalance";
    ack_t.jsonrpc=req_t.jsonrpc;
    std::string address = req_t.addr;
    if (address.substr(0, 2) == "0x") 
    {
        address = address.substr(2);
    }

    if (!isValidAddress(address)) {
        ack_t.code = -1;
        ack_t.message = "address is invalid";
        ack_t.addr = addHexPrefix(address);
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }

    uint64_t balance = 0;
    if (GetBalanceByUtxo(address.c_str(), balance) != 0 && GetBalanceByUtxo(address.c_str(), balance) != -2) {
        ack_t.addr = addHexPrefix(address);
        ack_t.code = -2;
        ack_t.message = "search balance failed";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }
    ack_t.addr = addHexPrefix(address);
    ack_t.balance=std::to_string(balance);
    ack_t.code = 0;
    ack_t.message = "success";
    res.set_content(ack_t._paseToString(), "application/json");
}

void _GetBlockTransactionCountByHash(const Request &req, Response &res){
	getblocktransactioncountReq req_t;
	getblocktransactioncountAck ack_t;
	CHECK_PARSE_REQ
    std::string blockStr;
	DBReader dbReader;
	ack_t.id=req_t.id;
    ack_t.method="GetBlockTransactionCountByHash";
    ack_t.jsonrpc=req_t.jsonrpc;
	std::string blockHash = req_t.blockHash;
    if (blockHash.substr(0, 2) == "0x") 
    {
        blockHash = blockHash.substr(2);
    }
	if (DBStatus::DB_SUCCESS != dbReader.GetBlockByBlockHash(blockHash, blockStr)){
        ack_t.code = -1;
        ack_t.message = "GetBlockByBlockHash error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }
	CBlock block;
    if (!block.ParseFromString(blockStr))
	{
        ack_t.code = -2;
        ack_t.message = "block parse string fail";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
	}
    uint64_t nums = 0;
    nums=block.txs().size();
    ack_t.txCount=std::to_string(nums);
	ack_t.code = 0;
    ack_t.message = "success";
	res.set_content(ack_t._paseToString(), "application/json");
}

void _GetAccounts(const Request &req, Response &res){
    getaccountsReq req_t;
    getaccountsAck ack_t;

    CHECK_PARSE_REQ
	ack_t.id=req_t.id;
    ack_t.method="GetAccounts";
    ack_t.jsonrpc=req_t.jsonrpc;
    DBReader dbReader;

    std::vector<std::string> list;
    std::vector<std::string> endlist;
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(list);
    auto it = std::find(list.begin(), list.end(), MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr());
    if (it != list.end()) {
        std::rotate(list.begin(), it, it + 1);
    }
      for (auto &i : list) {
        uint64_t amount = 0;
        endlist.push_back("0x"+i); 
    }
    ack_t.acccountlist=endlist;
    ack_t.code = 0;
    ack_t.message = "success";
    res.set_content(ack_t._paseToString(), "application/json");
}

void _GetChainId(const Request &req, Response &res){
    getchainidReq req_t;
    getchainidAck ack_t;

    CHECK_PARSE_REQ
	ack_t.id=req_t.id;
    ack_t.method="GetChainId";
    ack_t.jsonrpc=req_t.jsonrpc;

    std::string blockHash = global::ca::kGenesisBlockRaw;
    blockHash = blockHash.substr(0,8);
    ack_t.chainId= addHexPrefix(blockHash);
    ack_t.code = 0;
    ack_t.message = "success";
    res.set_content(ack_t._paseToString(), "application/json");
}

std::vector<std::string> splitString(const std::string& str) {
    std::vector<std::string> result;
    std::regex rgx(R"(ip\((\d+\.\d+\.\d+\.\d+)\)\s+port\((\d+)\)\s+ip_l\((\d+\.\d+\.\d+\.\d+)\)\s+port_l\((\d+)\)\s+kind\((\d+)\)\s+fd\((\d+)\)\s+addr\(0x([a-fA-F0-9]+)\)\s+pulse\((\d+)\)\s+height\(\s*(\d+)\s*\)\s+name\(([^)]*)\)\s+version\((\d+_\d+\.\d+\.\d+_[ptd])\)\s+logo\(([^)]*)\))");
    std::sregex_iterator iter(str.begin(), str.end(), rgx);
    std::sregex_iterator end;

    while (iter != end) {
        result.push_back(iter->str());
        ++iter; 
    }

    return result;
}

nlohmann::json parseEntry(const std::string& entry) {
    std::regex rgx(R"(ip\((\d+\.\d+\.\d+\.\d+)\)\s+port\((\d+)\)\s+ip_l\((\d+\.\d+\.\d+\.\d+)\)\s+port_l\((\d+)\)\s+kind\((\d+)\)\s+fd\((\d+)\)\s+addr\(0x([a-fA-F0-9]+)\)\s+pulse\((\d+)\)\s+height\(\s*(\d+)\s*\)\s+name\(([^)]*)\)\s+version\((\d+_\d+\.\d+\.\d+_[ptd])\)\s+logo\(([^)]*)\))");
    std::smatch match;
    nlohmann::json j;

    if (std::regex_search(entry, match, rgx)) {
        j["ip"] = match[1].str();
        j["port"] = match[2].str();
        j["ip_l"] = match[3].str();
        j["port_l"] = match[4].str();
        j["kind"] = match[5].str();
        j["fd"] = match[6].str();
        j["addr"] = "0x"+match[7].str();
        j["pulse"] = match[8].str();
        j["height"] = match[9].str();
        j["name"] =  match[10].str(); 
        j["version"] = match[11].str();
        j["logo"] = Base64Encode(match[12].str()); 
    }

    return j;
}


void _GetPeerList(const Request &req, Response &res) 
{
    getpeerlistReq req_t;
    getpeerlistAck ack_t;

    nlohmann::json infoList;
    std::ostringstream oss;
    CHECK_PARSE_REQ
	ack_t.id=req_t.id;
    ack_t.method="GetPeerList";
    ack_t.jsonrpc=req_t.jsonrpc;


    std::vector<std::string> baseList;
    std::vector<Node> nodeList =MagicSingleton<PeerNode>::GetInstance()->GetNodelist();
    std::string strlist=MagicSingleton<PeerNode>::GetInstance()->NodelistInfo(nodeList);

    std::vector<std::string> result = splitString(strlist);
    nlohmann::json j_array =  nlohmann::json::array();
    for (const auto& entry : result) {
        j_array.push_back(parseEntry(entry));
    }
    ack_t.peers=j_array;
    ack_t.size=nodeList.size();
    ack_t.code = 0;
    ack_t.message = "success";
    res.set_content(ack_t._paseToString(), "application/json");
}


void _ApiGetTransactionInfo(const Request &req,Response &res)
{
    getTransactionInfoReq req_t;
    getTransactionInfoAck ack_t;
    CHECK_PARSE_REQ

    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetTransactionByHash";

    DBReader dbReader;
	std::string strTx;
	if (DBStatus::DB_SUCCESS != dbReader.GetTransactionByHash(remove0xPrefix(req_t.txHash), strTx))
	{
        ack_t.code = -1;
        ack_t.message = "Tx hash error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
	}

	CTransaction tx;
	if (!tx.ParseFromString(strTx))
	{
        ack_t.code = -2;
        ack_t.message = "Failed to parse transaction body";
        res.set_content(ack_t._paseToString(), "application/json");
		return;
	}

    ack_t.code = 0;
    ack_t.message = "success";
    ack_t.tx = nlohmann::json::parse(TxInvet(tx));
    
    res.set_content(ack_t._paseToString(), "application/json");
}


void _APiGetBlockByTransactionHash(const Request & req, Response & res)
{
    getBlockInfoByTxHashReq req_t;
    getBlockInfoByTxHashAck ack_t;
    CHECK_PARSE_REQ

    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetBlockByTransactionHash";

    DBReader dbReader;
    std::string blockHash;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockHashByTransactionHash(remove0xPrefix(req_t.txHash), blockHash))
	{
        ack_t.code = -1;
        ack_t.message = "Tx hash error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
	}

	std::string strBlock;
	if (DBStatus::DB_SUCCESS != dbReader.GetBlockByBlockHash(blockHash, strBlock))
	{
        ack_t.code = -2;
        ack_t.message = "Block hash error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
	}

    nlohmann::json block;
    CBlock cblock;
    if(!cblock.ParseFromString(strBlock))
    {
        ack_t.code = -3;
        ack_t.message = "block_raw parse fail!";
        res.set_content(ack_t._paseToString(), "application/json");
        return ;
    }

    BlockInvert(cblock, block);
    if(block.empty())
    {
        ack_t.code = -4;
        ack_t.message = "Block invert error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }

    ack_t.code = 0;
    ack_t.message = "success";
    ack_t.blockInfo = nlohmann::json::parse(block.dump());
    res.set_content(ack_t._paseToString(), "application/json");
}



void _ApiGetBlockByHash(const Request &req,Response &res)
{
    getBlockInfoByHashReq req_t;
    getBlockInfoByHashAck ack_t;
    CHECK_PARSE_REQ

    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetBlockByHash";

    DBReader dbReader;
	std::string strBlock;
	if (DBStatus::DB_SUCCESS != dbReader.GetBlockByBlockHash(remove0xPrefix(req_t.blockHash), strBlock))
	{
        ack_t.code = -1;
        ack_t.message = "Block hash error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
	}

    nlohmann::json block;
    CBlock cblock;
    if(!cblock.ParseFromString(strBlock))
    {
        ERRORLOG("block_raw parse fail!");
        return ;
    }
    BlockInvert(cblock, block);

    ack_t.code = 0;
    ack_t.message = "success";
    ack_t.blockInfo = nlohmann::json::parse(block.dump());
    res.set_content(ack_t._paseToString(), "application/json");
}


void _ApiGetBlockByHeight(const Request &req,Response &res)
{
    getBlockInfoByHeightReq req_t;
    getBlockInfoByHeightAck ack_t;
    CHECK_PARSE_REQ

    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetBlockByHeight";

    DBReader dbReader;
    uint64_t blockHeight;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(blockHeight))
    {
        ack_t.code = -5;
        ack_t.message = "Database abnormal, Get block top error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }

    uint64_t beginHeight = std::stoull(req_t.beginHeight);
    uint64_t endHeight = std::stoull(req_t.endHeight);
    if(endHeight > blockHeight)
    {
        endHeight = blockHeight;
    }
    if(beginHeight > blockHeight)
    {
        beginHeight = blockHeight;
    }

    if(beginHeight > endHeight)
    {
        ack_t.code = -1;
        ack_t.message = "Block height error, beginHeight < endHeight";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }

    if(endHeight - beginHeight > 100)
    {
        ack_t.code = -2;
        ack_t.message = "The height of the request does not exceed 100";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
    }

    std::vector<std::string> blockHashes;
	if (DBStatus::DB_SUCCESS != dbReader.GetBlockHashesByBlockHeight(beginHeight, endHeight, blockHashes))
	{
        ack_t.code = -3;
        ack_t.message = "Database abnormal, Get block hashes by block height error";
        res.set_content(ack_t._paseToString(), "application/json");
        return;
	}

    std::string strBlock;
    for(const auto& t : blockHashes)
    {
        if (DBStatus::DB_SUCCESS != dbReader.GetBlockByBlockHash(t, strBlock))
        {
            ack_t.code = -4;
            ack_t.message = "Database abnormal, Get block by block hash error, block hash: " + t;
            res.set_content(ack_t._paseToString(), "application/json");
            ack_t.blocks.clear();
            return;
        }
        
        nlohmann::json block;
        CBlock cblock;
        if(!cblock.ParseFromString(strBlock))
        {
            ERRORLOG("block_raw parse fail!");
            return ;
        }
        BlockInvert(cblock, block);
        ack_t.blocks.emplace_back(std::move(nlohmann::json::parse(block.dump())));
    }

    ack_t.code = 0;
    ack_t.message = "success";
    res.set_content(ack_t._paseToString(), "application/json");
}

void _ApiSendMessage(const Request &req, Response &res) 
{
    rpcAck ack_t;
    txAck req_t;
    CHECK_PARSE_REQ;

    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "SendMessage";

    CTransaction tx;
    Vrf info;
    int height;
    TxHelper::vrfAgentType type;
    google::protobuf::util::Status status =
        google::protobuf::util::JsonStringToMessage(req_t.txJson, &tx);
    status = google::protobuf::util::JsonStringToMessage(req_t.vrfJson, &info);
   
    height = std::stoi(req_t.height);
    type = (TxHelper::vrfAgentType)std::stoi(req_t.txType);
    std::string txHash = Getsha256hash(tx.SerializeAsString());
    ack_t.txHash = addHexPrefix(txHash);
    int ret = SendMessage(tx, height, info, type);

    ack_t.code = ret;
    ret == 0 ? ack_t.message = "success" : ack_t.message = "TxHelper::SendMessage error";

    std::string back = ack_t._paseToString();
    res.set_content(back, "application/json");
}

void _ApiSendContractMessage(const Request & req,Response & res){
    contractAck ack;
    rpcAck ack_t;
    if(ack._paseFromJson(req.body)!="OK"){
        errorL("pase fail");
        return;
    }

    ack_t.id = ack.id;
    ack_t.jsonrpc = ack.jsonrpc;
    ack_t.method = "SendContractMessage"; 

    ContractTxMsgReq ContractMsg;
    CTransaction tx;
    google::protobuf::util::JsonStringToMessage(ack.contractJs, &ContractMsg);
    google::protobuf::util::JsonStringToMessage(ack.txJson, &tx);

    std::string txHash = Getsha256hash(tx.SerializeAsString());
    tx.set_hash(txHash);
    
    ack_t.txHash = addHexPrefix(txHash);
    ack_t.code = 0;
    ack_t.message = "success";

    TxMsgReq txReq= ContractMsg.txmsgreq();
    TxMsgInfo info=txReq.txmsginfo();
    info.set_tx(tx.SerializeAsString());
    txReq.clear_txmsginfo();
    TxMsgInfo *info_p=txReq.mutable_txmsginfo();
    info_p->CopyFrom(info);
    ContractMsg.clear_txmsgreq();
    TxMsgReq * txReq_p=ContractMsg.mutable_txmsgreq();
    txReq_p->CopyFrom(txReq);
    auto msg = std::make_shared<ContractTxMsgReq>(ContractMsg);
    DropCallShippingTx(msg,tx);

    res.set_content(ack_t._paseToString(), "application/json");
}

void _ApiGetDelegateInfoReq(const Request &req, Response &res)
{
    GetDelegateReq req_t;
    GetDelegateAck ack_t;
    CHECK_PARSE_REQ;

    ack_t.id = req_t.id;
    ack_t.jsonrpc = req_t.jsonrpc;
    ack_t.method = "GetDelegateInfo";

    std::string addr = req_t.addr;
    if (addr.substr(0, 2) == "0x") 
    {
        addr = addr.substr(2);
    }

    int ret = 0;
    std::string errMessage = "success";
    do
    {
        DBReader dbReader;
        std::vector<std::string> addresses;
        auto status = dbReader.GetInvestAddrsByBonusAddr(addr, addresses);
        if (status != DBStatus::DB_SUCCESS && status != DBStatus::DB_NOT_FOUND)
        {
            errMessage = "Database abnormal, Get invest addrs by node failed!";
            ret = -1;
            break;
        }
        if (addresses.size() + 1 > 999)
        {
            errMessage = "The account number to be invested have been invested by 999 people!";
            ret = -2;
            break;
        }

        // The node to be invested can only be be invested 100000 at most
        for (auto &address : addresses)
        {
            std::vector<std::string> utxos;
            if (dbReader.GetBonusAddrInvestUtxosByBonusAddr(addr, address, utxos) != DBStatus::DB_SUCCESS)
            {
                errMessage = "Database abnormal, Get bonus addr invest utxos by bonusAddr failed!";
                ret = -3;
                break;
            }

            for (const auto &utxo : utxos)
            {
                std::string strTx;
                if (dbReader.GetTransactionByHash(utxo, strTx) != DBStatus::DB_SUCCESS)
                {
                    errMessage = "Database abnormal, Get transaction by hash failed!";
                    ret = -4;
                    break;
                }

                CTransaction tx;
                if (!tx.ParseFromString(strTx))
                {
                    errMessage = "Failed to parse transaction body!";
                    ret = -5;
                    break;
                }
                uint64_t sumInvestAmount = 0;
                for (auto &vout : tx.utxo().vout())
                {
                    if (vout.addr() == global::ca::kVirtualInvestAddr)
                    {
                        sumInvestAmount += vout.value();
                        break;
                    }
                }
                ack_t.info.insert(std::make_pair(addHexPrefix(address), std::to_string(sumInvestAmount)));
            }
        }
    } while(0);
    
    ack_t.code = ret;
    ack_t.message = errMessage;
    if(ret != 0)
    {
        ack_t.info.clear();
    }
    res.set_content(ack_t._paseToString(), "application/json");
}

void _ApiPrintBlock(const Request &req, Response &res) 
{
    int num = 100;
    if (req.has_param("num")) {
        num = atol(req.get_param_value("num").c_str());
    }
    int startNum = 0;
    if (req.has_param("height")) {
        startNum = atol(req.get_param_value("height").c_str());
    }
    int hash = 0;
    if (req.has_param("hash")) {
        hash = atol(req.get_param_value("hash").c_str());
    }

    std::string str;

    if (hash) {
        str = PrintBlocksHash(num, req.has_param("pre_hash_flag"));
        res.set_content(str, "text/plain");
        return;
    }

    if (startNum == 0)
        str = PrintContractBlocks(num, req.has_param("pre_hash_flag"));
    else
        str = PrintRangeContractBlocks(startNum, num, req.has_param("pre_hash_flag"));

    res.set_content(str, "text/plain");
}

void ApiInfo(const Request &req, Response &res) 
{

    std::ostringstream oss;

    oss << "queue:" << std::endl;
    oss << "g_queueRead:" << global::g_queueRead.msgQueue.size() << std::endl;
    oss << "g_queueWork:" << global::g_queueWork.msgQueue.size() << std::endl;
    oss << "g_queueWrite:" << global::g_queueWrite.msgQueue.size() << std::endl;
    oss << "\n" << std::endl;

    oss << "amount:" << std::endl;
    std::vector<std::string> baseList;

    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(baseList);
    for (auto &i : baseList) {
        uint64_t amount = 0;
        GetBalanceByUtxo(i, amount);
        oss << "0x"+i + ":" + std::to_string(amount) << std::endl;
    }
    oss << "\n" << std::endl;

    std::vector<Node> nodeList =
        MagicSingleton<PeerNode>::GetInstance()->GetNodelist();
    oss << "Public PeerNode size is: " << nodeList.size() << std::endl;
    oss << MagicSingleton<PeerNode>::GetInstance()->NodelistInfo(nodeList);

    oss << std::endl << std::endl;

    res.set_content(oss.str(), "text/plain");
}

void _ApiGetBlock(const Request &req, Response &res) {
    nlohmann::json block;
    nlohmann::json blocks;

    int top = 0;
    if (req.has_param("top")) {
        top = atol(req.get_param_value("top").c_str());
    }
    int num = 0;
    if (req.has_param("num")) {
        num = atol(req.get_param_value("num").c_str());
    }

    num = num > 500 ? 500 : num;

    if (top < 0 || num < 0) {
        ERRORLOG("_ApiGetBlock top < 0||num <= 0");
        return;
    }

    DBReader dbReader;
    uint64_t myTop = 0;
    dbReader.GetBlockTop(myTop);
    if (top > (int)myTop) {
        ERRORLOG("_ApiGetBlock begin > myTop");
        return;
    }
    int k = 0;
    uint64_t countNum = top + num;
    if (countNum > myTop) {
        countNum = myTop;
    }
    for (auto i = top; i <= countNum; i++) {
        std::vector<std::string> blockHashs;

        if (dbReader.GetBlockHashsByBlockHeight(i, blockHashs) !=
            DBStatus::DB_SUCCESS) 
        {
            return;
        }

        for (auto hash : blockHashs) 
        {
            std::string strHeader;
            if (dbReader.GetBlockByBlockHash(hash, strHeader) !=
                DBStatus::DB_SUCCESS) 
            {
                return;
            }

            CBlock cblock;
            if(!cblock.ParseFromString(strHeader))
            {
                ERRORLOG("block_raw parse fail!");
                return ;
            }
            BlockInvert(cblock, block);
            blocks[k++] = block;
        }
    }
    std::string str = blocks.dump();
    res.set_content(str, "application/json");
}

void _ApiPub(const Request &req, Response &res) 
{
    std::ostringstream oss;
    const int MaxInformationSize = 256;
    char buff[MaxInformationSize] = {};
    FILE *f = fopen("/proc/self/cmdline", "r");
    if (f == NULL) {
        DEBUGLOG("Failed to obtain main information ");
    } else {
        char readc;
        int i = 0;
        while (((readc = fgetc(f)) != EOF)) {
            if (readc == '\0') {
                buff[i++] = ' ';
            } else {
                buff[i++] = readc;
            }
        }
        fclose(f);
        char *fileName = strtok(buff, "\n");
        oss << "file_name:" << fileName << std::endl;
        oss << "==================================" << std::endl;
    }
    MagicSingleton<ProtobufDispatcher>::GetInstance()->TaskInfo(oss);
    oss << "g_queueRead:" << global::g_queueRead.msgQueue.size() << std::endl;
    oss << "g_queueWork:" << global::g_queueWork.msgQueue.size() << std::endl;
    oss << "g_queueWrite:" << global::g_queueWrite.msgQueue.size() << std::endl;
    oss << "\n" << std::endl;

    double total = .0f;
    uint64_t n64Count = 0;
    oss << "------------------------------------------" << std::endl;
    for (auto &item : global::g_reqCntMap) {
        total += (double)item.second.second; // data size
        oss.precision(3);                    // Keep 3 decimal places
        // Type of data		        Number of calls convert MB
        oss << item.first << ": " << item.second.first
            << " size: " << (double)item.second.second / 1024 / 1024 << " MB"
            << std::endl;
        n64Count += item.second.first;
    }
    oss << "------------------------------------------" << std::endl;
    oss << "Count: " << n64Count << "   Total: " << total / 1024 / 1024 << " MB"
        << std::endl; // Total size

    oss << std::endl;
    oss << std::endl;

    oss << "amount:" << std::endl;
    std::vector<std::string> baseList;

    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(baseList);
    for (auto &i : baseList) 
    {
        uint64_t amount = 0;
        GetBalanceByUtxo(i, amount);
        oss << "0x"+i + ":" + std::to_string(amount) << std::endl;
    }

    oss << std::endl << std::endl;

    std::vector<Node> pubNodeList =
        MagicSingleton<PeerNode>::GetInstance()->GetNodelist();
    oss << "Public PeerNode size is: " << pubNodeList.size() << std::endl;
    oss << MagicSingleton<PeerNode>::GetInstance()->NodelistInfo(
        pubNodeList); //   Convert all public network node data to string for
                      //   saving
    res.set_content(oss.str(), "text/plain");
}

void _GetRequesterIP(const Request &req, Response & res){
    std::ostringstream oss;
    std::string ip = req.remote_addr;
    oss << ip;
    res.set_content(oss.str(), "application/json");
}

void ApiPrintCalc1000SumHash(const Request &req,Response &res)
{
    int startHeight = 1000;
    if (req.has_param("startHeight")) {
        startHeight = atol(req.get_param_value("startHeight").c_str());
    }
    if(startHeight <= 0 || startHeight % 1000 != 0)
    {
        res.set_content("startHeight error", "text/plain");
        return;
    }

    int endHeight = 0;
    if (req.has_param("endHeight")) {
        endHeight = atol(req.get_param_value("endHeight").c_str());
    }

    if(endHeight < startHeight || endHeight % 1000 != 0)
    {
        res.set_content("endHeight error", "text/plain");
        return;
    }

    uint64_t max_height = 0;
    DBReader dbReader;
    if(DBStatus::DB_SUCCESS != dbReader.GetTopThousandSumhash(max_height))
    {
        res.set_content("GetBlockComHashHeight error", "text/plain");
        return;
    }

    std::ostringstream oss;
    if(max_height < endHeight)
    {
        endHeight = max_height;
        oss << "max_height = " << max_height << std::endl;
    }


    for(int i = startHeight; i <= endHeight; i += 1000)
    {
        std::string sumHash;
        auto ret = dbReader.GetCheckBlockHashsByBlockHeight(i, sumHash);
        if(ret == DBStatus::DB_SUCCESS)
        {
            oss << "blockHeight: " << i << "\t sumHash: " << sumHash << std::endl;
        }
        else 
        {
            oss << "GetCheckBlockHashsByBlockHeight error" << std::endl;
        }
        
    }


    res.set_content(oss.str(), "text/plain");

}

void ApiPrintHundredSumHash(const Request & req, Response & res)
{
    int startHeight = 100;
    if (req.has_param("startHeight")) {
        startHeight = atol(req.get_param_value("startHeight").c_str());
    }
    if(startHeight <= 0 || startHeight % 100 != 0)
    {
        res.set_content("startHeight error", "text/plain");
        return;
    }

    int endHeight = 0;
    if (req.has_param("endHeight")) {
        endHeight = atol(req.get_param_value("endHeight").c_str());
    }

    if(endHeight < startHeight || endHeight % 100 != 0)
    {
        res.set_content("endHeight error", "text/plain");
        return;
    }

    DBReader dbReader;
    std::ostringstream oss;

    for(int i = startHeight; i <= endHeight; i += 100)
    {
        std::string sumHash;
        auto ret = dbReader.GetSumHashByHeight(i, sumHash);
        if(ret == DBStatus::DB_SUCCESS)
        {
            oss << "blockHeight: " << i << "\t sumHash: " << sumHash << std::endl;
        }
        else 
        {
            oss << "GetSumHashByHeight error, error height: " << i << std::endl;
        }
        
    }
    
    res.set_content(oss.str(), "text/plain");
}

void ApiPrintAllBlocks(const Request &req,Response &res)
{
    int startHeight = 1;
    if (req.has_param("startHeight")) {
        startHeight = atol(req.get_param_value("startHeight").c_str());
    }
    if(startHeight <= 0)
    {
        res.set_content("error startHeight <= 0", "text/plain");
        return;
    }

    int endHeight = 0;
    if (req.has_param("endHeight")) {
        endHeight = atol(req.get_param_value("endHeight").c_str());
    }

    uint64_t selfNodeHeight = 0;
    DBReader dbReader;
    auto status = dbReader.GetBlockTop(selfNodeHeight);
    if (DBStatus::DB_SUCCESS != status)
    {
        res.set_content("GetBlockTop error", "text/plain");
        return;
    }

    if(endHeight > selfNodeHeight)
    {
        res.set_content("endHeight > selfNodeHeight", "text/plain");
        return;
    }

    std::stringstream oss;
    oss << "block_hash_" << startHeight << "_" << endHeight << ".txt";
    std::ofstream fout(oss.str(), std::ios::out);
    for(int i = startHeight; i <= endHeight; ++i)
    {
        std::vector<std::string> selfBlockHashes;
        if (DBStatus::DB_SUCCESS != dbReader.GetBlockHashesByBlockHeight(i, i, selfBlockHashes))
        {
            res.set_content("GetBlockHashesByBlockHeight error", "text/plain");
            return;
        }
        std::sort(selfBlockHashes.begin(), selfBlockHashes.end());
        fout << "block height: " << i << "\tblock size: " << selfBlockHashes.size() << std::endl; 
        for(const auto& hash: selfBlockHashes)
        {
            std::string strHeader;
            if (DBStatus::DB_SUCCESS != dbReader.GetBlockByBlockHash(hash, strHeader)) 
            {
                res.set_content("GetBlockByBlockHash error", "text/plain");
                return;
            }

            CBlock block;
            if(!block.ParseFromString(strHeader))
            {
                res.set_content("ParseFromString error", "text/plain");
                return;
            }
            fout << block.hash() << std::endl;
        }
        fout << "==============================================\n\n";

    }

    res.set_content("print success", "text/plain");

}


void ApiComputeSumHash(const Request &req,Response &res)
{
   int startHeight = 100;
    if (req.has_param("startHeight")) {
        startHeight = atol(req.get_param_value("startHeight").c_str());
    }
    if(startHeight <= 0 || startHeight % 100 != 0)
    {
        res.set_content("startHeight error", "text/plain");
        return;
    }

    int endHeight = 0;
    if (req.has_param("endHeight")) {
        endHeight = atol(req.get_param_value("endHeight").c_str());
    }

    if(endHeight < startHeight || endHeight % 100 != 0)
    {
        res.set_content("endHeight error", "text/plain");
        return;
    }

    DBReadWriter dbReader;
    std::ostringstream oss;

    for(int i = startHeight; i <= endHeight; i += 100)
    {
        std::string sumHash;
        auto ret = dbReader.GetSumHashByHeight(i, sumHash);
        if(ret == DBStatus::DB_SUCCESS)
        {
            oss << "blockHeight: " << i << "\t sumHash: " << sumHash << std::endl;
        }
        else 
        {
            oss << "GetSumHashByHeight error, error height: " << i << std::endl;
        }
        
    }
    oss << "=====================================================================================\n";


    uint64_t newTop = 0;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(newTop))
    {
        oss << "aaa" << std::endl;
        res.set_content(oss.str(), "text/plain");
        return;
    }

    for(int i = startHeight; i <= endHeight; i += 100)
    {
        std::string sumHash;
        auto start = ca_algorithm::GetSumHashFloorHeight(i) + 1;
        auto end = std::min(newTop, ca_algorithm::GetSumHashCeilingHeight(i) + 1);
        if(!ca_algorithm::CalculateHeightSumHash(start, end, dbReader, sumHash))
        {
            oss << "CalculateHeightSumHash error, error height: " << i << std::endl;
            continue;
        }
        oss << "start: " << i << "\t sumHash: " << sumHash << std::endl;
    }


    res.set_content(oss.str(), "text/plain");
}




struct CPUStat 
{
    unsigned long long user;
    unsigned long long nice;
    unsigned long long system;
    unsigned long long idle;
    unsigned long long iowait;
    unsigned long long irq;
    unsigned long long softirq;
};

static std::vector<CPUStat> GetCpuStats() {
    std::vector<CPUStat> cpuStats;
    std::ifstream statFile("/proc/stat");

    std::string line;
    while (std::getline(statFile, line)) 
    {
        if (line.compare(0, 3, "cpu") == 0) 
        {
            std::istringstream ss(line);

            std::string cpuLabel;
            CPUStat stat;
            ss >> cpuLabel >> stat.user >> stat.nice >> stat.system >>
                stat.idle >> stat.iowait >> stat.irq >> stat.softirq;

            cpuStats.push_back(stat);
        }
    }

    return cpuStats;
}

static double CalculateCpuUsage(const CPUStat &prev, const CPUStat &curr) 
{
    auto prevTotal = prev.user + prev.nice + prev.system + prev.idle +
                      prev.iowait + prev.irq + prev.softirq;
    auto currTotal = curr.user + curr.nice + curr.system + curr.idle +
                      curr.iowait + curr.irq + curr.softirq;

    auto totalDiff = currTotal - prevTotal;
    auto idleDiff = curr.idle - prev.idle;

    return (totalDiff - idleDiff) * 100.0 / totalDiff;
}

static std::string DoubleToStringWithPrecision(double value, int precision) 
{
    std::ostringstream out;
    out << std::fixed << std::setprecision(precision) << value;
    return out.str();
}

// get cpu info
std::string ApiGetCpuInfo() 
{
    std::string sum;
    sum =
        "======================================================================"
        "=========";
    sum += "\n";
    sum += "get_cpu_info";
    sum += "\n";
    std::ifstream cpuinfoFile("/proc/cpuinfo");
    std::string line;
    int cpuCores = 0;
    std::string cpuModel;
    double cpuFrequency = 0;

    while (std::getline(cpuinfoFile, line)) 
    {
        if (line.compare(0, 9, "processor") == 0) 
        {
            cpuCores++;
        } else if (line.compare(0, 10, "model name") == 0) 
        {
            cpuModel = line.substr(line.find(":") + 2);
        } else if (line.compare(0, 7, "cpu MHz") == 0) 
        {
            cpuFrequency = std::stod(line.substr(line.find(":") + 2)) / 1000;
        }
    }

    auto prevStats = GetCpuStats();

    std::this_thread::sleep_for(std::chrono::seconds(1));
    auto currStats = GetCpuStats();

    double totalUsage = 0;
    for (size_t i = 1; i < prevStats.size(); ++i) {
        totalUsage += CalculateCpuUsage(prevStats[i], currStats[i]);
    }

    double avgUsage = totalUsage / (prevStats.size() - 1);
    sum +=
        "CPU Usage: " + DoubleToStringWithPrecision(avgUsage, 1) + "%" + "\n";
    sum += "CPU Frequency: " + DoubleToStringWithPrecision(cpuFrequency, 3) +
           " GHZ" + "\n";
    sum += "CPU Model: " + cpuModel + "\n";
    sum += "CPU Cores: " + std::to_string(cpuCores);
    return sum;
}


struct NetStat 
{
    unsigned long long bytesReceived;
    unsigned long long bytesSent;
};

static NetStat GetNetStat(const std::string &interface) {
    NetStat netStat = {0, 0};
    std::ifstream netDevFile("/proc/net/dev");
    std::string line;

    while (std::getline(netDevFile, line)) 
    {
        if (line.find(interface) != std::string::npos) 
        {
            std::istringstream ss(line);
            std::string iface;
            ss >> iface >> netStat.bytesReceived;

            for (int i = 0; i < 7; ++i) 
            {
                unsigned long long tmp;
                ss >> tmp;
            }

            ss >> netStat.bytesSent;
            break;
        }
    }

    return netStat;
}

static std::string formatSpeed(double speed) 
{
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << speed << " Mbps";
    return ss.str();
}


static std::string GetMacAddress(const std::string &interface) 
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) 
    {
        return "";
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) 
    {
        close(sock);
        return "";
    }

    close(sock);
    char macAddress[18];
    snprintf(macAddress, sizeof(macAddress), "%02x:%02x:%02x:%02x:%02x:%02x",
             static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[0]),
             static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[1]),
             static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[2]),
             static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[3]),
             static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[4]),
             static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[5]));

    return macAddress;
}

static std::string GetNetworkInterfaceModel(const std::string &interface) 
{
    std::string modelPath = "/sys/class/net/" + interface + "/device/modalias";
    std::ifstream modelFile(modelPath);
    if (!modelFile.is_open()) 
    {
        return "";
    }

    std::string modelInfo;
    std::getline(modelFile, modelInfo);
    modelFile.close();

    return modelInfo;
}

std::string GetNetRate() 
{
    std::string interface = "eth0";
    auto prevStat = GetNetStat(interface);
    std::string str;
    str =
        "======================================================================"
        "=========";
    str += "\n";
    str += "GetNetRate";
    str += "\n";
    std::this_thread::sleep_for(std::chrono::seconds(1));
    auto currStat = GetNetStat(interface);

    double downloadSpeed =
        (currStat.bytesReceived - prevStat.bytesReceived) * 8 / 1000.0 /
        1000.0;
    double uploadSpeed =
        (currStat.bytesSent - prevStat.bytesSent) * 8 / 1000.0 / 1000.0;

    std::string downloadSpeedStr = formatSpeed(downloadSpeed);
    std::string uploadSpeedStr = formatSpeed(uploadSpeed);

    str += "Download speed: " + downloadSpeedStr + "\n";
    str += "Upload speed: " + uploadSpeedStr + "\n";
    str += "Interface: " + interface + "\n";
    str += "MAC Address: " + GetMacAddress(interface);
    str += "Model Info: " + GetNetworkInterfaceModel(interface);
    prevStat = currStat;
    return str;
}

std::string Exec(const char *cmd) 
{
    char buffer[128];
    std::string result = "";
    FILE *pipe = popen(cmd, "r");
    if (!pipe)
        throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}


static std::string GetOsVersion() 
{
    struct utsname buffer;
    std::string osRelease = Exec("cat /etc/os-release");
    std::string str;
    if (uname(&buffer) != 0) {
        return "Error getting OS version";
    }
    str = std::string(buffer.sysname) + " " + std::string(buffer.release) +
          " " + std::string(buffer.version);
    str += osRelease;
    return str;
}

std::string ApiGetSystemInfo() 
{
    std::string str;
    str =
        "======================================================================"
        "=========";
    str += "\n";
    str += "ApiGetSystemInfo";
    str += "\n";
    str += "OS Version: " + GetOsVersion() + "\n";
    return str;
}

std::string ApiTime()
{
    std::string str;
	auto now = std::time(0);
    str += std::ctime(&now);	
   	auto now1 = std::chrono::system_clock::now();
    auto nowUs = std::chrono::duration_cast<std::chrono::microseconds>(now1.time_since_epoch()).count();
    auto stamp= std::to_string(nowUs) ;
    str  += stamp +"\n";

    addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    addrinfo *result;
    getaddrinfo(NULL, "0", &hints, &result);
    sockaddr_in *addr = (sockaddr_in *)result->ai_addr;

    auto timeMs = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    std::string netTime = std::to_string(timeMs) ; 
    str += netTime + "\n";

    if(timeMs >1000 + nowUs)
    {
        std::string cache = std::to_string(timeMs - nowUs); 
        str +=cache +"microsecond"+"slow" + "\n" ;
    }

    if(nowUs  > 1000 + timeMs)
    {
        std::string cache = std::to_string(timeMs - nowUs);
        str +=cache +"microsecond"+"fast" +"\n";
    }
    else 
    {
        str +="normal";
        str +="\n";
    }
    str +="time check======================" ;
    str +="\n";
    return str;
}


std::string GetProcessInfo() 
{
    const int BUFFER_SIZE = 1024;

    std::string str;
    str =
        "======================================================================"
        "=========";
    str += "\n";
    str += "GetProcessInfo";
    str += "\n";

    FILE *pipe = popen("ps -ef", "r");
    if (!pipe) {

        return "-1";
    }
    
    char buffer[BUFFER_SIZE];
    while (fgets(buffer, BUFFER_SIZE, pipe)) 
    {

        str += buffer;
        str += "\n";
    }
    pclose(pipe);
    return str;
}

int GetFileLine() 
{
    FILE *fp;
    int flag = 0, count = 0;
    if ((fp = fopen("/proc/meminfo", "r")) == NULL)
        return -1;
    while (!feof(fp)) 
    {
        flag = fgetc(fp);
        if (flag == '\n')
            count++;
    }
    fclose(fp);
    return count;
}

void GetMemOccupy(int lenNum, std::string &strMem) 
{
    strMem = "";
    FILE *fpMemInfo = fopen("/proc/meminfo", "r");
    if (NULL == fpMemInfo) 
    {
        strMem = "-1 meminfo fopen error";
        return;
    }

    int i = 0;
    int value = 0;
    char name[512];
    char line[512];
    int nFiledNumber = 2;
    int total = 0;
    int available = 0;
    while (fgets(line, sizeof(line) - 1, fpMemInfo)) 
    {
        if (sscanf(line, "%s%u", name, &value) != nFiledNumber) 
        {
            continue;
        }
        if (0 == strcmp(name, "MemTotal:")) 
        {
            total = value;
            strMem += "MemTotal:\t" + std::to_string(value) + '\n';
        } 
        else if (0 == strcmp(name, "MemFree:")) 
        {
            strMem += "MemFree:\t" + std::to_string(value) + '\n';
        } 
        else if (0 == strcmp(name, "MemAvailable:")) 
        {
            available = value;
            strMem += "MemAvailable:\t" + std::to_string(value) + '\n';
        } 
        else if (0 == strcmp(name, "Buffers:")) 
        {
            strMem += "MemBuffers:\t" + std::to_string(value) + '\n';
        } 
        else if (0 == strcmp(name, "Cached:")) 
        {
            strMem += "MemCached:\t" + std::to_string(value) + '\n';
        }
        else if (0 == strcmp(name, "SwapCached:")) 
        {
            strMem += "SwapCached:\t" + std::to_string(value) + '\n';
        } 
        else if (0 == strcmp(name, "SwapTotal:")) 
        {
            strMem += "SwapTotal:\t" + std::to_string(value) + '\n';
        } 
        else if (0 == strcmp(name, "SwapFree:")) 
        {
            strMem += "SwapFree:\t" + std::to_string(value) + '\n';
        }

        if (++i == lenNum) 
        {
            break;
        }
    }
    strMem += "Memory usage:\t" +
              std::to_string(100.0 * (total - available) / total) + "%\n";
    fclose(fpMemInfo);
}

void GetDiskType(std::string &strMem) {
    std::ifstream rotational("/sys/block/sda/queue/rotational");
    if (rotational.is_open()) {
        int isRotational;
        rotational >> isRotational;
        strMem += "Disk type:\t";
        strMem += (isRotational ? "HDD" : "SSD");
        rotational.close();
    } 
    else 
    {
        strMem += "-1 Disk rotational open error";
    }
}

void GetAllSystemInfo(const Request &req, Response &res) 
{
    std::string outPut;
    std::string MemStr;
    int lenNum = GetFileLine();
    GetMemOccupy(lenNum, MemStr);
    GetDiskType(MemStr);
    outPut =
        "=================================================================="
        "=============";
    outPut += "\n";
    outPut += "GetMemOccupy";
    outPut += MemStr;
    outPut += "\n";

    outPut += ApiGetCpuInfo() + "\n";
    outPut += GetNetRate() + "\n";
    outPut += ApiGetSystemInfo() + "\n";
    outPut += ApiTime() + "\n";
    outPut += GetProcessInfo() + "\n";
    

    res.set_content(outPut, "text/plain");
}