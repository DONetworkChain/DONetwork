#include "ca.h"

#include "unistd.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <random>
#include <map>
#include <array>
#include <fcntl.h>
#include <thread>
#include <shared_mutex>
#include <iomanip>
#include <filesystem>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>



#include "proto/interface.pb.h"
#include "proto/ca_protomsg.pb.h"
#include "net/msg_queue.h"
#include "db/db_api.h"
#include "ca/ca_sync_block.h"
#include "include/net_interface.h"
#include "net/net_api.h"
#include "net/ip_port.h"
#include "utils/qrcode.h"
#include "utils/string_util.h"
#include "utils/util.h"
#include "utils/time_util.h"
#include "utils/base64.h"
#include "utils/base64_2.h"
#include "utils/bip39.h"
#include "utils/MagicSingleton.h"
#include "utils/hexcode.h"
#include "utils/console.h"

#include "ca_txhelper.h"
#include "ca_test.h"
#include "ca_transaction.h"
#include "ca_global.h"
#include "ca_interface.h"
#include "ca_test.h"
#include "ca_txhelper.h"
#include "ca_block_http_callback.h"
#include "ca_block_http_callback.h"
#include "ca_transaction_cache.h"
#include "api/http_api.h"

#include "ca/ca_AdvancedMenu.h"
#include "ca_blockcache.h"
#include "ca/ca_tranmonitor.h"
#include "ca_protomsg.pb.h"
#include "ca_blockhelper.h"
#include "utils/AccountManager.h"
#include "ca_contract.h"
#include "api/interface/tx.h"
#include "utils/tmp_log.h"
#include "ca/ca_dispatchtx.h"
#include "google/protobuf/util/json_util.h"
// #include "ca/ca_check_blocks.h"
#include "api/interface/evm.h"
bool bStopTx = false;
bool bIsCreateTx = false;
const static uint64_t input_limit = 500000;
int ca_startTimerTask()
{
    // Blocking thread
    global::ca::kBlockPoolTimer.AsyncLoop(100, [](){ MagicSingleton<BlockHelper>::GetInstance()->Process(); });
    
    //SeekBlock Thread
    global::ca::kSeekBlockTimer.AsyncLoop(3 * 1000, [](){ MagicSingleton<BlockHelper>::GetInstance()->SeekBlockThread(); });
    
    //Start patch thread
    MagicSingleton<BlockHelper>::GetInstance()->SeekBlockThread();

    // Block synchronization thread
    MagicSingleton<SyncBlock>::GetInstance()->ThreadStart();
    // MagicSingleton<CheckBlocks>::GetInstance()->StartTimer();

    MagicSingleton<TranStroage>::GetInstance();
    MagicSingleton<BlockStroage>::GetInstance();
    // Run http callback
    return 0;
}

bool ca_init()
{
    RegisterInterface();

    // Register interface with network layer
    RegisterCallback();

    // Register HTTP related interfaces
    if(MagicSingleton<Config>::GetInstance()->GetRpc())
    {
        ca_register_http_callbacks();
    }

    // Start timer task
    ca_startTimerTask();

    // NTP verification
    checkNtpTime();

    MagicSingleton<CtransactionCache>::GetInstance()->process();
    
    MagicSingleton<ContractDispatcher>::GetInstance()->Process();
    // MagicSingleton<CheckBlocks>::GetInstance()->StopTimer();

    std::filesystem::create_directory("./contract");
    return true;
}

int ca_endTimerTask()
{
    global::ca::kDataBaseTimer.Cancel();
    return 0;
}

void ca_cleanup()
{
    ca_endTimerTask();
    MagicSingleton<SyncBlock>::GetInstance()->ThreadStop();
    sleep(5);
    DBDestory();
}

void ca_print_basic_info()
{
    std::string version = global::kVersion;
    std::string base58 = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();

    uint64_t balance = 0;
    GetBalanceByUtxo(base58, balance);
    DBReader db_reader;

    uint64_t blockHeight = 0;
    db_reader.GetBlockTop(blockHeight);



    std::string ownID = net_get_self_node_id();

    ca_console infoColor(kConsoleColor_Green, kConsoleColor_Black, true);
    double b = balance / double(100000000);
    
    cout << "*********************************************************************************" << endl;
    cout << "Version: " << version << endl;
    cout << "Base58: " << base58 << endl;
    cout << "Balance: " << setiosflags(ios::fixed) << setprecision(8) << b << endl;
    cout << "Block top: " << blockHeight << endl;
    cout << "*********************************************************************************" << endl;
  
}

void handle_transaction()
{
    std::cout << std::endl
              << std::endl;

    std::string strFromAddr;
    std::cout << "input FromAddr :" << std::endl;
    std::cin >> strFromAddr;

    std::string strToAddr;
    std::cout << "input ToAddr :" << std::endl;
    std::cin >> strToAddr;

    std::string strAmt;
    std::cout << "input amount :" << std::endl;
    std::cin >> strAmt;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(strAmt, pattern))
    {
        std::cout << "input amount error ! " << std::endl;
        return;
    }

    std::vector<std::string> fromAddr;
    fromAddr.emplace_back(strFromAddr);
    uint64_t amount = (std::stod(strAmt) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
    std::map<std::string, int64_t> toAddrAmount;
    toAddrAmount[strToAddr] = amount;

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgent_flag;

    Vrf info_;
    int ret = TxHelper::CreateTxTransaction(fromAddr, toAddrAmount, top + 1,  outTx,isNeedAgent_flag,info_);
    if (ret != 0)
    {
        ERRORLOG("CreateTxTransaction error!! ret:{}", ret);
        return;
    }

    {
        if (fromAddr.size() == 1 && CheckBase58Addr(fromAddr[0], Base58Ver::kBase58Ver_MultiSign))
        {

            {
                if (TxHelper::AddMutilSign("1BKJq6f73jYZBnRSH3rZ7bP7Ro2oYkY7me", outTx) != 0)
                {
                    return;
                }
                outTx.clear_hash();
                outTx.set_hash(getsha256hash(outTx.SerializeAsString()));
            }

            {
                if (TxHelper::AddMutilSign("1QD3H7vyNAGKW3VPEFCvz1BkkqbjLFNaQx", outTx) != 0)
                {
                    return;
                }
                outTx.clear_hash();
                outTx.set_hash(getsha256hash(outTx.SerializeAsString()));
            }

            std::shared_ptr<MultiSignTxReq> req = std::make_shared<MultiSignTxReq>();
            req->set_version(global::kVersion);
            req->set_txraw(outTx.SerializeAsString());

            MsgData msgdata;
            int ret = HandleMultiSignTxReq(req, msgdata);

            return;
        }
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info -> CopyFrom(info_);
    }

    auto msg = make_shared<TxMsgReq>(txMsg);
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret = DropshippingTx(msg,outTx);
    }
    else
    {
        ret = DoHandleTx(msg,outTx);
    }

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());

    return;
}

void handle_declaration()
{
    std::cout << std::endl
              << std::endl;

    std::vector<std::string> SignAddr;
    uint64_t num = 0;
    std::cout << "Please enter your alliance account number :" << std::endl;
    std::cin >> num;

    for (int i = 0; i < num; i++)
    {
        std::string addr;
        std::cout << "Please enter your alliance account[" << i << "] :" << std::endl;
        std::cin >> addr;
        SignAddr.emplace_back(addr);
    }

    uint64_t SignThreshold = 0;
    std::cout << "Please enter your MutliSign number( must be >= 2) :" << std::endl;
    std::cin >> SignThreshold;

    std::string strFromAddr;
    std::cout << "input FromAddr :" << std::endl;
    std::cin >> strFromAddr;

    std::string strToAddr;
    std::cout << "input ToAddr :" << std::endl;
    std::cin >> strToAddr;

    std::string strAmt;
    std::cout << "input amount :" << std::endl;
    std::cin >> strAmt;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(strAmt, pattern))
    {
        std::cout << "input amount error ! " << std::endl;
        return;
    }

    uint64_t amount = (std::stod(strAmt) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;

    Account multiSignAccount;
    EVP_PKEY_free(multiSignAccount.pkey);
    if (MagicSingleton<AccountManager>::GetInstance()->FindAccount(strToAddr, multiSignAccount) != 0)
    {
        return;
    }

    if (!CheckBase58Addr(multiSignAccount.base58Addr, Base58Ver::kBase58Ver_MultiSign))
    {
        return;
    }

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    int ret = 0;
    // CreateDeclaration
    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    if (TxHelper::CreateDeclareTransaction(strFromAddr, strToAddr, amount, multiSignAccount.pubStr, SignAddr, SignThreshold, top + 1, outTx,isNeedAgent_flag,info_) != 0)
    {
        ERRORLOG("CreateTxTransaction error!! ret = {}", ret);
        return;
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);
    }

    auto msg = make_shared<TxMsgReq>(txMsg);

    
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret=DropshippingTx(msg,outTx);
    }else{
        ret=DoHandleTx(msg,outTx);
    }
    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_stake()
{
    std::cout << std::endl
              << std::endl;

    Account account;
    EVP_PKEY_free(account.pkey);
    MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(account);
    std::string strFromAddr = account.base58Addr;
    std::cout << "stake addr: " << strFromAddr << std::endl;
    std::string strStakeFee;
    std::cout << "Please enter the amount to stake:" << std::endl;
    std::cin >> strStakeFee;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(strStakeFee, pattern))
    {
        std::cout << "input stake amount error " << std::endl;
        return;
    }

    TxHelper::PledgeType pledgeType = TxHelper::PledgeType::kPledgeType_Node;

    uint64_t stake_amount = std::stod(strStakeFee) * global::ca::kDecimalNum;

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }


    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    if (TxHelper::CreateStakeTransaction(strFromAddr, stake_amount, top + 1,  pledgeType, outTx, outVin,isNeedAgent_flag,info_) != 0)
    {
        return;
    }
    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);
    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);

    int ret=0;
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();

    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret=DropshippingTx(msg,outTx);
    }else{
        ret=DoHandleTx(msg,outTx);
    }

    if (ret != 0)
    {
        ret -= 100;
    }

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_unstake()
{
    std::cout << std::endl
              << std::endl;

    std::string strFromAddr;
    std::cout << "Please enter unstake addr:" << std::endl;
    std::cin >> strFromAddr;

    DBReader db_reader;
    std::vector<string> utxos;
    db_reader.GetStakeAddressUtxo(strFromAddr, utxos);
    std::reverse(utxos.begin(), utxos.end());
    std::cout << "-- Current pledge amount: -- " << std::endl;
    for (auto &utxo : utxos)
    {
        std::string txRaw;
        db_reader.GetTransactionByHash(utxo, txRaw);
        CTransaction tx;
        tx.ParseFromString(txRaw);
        uint64_t value = 0;
        for (auto &vout : tx.utxo().vout())
        {
            if (vout.addr() == global::ca::kVirtualStakeAddr)
            {
                value = vout.value();
                break;
            }
        }
        std::cout << "utxo: " << utxo << " value: " << value << std::endl;
    }
    std::cout << std::endl;

    std::string strUtxoHash;
    std::cout << "utxo:";
    std::cin >> strUtxoHash;

    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    if (TxHelper::CreatUnstakeTransaction(strFromAddr, strUtxoHash, top + 1, outTx, outVin,isNeedAgent_flag,info_) != 0)
    {
        return;
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);

    int ret=0;
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret=DropshippingTx(msg,outTx);
    }else{
        ret=DoHandleTx(msg,outTx);
    }
    if (ret != 0)
    {
        ret -= 100;
    }
    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_invest()
{
    std::cout << std::endl
              << std::endl;
    std::cout << "AddrList:" << std::endl;
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    std::string strFromAddr;
    std::cout << "Please enter your addr:" << std::endl;
    std::cin >> strFromAddr;
    if (!CheckBase58Addr(strFromAddr))
    {
        ERRORLOG("Input addr error!");
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    std::string strToAddr;
    std::cout << "Please enter the addr you want to invest to:" << std::endl;
    std::cin >> strToAddr;
    if (!CheckBase58Addr(strToAddr))
    {
        ERRORLOG("Input addr error!");
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    std::string strInvestFee;
    std::cout << "Please enter the amount to invest:" << std::endl;
    std::cin >> strInvestFee;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(strInvestFee, pattern))
    {
        ERRORLOG("Input invest fee error!");
        std::cout << "Input invest fee error!" << std::endl;
        return;
    }
    
    TxHelper::InvestType investType = TxHelper::InvestType::kInvestType_NetLicence;
    uint64_t invest_amount = std::stod(strInvestFee) * global::ca::kDecimalNum;

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    int ret = TxHelper::CreateInvestTransaction(strFromAddr, strToAddr, invest_amount, top + 1,  investType, outTx, outVin,isNeedAgent_flag,info_);
    if (ret != 0)
    {
        ERRORLOG("Failed to create investment transaction! The error code is:{}", ret);
        return;
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret=DropshippingTx(msg,outTx);
    }else{
        ret=DoHandleTx(msg,outTx);
    }
    if (ret != 0)
    {
        ret -= 100;
    }

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_disinvest()
{
    std::cout << std::endl
              << std::endl;

    std::cout << "AddrList : " << std::endl;
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    std::string strFromAddr;
    std::cout << "Please enter your addr:" << std::endl;
    std::cin >> strFromAddr;
    if (!CheckBase58Addr(strFromAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    std::string strToAddr;
    std::cout << "Please enter the addr you want to divest from:" << std::endl;
    std::cin >> strToAddr;
    if (!CheckBase58Addr(strToAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    DBReader db_reader;
    std::vector<string> utxos;
    db_reader.GetBonusAddrInvestUtxosByBonusAddr(strToAddr, strFromAddr, utxos);
    std::reverse(utxos.begin(), utxos.end());
    std::cout << "======================================= Current invest amount: =======================================" << std::endl;
    for (auto &utxo : utxos)
    {
        std::cout << "Utxo: " << utxo << std::endl;
    }
    std::cout << "======================================================================================================" << std::endl;

    std::string strUtxoHash;
    std::cout << "Please enter the utxo you want to divest:";
    std::cin >> strUtxoHash;

    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    int ret = TxHelper::CreateDisinvestTransaction(strFromAddr, strToAddr, strUtxoHash, top + 1, outTx, outVin,isNeedAgent_flag,info_);
    if (ret != 0)
    {
        ERRORLOG("Create divest transaction error!:{}", ret);
        return;
    }
    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);

    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret=DropshippingTx(msg,outTx);
    }else{
        ret=DoHandleTx(msg,outTx);
    }
    if (ret != 0)
    {
        ret -= 100;
    }
    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_bonus()
{
    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    std::string strFromAddr ;
    std::cout << "Please enter the account number you wish to claim >: ";
    std::cin >> strFromAddr;

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    int ret = TxHelper::CreateBonusTransaction(strFromAddr, top + 1,  outTx, outVin,isNeedAgent_flag,info_);
    if (ret != 0)
    {
        ERRORLOG("Failed to create bonus transaction! The error code is:{}", ret);
        return;
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }
    auto msg = std::make_shared<TxMsgReq>(txMsg);

    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret=DropshippingTx(msg,outTx);
    }else{
        ret=DoHandleTx(msg,outTx);
    }

    if (ret != 0)
    {
        ret -= 100;
    }
    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_AccountManger()
{
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    std::cout << std::endl
              << std::endl;
    while (true)
    {
        std::cout << "0.Exit" << std::endl;
        std::cout << "1. Set Defalut Account" << std::endl;
        std::cout << "2. Add Account" << std::endl;
        std::cout << "3. Remove " << std::endl;
        std::cout << "4. Import PrivateKey" << std::endl;
        std::cout << "5. Export PrivateKey" << std::endl;
        std::cout << "6. Export All PrivateKey" << std::endl;

        std::string strKey;
        std::cout << "Please input your choice: " << std::endl;
        std::cin >> strKey;
        std::regex pattern("^[0-6]$");
        if (!std::regex_match(strKey, pattern))
        {
            std::cout << "Invalid input." << std::endl;
            continue;
        }
        int key = std::stoi(strKey);
        switch (key)
        {
        case 0:
            return;
        case 1:
            handle_SetdefaultAccount();
            break;
        case 2:
            gen_key();
            break;
        case 3:
        {
            std::string addr;
            std::cout << "Please enter the address you want to remove :" << std::endl;
            std::cin >> addr;

            std::string confirm;
            std::cout << "Are you sure to delete (Y / N) " << std::endl;
            std::cin >> confirm;
            if(confirm == "Y")
            {
                MagicSingleton<AccountManager>::GetInstance()->DeleteAccount(addr);
            }
            else if(confirm == "N")
            {
                break;
            }
            else
            {
                std::cout << "Invalid input" << std::endl;
            }

            break;
        }
        case 4:
        {
            std::string pri_key;
            std::cout << "Please input private key :" << std::endl;
            std::cin >> pri_key;

            if (MagicSingleton<AccountManager>::GetInstance()->ImportPrivateKeyHex(pri_key) != 0)
            {
                std::cout << "Save PrivateKey failed!" << std::endl;
            }
            break;
        }
        case 5:
            handle_export_private_key();
            break;
        case 6:
            handle_export_all_private_key();
            break;
        default:
            std::cout << "Invalid input." << std::endl;
            continue;
        }
    }
}

void handle_SetdefaultAccount()
{
    std::string addr;
    std::cout << "Please enter the address you want to set :" << std::endl;
    std::cin >> addr;

    if(!CheckBase58Addr(addr, Base58Ver::kBase58Ver_Normal))
    {
        std::cout << "The address entered is illegal" <<std::endl;
        return;
    }

    Account oldAccount;
    EVP_PKEY_free(oldAccount.pkey);
    if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(oldAccount) != 0)
    {
        ERRORLOG("not found DefaultKeyBs58Addr  in the _accountList");
        return;
    }

    if (MagicSingleton<AccountManager>::GetInstance()->SetDefaultAccount(addr) != 0)
    {
        ERRORLOG("Set DefaultKeyBs58Addr failed!");
        return;
    }

    Account newAccount;
    EVP_PKEY_free(newAccount.pkey);
    if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(newAccount) != 0)
    {
        ERRORLOG("not found DefaultKeyBs58Addr  in the _accountList");
        return;
    }

    if (!CheckBase58Addr(oldAccount.base58Addr, Base58Ver::kBase58Ver_Normal) ||
        !CheckBase58Addr(newAccount.base58Addr, Base58Ver::kBase58Ver_Normal))
    {
        return;
    }

    // update base 58 addr
    NodeBase58AddrChangedReq req;
    req.set_version(global::kVersion);

    NodeSign *oldSign = req.mutable_oldsign();
    oldSign->set_pub(oldAccount.pubStr);
    std::string oldSignature;
    if (!oldAccount.Sign(getsha256hash(newAccount.base58Addr), oldSignature))
    {
        return;
    }
    oldSign->set_sign(oldSignature);

    NodeSign *newSign = req.mutable_newsign();
    newSign->set_pub(newAccount.pubStr);
    std::string newSignature;
    if (!newAccount.Sign(getsha256hash(oldAccount.base58Addr), newSignature))
    {
        return;
    }
    newSign->set_sign(newSignature);

    MagicSingleton<PeerNode>::GetInstance()->set_self_id(newAccount.base58Addr);
    MagicSingleton<PeerNode>::GetInstance()->set_self_identity(newAccount.pubStr);
    std::vector<Node> publicNodes = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
    for (auto &node : publicNodes)
    {
        net_com::send_message(node, req, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_2);
    }
    std::cout << "Set Default account success" << std::endl;
}

static string ReadFileIntoString(string filename)
{
	ifstream ifile(filename);
	ostringstream buf;
	char ch;
	while(buf&&ifile.get(ch))
    {
        buf.put(ch);
    }
	return buf.str();
}
static int LoopRead(const std::regex&& pattern, std::string_view input_name, std::string& input)
{
    if (input == "0")
    {
        input.clear();
    }
    else
    {
        while(!std::regex_match(input, pattern))
        {
            input.clear();
            std::cout << "invalid " <<  input_name << ", please enter again :(0 to skip, 1 to exit)" << std::endl;
            std::cin >> input;

            if (input == "0")
            {
                input.clear();
                return 0;
            }
            if (input == "1")
            {
                return -1;
            }
        }
    }
    if(input.size() > input_limit)
    {
        std::cout << "Input cannot exceed " << input_limit << " characters" << std::endl;
        return -2;
    }
    return 0;
}

static int LoopReadFile(std::string& input, std::string& output, const std::filesystem::path& filename = "")
{
    std::filesystem::path contract_path;
    bool raise_info = false;
    if (input == "0")
    {
        contract_path = std::filesystem::current_path() / "contract" / filename;
    }
    else
    {
        contract_path = input;
        raise_info = true;
    }

    if (raise_info)
    {
        while(!exists(contract_path))
        {
            input.clear();
            std::cout << contract_path << " doesn't exist! please enter again: (0 to skip, 1 to exit)" << std::endl;
            std::cin >> input;
            if (input == "0")
            {
                return 1;
            }
            if (input == "1")
            {
                return -1;
            }
            contract_path = input;
        }
    }
    else
    {
        if (!exists(contract_path))
        {
            return 1;
        }
    }

    output = ReadFileIntoString(contract_path.string());
    if(output.size() > input_limit)
    {
        std::cout << "Input cannot exceed " << input_limit << " characters" << std::endl;
        return -2;
    }
    return 0;
}

static int LoopReadJson(std::string& input, nlohmann::json& output, const std::filesystem::path& filename = "")
{
    std::string content;
    int ret = LoopReadFile(input, content, filename);
    if (ret < 0)
    {
        return -1;
    }
    else if (ret > 0)
    {
        output = "";
        return 0;
    }

    try
    {
        output = nlohmann::json::parse(content);
        return 0;
    }
    catch (...)
    {
        std::cout << "json parse fail, enter 0 to skip : (other key to exit)";
        std::cin >> input;
        if (input == "0")
        {
            output = "";
            return 0;
        }
        else
        {
            return -1;
        }
    }

    return 0;
}


void handle_deploy_contract()
{
        std::cout << std::endl
              << std::endl;

    std::cout << "AddrList : " << std::endl;
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    std::string strFromAddr;
    std::cout << "Please enter your addr:" << std::endl;
    std::cin >> strFromAddr;
    if (!CheckBase58Addr(strFromAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    DBReader data_reader;
    uint64_t top = 0;
	if (DBStatus::DB_SUCCESS != data_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return ;
    }

    uint32_t nContractType;
    std::cout << "Please enter contract type: (0: EVM) " << std::endl;
    std::cin >> nContractType;

    if(nContractType != 0 && nContractType != 1)
    {
        std::cout << "The contract type was entered incorrectly" << std::endl;
        return;
    }

    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgent_flag;
    NewVrf info_;
    std::vector<std::string> dirtyContract;
    int ret = 0;
    if(nContractType == 0)
    {

        std::string nContractPath;
        std::cout << "Please enter contract path : (enter 0 use default path ./contract/contract) " << std::endl;
        std::cin >> nContractPath;
        std::string code;

        ret = LoopReadFile(nContractPath, code, "contract");
        if (ret != 0)
        {
            return;
        }

        if(code.empty())
        {
            return;
        }        
        std::cout << "code :" << code << std::endl;

        std::string strInput;
        std::cout << "Please enter input data (enter 0 to skip):" << std::endl;
        std::cin >> strInput;

        if (strInput == "0")
        {
            strInput.clear();
        }
        else if(strInput.substr(0, 2) == "0x")
        {
            strInput = strInput.substr(2);
            code += strInput;
        }
        code.erase(std::remove_if(code.begin(), code.end(), ::isspace), code.end());
        Account launchAccount;
        if(MagicSingleton<AccountManager>::GetInstance()->FindAccount(strFromAddr, launchAccount) != 0)
        {
            std::cout<<RED << "Failed to find account:"<<strFromAddr << RESET << std::endl;
            ERRORLOG("Failed to find account {}", strFromAddr);
            return;
        }
        std::string OwnerEvmAddr = evm_utils::generateEvmAddr(launchAccount.pubStr);
        ret = MagicSingleton<TxHelper>::GetInstance()->CreateEvmDeployContractTransaction(strFromAddr, OwnerEvmAddr, code, top + 1,
                                                           outTx, dirtyContract,
                                                           isNeedAgent_flag,
                                                           info_);
        if(ret != 0)
        {
            ERRORLOG("Failed to create Deploycontract transaction! The error code is:{}", ret);
            return;
        }        
    }
    else 
    {
        return;
    }

    int sret=SigTx(outTx, strFromAddr);
    if(sret!=0){
        ERRORLOG("sig fial :{}",sret);
        return ;
    }
    std::string txHash = getsha256hash(outTx.SerializeAsString());
    outTx.set_hash(txHash);

    ContractTxMsgReq ContractMsg;
    ContractMsg.set_version(global::kVersion);
    ContractTempTxMsgReq * txMsg = ContractMsg.mutable_txmsgreq();
	txMsg->set_version(global::kVersion);
    TxMsgInfo * txMsgInfo = txMsg->mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);
    if(nContractType == 0)
    {
        for (const auto& addr : dirtyContract)
        {
            txMsgInfo->add_contractstoragelist(addr);
        }
    }

	if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        NewVrf * new_info=txMsg->mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }

    auto msg = make_shared<ContractTxMsgReq>(ContractMsg);
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf )
    {
        ret = DropCallShippingTx(msg,outTx);
    }


    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_call_contract()
{
    std::cout << std::endl
              << std::endl;

    std::cout << "AddrList : " << std::endl;
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    std::string strFromAddr;
    std::cout << "Please enter your addr:" << std::endl;
    std::cin >> strFromAddr;
    if (!CheckBase58Addr(strFromAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    DBReader data_reader;
    std::vector<std::string> vecDeployers;
    data_reader.GetAllDeployerAddr(vecDeployers);

    std::cout << "=====================deployers=====================" << std::endl;
    for(auto& deployer : vecDeployers)
    {
        std::cout << "deployer: " << deployer << std::endl;
    }
    std::cout << "=====================deployers=====================" << std::endl;
    std::string strToAddr;
    std::cout << "Please enter to addr:" << std::endl;
    std::cin >> strToAddr;
    if(!CheckBase58Addr(strToAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;        
    }

    std::vector<std::string> vecDeployUtxos;
    data_reader.GetDeployUtxoByDeployerAddr(strToAddr, vecDeployUtxos);
    std::cout << "=====================deployed utxos=====================" << std::endl;
    for(auto& deploy_utxo : vecDeployUtxos)
    {
        std::string ContractAddress = evm_utils::GenerateContractAddr(strToAddr + deploy_utxo);
        std::string deployHash;
        if(data_reader.GetContractDeployUtxoByContractAddr(ContractAddress, deployHash) != DBStatus::DB_SUCCESS)
        {
            continue;
        }
        std::cout << "deployed utxo: " << deploy_utxo << std::endl;
    }
    std::cout << "=====================deployed utxos=====================" << std::endl;
    std::string strTxHash;
    std::cout << "Please enter tx hash:" << std::endl;
    std::cin >> strTxHash;
    
    // args means selector + parameters
    std::string strInput;
    std::cout << "Please enter args:" << std::endl;
    std::cin >> strInput;
    if(strInput.substr(0, 2) == "0x")
    {
        strInput = strInput.substr(2);
    }

    std::string contractTipStr;
    std::cout << "input contract tip amount :" << std::endl;
    std::cin >> contractTipStr;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(contractTipStr, pattern))
    {
        std::cout << "input contract tip error ! " << std::endl;
        return;
    }
    
    std::string contractTransferStr;
    uint64_t contractTransfer;
    std::cout << "input contract transfer amount :" << std::endl;
    std::cin >> contractTransferStr;
    if (!std::regex_match(contractTransferStr, pattern))
    {
        std::cout << "input contract transfer error ! " << std::endl;
        return;
    }
    contractTransfer = (std::stod(contractTransferStr) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
    
    uint64_t contractTip = (std::stod(contractTipStr) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
    uint64_t top = 0;
	if (DBStatus::DB_SUCCESS != data_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return ;
    }


    CTransaction outTx;
    // std::vector<TxHelper::Utxo> outVin;
    CTransaction tx;
    std::string tx_raw;
    if (DBStatus::DB_SUCCESS != data_reader.GetTransactionByHash(strTxHash, tx_raw))
    {
        ERRORLOG("get contract transaction failed!!");
        return ;
    }
    if(!tx.ParseFromString(tx_raw))
    {
        ERRORLOG("contract transaction parse failed!!");
        return ;
    }
    

    nlohmann::json data_json = nlohmann::json::parse(tx.data());
    nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
    int vm_type = tx_info["VmType"].get<int>();
 
    int ret = 0;
    TxHelper::vrfAgentType isNeedAgent_flag;
    NewVrf info_;
    std::vector<std::string> dirtyContract;
    if (vm_type == global::ca::VmType::EVM)
    {
        Account launchAccount;
        if(MagicSingleton<AccountManager>::GetInstance()->FindAccount(strFromAddr, launchAccount) != 0)
        {
            ERRORLOG("Failed to find account {}", strFromAddr);
            return;
        }
        std::string OwnerEvmAddr = evm_utils::generateEvmAddr(launchAccount.pubStr);
        ret = MagicSingleton<TxHelper>::GetInstance()->CreateEvmCallContractTransaction(strFromAddr, strToAddr, strTxHash, strInput,
                                                         OwnerEvmAddr, top + 1,
                                                         outTx, isNeedAgent_flag, info_,contractTip, contractTransfer,
                                                         dirtyContract);

        if(ret != 0)
        {
            ERRORLOG("Create call contract transaction failed! ret:{}", ret);        
            return;
        }
    }
    else
    {
        return;
    }

    int sret = SigTx(outTx, strFromAddr);
    if(sret != 0){
        //errorL("sig fial %s",sret);
        return ;
    }

    std::string txHash = getsha256hash(outTx.SerializeAsString());
    outTx.set_hash(txHash);

    ContractTxMsgReq ContractMsg;
    ContractMsg.set_version(global::kVersion);
    ContractTempTxMsgReq * txMsg = ContractMsg.mutable_txmsgreq();
	txMsg->set_version(global::kVersion);

    TxMsgInfo * txMsgInfo = txMsg->mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    std::cout << "size = " << dirtyContract.size() << std::endl;
    for (const auto& addr : dirtyContract)
    {
        std::cout << "addr = " << addr << std::endl;
        txMsgInfo->add_contractstoragelist(addr);
    }

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        NewVrf * new_info=txMsg->mutable_vrfinfo();
        new_info -> CopyFrom(info_);

    }

    auto msg = make_shared<ContractTxMsgReq>(ContractMsg);
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        ret = DropCallShippingTx(msg,outTx);
    }

    return;
}


void write_handle_export_private_key(ofstream& file, std::string addr, int size)
{

    Account account;
    EVP_PKEY_free(account.pkey);
    MagicSingleton<AccountManager>::GetInstance()->FindAccount(addr, account);

    if(size >= 0)
    {
        file << size+1 << " ———————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————— " << std::endl;
    }
    file << "Please use Courier New font to view" << std::endl
         << std::endl;
    file << "Base58 addr: " << addr << std::endl;

    char out_data[1024] = {0};
    int data_len = sizeof(out_data);
    mnemonic_from_data((const uint8_t *)account.priStr.c_str(), account.priStr.size(), out_data, data_len);
    file << "Mnemonic: " << out_data << std::endl;

    std::string strPriHex = Str2Hex(account.priStr);
    file << "Private key: " << strPriHex << std::endl;

    file << "QRCode:";

    QRCode qrcode;
    uint8_t qrcodeData[qrcode_getBufferSize(5)];
    qrcode_initText(&qrcode, qrcodeData, 5, ECC_MEDIUM, strPriHex.c_str());

    file << std::endl
         << std::endl;


    if(size < 0)
    {
        std::cout << "Base58 addr: " << addr << std::endl;
        std::cout << "Mnemonic: " << out_data << std::endl;
        std::cout << "Private key: " << strPriHex << std::endl;
        std::cout << "QRCode:";
        std::cout << std::endl
        << std::endl;
    }

    for (uint8_t y = 0; y < qrcode.size; y++)
    {
        file << "        ";
        if(size < 0)
        {
            std::cout << "        ";
        }
        for (uint8_t x = 0; x < qrcode.size; x++)
        {
            file << (qrcode_getModule(&qrcode, x, y) ? "\u2588\u2588" : "  ");
            if(size < 0)
            {
                std::cout << (qrcode_getModule(&qrcode, x, y) ? "\u2588\u2588" : "  ");
            }
        }

        file << std::endl;
        if(size < 0)
        {
            std::cout << std::endl;
        }
    }
    if(size >= 0)
    {
        file << "————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————" << std::endl;
    }
    file << std::endl
         << std::endl
         << std::endl
         << std::endl
         << std::endl
         << std::endl;
    // }
    
    return;
}


void handle_export_private_key()
{
    std::cout << std::endl
              << std::endl;
    // 1 private key, 2 annotation, 3 QR code
    std::string addr;
    std::cout << "please input the addr you want to export" << std::endl;
    std::cin >> addr;

    std::string fileName("account_private_key.txt");
    ofstream file;
    file.open(fileName);

    write_handle_export_private_key(file, addr, -1);

    std::cout << std::endl
        << std::endl
        << std::endl
        << std::endl
        << std::endl
        << std::endl;
    ca_console redColor(kConsoleColor_Red, kConsoleColor_Black, true);
    std::cout << redColor.color() << "You can also view above in file:" << fileName << " of current directory." << redColor.reset() << std::endl;
    file.close();
    
    return;
}

void handle_export_all_private_key()
{
    std::vector<std::string> base58_list;
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(base58_list);

    std::string fileName("account_all_private_key.txt");
    ofstream file;
    file.open(fileName, std::ios::app);
    for(int i = 0; i < base58_list.size(); ++i)
    {
        write_handle_export_private_key(file, base58_list.at(i), i);
    }
    std::cout << "write successed" << std::endl << std::endl;
    file.close();
}


void handle_delegates_transaction()
{
    std::cout << std::endl
              << std::endl;

    std::string strFromAddr;
    std::cout << "input FromAddr :" << std::endl;
    std::cin >> strFromAddr;

    std::string strToAddr;
    std::cout << "input ToAddr :" << std::endl;
    std::cin >> strToAddr;

    std::string strAmt;
    std::cout << "input amount :" << std::endl;
    std::cin >> strAmt;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(strAmt, pattern))
    {
        std::cout << "input amount error ! " << std::endl;
        return;
    }

    std::vector<std::string> fromAddr;
    fromAddr.emplace_back(strFromAddr);
    uint64_t amount = (std::stod(strAmt) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
    std::map<std::string, int64_t> toAddrAmount;
    toAddrAmount[strToAddr] = amount;

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }
   
    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    int ret = TxHelper::CreateTxTransaction(fromAddr, toAddrAmount, top + 1,  outTx,isNeedAgent_flag,info_);
    if (ret != 0)
    {
        ERRORLOG("CreateTxTransaction error!!");
        return;
    }

    {
        if (fromAddr.size() == 1 && CheckBase58Addr(fromAddr[0], Base58Ver::kBase58Ver_MultiSign))
        {

            {
                if (TxHelper::AddMutilSign("1BKJq6f73jYZBnRSH3rZ7bP7Ro2oYkY7me", outTx) != 0)
                {
                    return;
                }
                outTx.clear_hash();
                outTx.set_hash(getsha256hash(outTx.SerializeAsString()));
            }

            {
                if (TxHelper::AddMutilSign("1QD3H7vyNAGKW3VPEFCvz1BkkqbjLFNaQx", outTx) != 0)
                {
                    return;
                }
                outTx.clear_hash();
                outTx.set_hash(getsha256hash(outTx.SerializeAsString()));
            }

            std::shared_ptr<MultiSignTxReq> req = std::make_shared<MultiSignTxReq>();
            req->set_version(global::kVersion);
            req->set_txraw(outTx.SerializeAsString());

            MsgData msgdata;
            int ret = HandleMultiSignTxReq(req, msgdata);

            return;
        }
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf){
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }

    auto msg = make_shared<TxMsgReq>(txMsg);
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {

        ret=DropshippingTx(msg,outTx);
    }
    else
    {
        net_send_message<TxMsgReq>(outTx.identity(), *msg, net_com::Priority::kPriority_High_1);
    }
    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());

    return;

}



int get_chain_height(unsigned int &chainHeight)
{
    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        return -1;
    }
    chainHeight = top;
    return 0;
}

void net_register_chain_height_callback()
{
    net_callback::register_chain_height_callback(get_chain_height);
}

/**
 * @description: Registering Callbacks
 * @param {*}
 * @return {*}
 */
void RegisterCallback()
{
    syncBlock_register_callback<FastSyncGetHashReq>(HandleFastSyncGetHashReq);
    syncBlock_register_callback<FastSyncGetHashAck>(HandleFastSyncGetHashAck);
    syncBlock_register_callback<FastSyncGetBlockReq>(HandleFastSyncGetBlockReq);
    syncBlock_register_callback<FastSyncGetBlockAck>(HandleFastSyncGetBlockAck);

    syncBlock_register_callback<SyncGetSumHashReq>(HandleSyncGetSumHashReq);
    syncBlock_register_callback<SyncGetSumHashAck>(HandleSyncGetSumHashAck);
    syncBlock_register_callback<SyncGetHeightHashReq>(HandleSyncGetHeightHashReq);
    syncBlock_register_callback<SyncGetHeightHashAck>(HandleSyncGetHeightHashAck);
    syncBlock_register_callback<SyncGetBlockReq>(HandleSyncGetBlockReq);
    syncBlock_register_callback<SyncGetBlockAck>(HandleSyncGetBlockAck);

    syncBlock_register_callback<SyncFromZeroGetSumHashReq>(HandleFromZeroSyncGetSumHashReq);
    syncBlock_register_callback<SyncFromZeroGetSumHashAck>(HandleFromZeroSyncGetSumHashAck);
    syncBlock_register_callback<SyncFromZeroGetBlockReq>(HandleFromZeroSyncGetBlockReq);
    syncBlock_register_callback<SyncFromZeroGetBlockAck>(HandleFromZeroSyncGetBlockAck);

    syncBlock_register_callback<GetBlockByUtxoReq>(HandleBlockByUtxoReq);
    syncBlock_register_callback<GetBlockByUtxoAck>(HandleBlockByUtxoAck);

    syncBlock_register_callback<GetBlockByHashReq>(HandleBlockByHashReq);
    syncBlock_register_callback<GetBlockByHashAck>(HandleBlockByHashAck);

    // syncBlock_register_callback<GetCheckSumHashReq>(HandleGetCheckSumHashReq);
    // syncBlock_register_callback<GetCheckSumHashAck>(HandleGetCheckSumHashAck);

    // PCEnd correlation
    tx_register_callback<TxMsgReq>(HandleTx); // PCEnd transaction flow
    tx_register_callback<TxMsgAck>(HandleDoHandleTxAck);
    tx_register_callback<ContractPackagerMsg>(HandleContractPackagerMsg);
    tx_register_callback<ContractTxMsgReq>(HandleContractTx);
                                        // PCEnd transaction flow

    tx_register_callback<BuildBlockBroadcastMsgAck>(HandleAddBlockAck);

    saveBlock_register_callback<BuildBlockBroadcastMsg>(HandleBuildBlockBroadcastMsg); // Building block broadcasting
    //saveBlock_register_callback<BuildContractBlockBroadcastMsg>(HandleBuildContractBlockBroadcastMsg);
    ca_register_callback<MultiSignTxReq>(HandleMultiSignTxReq);

    BlockRegisterCallback<BlockMsg>(HandleBlock); 
    BlockRegisterCallback<ContractBlockMsg>(HandleContractBlock); 

    
    // BlockRegisterCallback<newSeekContractPreHashReq>(_HandleSeekContractPreHashReq);
    // BlockRegisterCallback<newSeekContractPreHashAck>(_HandleSeekContractPreHashAck);

    syncBlock_register_callback<SyncNodeHashReq>(HandleSyncNodeHashReq);
    syncBlock_register_callback<SyncNodeHashAck>(HandleSyncNodeHashAck);
    syncBlock_register_callback<SeekPreHashByHightReq>(HandleSeekGetPreHashReq);
    syncBlock_register_callback<SeekPreHashByHightAck>(HandleSeekGetPreHashAck);
    //ca_register_callback<BlockStatus>(HandleBlockStatusMsg);
    net_register_chain_height_callback();
}

void TestCreateTx(const std::vector<std::string> &addrs, const int &sleepTime)
{
    if (addrs.size() < 2)
    {
        std::cout << "Insufficient number of accounts" << std::endl;
        return;
    }
#if 0
    bIsCreateTx = true;
    while (1)
    {
        if (bStopTx)
        {
            break;
        }
        int intPart = rand() % 10;
        double decPart = (double)(rand() % 100) / 100;
        double amount = intPart + decPart;
        std::string amountStr = std::to_string(amount);

        std::cout << std::endl << std::endl << std::endl << "=======================================================================" << std::endl;
        CreateTx("1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu", "18RM7FNtzDi41QEU5rAnrFdVaGBHvhTTH1", amountStr.c_str(), NULL, 6, "0.01");
        std::cout << "=====Transaction initiator:1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu" << std::endl;
        std::cout << "=====Transaction recipient:18RM7FNtzDi41QEU5rAnrFdVaGBHvhTTH1" << std::endl;
        std::cout << "=====Transaction amount:" << amountStr << std::endl;
        std::cout << "=======================================================================" << std::endl << std::endl << std::endl << std::endl;

        sleep(sleepTime);
    }
    bIsCreateTx = false;

#endif

#if 1
    bIsCreateTx = true;
    // while(1)
    for (int i = 0; i < addrs.size(); i++)
    {
        if (bStopTx)
        {
            std::cout << "Close the deal!" << std::endl;
            break;
        }
        int intPart = rand() % 10;
        double decPart = (double)(rand() % 100) / 100;
        std::string amountStr = std::to_string(intPart  + decPart );
        std::string from, to;
        if (i >= addrs.size() - 1)
        {
            from = addrs[addrs.size() - 1];
            to = addrs[0];
            i = 0;
        }
        else
        {
            from = addrs[i];
            to = addrs[i + 1];
        }
        if (from != "")
        {
            if (!MagicSingleton<AccountManager>::GetInstance()->IsExist(from))
            {
                DEBUGLOG("Illegal account.");
                continue;
            }
        }
        else
        {
            DEBUGLOG("Illegal account. from base58addr is null !");
            continue;
        }

        std::cout << std::endl
                  << std::endl
                  << std::endl
                  << "=======================================================================" << std::endl;

        std::vector<std::string> fromAddr;
        fromAddr.emplace_back(from);
        std::map<std::string, int64_t> toAddrAmount;
        uint64_t amount = (stod(amountStr) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
        if(amount == 0)
        {
            std::cout << "aomunt = 0" << std::endl;
            DEBUGLOG("aomunt = 0");
            continue;
        }
        toAddrAmount[to] = amount;



        DBReader db_reader;
        uint64_t top = 0;
        if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
        {
            ERRORLOG("db get top failed!!");
            continue;
        }

        CTransaction outTx;
        TxHelper::vrfAgentType isNeedAgent_flag;
        Vrf info_;
        int ret = TxHelper::CreateTxTransaction(fromAddr, toAddrAmount, top + 1,  outTx,isNeedAgent_flag,info_);
        if (ret != 0)
        {
            ERRORLOG("CreateTxTransaction error!!");
            continue;
        }

        TxMsgReq txMsg;
        txMsg.set_version(global::kVersion);
        TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
        txMsgInfo->set_type(0);
        txMsgInfo->set_tx(outTx.SerializeAsString());
        txMsgInfo->set_height(top);
        
        if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf){
            Vrf * new_info=txMsg.mutable_vrfinfo();
            new_info->CopyFrom(info_);

        }


        auto msg = make_shared<TxMsgReq>(txMsg);

        std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
        if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr){

            ret=DropshippingTx(msg,outTx);
        }else{
            ret=DoHandleTx(msg,outTx);
         }
        DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());

        std::cout << "=====Transaction initiator:" << from << std::endl;
        std::cout << "=====Transaction recipient:" << to << std::endl;
        std::cout << "=====Transaction amount:" << amountStr << std::endl;
        std::cout << "=======================================================================" << std::endl
                  << std::endl
                  << std::endl
                  << std::endl;

        usleep(sleepTime);
    }
    bIsCreateTx = false;
#endif
}

void ThreadStart()
{
    std::vector<std::string> addrs;
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(addrs);

    int sleepTime = 8;
    std::thread th(TestCreateTx, addrs, sleepTime);
    th.detach();
}

int checkNtpTime()
{
    // Ntp check
    int64_t getNtpTime = MagicSingleton<TimeUtil>::GetInstance()->getNtpTimestamp();
    int64_t getLocTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();

    int64_t tmpTime = abs(getNtpTime - getLocTime);

    std::cout << "UTC Time: " << MagicSingleton<TimeUtil>::GetInstance()->formatUTCTimestamp(getLocTime) << std::endl;
    std::cout << "Ntp Time: " << MagicSingleton<TimeUtil>::GetInstance()->formatUTCTimestamp(getNtpTime) << std::endl;

    if (tmpTime <= 1000000)
    {
        DEBUGLOG("ntp timestamp check success");
        return 0;
    }
    else
    {
        DEBUGLOG("ntp timestamp check fail");
        std::cout << "time check fail" << std::endl;
        return -1;
    }
}

void title_version() {
    
    std::string version = global::kVersion;
    std::string base58 = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();

    uint64_t balance = 0;
    GetBalanceByUtxo(base58, balance);
    DBReader db_reader;

    uint64_t blockHeight = 0;
    db_reader.GetBlockTop(blockHeight);

    std::string ownID = net_get_self_node_id();


    boost::multiprecision::cpp_int balancelog(std::to_string(balance));

    boost::multiprecision::cpp_dec_float_50 c = static_cast<boost::multiprecision::cpp_dec_float_50>(balancelog) / 100000000.0;
	
	std::cout << R"(  ____    _____   __  __      ____     __  __  ______  ______   __  __      )" << std::endl;
	
	std::cout << R"( /\  _`\ /\  __`\/\ \/\ \    /\  _`\  /\ \/\ \/\  _  \/\__  _\ /\ \/\ \     )" << std::endl;
	
	std::cout << R"( \ \ \/\ \ \ \/\ \ \ `\\ \   \ \ \/\_\\ \ \_\ \ \ \L\ \/_/\ \/ \ \ `\\ \    )" << std::endl;
	
	std::cout << R"(  \ \ \ \ \ \ \ \ \ \ , ` \   \ \ \/_/_\ \  _  \ \  __ \ \ \ \  \ \ , ` \   )" << std::endl;
	
	std::cout << R"(   \ \ \_\ \ \ \_\ \ \ \`\ \   \ \ \L\ \\ \ \ \ \ \ \/\ \ \_\ \__\ \ \`\ \  )" << std::endl;
	
	std::cout << R"(    \ \____/\ \_____\ \_\ \_\   \ \____/ \ \_\ \_\ \_\ \_\/\_____\\ \_\ \_\ )" << std::endl;
	
	std::cout << R"(     \/___/  \/_____/\/_/\/_/    \/___/   \/_/\/_/\/_/\/_/\/_____/ \/_/\/_/ )" << std::endl;
	
	std::cout << R"(                                                                            )"<< std::endl;

std::cout << " Version: " << version << std::endl
 << " Base58:" << base58 << std::endl
 << " Balance:" << setiosflags(ios::fixed) << setprecision(8) << c << std::endl
 << " Block top:" << blockHeight << std::endl;


}


void RPC_contrack_uitl(CTransaction & tx){
    tx.clear_hash();
    std::set<std::string> Miset;
	Base64 base;
	auto txUtxo = tx.mutable_utxo();
	int index = 0;
	auto vin = txUtxo->mutable_vin();
	for (auto& owner : txUtxo->owner()) {

		Miset.insert(owner);
		auto vin_t = vin->Mutable(index);
		vin_t->clear_vinsign();
		index++;
	}
	for (auto& owner : Miset) {
		CTxUtxo* txUtxo = tx.mutable_utxo();
		CTxUtxo copyTxUtxo = *txUtxo;
		copyTxUtxo.clear_multisign();
        txUtxo->clear_multisign();
	}
	
}

std::string handle__deploy_contract_rpc(void * arg,void *ack){

    deploy_contract_req * req_=(deploy_contract_req *)arg;

    
    int ret;
    std::string strFromAddr = req_->addr;
   
    if (!CheckBase58Addr(strFromAddr))
    {
       //return "base58 error!";
       errorL("Input addr error!");
       return "-1";
    }

    DBReader data_reader;
    uint64_t top = 0;
	if (DBStatus::DB_SUCCESS != data_reader.GetBlockTop(top))
    {
       ERRORLOG("db get top failed!!");
       return "-2";
    }

    uint32_t nContractType=std::stoi(req_->nContractType);

    // contract_info info_t;
    // if(info_t.paseFromJson(req_->info)==false){
    //     return "contract_info pase fail";
    // }

    nlohmann::json contract_info_ = nlohmann::json::parse(req_->info);
   

    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgent_flag;
    NewVrf info_;
    std::vector<std::string> dirtyContract;
    if(nContractType == 0)
    {

        std::string code=req_->contract;
        std::string strInput=req_->data;

        if (strInput == "0")
        {
            strInput.clear();
        }
        else if(strInput.substr(0, 2) == "0x")
        {
            strInput = strInput.substr(2);
            code += strInput;
        }
        Base64 base_;
        std::string pubstr=base_.Decode(req_->pubstr.c_str(),req_->pubstr.size());
        std::string OwnerEvmAddr = evm_utils::generateEvmAddr(pubstr);
      
        ret = MagicSingleton<TxHelper>::GetInstance()->CreateEvmDeployContractTransaction(strFromAddr, OwnerEvmAddr, code, top + 1, 
                                                           outTx,dirtyContract,
                                                           isNeedAgent_flag,
                                                           info_);
        if(ret != 0)
        {
            ERRORLOG("Failed to create DeployContract transaction! The error code is:{}", ret);
            return "-3";
        }        
    }
    else
    {
        return "-4";
    }
    ContractTxMsgReq ContractMsg;
    ContractMsg.set_version(global::kVersion);
    ContractTempTxMsgReq * txMsg = ContractMsg.mutable_txmsgreq();
	txMsg->set_version(global::kVersion);
    TxMsgInfo * txMsgInfo = txMsg->mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_height(top);
    for (const auto& addr : dirtyContract)
    {
        txMsgInfo->add_contractstoragelist(addr);
    }

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        NewVrf * newInfo=txMsg->mutable_vrfinfo();
        newInfo -> CopyFrom(info_);

    }

    contract_ack *ack_t=(contract_ack*)ack;

    //RPC_contrack_uitl(outTx);
    std::string contracJs;
    std::string txJs;
    google::protobuf::util::MessageToJsonString(ContractMsg,&contracJs);
    google::protobuf::util::MessageToJsonString(outTx,&txJs);
    ack_t->contractJs=contracJs;
    ack_t->txJs=txJs;
    return "0";
}


std::string handle__call_contract_rpc(void * arg,void *ack){
    
    call_contract_req * req_t=(call_contract_req*)arg;
    contract_ack *ack_t = (contract_ack*)ack;
    std::string strFromAddr=req_t->addr;
    bool isToChain=(req_t->istochain=="true" ? true:false);

    if (!CheckBase58Addr(strFromAddr))
    {
        ack_t->ErrorMessage = "from addr error!";
        ack_t->ErrorCode = "-1";
        ERRORLOG("Input addr error!");
        return "from addr error!";
        
        
    }

    DBReader data_reader;
    std::vector<std::string> vecDeployers;
    std::string strToAddr=req_t->deployer;
    if(!CheckBase58Addr(strToAddr))
    {
            ack_t->ErrorMessage = "to addr error!";
	        ack_t->ErrorCode = "-2";
	        ERRORLOG("to addr error!");
	        return "to addr error!";
    }

    std::string strTxHash=req_t->deployutxo;
    std::string strInput= req_t->args;

    if(strInput.substr(0, 2) == "0x")
    {
        strInput = strInput.substr(2);
    }

    std::string contractTipStr=req_t->tip;
   
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(contractTipStr, pattern))
    {
        ack_t->ErrorMessage = "input contract tip error ! ";
        ack_t->ErrorCode = "-3";
        ERRORLOG("input contract tip error ! " );
        return "input contract tip error !";

    }

    std::string contractTransferStr=req_t->money;
    if (!std::regex_match(contractTransferStr, pattern))
    {
        ack_t->ErrorMessage = "regex match error";
        ack_t->ErrorCode = "-4";
        ERRORLOG("regex match error");
        return "regex match error";
    }
    uint64_t contractTip = (std::stod(contractTipStr) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
    uint64_t contractTransfer = (std::stod(contractTransferStr) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
    uint64_t top = 0;
	if (DBStatus::DB_SUCCESS != data_reader.GetBlockTop(top))
    {
       ack_t->ErrorMessage = "db get top failed!!";
       ack_t->ErrorCode = "-5";
       ERRORLOG("db get top failed!!");
       return "db get top failed!!";
    }

    CTransaction outTx;
    CTransaction tx;
    std::string txRaw;
    if (DBStatus::DB_SUCCESS != data_reader.GetTransactionByHash(strTxHash, txRaw))
    {
	    ack_t->ErrorMessage = "get contract transaction failed!!";
	    ack_t->ErrorCode = "-6";
        ERRORLOG("get contract transaction failed!!");
        return "get contract transaction failed!!";

    }
    
    if(!tx.ParseFromString(txRaw))
    {
        ack_t->ErrorMessage = "contract transaction parse failed!!";
        ack_t->ErrorCode = "-7";
        ERRORLOG("contract transaction parse failed!!");
        return "contract transaction parse failed!!";

    }    

    nlohmann::json data_json = nlohmann::json::parse(tx.data());
    nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
    int vm_type = tx_info["VmType"].get<int>();
 
    int ret = 0;
    TxHelper::vrfAgentType isNeedAgent_flag;
    NewVrf info_;
    std::vector<std::string> dirtyContract;
    if (vm_type == global::ca::VmType::EVM)
    {
        Base64 base_;
        std::string pubstr=base_.Decode(req_t->pubstr.c_str(),req_t->pubstr.size());
        std::string OwnerEvmAddr = evm_utils::generateEvmAddr(pubstr);
        //isToChain = true;
        if(isToChain == true)
        {
            ret = MagicSingleton<TxHelper>::GetInstance()->CreateEvmCallContractTransaction(strFromAddr, strToAddr, strTxHash, strInput,
                                                         OwnerEvmAddr, top + 1,
                                                         outTx, isNeedAgent_flag, info_, contractTip, contractTransfer,
                                                         dirtyContract);
        }
        else
        {
        ret = rpc_evm::RpcCreateEvmCallContractTransaction(strFromAddr, strToAddr, strTxHash, strInput,
                                                         OwnerEvmAddr, top + 1,
                                                         outTx, isNeedAgent_flag, info_, contractTip, contractTransfer,isToChain,dirtyContract);
        }
        

        
        if(ret != 0)
        {
        ack_t->ErrorMessage = "Create call contract transaction failed!";
        ack_t->ErrorCode = "-8";
        ERRORLOG("Create call contract transaction failed! ret:{}", ret);        
        return "Create call contract transaction failed!";
        }
    }
    else
    {
	    ack_t->ErrorMessage = "VmType is not EVM";
	    ack_t->ErrorCode = "-9";
        return "VmType is not EVM";
    }

    ContractTxMsgReq ContractMsg;
    ContractMsg.set_version(global::kVersion);
    ContractTempTxMsgReq * txMsg = ContractMsg.mutable_txmsgreq();
	txMsg->set_version(global::kVersion);
    TxMsgInfo * txMsgInfo = txMsg->mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_height(top);
    std::cout << "size = " << dirtyContract.size() << std::endl;
    for (const auto& addr : dirtyContract)
    {
        std::cout << "addr = " << addr << std::endl;
        txMsgInfo->add_contractstoragelist(addr);
    }

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        NewVrf * new_info=txMsg->mutable_vrfinfo();
        new_info -> CopyFrom(info_);

    }
    std::string txJsonString;
	std::string contractJsonString;
	google::protobuf::util::Status status =google::protobuf::util::MessageToJsonString(outTx,&txJsonString);
	status=google::protobuf::util::MessageToJsonString(ContractMsg,&contractJsonString);
	ack_t->contractJs=contractJsonString;
    ack_t->txJs=txJsonString;
    return "0";

}

int SigTx(CTransaction &tx,const std::string & addr){
    std::set<std::string> Miset;
	Base64 base_;
	auto txUtxo = tx.mutable_utxo();
	int index = 0;
	auto vin = txUtxo->mutable_vin();
	for (auto& owner : txUtxo->owner()) {
		Miset.insert(owner);
		auto vin_t = vin->Mutable(index);
        if(!vin_t->contractaddr().empty()){
            continue;
        }
		std::string serVinHash = getsha256hash(vin_t->SerializeAsString());
		std::string signature;
		std::string pub;

        if(TxHelper::Sign(addr, serVinHash, signature, pub)){
            return -1;
        }
		CSign* vinSign = vin_t->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
		index++;
	}

    for (auto &owner : Miset) {
        CTxUtxo *txUtxo = tx.mutable_utxo();
        CTxUtxo copyTxUtxo = *txUtxo;
        copyTxUtxo.clear_multisign();
        std::string serTxUtxo = getsha256hash(copyTxUtxo.SerializeAsString());
        std::string signature;
        std::string pub;

        if (TxHelper::Sign(addr, serTxUtxo, signature, pub)) {
            return -2;
        }
        CSign *multiSign = txUtxo->add_multisign();
        multiSign->set_sign(signature);
        multiSign->set_pub(pub);
    }

    return 0;
}

static int _GenerateContractInfo(nlohmann::json& contract_info)
{
    int ret = 0;

    std::string nContractName = "0";
    if(nContractName.size() > input_limit)
    {
        std::cout << "Input cannot exceed " << input_limit << " characters" << std::endl;
        return -1;
    }

    uint32_t nContractLanguage = 0;
    if (nContractLanguage != 0)
    {
        std::cout << "error contract language choice" << std::endl;
        ret = -2;
        return ret;
    }

    std::string nContractLanguageVersion = "0";
    ret = LoopRead(std::regex(R"(^(\d+\.){1,2}(\d+)(-[a-zA-Z0-9]+(\.\d+)?)?(\+[a-zA-Z0-9]+(\.\d+)?)?$)"),
                        "contract language version", nContractLanguageVersion);
    if (ret != 0)
    {
        return ret;
    }

    std::string nContractStandard ="0";
    ret = LoopRead(std::regex(R"(^ERC-\d+$)"),
                    "contract Standard", nContractStandard);
    if (ret != 0)
    {
        return ret;
    }

    std::string nContractLogo = "0";
    ret = LoopRead(std::regex(R"(\b((?:[a-zA-Z0-9]+://)?[^\s]+\.[a-zA-Z]{2,}(?::\d{2,})?(?:/[^\s]*)?))"),
                    "url", nContractLogo);
    if (ret != 0)
    {
        return ret;
    }

    std::string nContractSource = "0";

    std::string source_code;
    ret = LoopReadFile(nContractSource, source_code, "source.sol");
    if (ret < 0)
    {
        return -3;
    }

    std::string nContractABI = "0";

    nlohmann::json ABI;
    ret = LoopReadJson(nContractABI, ABI, "abi.json");
    if (ret != 0)
    {
        return ret;
    }

    std::string nContractUserDoc = "0";
    nlohmann::json userDoc;
    ret = LoopReadJson(nContractUserDoc, userDoc, "userdoc.json");
    if (ret != 0)
    {
        return ret;
    }

    std::string nContractDevDoc = "0";
    nlohmann::json devDoc;
    ret = LoopReadJson(nContractDevDoc, devDoc, "devdoc.json");
    if (ret != 0)
    {
        return ret;
    }

    std::string nContractCompilerVersion = "0";
    ret = LoopRead(std::regex(R"(^\d+\.\d+\.\d+.*$)"),
                    "compiler version", nContractCompilerVersion);
    if (ret != 0)
    {
        return ret;
    }

    std::string nContractCompilerOptions = "0";
    nlohmann::json compilerOptions;
    ret = LoopReadJson(nContractCompilerOptions, compilerOptions, "compiler_options.json");
    if (ret != 0)
    {
        return ret;
    }

    std::string nContractSrcMap = "0";
    std::string srcMap;
    ret = LoopReadFile(nContractSrcMap, srcMap, "srcmap.txt");
    if (ret < 0)
    {
        return ret;
    }

    std::string nContractSrcMapRuntime = "0";
    std::string srcMapRuntime;
    ret = LoopReadFile(nContractSrcMapRuntime, srcMapRuntime, "srcmap_runtime.txt");
    if (ret < 0)
    {
        return ret;
    }

    std::string nContractMetadata = "0";
    nlohmann::json metadata;
    ret = LoopReadJson(nContractMetadata, metadata, "metadata.json");
    if (ret != 0)
    {
        return ret;
    }

    std::string nContractOther = "0";
    nlohmann::json otherData;
    ret = LoopReadJson(nContractOther, otherData, "otherdata.json");
    if (ret != 0)
    {
        return ret;
    }

    contract_info["name"] = nContractName;
    contract_info["language"] = "Solidity";
    contract_info["languageVersion"] = nContractLanguageVersion;
    contract_info["standard"] = nContractStandard;
    contract_info["logo"] = nContractLogo;
    contract_info["source"] = source_code;
    contract_info["ABI"] = ABI;
    contract_info["userDoc"] = userDoc;
    contract_info["developerDoc"] = devDoc;
    contract_info["compilerVersion"] = nContractCompilerVersion;
    contract_info["compilerOptions"] = compilerOptions;
    contract_info["srcMap"] = srcMap;
    contract_info["srcMapRuntime"] = srcMapRuntime;
    contract_info["metadata"] = metadata;
    contract_info["other"] = otherData;

    return 0;
}

void HandleMultiDeployContract(const std::string &strFromAddr,std::map<std::string,std::string> &_deployMap)
{
    
    if (!CheckBase58Addr(strFromAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    DBReader dataReader;
    uint64_t top = 0;
	if (DBStatus::DB_SUCCESS != dataReader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return ;
    }

    uint32_t nContractType = 0;
    nlohmann::json contract_info;
    int ret = _GenerateContractInfo(contract_info);
    if(ret != 0)
    {
        return;
    }
    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgentFlag;
    NewVrf info;
    std::vector<std::string> dirtyContract;
    if(nContractType == 0)
    {
        std::string nContractPath = "0";
        std::string code;

        ret = LoopReadFile(nContractPath, code, "contract");
        if (ret != 0)
        {
            return;
        }

        if(code.empty())
        {
            return;
        }

        std::string strInput = "0";
        if (strInput == "0")
        {
            strInput.clear();
        }
        else if(strInput.substr(0, 2) == "0x")
        {
            strInput = strInput.substr(2);
            code += strInput;
        }
        Account launchAccount;
        code.erase(std::remove_if(code.begin(), code.end(), ::isspace), code.end());
        if(MagicSingleton<AccountManager>::GetInstance()->FindAccount(strFromAddr, launchAccount) != 0) 
        {
            ERRORLOG("Failed to find account {}", strFromAddr);
            return;
        }
        std::string ownerEvmAddr = evm_utils::generateEvmAddr(launchAccount.GetPubStr());
        ret = TxHelper::CreateEvmDeployContractTransaction(strFromAddr, ownerEvmAddr, code, top + 1,
                                                           outTx, dirtyContract,
                                                           isNeedAgentFlag,
                                                           info);
        if(ret != 0)
        {
            ERRORLOG("Failed to create DeployContract transaction! The error code is:{}", ret);
            return;
        }        
    }
    else
    {
        return;
    }

    int sret=SigTx(outTx, strFromAddr);
    if(sret!=0){
        ERRORLOG("sig fial %s",sret);
        return ;
    }
    std::string txHash = getsha256hash(outTx.SerializeAsString());
    outTx.set_hash(txHash);
    

    ContractTxMsgReq ContractMsg;
    ContractMsg.set_version(global::kVersion);
    ContractTempTxMsgReq * txMsg = ContractMsg.mutable_txmsgreq();
	txMsg->set_version(global::kVersion);
    
    TxMsgInfo * txMsgInfo = txMsg->mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);
    for (const auto& addr : dirtyContract)
    {
        txMsgInfo->add_contractstoragelist(addr);
    }

    if(isNeedAgentFlag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        NewVrf * newInfo=txMsg->mutable_vrfinfo();
        newInfo -> CopyFrom(info);

    }

    _deployMap.insert(std::make_pair(strFromAddr,outTx.hash()));
    
    auto msg = make_shared<ContractTxMsgReq>(ContractMsg);
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgentFlag==TxHelper::vrfAgentType::vrfAgentType_vrf )
    {
        ret = DropCallShippingTx(msg,outTx);
    }

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
    std::cout << "Transaction result : " << ret << std::endl;
}

void printJson()
{
    std::multimap<std::string,std::string> _deployMap;
    std::string fileName = "print_Delopy_addr_utxo.txt";
    std::ofstream filestream;
    filestream.open(fileName);
    if (!filestream)
    {
        std::cout << "Open file failed!" << std::endl;
        return;
    }

    DBReader dbReader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }


    for(int i = 0 ; i <= top ; ++i)
    {
        std::vector<std::string> hashes;
        if (DBStatus::DB_SUCCESS != dbReader.GetBlockHashsByBlockHeight(i,hashes))
        {
            ERRORLOG("db get top failed!!");
            return;
        }

        for(auto &hash : hashes)
        {
            std::string blockStr;
            if (DBStatus::DB_SUCCESS != dbReader.GetBlockByBlockHash(hash,blockStr))
            {
                ERRORLOG("db get top failed!!");
                return;
            }
            CBlock block;
            block.ParseFromString(blockStr);
            for(auto & ContractTx : block.txs())
            {
                if ((global::ca::TxType)ContractTx.txtype() != global::ca::TxType::kTxTypeDeployContract)
                {
                    continue;
                }

                std::string fromAddr = ContractTx.utxo().owner(0);
                _deployMap.insert({fromAddr,ContractTx.hash()});
            }
        }
    }

    std::string arg;
    std::cout << "print arg :";
    std::cin >> arg;
    nlohmann::json addr_utxo;
    for(auto & item : _deployMap)
    {
        
        nlohmann::json addr;
        addr["deployer"] =  item.first;
        addr["deployutxo"] =  item.second;
        addr["arg"] = arg;
        addr["money"] = "0";
        addr_utxo["addr_utxo"].push_back(addr);
    }

    filestream << addr_utxo.dump();
    filestream.close();
}

void CreateMultiThreadAutomaticDeployContract()
{
    std::vector<std::string> _fromaddr;
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(_fromaddr);
    std::map<std::string,std::string> _deployMap;

    uint64_t time;
    std::cout << "please input time seconds >:";
    std::cin >> time;

    for(auto &i :_fromaddr)
    {
        HandleMultiDeployContract(i,_deployMap);
        sleep(time);
    }
    std::cout << "end................" << std::endl;   
}


