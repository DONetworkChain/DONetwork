#include "advanced_menu.h"

#include <map>
#include <regex>
#include <thread>
#include <ostream>
#include <fstream>
#include <cstdio>
#include <memory>
#include <array>
#include <stdexcept>
#include <cstring>

#include "ca/ca.h"
#include "ca/test.h"
#include "ca/global.h"
#include "ca/contract.h"
#include "ca/txhelper.h"
#include "ca/interface.h"
#include "ca/algorithm.h"

#include "ca/transaction.h"
#include "ca/block_helper.h"
#include "ca/block_monitor.h"
#include "ca/evm/evm_manager.h"

#include "net/api.h"
#include "net/peer_node.h"

#include "include/scope_guard.h"
#include "include/logging.h"

#include "utils/tmp_log.h"
#include "utils/console.h"
#include "utils/time_util.h"
#include "utils/contract_utils.h"
#include "utils/don_bench_mark.h"
#include "utils/magic_singleton.h"
#include "utils/account_manager.h"
#include "utils/base64.h"
#include "utils/time_util.h"

#include "db/db_api.h"
#include "openssl/rand.h"
#include "api/interface/http_api.h"
struct contractJob
{
    std::string fromAddr;
    std::string deployer;
    std::string contractAddresses;
    std::string arg;
    std::string tip;
    std::string money;
};

std::vector<contractJob> jobs;
std::atomic<int> jobs_index = 0;
std::atomic<int> perrnode_index = 0;
boost::threadpool::pool test_pool;

void ReadContract_json(const std::string &file_name)
{
    std::ifstream file(file_name);
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string contents(buffer.str());
    if (contents.empty())
    {
        errorL("no data");
        return;
    }
    nlohmann::json jsonboj;
    try
    {
        jsonboj = nlohmann::json::parse(contents);
    }
    catch (std::exception &e)
    {
        errorL(e.what());
        return;
    }

    if (!jsonboj.is_array())
    {
        errorL("not a array");
        return;
    }
    try
    {
        for (auto &aitem : jsonboj)
        {
            contractJob job;
            job.deployer = aitem["deployer"];
            job.contractAddresses = aitem["contractAddresses"];
            job.arg = aitem["arg"];
            job.money = aitem["money"];
            jobs.push_back(job);
        }
    }
    catch (std::exception &e)
    {
        errorL("wath:%s", e.what());
        return;
    }
}

void ContrackInvke(contractJob job)
{

    infoL("fromAddr:%s", job.fromAddr);
    infoL("deployer:%s", job.deployer);
    infoL("deployutxo:%s", job.contractAddresses);
    infoL("money:%s", job.money);
    infoL("arg:%s", job.arg);

    std::string strFromAddr = job.fromAddr;

    if (!isValidAddress(strFromAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }
    DBReader dataReader;

    std::string strToAddr = job.deployer;
    if (!isValidAddress(strToAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    std::string _contractAddresses = job.contractAddresses;
    std::string strInput = job.arg;
    if (strInput.substr(0, 2) == "0x")
    {
        strInput = strInput.substr(2);
    }

    std::string contractTipStr = "0";
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(contractTipStr, pattern))
    {
        std::cout << "input contract tip error ! " << std::endl;
        return;
    }

    std::string contractTransferStr = job.money;
    if (!std::regex_match(contractTransferStr, pattern))
    {
        std::cout << "input contract transfer error ! " << std::endl;
        return;
    }
    uint64_t contractTip = (std::stod(contractTipStr) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
    uint64_t contractTransfer = (std::stod(contractTransferStr) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != dataReader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    CTransaction outTx;
    //    CTransaction tx;
    //    std::string txRaw;
    //    if (DBStatus::DB_SUCCESS != dataReader.GetTransactionByHash(strTxHash, txRaw))
    //    {
    //        ERRORLOG("get contract transaction failed!!");
    //        return ;
    //    }
    //    if(!tx.ParseFromString(txRaw))
    //    {
    //        ERRORLOG("contract transaction parse failed!!");
    //        return ;
    //    }
    //
    //
    //    nlohmann::json dataJson = nlohmann::json::parse(tx.data());
    //    nlohmann::json txInfo = dataJson["TxInfo"].get<nlohmann::json>();
    //    int vmType = txInfo[Evmone::contractVirtualMachineKeyName].get<int>();

    int ret = 0;
    TxHelper::vrfAgentType isNeedAgentFlag;
    Vrf info;
    std::vector<std::string> dirtyContract;
    std::string encodedInfo = "";
    ret = TxHelper::CreateEvmCallContractTransaction(strFromAddr, strToAddr, strInput, encodedInfo, top + 1,
                                                     outTx, isNeedAgentFlag, info, contractTip, contractTransfer,
                                                     dirtyContract, _contractAddresses);
    //    if (vmType == global::ca::VmType::EVM)
    //    {
    // const std::string& contractAddress = evm_utils::GenerateContractAddr(strToAddr + strTxHash);
    // ret = TxHelper::CreateEvmCallContractTransaction(strFromAddr, strToAddr, strTxHash, strInput, top + 1,
    //                                                outTx, isNeedAgentFlag, info, contractTip, contractTransfer,
    //                                                 dirtyContract, contractAddress);
    // if(ret != 0)
    //{
    //    ERRORLOG("Create call contract transaction failed! ret:{}", ret);
    //     return;
    // }
    //    }
    //    else
    //    {
    //        return;
    //    }

    if (ret != 0)
    {
        return;
    }

    ContractTxMsgReq ContractMsg;
    ContractMsg.set_version(global::kVersion);
    TxMsgReq *txMsg = ContractMsg.mutable_txmsgreq();
    txMsg->set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg->mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_nodeheight(top);

    // uint64_t localTxUtxoHeight;
    // ret = TxHelper::GetTxUtxoHeight(outTx, localTxUtxoHeight);
    // if(ret != 0)
    // {
    //     ERRORLOG("GetTxUtxoHeight fail!!! ret = {}", ret);
    //     return;
    // }

    // txMsgInfo->set_txutxoheight(localTxUtxoHeight);

    DEBUGLOG("size =  {}",dirtyContract.size());
    for (const auto &addr : dirtyContract)
    {
        std::cout << "addr = " << "0x" + addr << std::endl;
        txMsgInfo->add_contractstoragelist(addr);
    }

    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf *newInfo = txMsg->mutable_vrfinfo();
        newInfo->CopyFrom(info);
    }

    auto msg = std::make_shared<ContractTxMsgReq>(ContractMsg);
    std::string defaultAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr();
    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        ret = DropCallShippingTx(msg, outTx);
        MagicSingleton<BlockMonitor>::GetInstance()->addDropshippingTxVec(outTx.hash());
    }

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void test_contact_thread()
{
    ReadContract_json("contract.json");
    std::vector<std::string> acccountlist;
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(acccountlist);

    jobs_index = 0;
    perrnode_index = 0;
    int time_s;
    std::cout << "time_s:";
    std::cin >> time_s;
    std::cout << "second:";
    long long _second;
    std::cin >> _second;
    std::cout << "hom much:";
    long long _much;
    std::cin >> _much; 
    int oneSecond = 0;
    while (time_s)
    {
        oneSecond++;
        std::cout << "hhh h" << std::endl;
        jobs[jobs_index].fromAddr = acccountlist[perrnode_index];
        test_pool.schedule(boost::bind(ContrackInvke, jobs[jobs_index]));
        std::thread th = std::thread(ContrackInvke, jobs[jobs_index]);
        th.detach();
        jobs_index = ++jobs_index % jobs.size();
        perrnode_index = ++perrnode_index % acccountlist.size();
        ::usleep(_second * 1000 * 1000 / _much);
        if (oneSecond == _much)
        {
            time_s--;
            oneSecond = 0;
        }
    }
}

std::atomic_bool rpcConTxFlag = false;
void SetRpcConTxFlag(const bool flag)
{
    rpcConTxFlag = flag;
}
void GetRpcConTxFlag(bool& flag)
{
    flag = rpcConTxFlag;
}

void TestRpcContactThread(int TxNum, int timeout)
{
    std::thread th([TxNum, timeout](){
        ReadContract_json("contract.json");
        std::vector<std::string> acccountlist;
        MagicSingleton<AccountManager>::GetInstance()->GetAccountList(acccountlist);

        while (rpcConTxFlag)
        {
            jobs[jobs_index].fromAddr = acccountlist[perrnode_index];
            test_pool.schedule(boost::bind(ContrackInvke, jobs[jobs_index]));
            std::thread th = std::thread(ContrackInvke, jobs[jobs_index]);
            th.detach();
            jobs_index = ++jobs_index % jobs.size();
            perrnode_index = ++perrnode_index % acccountlist.size();
            ::usleep(timeout * 1000 * 1000 / TxNum);
        }
    });
    th.detach();
}

void GenKey()
{
    std::cout << "Please enter the number of accounts to be generated: ";
    int num = 0;
    std::cin >> num;
    if (num <= 0)
    {
        return;
    }

    for (int i = 0; i != num; ++i)
    {
        Account acc(true);
        MagicSingleton<AccountManager>::GetInstance()->AddAccount(acc);
        MagicSingleton<AccountManager>::GetInstance()->SavePrivateKeyToFile(acc.GetAddr());
    }

    std::cout << "Successfully generated account " << std::endl;
}

void RollBack()
{
    MagicSingleton<BlockHelper>::GetInstance()->RollbackTest();
}

void GetStakeList()
{
    DBReader dbReader;
    std::vector<std::string> addResses;
    dbReader.GetStakeAddress(addResses);
    uint64_t height;
    dbReader.GetBlockTop(height);
    std::cout << "StakeList :" << std::endl;
    for (auto &it : addResses)
    {
        double timp = 0.0;
        ca_algorithm::GetCommissionPercentage(it, height, timp);
        std::cout << "addr: " << "0x" + it << "\tbonus pumping: " << timp << std::endl;
    }
}
int GetBonusAddrInfo()
{
    DBReader dbReader;
    std::vector<std::string> addResses;
    std::vector<std::string> bonusAddrs;
    dbReader.GetBonusaddr(bonusAddrs);
    for (auto &bonusAddr : bonusAddrs)
    {
        std::cout << YELLOW << "BonusAddr: " << addHexPrefix(bonusAddr) << RESET << std::endl;
        auto ret = dbReader.GetInvestAddrsByBonusAddr(bonusAddr, addResses);
        if (ret != DBStatus::DB_SUCCESS && ret != DBStatus::DB_NOT_FOUND)
        {
            return -1;
        }

        uint64_t sumInvestAmount = 0;
        std::cout << "InvestAddr:" << std::endl;
        for (auto &address : addResses)
        {
            std::cout << addHexPrefix(address) << std::endl;
            std::vector<std::string> utxos;
            ret = dbReader.GetBonusAddrInvestUtxosByBonusAddr(bonusAddr, address, utxos);
            if (ret != DBStatus::DB_SUCCESS && ret != DBStatus::DB_NOT_FOUND)
            {
                return -2;
            }

            uint64_t investAmount = 0;
            for (const auto &hash : utxos)
            {
                std::string txRaw;
                if (dbReader.GetTransactionByHash(hash, txRaw) != DBStatus::DB_SUCCESS)
                {
                    return -3;
                }
                CTransaction tx;
                if (!tx.ParseFromString(txRaw))
                {
                    return -4;
                }
                for (int i = 0; i < tx.utxo().vout_size(); i++)
                {
                    if (tx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr)
                    {
                        investAmount += tx.utxo().vout(i).value();
                        break;
                    }
                }
            }
            sumInvestAmount += investAmount;
        }
        std::cout << "total invest amount :" << sumInvestAmount << std::endl;
    }
    return 0;
}

#pragma region netMenu
void SendMessageToUser()
{
    if (net_com::SendOneMessageByInput() == 0)
    {
        DEBUGLOG("send one msg Succ.");
    }
    else
    {
        DEBUGLOG("send one msg Fail.");
    }
}

void ShowMyKBucket()
{
    std::cout << "The K bucket is being displayed..." << std::endl;
    auto nodeList = MagicSingleton<PeerNode>::GetInstance()->GetNodelist();
    MagicSingleton<PeerNode>::GetInstance()->Print(nodeList);
}

void KickOutNode()
{
    std::string id;
    std::cout << "input id:" << std::endl;
    std::cin >> id;
    MagicSingleton<PeerNode>::GetInstance()->DeleteNode(id);
    std::cout << "Kick out node succeed!" << std::endl;
}

void TestEcho()
{

    std::string message;
    std::cout << "please input message:" << std::endl;
    std::cin >> message;
    std::stringstream ss;
    ss << message << "_" << std::to_string(MagicSingleton<TimeUtil>::GetInstance()->GetUTCTimestamp());

    EchoReq echoReq;
    echoReq.set_id(MagicSingleton<PeerNode>::GetInstance()->GetSelfId());
    echoReq.set_message(ss.str());
    bool isSucceed = net_com::BroadCastMessage(echoReq, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_Low_0);
    if (isSucceed == false)
    {
        ERRORLOG(":broadcast EchoReq failed!");
        return;
    }
}

void PrintReqAndAck()
{
    double total = .0f;
    std::cout << "------------------------------------------" << std::endl;
    for (auto &item : global::g_reqCntMap)
    {
        total += (double)item.second.second;
        std::cout.precision(3);
        std::cout << item.first << ": " << item.second.first << " size: " << (double)item.second.second / 1024 / 1024 << " MB" << std::endl;
    }
    std::cout << "------------------------------------------" << std::endl;
    std::cout << "Total: " << total / 1024 / 1024 << " MB" << std::endl;
}

void MenuBlockInfo()
{
    while (true)
    {
        DBReader reader;
        uint64_t top = 0;
        reader.GetBlockTop(top);

        std::cout << std::endl;
        std::cout << "Height: " << top << std::endl;
        std::cout << "1.Get the total number of transactions \n"
                     "2.Get transaction block details\n"
                     "5.Get device password \n"
                     "6.Set device password\n"
                     "7.Get device private key\n"
                     "0.Exit \n";

        std::string strKey;
        std::cout << "please input your choice:";
        std::cin >> strKey;

        std::regex pattern("^[0-7]$");
        if (!std::regex_match(strKey, pattern))
        {
            std::cout << "Input invalid." << std::endl;
            return;
        }
        int key = std::stoi(strKey);
        switch (key)
        {
        case 0:
            return;

        case 2:
            getTxBlockInfo(top);
            break;

        default:
            std::cout << "Invalid input." << std::endl;
            continue;
        }

        sleep(1);
    }
}

void getTxBlockInfo(uint64_t &top)
{
    auto amount = std::to_string(top);
    std::string inputStart, inputEnd;
    uint64_t start, end;

    std::cout << "amount: " << amount << std::endl;
    std::cout << "pleace input start: ";
    std::cin >> inputStart;
    if (inputStart == "a" || inputStart == "pa")
    {
        inputStart = "0";
        inputEnd = amount;
    }
    else
    {
        if (std::stoul(inputStart) > std::stoul(amount))
        {
            std::cout << "input > amount" << std::endl;
            return;
        }
        std::cout << "pleace input end: ";
        std::cin >> inputEnd;
        if (std::stoul(inputStart) < 0 || std::stoul(inputEnd) < 0)
        {
            std::cout << "params < 0!!" << std::endl;
            return;
        }
        if (std::stoul(inputStart) > std::stoul(inputEnd))
        {
            inputStart = inputEnd;
        }
        if (std::stoul(inputEnd) > std::stoul(amount))
        {
            inputEnd = std::to_string(top);
        }
    }
    start = std::stoul(inputStart);
    end = std::stoul(inputEnd);

    std::cout << "Print to screen[0] or file[1] ";
    uint64_t nType = 0;
    std::cin >> nType;
    if (nType == 0)
    {
        PrintRocksdb(start, end, true, std::cout);
    }
    else if (nType == 1)
    {
        std::string fileName = "print_block_" + std::to_string(start) + "_" + std::to_string(end) + ".txt";
        std::ofstream filestream;
        filestream.open(fileName);
        if (!filestream)
        {
            std::cout << "Open file failed!" << std::endl;
            return;
        }
        PrintRocksdb(start, end, true, filestream);
    }
}

void GenMnemonic()
{
    char out[1024 * 10] = {0};

    std::string mnemonic;
    Account defaultEd;
    MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultEd);
    MagicSingleton<AccountManager>::GetInstance()->GetMnemonic(defaultEd.GetAddr(), mnemonic);
    std::cout << "mnemonic : " << mnemonic << std::endl;
    std::cout << "priStr : " << Str2Hex(defaultEd.GetPriStr()) << std::endl;
    std::cout << "pubStr : " << Str2Hex(defaultEd.GetPubStr()) << std::endl;

    std::cout << "input mnemonic:" << std::endl;
    std::string str;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, str);

    int len = 0;
    if (mnemonic.size() > str.size())
    {
        len = mnemonic.size();
    }
    else
    {
        len = str.size();
    }

    for (int i = 0; i < len; i++)
    {
        if (mnemonic[i] != str[i])
        {
            std::cout << "not equal!" << std::endl;
        }
    }

    if (str != mnemonic)
    {
        std::cout << "mnemonic error !!! " << std::endl;
    }
    std::cout << "final mnemonic : " << str << std::endl;
    MagicSingleton<AccountManager>::GetInstance()->ImportMnemonic(mnemonic);
}

void PrintTxData()
{
    std::string hash;
    std::cout << "TX hash: ";
    std::cin >> hash;

    DBReader dbReader;

    CTransaction tx;
    std::string TxRaw;
    auto ret = dbReader.GetTransactionByHash(hash, TxRaw);
    if (ret != DBStatus::DB_SUCCESS)
    {
        ERRORLOG("GetTransactionByHash failed!");
        return;
    }
    if (!tx.ParseFromString(TxRaw))
    {
        ERRORLOG("Transaction Parse failed!");
        return;
    }

    nlohmann::json dataJson = nlohmann::json::parse(tx.data());
    std::string data = dataJson.dump(4);
    std::cout << data << std::endl;
}

void MultiTx()
{
    std::ifstream fin;
    fin.open("toaddr.txt", std::ifstream::binary);
    if (!fin.is_open())
    {
        std::cout << "open file error" << std::endl;
        return;
    }

    std::vector<std::string> fromAddr;

    std::string addr;
    std::cout << "input fromaddr >:";
    std::cin >> addr;
    if (addr.substr(0, 2) == "0x")
    {
        addr = addr.substr(2);
    }
    fromAddr.push_back(addr);

    std::vector<std::string> toAddrs;
    std::map<std::string, int64_t> toAddr;
    std::string Addr;
    double amt = 0;
    std::cout << "input amount>:";
    std::cin >> amt;

    while (getline(fin, Addr))
    {
        if (Addr[Addr.length() - 1] == '\r')
        {
            Addr = Addr.substr(0, Addr.length() - 1);
        }
        toAddrs.push_back(Addr);
    }

    uint32_t startCount = 0;
    uint32_t endCount = 0;
    std::cout << "please input start index>:";
    std::cin >> startCount;

    std::cout << "please input end index>:";
    std::cin >> endCount;

    for (uint32_t i = startCount; i <= endCount; i++)
    {
        toAddr.insert(std::make_pair(toAddrs[i], amt * global::ca::kDecimalNum));
    }

    fin.close();

    DBReader dbReader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    TxMsgReq txMsg;
    TxHelper::vrfAgentType isNeedAgentFlag;
    CTransaction outTx;
    Vrf info;
    std::string encodedInfo;
    int ret = TxHelper::CreateTxTransaction(fromAddr, toAddr, encodedInfo, top + 1, outTx, isNeedAgentFlag, info, false);
    if (ret != 0)
    {
        ERRORLOG("CreateTxTransaction error!!");
        return;
    }

    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_nodeheight(top);

    uint64_t localTxUtxoHeight;
    ret = TxHelper::GetTxUtxoHeight(outTx, localTxUtxoHeight);
    if (ret != 0)
    {
        ERRORLOG("GetTxUtxoHeight fail!!! ret = {}", ret);
        return;
    }

    txMsgInfo->set_txutxoheight(localTxUtxoHeight);

    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf *new_info = txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info);
    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);

    std::string defaultAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr();
    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultAddr)
    {

        ret = DropshippingTx(msg, outTx);
    }
    else
    {
        ret = DoHandleTx(msg, outTx);
    }
    DEBUGLOG("Transaction result, ret:{}  txHash: {}", ret, outTx.hash());
}

void testaddr1()
{
    Account acc(true);
    MagicSingleton<AccountManager>::GetInstance()->AddAccount(acc);
    MagicSingleton<AccountManager>::GetInstance()->SavePrivateKeyToFile(acc.GetAddr());

    std::cout << "addr:" << addHexPrefix(acc.GetAddr()) << std::endl;
    if (!isValidAddress(acc.GetAddr()))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }
}

void testaddr2()
{
    while (true)
    {
        std::cout << "isValidAddress: " << std::endl;
        std::string addr;
        std::cin >> addr;
        if (addr.substr(0, 2) == "0x")
        {
            addr = addr.substr(2);
        }
        if (!isValidAddress(addr))
        {
            std::cout << "Input addr error!" << std::endl;
            return;
        }
    }
}

void testaddr3()
{
    std::map<std::string, Account> accs;
    while (true)
    {
        Account acc(true);
        MagicSingleton<AccountManager>::GetInstance()->AddAccount(acc);
        if (accs.find(acc.GetAddr()) != accs.end())
        {
            std::cout << "errrrrrrrre addr:{}" << addHexPrefix(acc.GetAddr()) << std::endl;
            return;
        }
        accs[acc.GetAddr()] = acc;
        if (acc.GetAddr().substr(0, 3) == "666")
        {
            MagicSingleton<AccountManager>::GetInstance()->SavePrivateKeyToFile(acc.GetAddr());
        }
        std::cout << "addr:" << addHexPrefix(acc.GetAddr()) << std::endl;
        if (!isValidAddress(acc.GetAddr()))
        {
            std::cout << "Input addr error!" << std::endl;
            return;
        }
    }
}
void testNewAddr()
{
    testaddr3();
}

void getContractAddr()
{
    // std::cout << std::endl
    //           << std::endl;

    // std::cout << "AddrList : " << std::endl;
    // MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    // std::string strFromAddr;
    // std::cout << "Please enter your addr:" << std::endl;
    // std::cin >> strFromAddr;
    // if (!isValidAddress(strFromAddr))
    // {
    //     std::cout << "Input addr error!" << std::endl;
    //     return;
    // }

    // DBReader dbReader;
    // std::vector<std::string> vecDeployers;
    // dbReader.GetAllEvmDeployerAddr(vecDeployers);
    // std::cout << "=====================deployers=====================" << std::endl;
    // for(auto& deployer : vecDeployers)
    // {
    //     std::cout << "deployer: " << deployer << std::endl;
    // }
    // std::cout << "=====================deployers=====================" << std::endl;
    // std::string strToAddr;
    // std::cout << "Please enter to addr:" << std::endl;
    // std::cin >> strToAddr;
    // if(!isValidAddress(strToAddr))
    // {
    //     std::cout << "Input addr error!" << std::endl;
    //     return;
    // }

    // std::vector<std::string> vecDeployUtxos;
    // dbReader.GetDeployUtxoByDeployerAddr(strToAddr, vecDeployUtxos);
    // std::cout << "=====================deployed utxos=====================" << std::endl;
    // for(auto& deployUtxo : vecDeployUtxos)
    // {
    //     std::cout << "deployed utxo: " << deployUtxo << std::endl;
    // }
    // std::cout << "=====================deployed utxos=====================" << std::endl;
    // std::string strTxHash;
    // std::cout << "Please enter tx hash:" << std::endl;
    // std::cin >> strTxHash;

    // std::string addr = evm_utils::GenerateContractAddr(strToAddr+strTxHash);

    // std::cout << addr << std::endl;
}

static bool benchmarkAutomicWriteSwitch = false;
void PrintBenchmarkToFile()
{
    if (benchmarkAutomicWriteSwitch)
    {
        benchmarkAutomicWriteSwitch = false;
        std::cout << "benchmark automic write has stoped" << std::endl;
        return;
    }
    std::cout << "enter write time interval (unit second) :";
    int interval = 0;
    std::cin >> interval;
    if (interval <= 0)
    {
        std::cout << "time interval less or equal to 0" << std::endl;
        return;
    }
    benchmarkAutomicWriteSwitch = true;
    auto benchmarkAutomicWriteThread = std::thread(
        [interval]()
        {
            while (benchmarkAutomicWriteSwitch)
            {
                MagicSingleton<DONbenchmark>::GetInstance()->PrintBenchmarkSummary(true);
                MagicSingleton<DONbenchmark>::GetInstance()->PrintBenchmarkSummary_DoHandleTx(true);
                sleep(interval);
            }
        });
    benchmarkAutomicWriteThread.detach();
    return;
}

void GetBalanceByUtxo()
{
    std::cout << "Inquiry address:";
    std::string addr;
    std::cin >> addr;
    if (addr.substr(0, 2) == "0x")
    {
        addr = addr.substr(2);
    }
    DBReader reader;
    std::vector<std::string> utxoHashs;
    reader.GetUtxoHashsByAddress(addr, utxoHashs);

    auto utxoOutput = [addr, utxoHashs, &reader](std::ostream &stream)
    {
        stream << "account:" << addHexPrefix(addr) << " utxo list " << std::endl;

        uint64_t total = 0;
        for (auto i : utxoHashs)
        {
            std::string txRaw;
            reader.GetTransactionByHash(i, txRaw);

            CTransaction tx;
            tx.ParseFromString(txRaw);

            uint64_t value = 0;
            for (int j = 0; j < tx.utxo().vout_size(); j++)
            {
                CTxOutput txout = tx.utxo().vout(j);
                if (txout.addr() != addr)
                {
                    continue;
                }
                value += txout.value();
            }
            stream << i << " : " << value << std::endl;
            total += value;
        }

        stream << "address: " << addHexPrefix(addr) << " UTXO total: " << utxoHashs.size() << " UTXO gross value:" << total << std::endl;
    };

    if (utxoHashs.size() < 10)
    {
        utxoOutput(std::cout);
    }
    else
    {
        std::string fileName = "utxo_" + addr + ".txt";
        std::ofstream file(fileName);
        if (!file.is_open())
        {
            ERRORLOG("Open file failed!");
            return;
        }
        utxoOutput(file);
        file.close();
    }
}

int ImitateCreateTxStruct()
{
    // Account acc;
    // if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(acc) != 0)
    // {
    //     return -1;
    // }
    Account acc;
    MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(acc);

    const std::string addr = acc.GetAddr();
    uint64_t time = global::ca::kGenesisTime;

    CTransaction tx;
    tx.set_version(global::ca::kCurrentTransactionVersion);
    tx.set_time(time);
    tx.set_n(0);
    tx.set_identity(addr);
    tx.set_type(global::ca::kGenesisSign);

    // Check whether the Genesis account is in the address list
    std::vector<std::string> List;
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(List);
    if (std::find(List.begin(), List.end(), global::ca::kInitAccountAddr) == List.end())
    {
        std::cout << "The Genesis account is not in the node list !" << std::endl;
        return -1;
    }

    std::unordered_map<std::string, uint64_t> addrValue;

    CTxUtxo *utxo = tx.mutable_utxo();
    utxo->add_owner(addr);
    {
        CTxInput *txin = utxo->add_vin();
        CTxPrevOutput *prevOut = txin->add_prevout();
        prevOut->set_hash(std::string(64, '0'));
        prevOut->set_n(0);
        txin->set_sequence(0);

        std::string serVinHash = Getsha256hash(txin->SerializeAsString());
        std::string signature;
        std::string pub;

        if (acc.Sign(serVinHash, signature) == false)
        {
            return -3;
        }

        CSign *sign = txin->mutable_vinsign();
        sign->set_sign(signature);
        sign->set_pub(acc.GetPubStr());
    }

    {
        CTxOutput *txout = utxo->add_vout();
        txout->set_value(global::ca::KoldKM2 * global::ca::kDecimalNum * 1000);
        txout->set_addr(addr);

        // for(auto & obj : addrValue)
        // {
        //     CTxOutput *newTxout = utxo->add_vout();
        //     newTxout->set_value(obj.second);
        //     newTxout->set_addr(obj.first);
        // }
    }

    {
        std::string serUtxo = Getsha256hash(utxo->SerializeAsString());
        std::string signature;
        if (acc.Sign(serUtxo, signature) == false)
        {
            return -4;
        }

        CSign *multiSign = utxo->add_multisign();
        multiSign->set_sign(signature);
        multiSign->set_pub(acc.GetPubStr());
    }

    tx.set_txtype((uint32)global::ca::TxType::kTxTypeGenesis);

    tx.set_hash(Getsha256hash(tx.SerializeAsString()));

    CBlock block;
    block.set_time(time);
    block.set_version(global::ca::kCurrentBlockVersion);
    block.set_prevhash(std::string(64, '0'));
    block.set_height(0);

    CTransaction *tx0 = block.add_txs();
    *tx0 = tx;

    nlohmann::json blockData;
    blockData["Name"] = "DoNetwork";
    blockData["Type"] = "Genesis";
    block.set_data(blockData.dump());

    block.set_merkleroot(ca_algorithm::CalcBlockMerkle(block));
    block.set_hash(Getsha256hash(block.SerializeAsString()));

    std::string hex = Str2Hex(block.SerializeAsString());
    // std::cout << std::endl
    //           << hex << std::endl;
    std::ofstream ofs;
    ofs.open("HexBlock.txt");
    if (!ofs)
    {
        std::cout << "Open file failed!" << std::endl;
        return -5;
    }
    ofs << hex;

    return 0;
}

void MultiTransaction()
{
    int addrCount = 0;
    std::cout << "Number of initiator accounts:";
    std::cin >> addrCount;

    std::vector<std::string> fromAddr;
    for (int i = 0; i < addrCount; ++i)
    {
        std::string addr;
        std::cout << "Initiating account" << i + 1 << ": ";
        std::cin >> addr;
        if (addr.substr(0, 2) == "0x")
        {
            addr = addr.substr(2);
        }
        fromAddr.push_back(addr);
    }

    std::cout << "Number of receiver accounts:";
    std::cin >> addrCount;

    std::map<std::string, int64_t> toAddr;
    for (int i = 0; i < addrCount; ++i)
    {
        std::string addr;
        double amt = 0;
        std::cout << "Receiving account" << i + 1 << ": ";
        std::cin >> addr;
        if (addr.substr(0, 2) == "0x")
        {
            addr = addr.substr(2);
        }
        std::cout << "amount : ";
        std::cin >> amt;
        toAddr.insert(make_pair(addr, amt * global::ca::kDecimalNum));
    }

    DBReader dbReader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    TxMsgReq txMsg;
    TxHelper::vrfAgentType isNeedAgentFlag;
    CTransaction outTx;
    Vrf info;
    std::string encodedInfo = "";
    int ret = TxHelper::CreateTxTransaction(fromAddr, toAddr, encodedInfo, top + 1, outTx, isNeedAgentFlag, info, false);
    if (ret != 0)
    {
        ERRORLOG("CreateTxTransaction error!!");
        return;
    }
    uint64_t txUtxoHeight;
    ret = TxHelper::GetTxUtxoHeight(outTx, txUtxoHeight);

    if (ret != 0)
    {
        ERRORLOG("GetTxUtxoHeight fail!!! ret = {}", ret);
        return;
    }

    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_nodeheight(top);

    uint64_t localTxUtxoHeight;
    ret = TxHelper::GetTxUtxoHeight(outTx, localTxUtxoHeight);
    if (ret != 0)
    {
        ERRORLOG("GetTxUtxoHeight fail!!! ret = {}", ret);
        return;
    }

    txMsgInfo->set_txutxoheight(localTxUtxoHeight);

    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf *new_info = txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info);
    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);

    std::string defaultAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr();
    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultAddr)
    {

        ret = DropshippingTx(msg, outTx);
    }
    else
    {
        ret = DoHandleTx(msg, outTx);
    }
    DEBUGLOG("Transaction result, ret:{}  txHash: {}", ret, outTx.hash());
}

void GetAllPledgeAddr()
{
    DBReader reader;
    std::vector<std::string> addressVec;
    reader.GetStakeAddress(addressVec);

    auto allPledgeOutput = [addressVec](std::ostream &stream)
    {
        stream << std::endl
               << "---- Pledged address start ----" << std::endl;
        for (auto &addr : addressVec)
        {
            uint64_t pledgeamount = 0;
            SearchStake(addr, pledgeamount, global::ca::StakeType::kStakeType_Node);
            stream << addHexPrefix(addr) << " : " << pledgeamount << std::endl;
        }
        stream << "---- Number of pledged addresses:" << addressVec.size() << " ----" << std::endl
               << std::endl;
        stream << "---- Pledged address end  ----" << std::endl
               << std::endl;
    };

    if (addressVec.size() <= 10)
    {
        allPledgeOutput(std::cout);
    }
    else
    {
        std::string fileName = "all_pledge.txt";

        std::cout << "output to a file" << fileName << std::endl;

        std::ofstream fileStream;
        fileStream.open(fileName);
        if (!fileStream)
        {
            std::cout << "Open file failed!" << std::endl;
            return;
        }

        allPledgeOutput(fileStream);

        fileStream.close();
    }
}

void AutoTx()
{
    if (bIsCreateTx)
    {
        int i = 0;
        std::cout << "1. Close the transaction" << std::endl;
        std::cout << "0. Continue trading" << std::endl;
        std::cout << ">>>" << std::endl;
        std::cin >> i;
        if (i == 1)
        {
            bStopTx = true;
        }
        else if (i == 0)
        {
            return;
        }
        else
        {
            std::cout << "Error!" << std::endl;
            return;
        }
    }
    else
    {
        bStopTx = false;
        std::vector<std::string> addrs;

        MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();
        MagicSingleton<AccountManager>::GetInstance()->GetAccountList(addrs);

        double sleepTime = 0;
        std::cout << "Interval time (seconds):";
        std::cin >> sleepTime;
        sleepTime *= 1000000;
        std::thread th(TestCreateTx, addrs, (int)sleepTime);
        th.detach();
        return;
    }
}

void GetBlockinfoByTxhash()
{
    DBReader reader;

    std::cout << "Tx Hash : ";
    std::string txHash;
    std::cin >> txHash;

    std::string blockHash;
    reader.GetBlockHashByTransactionHash(txHash, blockHash);

    if (blockHash.empty())
    {
        std::cout << RED << "Error : GetBlockHashByTransactionHash failed !" << RESET << std::endl;
        return;
    }

    std::string blockStr;
    reader.GetBlockByBlockHash(blockHash, blockStr);
    CBlock block;
    block.ParseFromString(blockStr);

    std::cout << GREEN << "Block Hash : " << blockHash << RESET << std::endl;
    std::cout << GREEN << "Block height : " << block.height() << RESET << std::endl;
}

void GetTxHashByHeight(int64_t start, int64_t end, std::ofstream &filestream)
{
    int64_t localStart = start;
    int64_t localEnd = end;

    if (localEnd < localStart)
    {
        std::cout << "input invalid" << std::endl;
        return;
    }

    if (!filestream)
    {
        std::cout << "Open file failed!" << std::endl;
        return;
    }
    filestream << "TPS_INFO:" << std::endl;
    DBReader dbReader;
    uint64_t txTotal = 0;
    uint64_t blockTotal = 0;
    for (int64_t i = localEnd; i >= localStart; --i)
    {

        std::vector<std::string> tmpBlockHashs;
        if (DBStatus::DB_SUCCESS != dbReader.GetBlockHashsByBlockHeight(i, tmpBlockHashs))
        {
            ERRORLOG("(GetTxHashByHeight) GetBlockHashsByBlockHeight  Failed!!");
            return;
        }

        int txHashCount = 0;
        for (auto &blockhash : tmpBlockHashs)
        {
            std::string blockstr;
            dbReader.GetBlockByBlockHash(blockhash, blockstr);
            CBlock block;
            block.ParseFromString(blockstr);
            txHashCount += block.txs_size();
        }
        txTotal += txHashCount;
        blockTotal += tmpBlockHashs.size();
        filestream << "Height >: " << i << " Blocks >: " << tmpBlockHashs.size() << " Txs >: " << txHashCount << std::endl;
        for (auto &blockhash : tmpBlockHashs)
        {
            std::string blockstr;
            dbReader.GetBlockByBlockHash(blockhash, blockstr);
            CBlock block;
            block.ParseFromString(blockstr);
            std::string tmpBlockHash = block.hash();
            tmpBlockHash = tmpBlockHash.substr(0, 6);
            int tmpHashSize = block.txs_size();
            filestream << " BlockHash: " << tmpBlockHash << " TxHashSize: " << tmpHashSize << std::endl;
        }
    }

    filestream << "Total block sum >:" << blockTotal << std::endl;
    filestream << "Total tx sum >:" << txTotal << std::endl;
    std::vector<std::string> startHashes;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockHashsByBlockHeight(localStart, startHashes))
    {
        ERRORLOG("GetBlockHashsByBlockHeight fail  top = {} ", localStart);
        return;
    }

    // Take out the blocks at the starting height and sort them from the smallest to the largest in time
    std::vector<CBlock> startBlocks;
    for (auto &hash : startHashes)
    {
        std::string blockStr;
        dbReader.GetBlockByBlockHash(hash, blockStr);
        CBlock block;
        block.ParseFromString(blockStr);
        startBlocks.push_back(block);
    }
    std::sort(startBlocks.begin(), startBlocks.end(), [](const CBlock &x, const CBlock &y)
              { return x.time() < y.time(); });

    std::vector<std::string> endHashes;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockHashsByBlockHeight(localEnd, endHashes))
    {
        ERRORLOG("GetBlockHashsByBlockHeight fail  top = {} ", localEnd);
        return;
    }

    // Take out the blocks at the end height and sort them from small to large in time
    std::vector<CBlock> endBlocks;
    for (auto &hash : endHashes)
    {
        std::string blockStr;
        dbReader.GetBlockByBlockHash(hash, blockStr);
        CBlock block;
        block.ParseFromString(blockStr);
        endBlocks.push_back(block);
    }
    std::sort(endBlocks.begin(), endBlocks.end(), [](const CBlock &x, const CBlock &y)
              { return x.time() < y.time(); });

    float timeDiff = 0;
    if (endBlocks[endBlocks.size() - 1].time() - startBlocks[0].time() != 0)
    {
        timeDiff = float(endBlocks[endBlocks.size() - 1].time() - startBlocks[0].time()) / float(1000000);
    }
    else
    {
        timeDiff = 1;
    }
    uint64_t tx_conut = txTotal;
    float tps = float(tx_conut) / float(timeDiff);
    filestream << "TPS : " << tps << std::endl;
}

void TpsCount()
{
    int64_t start = 0;
    int64_t end = 0;
    std::cout << "Please input start height:";
    std::cin >> start;

    std::cout << "Please input end height:";
    std::cin >> end;

    if (end < start)
    {
        std::cout << "input invalid" << std::endl;
        return;
    }
    std::string StartW = std::to_string(start);
    std::string EndW = std::to_string(end);
    std::string fileName = "TPS_INFO_" + StartW + "_" + EndW + ".txt";
    std::ofstream filestream;
    filestream.open(fileName);
    GetTxHashByHeight(start, end, filestream);
}

void Get_InvestedNodeBlance()
{
    std::string addr;
    std::cout << "Please enter the address you need to inquire: " << std::endl;
    std::cin >> addr;
    if (addr.substr(0, 2) == "0x")
    {
        addr = addr.substr(2);
    }
    std::shared_ptr<GetAllInvestAddressReq> req = std::make_shared<GetAllInvestAddressReq>();
    req->set_version(global::kVersion);
    req->set_addr(addr);

    GetAllInvestAddressAck ack;
    GetAllInvestAddressReqImpl(req, ack);
    if (ack.code() != 0)
    {
        std::cout << "code: " << ack.code() << std::endl;
        ERRORLOG("Get_InvestedNodeBlance failed!");
        return;
    }

    std::cout << "------------" << ack.addr() << "------------" << std::endl;
    std::cout << "size: " << ack.list_size() << std::endl;
    for (int i = 0; i < ack.list_size(); i++)
    {
        const InvestAddressItem info = ack.list(i);
        std::cout << "addr:" << "0x" + info.addr() << "\tamount:" << info.value() << std::endl;
    }
}
void PrintDatabaseBlock()
{
    DBReader dbReader;
    std::string str = PrintBlocks(100, false);
    std::cout << str << std::endl;
}

void ThreadTest::TestCreateTx_2(const std::string &from, const std::string &to)
{
    std::cout << "from:" << addHexPrefix(from) << std::endl;
    std::cout << "to:" << addHexPrefix(to) << std::endl;

    uint64_t startTime = MagicSingleton<TimeUtil>::GetInstance()->GetUTCTimestamp();
    bool Initiate = false;
    ON_SCOPE_EXIT
    {
        if (!Initiate)
        {
            MagicSingleton<DONbenchmark>::GetInstance()->ClearTransactionInitiateMap();
        }
    };

    int intPart = 0;
    double decPart = (double)(rand() % 10) / 10000;
    std::string amountStr = std::to_string(intPart + decPart);

    std::vector<std::string> fromAddr;
    fromAddr.emplace_back(from);
    std::map<std::string, int64_t> toAddrAmount;
    uint64_t amount = (stod(amountStr) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;

    if (amount == 0)
    {
        std::cout << "amount = 0" << std::endl;
        DEBUGLOG("amount = 0");
        return;
    }

    toAddrAmount[to] = amount;

    DBReader dbReader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgentFlag;
    Vrf info;
    std::string encodedInfo = "";
    int ret = TxHelper::CreateTxTransaction(fromAddr, toAddrAmount, encodedInfo, top + 1, outTx, isNeedAgentFlag, info, false);
    if (ret != 0)
    {
        ERRORLOG("CreateTxTransaction error!!");
        return;
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_nodeheight(top);

    uint64_t localTxUtxoHeight;
    ret = TxHelper::GetTxUtxoHeight(outTx, localTxUtxoHeight);
    if (ret != 0)
    {
        ERRORLOG("GetTxUtxoHeight fail!!! ret = {}", ret);
        return;
    }

    txMsgInfo->set_txutxoheight(localTxUtxoHeight);

    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf *new_info = txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info);
    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);
    std::string defaultAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr();
    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultAddr)
    {
        MagicSingleton<BlockMonitor>::GetInstance()->addDropshippingTxVec(outTx.hash());
        ret = DropshippingTx(msg, outTx);
    }
    else
    {
        MagicSingleton<BlockMonitor>::GetInstance()->addDoHandleTxTxVec(outTx.hash());
        ret = DoHandleTx(msg, outTx);
    }
    global::ca::TxNumber++;
    DEBUGLOG("Transaction result,ret:{}  txHash:{}, TxNumber:{}", ret, outTx.hash(), global::ca::TxNumber);
    Initiate = true;
    MagicSingleton<DONbenchmark>::GetInstance()->AddTransactionInitiateMap(startTime, MagicSingleton<TimeUtil>::GetInstance()->GetUTCTimestamp());

    std::cout << "=====Transaction initiator:" << addHexPrefix(from) << std::endl;
    std::cout << "=====Transaction recipient:" << addHexPrefix(to) << std::endl;
    std::cout << "=====Transaction amount:" << amountStr << std::endl;
    std::cout << "=======================================================================" << std::endl
              << std::endl
              << std::endl;
}

std::atomic<bool> bStopTx_2 = true;
bool bIsCreateTx_2 = false;
static int i = -1;
int GetIndex(uint32_t &tranNum, std::vector<std::string> &addrs, bool flag = false)
{
    if ((i + 1) > ((tranNum * 2) - 1))
    {
        i = 0;
    }
    else
    {
        i += 1;
    }
    if (flag)
    {
        std::vector<CTransaction> vectTxs;
    }
    return i;
}
void ThreadTest::SetStopTxFlag(const bool &flag)
{
    bStopTx_2 = flag;
}

void ThreadTest::GetStopTxFlag(bool &flag)
{
    flag = bStopTx_2;
}

void ThreadTest::TestCreateTx(uint32_t tranNum, std::vector<std::string> addrs_, int timeout)
{
    DEBUGLOG("TestCreateTx start at {}", MagicSingleton<TimeUtil>::GetInstance()->GetUTCTimestamp());
    Cycliclist<std::string> addrs;

    for (auto &U : addrs_)
    {
        addrs.push_back(U);
    }

    if (addrs.isEmpty())
    {
        std::cout << "account list is empty" << std::endl;
        return;
    }
    auto iter = addrs.begin();
    while (bStopTx_2 == false)
    {
        MagicSingleton<DONbenchmark>::GetInstance()->SetTransactionInitiateBatchSize(tranNum);
        for (int i = 0; i < tranNum; i++)
        {

            std::string from = iter->data;
            iter++;
            std::string to = iter->data;
            std::thread th(ThreadTest::TestCreateTx_2, from, to);
            th.detach();
        }
        sleep(timeout);
    }
}

void CreateMultiThreadAutomaticTransaction()
{
    std::cout << "1. tx " << std::endl;
    std::cout << "2. close" << std::endl;

    int check = 0;
    std::cout << "chose:";
    std::cin >> check;

    if (check == 1)
    {
        if (bStopTx_2 == true)
        {

            bStopTx_2 = false;
        }
        else
        {

            std::cout << "has run" << std::endl;
            return;
        }
    }
    else if (check == 2)
    {
        bStopTx_2 = true;
        return;
    }
    else
    {
        std::cout << " invalui" << std::endl;
        return;
    }
    if (bStopTx_2)
    {
        return;
    }

    int TxNum = 0;
    int timeout = 0;

    std::cout << "Interval time (seconds):";
    std::cin >> timeout;

    std::cout << "Interval frequency :";

    std::cin >> TxNum;
    std::vector<std::string> addrs;

    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(addrs);

    std::thread th(ThreadTest::TestCreateTx, TxNum, addrs, timeout);
    th.detach();
}

void TestCreateStake_2(const std::string &from)
{
    TxHelper::pledgeType pledgeType = TxHelper::pledgeType::kPledgeType_Node;
    uint64_t stakeAmount = 10 * global::ca::kDecimalNum;

    // DBReader data_reader;
    // uint64_t top = 0;
    // if (DBStatus::DB_SUCCESS != data_reader.GetBlockTop(top))
    // {
    //     ERRORLOG("db get top failed!!");
    //     return;
    // }

    uint64_t top = 0;
    int retNum = discoverTransactionHeight(top);
    if(retNum != 0){
        ERRORLOG("discoverTransactionHeight error {}", retNum);
        return;
    }

    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgentFlag;
    Vrf info;
    std::vector<TxHelper::Utxo> outVin;
    std::string encodedInfo = "";
    if (TxHelper::CreateStakeTransaction(from, stakeAmount, encodedInfo, top + 1, pledgeType, outTx, outVin, isNeedAgentFlag, info, global::ca::KMaxCommissionRate) != 0)
    {
        return;
    }
    std::cout << " from: " << addHexPrefix(from) << " amout: " << stakeAmount << std::endl;
    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_nodeheight(top);

    uint64_t localTxUtxoHeight;
    auto ret = TxHelper::GetTxUtxoHeight(outTx, localTxUtxoHeight);
    if (ret != 0)
    {
        ERRORLOG("GetTxUtxoHeight fail!!! ret = {}", ret);
        return;
    }

    txMsgInfo->set_txutxoheight(localTxUtxoHeight);

    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf *newInfo = txMsg.mutable_vrfinfo();
        newInfo->CopyFrom(info);
    }
    auto msg = std::make_shared<TxMsgReq>(txMsg);
    std::string defaultAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr();
    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultAddr)
    {
        ret = DropshippingTx(msg, outTx);
    }
    else
    {
        ret = DoHandleTx(msg, outTx);
    }

    if (ret != 0)
    {
        ret -= 100;
    }
    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void CreateMultiThreadAutomaticStakeTransaction()
{
    std::vector<std::string> addrs;

    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(addrs);

    std::vector<std::string>::iterator it = std::find(addrs.begin(), addrs.end(), MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr());
    if (it != addrs.end())
    {
        addrs.erase(it);
    }

    for (int i = 0; i < addrs.size(); ++i)
    {
        std::thread th(TestCreateStake_2, addrs[i]);
        th.detach();
    }
}

void TestCreateInvestment(const std::string &strFromAddr, const std::string &strToAddr, const std::string &amountStr)
{
    TxHelper::InvestType investType = TxHelper::InvestType::kInvestType_NetLicence;
    uint64_t invest_amount = std::stod(amountStr) * global::ca::kDecimalNum;

    // DBReader dbReader;
    // uint64_t top = 0;
    // if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(top))
    // {
    //     ERRORLOG("db get top failed!!");
    //     return;
    // }
    uint64_t top = 0;
    int retNum = discoverTransactionHeight(top);
    if(retNum != 0){
        ERRORLOG("discoverTransactionHeight error {}", retNum);
        return;
    }

    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgentFlag;
    Vrf info;
    std::string encodedInfo;
    int ret = TxHelper::CreateInvestTransaction(strFromAddr, strToAddr, invest_amount, encodedInfo, top + 1, investType, outTx, outVin, isNeedAgentFlag, info);
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
    txMsgInfo->set_nodeheight(top);

    uint64_t localTxUtxoHeight;
    ret = TxHelper::GetTxUtxoHeight(outTx, localTxUtxoHeight);
    if (ret != 0)
    {
        ERRORLOG("GetTxUtxoHeight fail!!! ret = {}", ret);
        return;
    }

    txMsgInfo->set_txutxoheight(localTxUtxoHeight);

    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf *newInfo = txMsg.mutable_vrfinfo();
        newInfo->CopyFrom(info);
    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);

    std::string defaultAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr();

    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultAddr)
    {

        ret = DropshippingTx(msg, outTx);
    }
    else
    {
        ret = DoHandleTx(msg, outTx);
    }

    std::cout << "=====Transaction initiator:" << addHexPrefix(strFromAddr) << std::endl;
    std::cout << "=====Transaction recipient:" << addHexPrefix(strToAddr) << std::endl;
    std::cout << "=====Transaction amount:" << amountStr << std::endl;
    std::cout << "=======================================================================" << std::endl
              << std::endl
              << std::endl
              << std::endl;
}

void AutoInvestment()
{

    std::cout << "input aummot: ";
    std::string aummot;
    std::cin >> aummot;
    std::cout << "to addr: ";
    std::string toAddr;
    std::cin >> toAddr;
    std::string to = remove0xPrefix(toAddr);

    std::vector<std::string> addrs;

    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(addrs);

    std::vector<std::string>::iterator it = std::find(addrs.begin(), addrs.end(), MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr());
    if (it != addrs.end())
    {
        addrs.erase(it);
    }

    int i = 0;
    while (i < addrs.size())
    {
        std::string from;
        // std::string to;
        from = addrs[i];
        if ((i + 1) >= addrs.size())
        {
            i = 0;
        }
        else
        {
            i += 1;
        }

        // to = addrs[i];

        if (from != "")
        {
            if (!MagicSingleton<AccountManager>::GetInstance()->IsExist(from))
            {
                DEBUGLOG("Illegal account.");
                return;
            }
        }
        else
        {
            DEBUGLOG("Illegal account. from addr is null !");
            return;
        }
        std::thread th(TestCreateInvestment, from, to, aummot);
        th.detach();
        if (i == 0)
        {
            return;
        }
        sleep(1);
    }
}

void PrintVerifyNode()
{
    std::vector<Node> nodelist = MagicSingleton<PeerNode>::GetInstance()->GetNodelist();

    std::vector<Node> resultNode;
    for (const auto &node : nodelist)
    {
        int ret = CheckVerifyNodeQualification(node.address);
        if (ret == 0)
        {
            resultNode.push_back(node);
        }
    }

    std::string fileName = "verify_node.txt";
    std::ofstream filestream;
    filestream.open(fileName);
    if (!filestream)
    {
        std::cout << "Open file failed!" << std::endl;
        return;
    }

    filestream << "------------------------------------------------------------------------------------------------------------" << std::endl;
    for (auto &i : resultNode)
    {
        filestream
            << "  addr(" << addHexPrefix(i.address) << ")"
            << std::endl;
    }
    filestream << "------------------------------------------------------------------------------------------------------------" << std::endl;
    filestream << "PeerNode size is: " << resultNode.size() << std::endl;
}

void GetRewardAmount()
{
    int64_t startHeight = 0;
    int64_t endHeight = 0;
    std::string addr;
    std::cout << "Please input start height:";
    std::cin >> startHeight;
    std::cout << "Please input end height:";
    std::cin >> endHeight;
    if (endHeight < startHeight)
    {
        std::cout << "input invalid" << std::endl;
        return;
    }
    std::cout << "Please input the address:";
    std::cin >> addr;
    if (addr.substr(0, 2) == "0x")
    {
        addr = addr.substr(2);
    }

    if (!isValidAddress(addr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }
    DBReader dbReader;

    uint64_t txTotall = 0;
    uint64_t claimAmount = 0;
    for (int64_t i = startHeight; i <= endHeight; ++i)
    {
        std::vector<std::string> block_hashs;
        if (DBStatus::DB_SUCCESS != dbReader.GetBlockHashsByBlockHeight(i, block_hashs))
        {
            ERRORLOG("(GetTxHashByHeight) GETBlockHashsByBlockHeight  Failed!!");
            return;
        }
        std::vector<CBlock> blocks;
        for (auto &blockhash : block_hashs)
        {
            std::string blockstr;
            if (DBStatus::DB_SUCCESS != dbReader.GetBlockByBlockHash(blockhash, blockstr))
            {
                ERRORLOG("(GetBlockByBlockHash) GetBlockByBlockHash Failed!!");
                return;
            }
            CBlock block;
            block.ParseFromString(blockstr);
            blocks.push_back(block);
        }
        std::sort(blocks.begin(), blocks.end(), [](CBlock &a, CBlock &b)
                  { return a.time() < b.time(); });

        for (auto &block : blocks)
        {
            time_t s = (time_t)(block.time() / 1000000);
            struct tm *gmDate;
            gmDate = localtime(&s);
            std::cout << gmDate->tm_year + 1900 << "-" << gmDate->tm_mon + 1 << "-" << gmDate->tm_mday << " " << gmDate->tm_hour << ":" << gmDate->tm_min << ":" << gmDate->tm_sec << "(" << time << ")" << std::endl;
            for (auto tx : block.txs())
            {
                if ((global::ca::TxType)tx.txtype() == global::ca::TxType::kTxTypeBonus)
                {
                    std::map<std::string, uint64_t> kmap;
                    try
                    {
                        nlohmann::json dataJson = nlohmann::json::parse(tx.data());
                        nlohmann::json txInfo = dataJson["TxInfo"].get<nlohmann::json>();
                        claimAmount = txInfo["BonusAmount"].get<uint64_t>();
                    }
                    catch (...)
                    {
                        ERRORLOG(RED "JSON failed to parse data field!" RESET);
                    }
                    for (auto &owner : tx.utxo().owner())
                    {
                        if (owner != addr)
                        {
                            for (auto &vout : tx.utxo().vout())
                            {
                                if (vout.addr() != owner && vout.addr() != "VirtualBurnGas")
                                {
                                    kmap[vout.addr()] = vout.value();
                                    txTotall += vout.value();
                                }
                            }
                        }
                    }
                    for (auto it = kmap.begin(); it != kmap.end(); ++it)
                    {
                        std::cout << "reward addr:" << addHexPrefix(it->first) << "reward amount" << it->second << std::endl;
                    }
                    if (claimAmount != 0)
                    {
                        std::cout << "self node reward addr:" << addHexPrefix(addr) << "self node reward amount:" << claimAmount - txTotall;
                        std::cout << "total reward amount" << claimAmount;
                    }
                }
            }
        }
    }
}

void TestsHandleInvest()
{
    std::cout << std::endl
              << std::endl;
    std::cout << "AddrList:" << std::endl;
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    Account account;
    MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(account);
    std::string strFromAddr = account.GetAddr();

    std::cout << "Please enter your addr:" << std::endl;
    std::cout << addHexPrefix(strFromAddr) << std::endl;
    if (!isValidAddress(strFromAddr))
    {
        ERRORLOG("Input addr error!");
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    std::cout << "Please enter the addr you want to delegate to:" << std::endl;
    std::cout << addHexPrefix(strFromAddr) << std::endl;
    if (!isValidAddress(strFromAddr))
    {
        ERRORLOG("Input addr error!");
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    std::string strInvestFee = "500000";
    std::cout << "Please enter the amount to delegate:" << std::endl;
    std::cout << strInvestFee << std::endl;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(strInvestFee, pattern))
    {
        ERRORLOG("Input invest fee error!");
        std::cout << "Input delegate fee error!" << std::endl;
        return;
    }

    TxHelper::InvestType investType = TxHelper::InvestType::kInvestType_NetLicence;
    uint64_t investAmount = std::stod(strInvestFee) * global::ca::kDecimalNum;

    // DBReader dbReader;
    // uint64_t top = 0;
    // if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(top))
    // {
    //     ERRORLOG("db get top failed!!");
    //     return;
    // }
    uint64_t top = 0;
    int retNum = discoverTransactionHeight(top);
    if(retNum != 0){
        ERRORLOG("discoverTransactionHeight error {}", retNum);
        return;
    }

    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgentFlag;
    Vrf info_;
    std::string encodedInfo;
    int ret = TxHelper::CreateInvestTransaction(strFromAddr, strFromAddr, investAmount, encodedInfo, top + 1, investType, outTx, outVin, isNeedAgentFlag, info_);
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
    txMsgInfo->set_nodeheight(top);

    uint64_t localTxUtxoHeight;
    ret = TxHelper::GetTxUtxoHeight(outTx, localTxUtxoHeight);
    if (ret != 0)
    {
        ERRORLOG("GetTxUtxoHeight fail!!! ret = {}", ret);
        return;
    }

    txMsgInfo->set_txutxoheight(localTxUtxoHeight);

    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf *new_info = txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);
    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);
    std::string defaultAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr();
    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultAddr)
    {
        ret = DropshippingTx(msg, outTx);
    }
    else
    {
        ret = DoHandleTx(msg, outTx);
    }
    if (ret != 0)
    {
        ret -= 100;
    }

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void TestHandleInvestMoreToOne(std::string strFromAddr, std::string strToAddr, std::string strInvestFee)
{

    TxHelper::InvestType investType = TxHelper::InvestType::kInvestType_NetLicence;
    uint64_t investAmount = std::stod(strInvestFee) * global::ca::kDecimalNum;

    // DBReader dbReader;
    // uint64_t top = 0;
    // if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(top))
    // {
    //     ERRORLOG("db get top failed!!");
    //     return;
    // }
    uint64_t top = 0;
    int retNum = discoverTransactionHeight(top);
    if(retNum != 0){
        ERRORLOG("discoverTransactionHeight error {}", retNum);
        return;
    }

    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgentFlag;
    Vrf info;
    std::string encodedInfo;
    int ret = TxHelper::CreateInvestTransaction(strFromAddr, strToAddr, investAmount, encodedInfo, top + 1, investType, outTx, outVin, isNeedAgentFlag, info);
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
    txMsgInfo->set_nodeheight(top);

    uint64_t localTxUtxoHeight;
    ret = TxHelper::GetTxUtxoHeight(outTx, localTxUtxoHeight);
    if (ret != 0)
    {
        ERRORLOG("GetTxUtxoHeight fail!!! ret = {}", ret);
        return;
    }

    txMsgInfo->set_txutxoheight(localTxUtxoHeight);

    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf *newInfo = txMsg.mutable_vrfinfo();
        newInfo->CopyFrom(info);
    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);
    std::string defaultAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr();
    if (isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultAddr)
    {
        ret = DropshippingTx(msg, outTx);
    }
    else
    {
        ret = DoHandleTx(msg, outTx);
    }
    if (ret != 0)
    {
        ret -= 100;
    }

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void TestManToOneDelegate()
{
    uint32_t num = 0;
    std::cout << "plase inter delegate num: " << std::endl;
    std::cin >> num;

    std::vector<std::string> _list;
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(_list);

    if (num > _list.size())
    {
        std::cout << "error: Account num < " << num << std::endl;
        return;
    }

    std::string strToAddr;
    std::cout << "Please enter the addr you want to delegate to:" << std::endl;
    std::cin >> strToAddr;
    if (strToAddr.substr(0, 2) == "0x")
    {
        strToAddr = strToAddr.substr(2);
    }
    if (!isValidAddress(strToAddr))
    {
        ERRORLOG("Input addr error!");
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    std::string strInvestFee;
    std::cout << "Please enter the amount to delegate:" << std::endl;
    std::cin >> strInvestFee;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(strInvestFee, pattern))
    {
        ERRORLOG("Input invest fee error!");
        std::cout << "Input delegate fee error!" << std::endl;
        return;
    }

    DBReadWriter dbReader;
    std::set<std::string> pledgeAddr;

    std::vector<std::string> stakeAddr;
    auto status = dbReader.GetStakeAddress(stakeAddr);
    if (DBStatus::DB_SUCCESS != status && DBStatus::DB_NOT_FOUND != status)
    {
        std::cout << "GetStakeAddress error" << std::endl;
        return;
    }

    for (const auto &addr : stakeAddr)
    {
        if(CheckVerifyNodeQualification(addr) == 0)
		{
            pledgeAddr.insert(addr);
		}
    }

    int successNum = 0;
    int testNum = 0;
    for (int i = 0; successNum != num; ++i)
    {
        std::string fromAddr;
        try
        {
            fromAddr = _list.at(i);
        }
        catch (const std::exception &)
        {
            break;
        }

        if (!isValidAddress(fromAddr))
        {
            ERRORLOG("fromAddr addr error!");
            std::cout << "fromAddr addr error! : " << addHexPrefix(fromAddr) << std::endl;
            continue;
        }

        auto it = pledgeAddr.find(fromAddr);
        if (it != pledgeAddr.end())
        {
            ++testNum;
            continue;
        }

        TestHandleInvestMoreToOne(fromAddr, strToAddr, strInvestFee);
        ++successNum;
    }

    std::cout << "testNum: " << testNum << std::endl;
}
void OpenLog()
{
    Config::Log log = {};
    MagicSingleton<Config>::GetInstance()->GetLog(log);
    MagicSingleton<Log>::GetInstance()->LogInit(log.path, log.console, "debug");
}

void CloseLog()
{

    Config::Log log = {};
    MagicSingleton<Config>::GetInstance()->GetLog(log);
    MagicSingleton<Log>::GetInstance()->LogDeinit();
    std::string tmpString = "logs";
    if (std::filesystem::remove_all(tmpString))
    {
        std::cout << "File deleted successfully" << std::endl;
    }
    else
    {
        std::cout << "Failed to delete the file" << std::endl;
    }
}

void TestSign()
{
    Account account(true);
    std::string serVinHash = Getsha256hash("1231231asdfasdf");
    std::string signature;
    std::string pub;

    if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(account) == -1)
    {
        std::cout << "get account error";
    }
    if (account.Sign(serVinHash, signature) == true)
    {
        std::cout << "tx sign true !" << std::endl;
    }
    if (account.Verify(serVinHash, signature) == true)
    {
        std::cout << "tx verify true" << std::endl;
    }
}

void SeekLog()
{
    while (true)
    {
        std::cout << std::endl;
        std::cout << "1.Get the log by time" << std::endl;
        std::cout << "2.Get the log by the last few lines" << std::endl;
        std::cout << "0.Exit" << std::endl;

        std::string strKey;
        std::cout << "please input your choice:";
        std::cin >> strKey;

        std::regex pattern("[0-2]");
        if (!std::regex_match(strKey, pattern))
        {
            std::cout << "Input invalid." << std::endl;
            return;
        }
        int key = std::stoi(strKey);
        switch (key)
        {
        case 0:
            return;
        case 1:
            SeekLogByTime();
            break;
        case 2:
            SeekLogByLines();
            break;
        default:
            std::cout << "Invalid input." << std::endl;
            continue;
        }
        sleep(1);
    }
}

bool IsValidTimeFormat(const std::string &time) {
  
    std::regex timePattern(R"(\d{4}-\d{2}-\d{2}-\d{2}:\d{2}:\d{2})");
    return std::regex_match(time, timePattern);
}

void SeekLogByTime()
{
    std::string startTime, endTime, fileName, nodeId,startTime_t,endTime_t;
    int lines = 0;

    std::cout << "Please enter the startTime minutes(UTC format) (eg: from 2025-01-05-00:00:00 to 2025-01-05-23:59:59)" << std::endl;
    std::cin >> startTime;
    if (IsValidTimeFormat(startTime)) {
        startTime_t = ReplaceThirdDashWithSpace(startTime);
    } 
    else {
        std::cerr << "Error: Invalid start time format. Please try again." << std::endl;
        return;
    }
    

    std::cout << "Please enter the endTime minutes(UTC format) (eg: from 2025-01-05-00:00:00 to 2025-01-05-23:59:59)" << std::endl;
    std::cin >> endTime;
    if (IsValidTimeFormat(endTime))
    {
        endTime_t = ReplaceThirdDashWithSpace(endTime);
        auto endTimeStamp = TimePointToTimeStamp(endTime_t);
        auto startTimeStamp = TimePointToTimeStamp(startTime_t);
        if (startTimeStamp >= endTimeStamp)
        {
            std::cerr << "Error : end time less or equal to start time ";
            return;
        }
    }
    else 
    {
        std::cerr << "Error: Invalid endTime time format. Please try again." << std::endl;
        return;
    }

    std::cout
        << "Please enter the remote log compeletely name: (eg:don_2025-01-08.log)" << std::endl;
    std::cin >> fileName;
    if (fileName.length() != 18)
    {
        std::cerr << "Invalid fileName. Please try again." << std::endl;
        return;
    }
    std::cout << "Please enter the node account:" << std::endl;
    std::cin >> nodeId;

    if (nodeId.substr(0, 2) == "0x") 
    {
        nodeId = nodeId.substr(2);
    }
    if(nodeId.length()!=40)
    {
        std::cerr << "Invalid nodeId format. Please try again." << std::endl;
        return;
    }
    std::string msgId;
    size_t sendNum = 1;
    if (!GLOBALDATAMGRPTR.CreateWait(80, sendNum, msgId))
    {
        ERRORLOG("Waiting timeout");
    }
    std::string selfNodeId = MagicSingleton<PeerNode>::GetInstance()->GetSelfId();

    GetLogReq req;
    req.set_address(selfNodeId);
    req.set_filename(fileName);
    req.set_starttime(startTime_t);
    req.set_endtime(endTime_t);
    req.set_lines(lines);
    req.set_msg_id(msgId);
    if (!GLOBALDATAMGRPTR.AddResNode(msgId, nodeId))
    {
        ERRORLOG("AddResNode fail");
        std::cout << "AddResNode;";
        return;
    }
    NetSendMessage<GetLogReq>(nodeId, req, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);

    std::vector<std::string> retDatas;
    if (!GLOBALDATAMGRPTR.WaitData(msgId, retDatas))
    {
        ERRORLOG("Waiting data timeout");
        std::cout << "Wait too much time;";
        return;
    }

    GetLogAck ack;
    std::string log = "";
    {
        auto iter = retDatas.begin();
        {
            ack.Clear();
            if (!ack.ParseFromString(*iter))
            {
                ERRORLOG("ParseFromString Fail");
            }
            if (iter == retDatas.begin())
            {
                log = std::string(ack.data().begin(), ack.data().end());
            }
        }
    }
    if (log == "")
    {
        ERRORLOG("blockRaw is empty!");
        
    }

    std::string date_part = startTime.substr(0, 10); 
    std::string startTimePart = startTime_t.substr(11, 10);
    std::string endTimePart = endTime_t.substr(11, 10);
    
    // Store the log in the remotelog file
    std::string outFilename = nodeId + "_" + date_part  + "_" + startTimePart+ "-" + endTimePart+ "_" + fileName;
    std::ofstream outFile(outFilename);
    if (outFile.is_open())
    {
        outFile << log;  
        outFile.close();
    }
    else
    {
        ERRORLOG("Failed to open remotelog.txt for writing!");
    }

    ERRORLOG("Log has been written to remotelog.txt.");
}


void SeekLogByLines()
{
    std::string fileName, nodeId;
    int lines;
    std::cout << "Please enter the line number:" << std::endl;
    std::cin >> lines;
    std::cout << "Please enter the remote log compeletely name: (eg:don_2025-01-08.log)" << std::endl;
    std::cin >> fileName;
    std::cout << "Enter the node account to be obtained:" << std::endl;
    std::cin >> nodeId;
    if (nodeId.substr(0, 2) == "0x") 
    {
        nodeId = nodeId.substr(2);
    }
    std::string msgId;
    size_t sendNum = 1;
    if (!GLOBALDATAMGRPTR.CreateWait(80, sendNum, msgId))
    {
        ERRORLOG("Waiting timeout");
    }
    std::string selfNodeId = MagicSingleton<PeerNode>::GetInstance()->GetSelfId();

    GetLogReq req;
    req.set_address(selfNodeId);
    req.set_filename(fileName);
    req.set_lines(lines);
    req.set_msg_id(msgId);
    if (!GLOBALDATAMGRPTR.AddResNode(msgId, nodeId))
    {
        ERRORLOG("AddResNode fail");
        std::cout << "Add Res Node Fail" << std::endl;
        return;
        }
    NetSendMessage<GetLogReq>(nodeId, req, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);

    std::vector<std::string> retDatas;
    if (!GLOBALDATAMGRPTR.WaitData(msgId, retDatas))
    {
        ERRORLOG("Waiting data timeout");
        std::cout << "Wait too much time;";
        return;
    }
    GetLogAck ack;
    std::string log = "";
    {
        auto iter = retDatas.begin();
        {
            ack.Clear();
            if (!ack.ParseFromString(*iter))
            {
                ERRORLOG("ParseFromString Fail");
            }
            if (iter == retDatas.begin())
            {
                log = std::string(ack.data().begin(), ack.data().end());
            }
        }
    }

    if (log == "")
    {
        ERRORLOG("blockRaw is empty!");
    }

    // Store the log in the remotelog file
    std::string outFileName = nodeId + "_" + std::to_string(lines) + "_" + fileName;
    std::ofstream outFile(outFileName);
    if (outFile.is_open())
    {
        outFile << log;  
        outFile.close(); 
    }
    else
    {
        ERRORLOG("Failed to open remotelog.txt for writing!");
    }

    ERRORLOG("Log has been written to remotelog.txt.");
}

//test get log
int HandleLogReq(const std::shared_ptr<GetLogReq> &msg, const MsgData &msgdata)
{
    if(!PeerNode::PeerNodeVerifyNodeId(msgdata.fd, msg->address()))
    {
        return -1;
    }
    SendLogAck(msg->starttime(), msg->endtime(), msg->lines(),msg->address(),msg->msg_id(),msg->filename());
    return 0;
}


int HandleLogAck(const std::shared_ptr<GetLogAck> &msg, const MsgData &msgdata)
{
    if(!PeerNode::PeerNodeVerifyNodeId(msgdata.fd, msg->address()))
    {
        return -1;
    }

    GLOBALDATAMGRPTR.AddWaitData(msg->msg_id(), msg->address(), msg->SerializeAsString());
    return 0;
}

/**
 * @brief The log confirmation message was sent
 *
 * This function is used to send a log confirmation message with a start time, end time, and message ID.
 * First log the debug, then read the local file data.
 * Then build the GetLogAck object and set the address and data.
 * Finally, a compressed and unencrypted high-priority message is sent over the network.
 *
 * @param startTime 
 * @param endTime 
 * @param msgId 
 * @return 
 */
int SendLogAck(const std::string &startTime, const std::string &endTime, const int &lines,const std::string &addr, const std::string &msgId, const std::string &fileName)
{
    DEBUGLOG("start time {},end time {}lines{}", startTime, endTime,lines);
    std::string data;
    std::string fileReadName = "logs/"+fileName;
    
    if (lines == 0)
    {
        data = FileSeekFilterLogs(fileReadName.c_str(), startTime, endTime);
    }
    else
    {
        data =  ReadLastNLines(fileReadName,lines);
    }

    int max_size = 60 * 1024 * 1024;
    if (data.size() > max_size) { // 80MB
        data.resize(max_size);     // Replace it with a prompt message
    }
    data = CleanInvalidUtf8(data);
    GetLogAck ack;
    ack.set_address(MagicSingleton<PeerNode>::GetInstance()->GetSelfId());
    ack.set_data(data);
    ack.set_msg_id(msgId);

    NetSendMessage<GetLogAck>(addr, ack, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
    return 0;
}

std::string ReadLastNLines(const std::string &inputFile, size_t n) {
    std::string command = "tail -n " + std::to_string(n) + " " + inputFile+" 2>/dev/null";;

    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    
    if (!pipe) {
        return "Read failed: Unable to execute tail command";
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    if (ferror(pipe.get()))
    {
        return "Read failed: Error reading pipe data";
    }

    return result;
}

std::string ReplaceThirdDashWithSpace(const std::string &input)
{
    std::string result = input;
    size_t dash_count = 0; // Count the number of short horizontal lines

    for (size_t i = 0; i < result.length(); ++i)
    {
        if (result[i] == '-')
        {
            dash_count++;
            if (dash_count == 3)
            {                    // When the count reaches 3, replace the current short horizontal line
                result[i] = ' '; // Replace with a space
                break;           // Exit the loop after replacement
            }
        }
    }

    return result; // Returns the processed string
}

bool IsValidUtf8(const std::string &data) {
    int expected_bytes = 0;
    for (unsigned char c : data) {
        if (expected_bytes == 0) {
            if ((c & 0x80) == 0) {
                continue; // 1-byte character
            } else if ((c & 0xE0) == 0xC0) {
                expected_bytes = 1; // 2-byte character
            } else if ((c & 0xF0) == 0xE0) {
                expected_bytes = 2; // 3-byte character
            } else if ((c & 0xF8) == 0xF0) {
                expected_bytes = 3; // 4-byte character
            } else {
                return false; // Invalid lead byte
            }
        } else {
            if ((c & 0xC0) != 0x80) {
                return false; // Invalid continuation byte
            }
            expected_bytes--;
        }
    }
    return expected_bytes == 0; // Must be zero at the end
}

std::string CleanInvalidUtf8(const std::string &input)
{
    std::string output;
    for (size_t i = 0; i < input.size();)
    {
        unsigned char c = input[i];
        if ((c & 0x80) == 0)
        { // 1-byte character
            output += c;
            i++;
        }
        else if ((c & 0xE0) == 0xC0 && i + 1 < input.size() &&
                 (input[i + 1] & 0xC0) == 0x80)
        { // 2-byte character
            output += input.substr(i, 2);
            i += 2;
        }
        else if ((c & 0xF0) == 0xE0 && i + 2 < input.size() &&
                 (input[i + 1] & 0xC0) == 0x80 &&
                 (input[i + 2] & 0xC0) == 0x80)
        { // 3-byte character
            output += input.substr(i, 3);
            i += 3;
        }
        else if ((c & 0xF8) == 0xF0 && i + 3 < input.size() &&
                 (input[i + 1] & 0xC0) == 0x80 &&
                 (input[i + 2] & 0xC0) == 0x80 &&
                 (input[i + 3] & 0xC0) == 0x80)
        { // 4-byte character
            output += input.substr(i, 4);
            i += 4;
        }
        else
        {
            i++; // Skip invalid byte
        }
    }
    return output;
}

int HandleRpcBlockReq(const std::shared_ptr<GetRpcBlockReq> &msg, const MsgData &msgdata)
{
    if (!PeerNode::PeerNodeVerifyNodeId(msgdata.fd, msg->address()))
    {
        return -1;
    }
    SendRpcBlockAck(msg->address(), msg->num(), msg->height(), msg->hash(), msg->prehashflag(),msg->msg_id());
    return 0;
}

int HandleRpcBlockAck(const std::shared_ptr<GetRpcBlockAck> &msg, const MsgData &msgdata)
{
    if (!PeerNode::PeerNodeVerifyNodeId(msgdata.fd, msg->address()))
    {
        return -1;
    }

    GLOBALDATAMGRPTR.AddWaitData(msg->msg_id(), msg->address(), msg->SerializeAsString());
    return 0;
}

int HandleRpcSySInfoReq(const std::shared_ptr<GetRpcSySInfoReq> &msg, const MsgData &msgdata)
{
    if (!PeerNode::PeerNodeVerifyNodeId(msgdata.fd, msg->address()))
    {
        return -1;
    }
    SendRpcSySInfoAck(msg->address(), msg->msg_id());
    return 0;
}

int HandleRpcSySInfoAck(const std::shared_ptr<GetRpcSySInfoAck> &msg, const MsgData &msgdata)
{
    if (!PeerNode::PeerNodeVerifyNodeId(msgdata.fd, msg->address()))
    {
        return -1;
    }

    GLOBALDATAMGRPTR.AddWaitData(msg->msg_id(), msg->address(), msg->SerializeAsString());
    return 0;
}

int HandleRpcPubReq(const std::shared_ptr<GetRpcPubReq> &msg, const MsgData &msgdata)
{
    if (!PeerNode::PeerNodeVerifyNodeId(msgdata.fd, msg->address()))
    {
        return -1;
    }
    SendRpcPubAck(msg->address(), msg->msg_id());
    return 0;
}

int HandleRpcPubAck(const std::shared_ptr<GetRpcPubAck> &msg, const MsgData &msgdata)
{
    if (!PeerNode::PeerNodeVerifyNodeId(msgdata.fd, msg->address()))
    {
        return -1;
    }

    GLOBALDATAMGRPTR.AddWaitData(msg->msg_id(), msg->address(), msg->SerializeAsString());
    return 0;
}
int HandleRpcBlockInfoReq(const std::shared_ptr<GetRpcBlockInfoReq> &msg, const MsgData &msgdata)
{
    if (!PeerNode::PeerNodeVerifyNodeId(msgdata.fd, msg->address()))
    {
        return -1;
    }
    SendRpcBlockInfoAck(msg->address(), msg->num() ,msg->top(),msg->msg_id());
    return 0;
}

int HandleRpcBlockInfoAck(const std::shared_ptr<GetRpcBlockInfoAck> &msg, const MsgData &msgdata)
{
    if (!PeerNode::PeerNodeVerifyNodeId(msgdata.fd, msg->address()))
    {
        return -1;
    }

    GLOBALDATAMGRPTR.AddWaitData(msg->msg_id(), msg->address(), msg->SerializeAsString());
    return 0;
}

int SendRpcBlockAck(const std::string &addr, int num, int height, const bool &hash,const bool &prehashflag, const std::string &msgId)
{
    DEBUGLOG("num {},height {},hash {},prehashflag{}", num, height, hash,prehashflag);


    std::string data;

    if (hash)
    {
        data = PrintBlocksHash(num, prehashflag);
        GetRpcBlockAck ack;
        ack.set_address(MagicSingleton<PeerNode>::GetInstance()->GetSelfId());
        ack.set_data(data);
        ack.set_msg_id(msgId);

        NetSendMessage<GetRpcBlockAck>(addr, ack, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
        return 0;
    }

    if (height == 0)
        data = PrintContractBlocks(num, prehashflag);
    else
        data = PrintRangeContractBlocks(height, num, prehashflag);

    GetRpcBlockAck ack;
    ack.set_address(MagicSingleton<PeerNode>::GetInstance()->GetSelfId());
    ack.set_data(data);
    ack.set_msg_id(msgId);

    NetSendMessage<GetRpcBlockAck>(addr, ack, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
    return 0;

}
int SendRpcSySInfoAck(const std::string &addr, const std::string &msgId){


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

    GetRpcSySInfoAck ack;
    ack.set_address(MagicSingleton<PeerNode>::GetInstance()->GetSelfId());
    ack.set_data(outPut);
    ack.set_msg_id(msgId);

    NetSendMessage<GetRpcSySInfoAck>(addr, ack, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
    return 0;
}
int SendRpcPubAck(const std::string &addr, const std::string &msgId){
    std::ostringstream oss;
    const int MaxInformationSize = 256;
    char buff[MaxInformationSize] = {};
    FILE *f = fopen("/proc/self/cmdline", "r");
    if (f == NULL)
    {
        DEBUGLOG("Failed to obtain main information ");
    }
    else
    {
        char readc;
        int i = 0;
        while (((readc = fgetc(f)) != EOF))
        {
            if (readc == '\0')
            {
                buff[i++] = ' ';
            }
            else
            {
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
    oss << "\n"
        << std::endl;

    double total = .0f;
    uint64_t n64Count = 0;
    oss << "------------------------------------------" << std::endl;
    for (auto &item : global::g_reqCntMap)
    {
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
        oss << "0x" + i + ":" + std::to_string(amount) << std::endl;
    }

    oss << std::endl
        << std::endl;

    std::vector<Node> pubNodeList =
        MagicSingleton<PeerNode>::GetInstance()->GetNodelist();
    oss << "Public PeerNode size is: " << pubNodeList.size() << std::endl;
    oss << MagicSingleton<PeerNode>::GetInstance()->NodelistInfo(
        pubNodeList); //   Convert all public network node data to string for
                      //   saving
    std::string data = oss.str();
    GetRpcPubAck ack;
    ack.set_address(MagicSingleton<PeerNode>::GetInstance()->GetSelfId());
    ack.set_data(data);
    ack.set_msg_id(msgId);

    NetSendMessage<GetRpcPubAck>(addr, ack, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
    return 0;
}
int SendRpcBlockInfoAck(const std::string &addr, int num, int top, const std::string &msgId)
{
    nlohmann::json block;
    nlohmann::json blocks;



    num = num > 500 ? 500 : num;

    if (top < 0 || num < 0)
    {
        ERRORLOG("_ApiGetBlock top < 0||num <= 0");
        return -1;
    }

    DBReader dbReader;
    uint64_t myTop = 0;
    dbReader.GetBlockTop(myTop);
    if (top > (int)myTop)
    {
        ERRORLOG("_ApiGetBlock begin > myTop");
        return -2;
    }
    int k = 0;
    uint64_t countNum = top + num;
    if (countNum > myTop)
    {
        countNum = myTop;
    }
    for (auto i = top; i <= countNum; i++)
    {
        std::vector<std::string> blockHashs;

        if (dbReader.GetBlockHashsByBlockHeight(i, blockHashs) !=
            DBStatus::DB_SUCCESS)
        {
            return -3;
        }

        for (auto hash : blockHashs)
        {
            std::string strHeader;
            if (dbReader.GetBlockByBlockHash(hash, strHeader) !=
                DBStatus::DB_SUCCESS)
            {
                return -4;
            }

            CBlock cblock;
            if (!cblock.ParseFromString(strHeader))
            {
                ERRORLOG("block_raw parse fail!");
                return -5;
            }
            BlockInvert(cblock, block);
            blocks[k++] = block;
        }
    }
    std::string str = blocks.dump(4);

    GetRpcBlockInfoAck ack;
    ack.set_address(MagicSingleton<PeerNode>::GetInstance()->GetSelfId());
    ack.set_data(str);
    ack.set_msg_id(msgId);

    NetSendMessage<GetRpcBlockInfoAck>(addr, ack, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
    return 0;
}

void SeekInfo()
{
    while (true)
    {

        std::cout << std::endl;
        std::cout << "1.Get the Block" << std::endl;
        std::cout << "2.Get the SyS Info" << std::endl;
        std::cout << "3.Get the Pub info" << std::endl;
        std::cout << "4.Get the Blockdetails" << std::endl;
        std::cout << "0.Exit" << std::endl;

        std::string strKey;
        std::cout << "please input your choice:";
        std::cin >> strKey;

        std::regex pattern("[0-4]");
        if (!std::regex_match(strKey, pattern))
        {
            std::cout << "Input invalid." << std::endl;
            return;
        }
        int key = std::stoi(strKey);
        switch (key)
        {
        case 0:
            return;
        case 1:
            SendRpcBlock();
            break;
        case 2:
            SendRpcSySInfo();
            break;
        case 3:
            SendRpcPub();
            break;
        case 4:
            SendRpcBlockInfo();
            break;            
        default:
            std::cout << "Invalid input." << std::endl;
            continue;
        }
        sleep(1);
    }
}
void SendRpcBlock()
{
    std::string nodeId;
    int num ,height,input,hash;
    bool prehashflag;
    std::cout << "default please input 0 ,Manual input 1" << std::endl;
    std::cin >> input;
    if(input == 0)
    {
        num = 100;
        height = 0;
        hash = 0;
        prehashflag = 0;
    }
    else
    {
        std::cout << "if you need,please input blocks' num,atmost 500 at least 100" << std::endl;
        std::cin >> num;
        std::cout << "if you need,please input height:" << std::endl;
        std::cin >> height;
        std::cout << "if you need,please input prehashflag (0 or 1):" << std::endl;
        std::cin >> prehashflag;
        std::cout << "if you need compeletely hash,please input hash (0 or 1):" << std::endl;
        std::cin >> hash;
    }
    std::cout << "Enter the node account to be obtained:" << std::endl;
    std::cin >> nodeId;
    if (nodeId.substr(0, 2) == "0x")
    {
        nodeId = nodeId.substr(2);
    }
    std::string msgId;
    size_t sendNum = 1;
    if (!GLOBALDATAMGRPTR.CreateWait(80, sendNum, msgId))
    {
        ERRORLOG("Waiting timeout");
    }
    std::string selfNodeId = MagicSingleton<PeerNode>::GetInstance()->GetSelfId();

    GetRpcBlockReq req;
    req.set_address(selfNodeId);
    req.set_height(height);
    req.set_num(num);
    req.set_prehashflag(prehashflag);
    req.set_hash(hash);
    req.set_msg_id(msgId);
    if (!GLOBALDATAMGRPTR.AddResNode(msgId, nodeId))
    {
        ERRORLOG("AddResNode fail");
        std::cout << "Add Res Node Fail" << std::endl;
        return;
    }
    NetSendMessage<GetRpcBlockReq>(nodeId, req, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);

    std::vector<std::string> retDatas;
    if (!GLOBALDATAMGRPTR.WaitData(msgId, retDatas))
    {
        ERRORLOG("Waiting data timeout");
        std::cout << "Wait too much time;";
        return;
    }
    GetRpcBlockAck ack;
    std::string blockack = "";
    {
        auto iter = retDatas.begin();
        {
            ack.Clear();
            if (!ack.ParseFromString(*iter))
            {
                ERRORLOG("ParseFromString Fail");
            }
            if (iter == retDatas.begin())
            {
                blockack = std::string(ack.data().begin(), ack.data().end());
            }
        }
    }

    if (blockack == "")
    {
        ERRORLOG("blockRaw is empty!");
    }

    std::string fileTime =  MagicSingleton<TimeUtil>::GetInstance()->GetCurrentTimeString();
    std::string outFileName = nodeId + "_" + "blockack" + "_" + fileTime;
    outFileName = ReplaceSpacesWithUnderscores(outFileName);
    std::ofstream outFile(outFileName);
    if (outFile.is_open())
    {
        outFile << blockack;
        outFile.close();
    }
    else
    {
        ERRORLOG("Failed to open blockack.txt for writing!");
    }

    ERRORLOG("Log has been written to blockack.txt.");
}
void SendRpcSySInfo()
{
    std::string nodeId;
    std::cout << "Enter the node account to be obtained:" << std::endl;
    std::cin >> nodeId;
    if (nodeId.substr(0, 2) == "0x")
    {
        nodeId = nodeId.substr(2);
    }
    std::string msgId;
    size_t sendNum = 1;
    if (!GLOBALDATAMGRPTR.CreateWait(80, sendNum, msgId))
    {
        ERRORLOG("Waiting timeout");
    }
    std::string selfNodeId = MagicSingleton<PeerNode>::GetInstance()->GetSelfId();

    GetRpcSySInfoReq req;
    req.set_address(selfNodeId);
    req.set_msg_id(msgId);
    if (!GLOBALDATAMGRPTR.AddResNode(msgId, nodeId))
    {
        ERRORLOG("AddResNode fail");
        std::cout << "Add Res Node Fail" << std::endl;
        return;
    }
    NetSendMessage<GetRpcSySInfoReq>(nodeId, req, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);

    std::vector<std::string> retDatas;
    if (!GLOBALDATAMGRPTR.WaitData(msgId, retDatas))
    {
        ERRORLOG("Waiting data timeout");
        std::cout << "Wait too much time;";
        return;
    }
    GetRpcSySInfoAck ack;
    std::string sysinfoack = "";
    {
        auto iter = retDatas.begin();
        {
            ack.Clear();
            if (!ack.ParseFromString(*iter))
            {
                ERRORLOG("ParseFromString Fail");
            }
            if (iter == retDatas.begin())
            {
                sysinfoack = std::string(ack.data().begin(), ack.data().end());
            }
        }
    }

    if (sysinfoack == "")
    {
        ERRORLOG("blockRaw is empty!");
    }

    
    std::string fileTime =  MagicSingleton<TimeUtil>::GetInstance()->GetCurrentTimeString();
    std::string outFileName = nodeId + "_" + "sysinfoack" + "_" + fileTime;
    outFileName = ReplaceSpacesWithUnderscores(outFileName);
    std::ofstream outFile(outFileName);
    if (outFile.is_open())
    {
        outFile << sysinfoack;
        outFile.close();
    }
    else
    {
        ERRORLOG("Failed to open sysinfoack.txt for writing!");
    }

    ERRORLOG("Log has been written to sysinfoack.txt.");
}
void SendRpcPub()
{
    std::string nodeId;
    std::cout << "Enter the node account to be obtained:" << std::endl;
    std::cin >> nodeId;
    if (nodeId.substr(0, 2) == "0x")
    {
        nodeId = nodeId.substr(2);
    }
    std::string msgId;
    size_t sendNum = 1;
    if (!GLOBALDATAMGRPTR.CreateWait(80, sendNum, msgId))
    {
        ERRORLOG("Waiting timeout");
    }
    std::string selfNodeId = MagicSingleton<PeerNode>::GetInstance()->GetSelfId();

    GetRpcPubReq req;
    req.set_address(selfNodeId);
    req.set_msg_id(msgId);
    if (!GLOBALDATAMGRPTR.AddResNode(msgId, nodeId))
    {
        ERRORLOG("AddResNode fail");
        std::cout << "Add Res Node Fail" << std::endl;
        return;
    }
    NetSendMessage<GetRpcPubReq>(nodeId, req, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);

    std::vector<std::string> retDatas;
    if (!GLOBALDATAMGRPTR.WaitData(msgId, retDatas))
    {
        ERRORLOG("Waiting data timeout");
        std::cout << "Wait too much time;";
        return;
    }
    GetRpcPubAck ack;
    std::string puback = "";
    {
        auto iter = retDatas.begin();
        {
            ack.Clear();
            if (!ack.ParseFromString(*iter))
            {
                ERRORLOG("ParseFromString Fail");
            }
            if (iter == retDatas.begin())
            {
                puback = std::string(ack.data().begin(), ack.data().end());
            }
        }
    }

    if (puback == "")
    {
        ERRORLOG("blockRaw is empty!");
    }

    // Store the log in the remotelog file
    std::string fileTime = MagicSingleton<TimeUtil>::GetInstance()->GetCurrentTimeString();
    std::string outFileName = nodeId +"_"+"puback" +"_" +fileTime;
    outFileName = ReplaceSpacesWithUnderscores(outFileName);
    std::ofstream outFile(outFileName);
    if (outFile.is_open())
    {
        outFile << puback;
        outFile.close();
    }
    else
    {
        ERRORLOG("Failed to open puback.txt for writing!");
    }

    ERRORLOG("Log has been written to puback.txt.");
}
void SendRpcBlockInfo()
{
    std::string nodeId;
    int num, top;
    bool prehashflag;
    std::cout << "input you need block's num:" << std::endl;
    std::cin >> num;
    std::cout << "please input start block height:" << std::endl;
    std::cin >> top;
    std::cout << "Enter the node account to be obtained:" << std::endl;
    std::cin >> nodeId;
    if (nodeId.substr(0, 2) == "0x")
    {
        nodeId = nodeId.substr(2);
    }
    std::string msgId;
    size_t sendNum = 1;
    if (!GLOBALDATAMGRPTR.CreateWait(80, sendNum, msgId))
    {
        ERRORLOG("Waiting timeout");
    }
    std::string selfNodeId = MagicSingleton<PeerNode>::GetInstance()->GetSelfId();

    GetRpcBlockInfoReq req;
    req.set_address(selfNodeId);
    req.set_top(top);
    req.set_num(num);
    req.set_msg_id(msgId);
    if (!GLOBALDATAMGRPTR.AddResNode(msgId, nodeId))
    {
        ERRORLOG("AddResNode fail");
        std::cout << "Add Res Node Fail" << std::endl;
        return;
    }
    NetSendMessage<GetRpcBlockInfoReq>(nodeId, req, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);

    std::vector<std::string> retDatas;
    if (!GLOBALDATAMGRPTR.WaitData(msgId, retDatas))
    {
        ERRORLOG("Waiting data timeout");
        std::cout << "Wait too much time;";
        return;
    }
    GetRpcBlockAck ack;
    std::string blockinfoack = "";
    {
        auto iter = retDatas.begin();
        {
            ack.Clear();
            if (!ack.ParseFromString(*iter))
            {
                ERRORLOG("ParseFromString Fail");
            }
            if (iter == retDatas.begin())
            {
                blockinfoack = std::string(ack.data().begin(), ack.data().end());
            }
        }
    }

    if (blockinfoack == "")
    {
        ERRORLOG("blockRaw is empty!");
    }

    std::string fileTime = MagicSingleton<TimeUtil>::GetInstance()->GetCurrentTimeString();
    std::string outFileName = nodeId + "_" + "blockInfoack" + "_" +fileTime;
    outFileName = ReplaceSpacesWithUnderscores(outFileName);
    std::ofstream outFile(outFileName);
    if (outFile.is_open())
    {
        outFile << blockinfoack;
        outFile.close();
    }
    else
    {
        ERRORLOG("Failed to open blockInfoack.txt for writing!");
    }

    ERRORLOG("Log has been written to blockInfoack.txt.");
}

std::string ReplaceSpacesWithUnderscores(const std::string &input)
{
    std::string result = input;
    for (char &c : result)
    {
        if (c == ' ')
        {
            c = '_'; 
        }
    }
    return result;
}

std::string FileSeekFilterLogs(const char *inputFile,std::string startTime,std::string endTime)
{
    int64_t searchStamp = TimePointToTimeStamp(startTime);
//
    //double percent = FileTimePercent(startStamp, endStamp, searchStamp);
    //int line = GetLineByPercent(inputFile, percent);
    FILE *infile = fopen(inputFile, "r");
    if (!infile)
    {
        DEBUGLOG("Could not open the input file");
        return "Read fail";
    }
    fseek(infile, 0, SEEK_END);
    long fileSize = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    fclose(infile);
    return GetExactLine(searchStamp, inputFile, fileSize, endTime);
}

std::string LogToDateTime(std::string strlog)
{
    std::string dateTime = strlog.substr(1, 23);
    return dateTime;
}

int64_t TimePointToTimeStamp(std::string dateTime)
{
    auto datetimePoint = StringToTimePoint(dateTime);
    auto datetimeStamp = std::chrono::duration_cast<std::chrono::milliseconds>(datetimePoint.time_since_epoch()).count();
    return datetimeStamp;
}

std::chrono::time_point<std::chrono::system_clock> StringToTimePoint(const std::string &dateTime)
{
    std::tm tm = {};
    std::istringstream ss(dateTime);

    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    if (ss.fail())
    {
        throw std::runtime_error("Failed to parse date/time");
    }

    std::string microseconds;
    if (ss.peek() == '.')
    {
        ss.ignore();                    
        std::getline(ss, microseconds); 
    }

    auto timePoint = std::chrono::system_clock::from_time_t(std::mktime(&tm));

    if (!microseconds.empty())
    {
        long us = std::stol(microseconds);          
        timePoint += std::chrono::microseconds(us); 
    }

    return timePoint;
}

std::string GetExactLine(int64_t currentTimeStamp, const char *input_file, long line,const std::string &endTime)
{
    FILE *infile = fopen(input_file, "r");
    if (!infile)
    {
        DEBUGLOG("Could not open the input file");
        return "Failed to read log file";
    }

    std::string currentStr;
    long currentOffset = line / 2;
    while(FindCurrentLine(infile, currentOffset, currentStr)!=0)
    {
        currentOffset--;
    }
    std::string currentDate = LogToDateTime(currentStr);
    int64_t currentFileTimeStamp = TimePointToTimeStamp(currentDate);

    int64_t firstTimeStamp = GetFirstLineTimestamp(infile);
    
    if (firstTimeStamp == -1) {
        fclose(infile);
        return "Log file timestamp parsing failed";
    }
    
    if(currentTimeStamp < firstTimeStamp)
    {
        currentTimeStamp = firstTimeStamp;
    }

    long offset = line; 


    long origin_offset = line/2;
    int line_length = 0;
    bool flag_mix = false;
    std::string currentstr;
    std::string currentstrtime;
    long final_offset = 0;
    if (currentFileTimeStamp < currentTimeStamp)
    {
        while (currentFileTimeStamp < currentTimeStamp)
        {
            if(offset < line)
            {
                offset = offset * 2;
            }
            else{
                offset = line;
            }
            while(FindPreviousLine(infile, offset, currentstr, line_length) != 0)
            {
                offset -= line_length;
            };
            currentstrtime = LogToDateTime(currentstr);
            currentFileTimeStamp = TimePointToTimeStamp(currentstrtime);
        }
        // Double the value
    }
    else
    {
        // When starting value is greater than target
        while (currentFileTimeStamp > currentTimeStamp)
        {
            //offset < origin_offset
            offset = offset / 2;
            while (FindPreviousLine(infile, offset, currentstr, line_length) != 0)
            {
                offset += line_length;
            }
            if (offset < 100)
            {
                final_offset = 0;
                flag_mix = true;
                break;
            }
            currentstrtime = LogToDateTime(currentstr);
            currentFileTimeStamp = TimePointToTimeStamp(currentstrtime);
        }
    }
    // When x >= target


    if(offset > origin_offset)
    {
        final_offset = FindOffsetAndLowerOffset(currentTimeStamp, currentFileTimeStamp, 0, offset, origin_offset, 0, infile, currentTimeStamp,0,0);
    }

    if (offset < origin_offset && flag_mix == false) 
    {
        final_offset = FindOffsetAndLowerOffset(currentFileTimeStamp, currentTimeStamp, 0, origin_offset, offset, 0, infile, currentTimeStamp,0, 0);
    }

    fseek(infile, final_offset, SEEK_SET);

    char buffer[256];               
    const int maxLineNum = 60 * 1024 *1024;
    std::ostringstream oss;


    while (fgets(buffer, sizeof(buffer), infile) != nullptr)
    {
        std::streampos currentSize = oss.tellp();
        oss << buffer;
        if (strstr(buffer, endTime.c_str()) != nullptr || currentSize > maxLineNum)
        {
        break;
        }
    }

    
    std::string allLines = oss.str();
    // file begin this
    fseek(infile, 0, SEEK_END);
    fclose(infile);
    return allLines;
    
}

int FindPreviousLine(FILE *infile, long &offset, std::string &line_str,int &line_length)
{
    line_str.clear(); 
    fseek(infile, offset, SEEK_SET);

    std::string str;
    char ch = fgetc(infile);
    while (offset > 0)
    {
        char ch = fgetc(infile);
        if (ch == '\n')
        {
            break;
        }

        offset--; 
        fseek(infile, offset, SEEK_SET);
    }
    // char ch = fgetc(infile);
    while (ch != '\n')
    {
        offset--;
        fseek(infile, offset, SEEK_SET);
        char ch = fgetc(infile);
        if (ch != '\n')
        {
            line_str.insert(line_str.end(), ch);
        }
        if (ch == '\n')
        {
            break;
        }
    }
    std::reverse(line_str.begin(), line_str.end());
    line_str.push_back('\n');
    line_length = line_str.length();
    if (line_str[0] == '[' && '2'==line_str[1] && line_str[2] == '0' && line_str[3] == '2')
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

int FindCurrentLine(FILE *infile, long &offset, std::string &line_str, int &line_length)
{
    line_str.clear();
    fseek(infile, offset, SEEK_SET);

    char ch = fgetc(infile);
    while (offset > 0)
    {
        char ch = fgetc(infile);
        if (ch == '\n')
        {
            break;
        }

        offset--; 
        fseek(infile, offset, SEEK_SET);
    }
    int output = offset;
    while (1)
    {
        offset++;
        fseek(infile, offset, SEEK_SET);
        char ch = fgetc(infile);
        line_str.insert(line_str.end(), ch);
        if (ch == '\n')
        {
            break;
        }
    }
    line_length = line_str.length();
    if (line_str[0] == '[' && '2' == line_str[1] && line_str[2] == '0' && line_str[3] == '2')
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

int FindNextLine(FILE *infile, long &offset, std::string &line_str,int &line_length)
{
    line_str.clear();
    fseek(infile, offset, SEEK_SET);

    char ch = fgetc(infile);
    while (offset > 0)
    {
        char ch = fgetc(infile);
        if (ch == '\n')
        {
            break;
        }

        offset++;
        fseek(infile, offset, SEEK_SET);
    }

    while (ch != '\n')
    {
        offset++;
        fseek(infile, offset, SEEK_SET);
        char ch = fgetc(infile);
        line_str.insert(line_str.end(), ch);
        if (ch == '\n')
        {
            break;
        }
    }
    line_length = line_str.length();
    if (line_str[0] == '[' && '2' == line_str[1] && line_str[2] == '0' && line_str[3] == '2')
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

int FindNextLine(FILE *infile, long &offset, std::string &line_str)
{
    int line_length = 0;
    return FindNextLine(infile, offset, line_str,line_length);
}

int FindPreviousLine(FILE *infile, long &offset, std::string &line_str)
{
    int line_length = 0;
    return FindPreviousLine(infile, offset, line_str,line_length);
}

int FindCurrentLine(FILE *infile, long &offset, std::string &line_str)
{
    int line_length = 0;
    return FindPreviousLine(infile, offset, line_str, line_length);
}

long FindOffsetAndLowerOffset(long lowerBound, long upperBound, int mid, long upper_offset, long lower_offset, long mid_offset, FILE *infile, int64_t currentTimeStamp, long last_offset, long loop_mid_num)
{
    while (lowerBound <= upperBound)
    {
        int line_length = 0;
        std::string nextStr{};
        mid_offset =  (upper_offset + lower_offset) / 2;
        while (FindCurrentLine(infile, mid_offset, nextStr, line_length) != 0)
        {
            mid_offset += line_length;
        }
        last_offset = mid_offset;
        std::string nextDate = LogToDateTime(nextStr);
        int64_t midTimeStamp = TimePointToTimeStamp(nextDate);
        if (midTimeStamp == currentTimeStamp || loop_mid_num > 500)
        {
            return mid_offset;
        }
        else if (midTimeStamp < currentTimeStamp)
        {
            if (last_offset == mid_offset)
            {
                loop_mid_num++;
            }
            mid_offset = mid_offset + 1;
            auto result = FindOffsetAndLowerOffset(midTimeStamp, currentTimeStamp, mid, upper_offset, mid_offset, mid_offset, infile, currentTimeStamp, last_offset, loop_mid_num);
            if (result > 0) 
            {
                return result;
            }
        }
        else
        {
            if(last_offset == mid_offset)
            {
                loop_mid_num++;
            }
            mid_offset = mid_offset - 1;
            auto result = FindOffsetAndLowerOffset(currentTimeStamp, midTimeStamp, mid, mid_offset, lower_offset, mid_offset, infile, currentTimeStamp, last_offset, loop_mid_num);
            if (result > 0) 
            {
                return result;
            }
        }
    }
}

int GetDataBaseInitVersion(DBReadWriter *dbReadWriter)
{
    if (!dbReadWriter)
    {
        ERRORLOG("DBReadWriter pointer is null!");
        return -6;  
    }

    std::string tmpInitVersion = {};
	auto ret = dbReadWriter->GetInitVer(tmpInitVersion);
    if (ret == DBStatus::DB_NOT_FOUND)
    {
		dbReadWriter->SetInitVer(global::kVersion);
	}
    ret = dbReadWriter->GetInitVer(tmpInitVersion);
    if (ret != DBStatus::DB_SUCCESS)
    {
		ERRORLOG("GetInitVer Error {} !",ret);
		return -7;
	}

	if (tmpInitVersion != global::kVersion)
	{
        std::cout << "Database version now is:" << tmpInitVersion << std::endl;
        std::cout << "Please replace the database with the latest " << std::endl;
        ERRORLOG("The current version data is inconsistent with the new version !");
		return -8;
	}
    return 0;
}

int64_t GetFirstLineTimestamp(FILE* infile) {
    fseek(infile, 0, SEEK_SET);
    std::string line;
    char buffer[256];
    if (fgets(buffer, sizeof(buffer), infile)) {
        std::string firstLine = LogToDateTime(buffer);
        return TimePointToTimeStamp(firstLine);
    }
    return -1;
}

int64_t GetLastLineTimestamp(FILE* infile) {
    fseek(infile, 0, SEEK_END);
    long pos = ftell(infile);
    std::string lastLine;
    
    while (pos > 0) {
        pos--;
        fseek(infile, pos, SEEK_SET);
        char c = fgetc(infile);
        if (c == '\n' && pos != ftell(infile)-1) {
            break;
        }
    }
    
    char buffer[256];
    if (fgets(buffer, sizeof(buffer), infile)) {
        std::string lastLine = LogToDateTime(buffer);
        return TimePointToTimeStamp(lastLine);
    }
    return -1;
}
