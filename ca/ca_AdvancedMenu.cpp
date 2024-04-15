#include "ca_AdvancedMenu.h"

#include <sys/time.h>
#include "sys/socket.h"
#include "netinet/in.h"
#include "arpa/inet.h"

#include <regex>
#include <iomanip>

#include "net/net_api.h"
#include "net/peer_node.h"
#include "net/socket_buf.h"
#include "include/logging.h"
#include "include/ScopeGuard.h"
#include "utils/time_util.h"
#include "utils/qrcode.h"
#include "common/time_report.h"
#include "common/global_data.h"
#include "utils/MagicSingleton.h"
#include "ca/ca_test.h"
#include "ca/ca_global.h"
#include "ca/ca_transaction.h"
#include "ca/ca_interface.h"
#include "utils/hexcode.h"

#include "ca/ca_txhelper.h"
#include "utils/bip39.h"
#include "ca/ca.h"
#include "ca/ca_sync_block.h"
#include "ca/ca_blockcache.h"
#include "ca/ca_blockcache.h"
#include "ca/ca_algorithm.h"
#include "utils/console.h"
#include "ca/ca_blockcache.h"
#include "ca/ca_tranmonitor.h"
#include "utils/AccountManager.h"
#include "utils/ContractUtils.h"
#include "utils/Cycliclist.hpp"
#include "utils/DONbenchmark.h"
#include "ca_blockhelper.h"
#include "ca/ca_contract.h"
//#include "utils/tmp_log.h"
#include <boost/threadpool.hpp>
#include "db_api.h"

struct contractJob{
    std::string fromAddr;
    std::string deployer;
    std::string deployutxo;
    std::string arg;
    std::string tip;
    std::string money;
};

std::vector<contractJob> jobs;
std::atomic<int> jobs_index=0;
std::atomic<int> perrnode_index=0;
boost::threadpool::pool test_pool;

void ReadContract_json(const std::string & file_name){
    std::ifstream file(file_name);
    std::stringstream buffer;  
    buffer << file.rdbuf();  
    std::string contents(buffer.str());
    if(contents.empty()){
        ERRORLOG("no data");
        return;
    }
    nlohmann::json jsonboj;
    try {
       jsonboj=nlohmann::json::parse(contents);
    } catch (std::exception & e) {
       ERRORLOG(e.what());
       return;
    }

    if(!jsonboj.is_array()){
        ERRORLOG("not a array");
       return;
    }
    try{
       for(auto &aitem:jsonboj){
            contractJob job;
            job.deployer=aitem["deployer"];
            job.deployutxo=aitem["deployutxo"];
            job.arg=aitem["arg"];
            job.money=aitem["money"];
            jobs.push_back(job);
       }
    }catch(std::exception & e){
        ERRORLOG("wath:%s",e.what());
       return;
    }
}

void menu_advanced()
{
    #ifndef NDEBUG
    title_version();
    while (true)
    {
        std::cout << std::endl;
        std::cout << "1.Ca" << std::endl;
        std::cout << "2.Net" << std::endl;
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
            menu_ca();
            break;
        case 2:
            menu_net();
            break;
        default:
            std::cout << "Invalid input." << std::endl;
            continue;
        }
        sleep(1);
    }
    #endif
    
}


void menu_ca()
{
    while (true)
    {
        std::cout << std::endl;
        std::cout << "1.testEDFunction" << std::endl;
        std::cout << "2.TestED25519Time." << std::endl;
        std::cout << "3.menu_blockinfo." << std::endl;
        std::cout << "4.rollback." << std::endl;
        std::cout << "5.See which addr have been invested." << std::endl;
        std::cout << "6.Calculate pledge yield." << std::endl;
        std::cout << "7.Obtain block information through transaction hash" << std::endl;
        std::cout << "8.Get all transaction hashes in the height" << std::endl;
        std::cout << "9.Check the address and amount of the investee account" << std::endl;
        std::cout << "10.Stake List" << std::endl;
        std::cout << "11.menu_test." << std::endl;
        std::cout << "12.tps" << std::endl;
        std::cout << "0.Exit." << std::endl;

        std::cout << "AddrList : " << std::endl;
        MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

        std::string strKey;
        std::cout << "please input your choice:";
        std::cin >> strKey;

        std::regex pattern("^[0-9]|([1][0-9])|([2][0-4])$");
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
            testEDFunction();
            break;
        case 2:
            TestED25519Time();
            break;
        case 3:
            menu_blockinfo();
            break;
        case 4:
            rollback();
            break;
        case 5:
            {
                auto ret = GetBounsAddrInfo();
                std::cout << "ret :" << ret << std::endl;
            
            }
            break;
        case 6:
            {
                auto ret = ca_algorithm::CalcBonusValue();
                std::cout << "ret :" << ret << std::endl;
            }
            break;
        case 7:
            get_blockinfo_by_txhash();
            break;
        case 8:
            get_tx_hash_by_height();
            break;
        case 9:
            get_investedNodeBlance();
            break;
        case 10:
            GetStakeList();
            break;
        case 11:
            menu_test();
            break;
        case 12:
            TpsCount();
            break;
        default:
            std::cout << "Invalid input." << std::endl;
            continue;
        }
    }
}

void gen_key()
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
        Account acc(Base58Ver::kBase58Ver_Normal);
        MagicSingleton<AccountManager>::GetInstance()->AddAccount(acc);
        MagicSingleton<AccountManager>::GetInstance()->SavePrivateKeyToFile(acc.base58Addr);
    }

    std::cout << "Successfully generated account " << std::endl;
}


void rollback()
{
    MagicSingleton<BlockHelper>::GetInstance()->rollback_test();
}


void GetStakeList()
{
    DBReader db_reader;
    std::vector<std::string> addresses;
    db_reader.GetStakeAddress(addresses);
    std::cout << "StakeList :" << std::endl;
    for (auto &it : addresses)
    {
        std::cout << it << std::endl;
    }
}

void ContrackInvke(contractJob job){
    

    INFOLOG("fromAddr:%s{}",job.fromAddr);
    INFOLOG("deployer:%s{}",job.deployer);
    INFOLOG("deployutxo:%s{}",job.deployutxo);
    INFOLOG("money:%s{}",job.money);
    INFOLOG("arg:%s{}",job.arg);

    std::string strFromAddr=job.fromAddr;

    if (!CheckBase58Addr(strFromAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    DBReader dataReader;

    std::string strToAddr=job.deployer;
    // std::cout << "Please enter to addr:" << std::endl;
    // std::cin >> strToAddr;
    if(!CheckBase58Addr(strToAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;        
    }

    std::string strTxHash=job.deployutxo;
    // std::cout << "Please enter tx hash:" << std::endl;
    // std::cin >> strTxHash;
    
    std::string strInput=job.arg;
    // std::cout << "Please enter args:" << std::endl;
    // std::cin >> strInput;
    if(strInput.substr(0, 2) == "0x")
    {
        strInput = strInput.substr(2);
    }
    else{
        strInput.clear();
    }

    std::string contractTipStr="0";
    // std::cout << "input contract tip amount :" << std::endl;
    // std::cin >> contractTipStr;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(contractTipStr, pattern))
    {
        std::cout << "input contract tip error ! " << std::endl;
        return;
    }

    std::string contractTransferStr=job.money;
    // std::cout << "input contract transfer amount :" << std::endl;
    // std::cin >> contractTransferStr;
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
        return ;
    }


    CTransaction outTx;
    CTransaction tx;
    std::string txRaw;
    if (DBStatus::DB_SUCCESS != dataReader.GetTransactionByHash(strTxHash, txRaw))
    {
        ERRORLOG("get contract transaction failed!!, strTxHash:{}", strTxHash);
        return ;
    }
    if(!tx.ParseFromString(txRaw))
    {
        ERRORLOG("contract transaction parse failed!!");
        return ;
    }
    

    nlohmann::json dataJson = nlohmann::json::parse(tx.data());
    nlohmann::json txInfo = dataJson["TxInfo"].get<nlohmann::json>();
    int vmType = txInfo["VmType"].get<int>();
 
    int ret = 0;
    TxHelper::vrfAgentType isNeedAgentFlag;
    NewVrf info;
    std::vector<std::string> dirtyContract;
    if (vmType == global::ca::VmType::EVM)
    {
        Account launchAccount;
        if(MagicSingleton<AccountManager>::GetInstance()->FindAccount(strFromAddr, launchAccount) != 0)
        {
            ERRORLOG("Failed to find account {}", strFromAddr);
            return;
        }
        std::string ownerEvmAddr = evm_utils::generateEvmAddr(launchAccount.GetPubStr());
        ret = TxHelper::CreateEvmCallContractTransaction(strFromAddr, strToAddr, strTxHash, strInput,
                                                         ownerEvmAddr, top + 1,
                                                         outTx, isNeedAgentFlag, info, contractTip, contractTransfer,
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

    
    std::cout << "size = " << dirtyContract.size() << std::endl;
    for (const auto& addr : dirtyContract)
    {
        std::cout << "addr = " << addr << std::endl;
        txMsgInfo->add_contractstoragelist(addr);
    }

    //Fill in the deployer's contract address if there is no dependency
//    if(dirtyContract.empty())
//    {
//        std::string contractAddress = evm_utils::GenerateContractAddr(strToAddr + strTxHash);
//        txMsgInfo->add_contractstoragelist(contractAddress);
//    }

    if(isNeedAgentFlag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        NewVrf * newInfo=txMsg->mutable_vrfinfo();
        newInfo -> CopyFrom(info);

    }
 
    auto msg = make_shared<ContractTxMsgReq>(ContractMsg);
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgentFlag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        ret = DropCallShippingTx(msg, outTx);
        MagicSingleton<BlockMonitor>::GetInstance()->addDropshippingTxVec(outTx.hash());
    }

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void test_contact_thread(uint32_t time, uint32_t second, uint32_t much)
{
    ReadContract_json("contract.json");
    std::vector<std::string> acccountlist;
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(acccountlist);

    jobs_index=0;
    perrnode_index=0;

    int oneSecond=0;
    int count = 1;
    while(time){
        oneSecond++;
        std::cout <<"count" <<count << std::endl;
        jobs[jobs_index].fromAddr=acccountlist[perrnode_index];
        test_pool.schedule(boost::bind(ContrackInvke, jobs[jobs_index]));
        std::thread th=std::thread(ContrackInvke,jobs[jobs_index]);
        th.detach();
        jobs_index=++jobs_index%jobs.size();
        perrnode_index=++perrnode_index%acccountlist.size();
        ::usleep(second *1000 *1000 / much);
        if(oneSecond == much){
            time--;
            oneSecond=0;
        }
        count++;
    }
}

void contact_thread()
{
    uint32_t time;
    std::cout << "time:" ;
    std::cin >>  time;
    std::cout << "second:";
    uint32_t second;
    std::cin >> second;
    std::cout << "hom much:";
    uint32_t much;
    std::cin >> much;

    test_contact_thread(time, second, much);
}

int GetBounsAddrInfo()
{
    DBReader db_reader;
    std::vector<std::string> addresses;
    std::vector<std::string> bonusAddrs;
    db_reader.GetBonusaddr(bonusAddrs);
    for (auto &bonusAddr : bonusAddrs)
    {
        std::cout << YELLOW << "BonusAddr: " << bonusAddr << RESET << std::endl;
        auto ret = db_reader.GetInvestAddrsByBonusAddr(bonusAddr, addresses);
        if (ret != DBStatus::DB_SUCCESS && ret != DBStatus::DB_NOT_FOUND)
        {
            return -1;
        }

        uint64_t sum_invest_amount = 0;
        std::cout << "InvestAddr:" << std::endl;
        for (auto &address : addresses)
        {
            std::cout << address << std::endl;
            std::vector<string> utxos;
            ret = db_reader.GetBonusAddrInvestUtxosByBonusAddr(bonusAddr, address, utxos);
            if (ret != DBStatus::DB_SUCCESS && ret != DBStatus::DB_NOT_FOUND)
            {
                return -2;
            }

            uint64_t invest_amount = 0;
            for (const auto &hash : utxos)
            {
                std::string tx_raw;
                if (db_reader.GetTransactionByHash(hash, tx_raw) != DBStatus::DB_SUCCESS)
                {
                    return -3;
                }
                CTransaction tx;
                if (!tx.ParseFromString(tx_raw))
                {
                    return -4;
                }
                for (int i = 0; i < tx.utxo().vout_size(); i++)
                {
                    if (tx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr)
                    {
                        invest_amount += tx.utxo().vout(i).value();
                        break;
                    }
                }
            }
            sum_invest_amount += invest_amount;
        }
        std::cout << "total invest amount :" << sum_invest_amount << std::endl;
    }
    return 0;
}

#pragma region netMenu
void menu_net()
{
    while (true)
    {
        std::cout << std::endl;
        std::cout << "1.Send message To user." << std::endl;
        std::cout << "2.Show my K bucket." << std::endl;
        std::cout << "3.Kick out node." << std::endl;
        std::cout << "4.Test echo." << std::endl;
        std::cout << "5.Broadcast sending Messages." << std::endl;
        std::cout << "6.Print req and ack." << std::endl;
        std::cout << "7.Print buffers." << std::endl;
        std::cout << "8.Big data send to user." << std::endl;
        std::cout << "9.Show my ID." << std::endl;
        std::cout << "0.Exit" << std::endl;

        std::string strKey;
        std::cout << "please input your choice:";
        std::cin >> strKey;

        std::regex pattern("^[0-9]|([1][0])$");
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
            send_message_to_user();
            break;
        case 2:
            show_my_k_bucket();
            break;
        case 3:
            kick_out_node();
            break;
        case 4:
            test_echo();
            break;
        case 5:
            net_com::test_broadcast_message();
            break;
        case 6:
            print_req_and_ack();
            break;
        case 7:
            MagicSingleton<BufferCrol>::GetInstance()->print_bufferes();
            break;
        case 8:
            net_com::test_send_big_data();
            break;
        case 9:
            printf("MyID : %s\n", MagicSingleton<PeerNode>::GetInstance()->get_base58addr().c_str());
            break;
        default:
            std::cout << "Invalid input." << std::endl;
            continue;
        }
    }
}

void send_message_to_user()
{
    if (net_com::input_send_one_message() == 0)
        DEBUGLOG("send one msg Succ.");
    else
        DEBUGLOG("send one msg Fail.");
}

void show_my_k_bucket()
{
    std::cout << "The K bucket is being displayed..." << std::endl;
    auto nodelist = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
    MagicSingleton<PeerNode>::GetInstance()->print(nodelist);
}

void kick_out_node()
{
    std::string id;
    std::cout << "input id:" << std::endl;
    std::cin >> id;
    MagicSingleton<PeerNode>::GetInstance()->delete_node(id);
    std::cout << "Kick out node succeed!" << std::endl;
}

void test_echo()
{

    std::string message;
    std::cout << "please input message:" << std::endl;
    std::cin >> message;

    EchoReq echoReq;
    echoReq.set_id(MagicSingleton<PeerNode>::GetInstance()->get_self_id());
    echoReq.set_message(message);
    bool isSucceed = net_com::broadcast_message(echoReq, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_Low_0);
    if (isSucceed == false)
    {
        ERRORLOG(":broadcast EchoReq failed!");
        return;
    }
}

void print_req_and_ack()
{
    double total = .0f;
    std::cout << "------------------------------------------" << std::endl;
    for (auto &item : global::reqCntMap)
    {
        total += (double)item.second.second;
        std::cout.precision(3);
        std::cout << item.first << ": " << item.second.first << " size: " << (double)item.second.second / 1024 / 1024 << " MB" << std::endl;
    }
    std::cout << "------------------------------------------" << std::endl;
    std::cout << "Total: " << total / 1024 / 1024 << " MB" << std::endl;
}

void menu_blockinfo()
{
    while (true)
    {
        DBReader reader;
        uint64_t top = 0;
        reader.GetBlockTop(top);

        std::cout << std::endl;
        std::cout << "Height: " << top << std::endl;
        std::cout << "1.Get the total number of blocks \n"
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
        case 1:
            get_tx_block_info(top);
            break;
        default:
            std::cout << "Invalid input." << std::endl;
            continue;
        }

        sleep(1);
    }
}


void get_tx_block_info(uint64_t &top)
{
    auto amount = to_string(top);
    std::string input_s, input_e;
    uint64_t start, end;

    std::cout << "amount: " << amount << std::endl;
    std::cout << "pleace input start: ";
    std::cin >> input_s;
    if (input_s == "a" || input_s == "pa")
    {
        input_s = "0";
        input_e = amount;
    }
    else
    {
        if (std::stoul(input_s) > std::stoul(amount))
        {
            std::cout << "input > amount" << std::endl;
            return;
        }
        std::cout << "pleace input end: ";
        std::cin >> input_e;
        if (std::stoul(input_s) < 0 || std::stoul(input_e) < 0)
        {
            std::cout << "params < 0!!" << endl;
            return;
        }
        if (std::stoul(input_s) > std::stoul(input_e))
        {
            input_s = input_e;
        }
        if (std::stoul(input_e) > std::stoul(amount))
        {
            input_e = std::to_string(top);
        }
    }
    start = std::stoul(input_s);
    end = std::stoul(input_e);

    std::cout << "Print to screen[0] or file[1] ";
    uint64_t nType = 0;
    std::cin >> nType;
    if (nType == 0)
    {
        printRocksdb(start, end, true, std::cout);
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
        printRocksdb(start, end, true, filestream);
    }
}

void menu_test()
{
    while (true)
    {
        std::cout << std::endl;
        std::cout << "1. Generate mnemonics."<<  std::endl;
        std::cout << "2. Query balance according to utxo" << std::endl;
        std::cout << "3. Imitate create tx" << std::endl;
        std::cout << "4. Multi account transaction" << std::endl;
        std::cout << "5. Query all stake addresses" << std::endl;
        std::cout << "6. Automatic disordered transaction (simplified version)" << std::endl;
        std::cout << "7. Output the block in database" << std::endl;
        std::cout << "8. PrintAllAccount" << std::endl;
        std::cout << "9. Create multi thread automatic transaction" << std::endl;
        std::cout << "10. Create multi thread automatic stake transaction" << std::endl;
        std::cout << "11. Automatic investment" << std::endl;
        std::cout << "12. print block cache" << std::endl;
        std::cout << "13. Print Signable Verification Nodes" << std::endl;
        std::cout << "14. get TX data." << std::endl;
        std::cout << "15. get checksum EvmAddr." << std::endl;
        std::cout << "16. Benchmark." << std::endl;
        std::cout << "17. Benchmark Clear." << std::endl;
        std::cout << "18. Benchmark automatic write" << std::endl;
        std::cout << "19. PrintBenchmarkSummary DoHandleTx" << std::endl;
        std::cout << "20. Get simple transaction count" << std::endl;
        std::cout << "21. multiTx" << std::endl;
        std::cout << "22. Query the on-chain ratio of transactions" << std::endl;
        std::cout << "23. test handle invest" << std::endl;
        std::cout << "24. test contracl pool" << std::endl;
        std::cout << "25. multi deploy"<< std::endl;
        std::cout << "26. print json"<< std::endl;
        std::cout << "27. Check the success rate of automatic transactions" << std::endl;
        std::cout << "0. Exit" << std::endl;

        std::string strKey;
        std::cout << "please input your choice:";
        std::cin >> strKey;
        std::regex pattern("^[0-9]|([1][0-9])|([2][0-7])$");
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
            gen_mnemonic();
            break;
        case 2:
            get_balance_by_utxo();
            break;
        case 3:
            imitate_create_tx_struct();
            break;
        case 4:
            multi_tx();
            break;
        case 5:
            get_all_pledge_addr();
            break;
        case 6:
            auto_tx();
            break;
        case 7:
            print_database_block();
            break;
        case 8:
            MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();
            break;
        case 9:
            Create_multi_thread_automatic_transaction();
            break;
        case 10:
            Create_multi_thread_automatic_stake_transaction();
            break;
        case 11:
            Auto_investment();
            break;
        case 12:
            print_block_cache();
            break;
        case 13:
            print_verify_node();
            break;
        case 14:
            printTxdata();
            break;
        case 15:
            evmAddrConversion();
            break;
        case 16:
            MagicSingleton<DONbenchmark>::GetInstance()->PrintBenchmarkSummary(false);
            break;
        case 17:
            MagicSingleton<DONbenchmark>::GetInstance()->Clear();
            break;
        case 18:
            printBenchmarkToFile();
            break;
        case 19:
            MagicSingleton<DONbenchmark>::GetInstance()->PrintBenchmarkSummary_DoHandleTx(true);
            break;
        case 20:
            MagicSingleton<DONbenchmark>::GetInstance()->PrintTxCount();
            break;
        case 21:
            multiTx();
            break;
        case 22:
            {
                std::string txhash;
                std::cout << "input hash >:" << std::endl;
                std::cin >> txhash;
                
                IsOnChainReq txreq;
                txreq.set_version(global::kVersion);
                txreq.add_txhash(txhash);
                txreq.set_time(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());

                auto msg = make_shared<IsOnChainReq>(txreq);
                IsOnChainAck txack;
                SendCheckTxReq(msg,txack);
                
                std::cout << "ack time =" << txack.time() << std::endl;

                for(auto & item : txack.percentage())
                {
                    std::cout << "ack hash =" << item.hash() << std::endl;
                    std::cout << "ack rate =" << item.rate() << std::endl;    
                }
            }
        case 23:
            test_handle_invest();
        case 24:
            contact_thread();
            break;
        case 25:
            CreateMultiThreadAutomaticDeployContract();
            break;
        case 26:
            printJson();
            break;
        case 27:
            {
                MagicSingleton<BlockMonitor>::GetInstance()->checkTxSuccessRate();
                break;
            }
        default:
            std::cout << "Invalid input." << std::endl;
            continue;
        }

        sleep(1);
    }
}

void gen_mnemonic()
{
    char out[1024 * 10] = {0};

    std::string mnemonic;

    Account defaultEd;
    MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultEd);
    MagicSingleton<AccountManager>::GetInstance()->GetMnemonic(defaultEd.base58Addr, mnemonic);
    std::cout << "mnemonic : " << mnemonic << std::endl;
    std::cout << "priStr : " << Str2Hex(defaultEd.priStr) << std::endl;
    std::cout << "pubStr : " << Str2Hex(defaultEd.pubStr) << std::endl;

    std::cout << "input mnemonic:" << std::endl;
    std::string str;
    std::cin.ignore(std::numeric_limits<streamsize>::max(), '\n');
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

void printTxdata()
{
    std::string hash;
    std::cout << "TX hash: ";
    std::cin >> hash;

    DBReader data_reader;

    CTransaction tx;
    std::string TxRaw;
    auto ret = data_reader.GetTransactionByHash(hash, TxRaw);
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

    nlohmann::json data_json = nlohmann::json::parse(tx.data());
    std::string data = data_json.dump(4);
    std::cout << data << std::endl;
}


void multiTx()
{
    std::ifstream fin;
	fin.open("toaddr.txt", ifstream::binary);
    if (!fin.is_open())
	{
		cout << "open file error" << endl;
		return;
	}

    std::vector<std::string> fromAddr;

    std::string addr;
    std::cout << "input fromaddr >:";
    std::cin >> addr;
    fromAddr.push_back(addr);

    std::vector<std::string> to_addrs;
    std::map<std::string, int64_t> toAddr;
    std::string Addr;
    double amt = 0;
    std::cout << "input amount>:";
    std::cin >> amt;


     
    while (getline(fin, Addr))
    {
        if(Addr[Addr.length()-1]=='\r')
        {
            Addr=Addr.substr(0,Addr.length()-1);
        }
        to_addrs.push_back(Addr);
    }


    uint32_t start_count = 0;
    uint32_t end_count = 0;
    std::cout << "please input start index>:" ;
    std::cin >> start_count;

    std::cout << "please input end index>:" ;
    std::cin >> end_count;

    for(uint32_t i = start_count ; i <= end_count ; i++)
    {
        toAddr.insert(std::make_pair(to_addrs[i],amt * global::ca::kDecimalNum));
    }


    fin.close();

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    TxMsgReq txMsg;
    TxHelper::vrfAgentType isNeedAgent_flag;
    CTransaction outTx;
    Vrf info_;
    int ret = TxHelper::CreateTxTransaction(fromAddr, toAddr, top + 1, outTx,isNeedAgent_flag,info_);
    if (ret != 0)
	{
		ERRORLOG("CreateTxTransaction error!!");
		return;
	}


	txMsg.set_version(global::kVersion);
    TxMsgInfo * txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf){
        Vrf * new_info = txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);
    }

    auto msg = make_shared<TxMsgReq>(txMsg);

    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if (isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {

        ret = DropshippingTx(msg, outTx);
    }
    else
    {
        ret = DoHandleTx(msg, outTx);
    }
    DEBUGLOG("Transaction result, ret:{}  txHash: {}", ret, outTx.hash());
}


void test_handle_invest()
{
    std::cout << std::endl
              << std::endl;
    std::cout << "AddrList:" << std::endl;
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    Account account;
    EVP_PKEY_free(account.pkey);
    MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(account);
    std::string strFromAddr = account.base58Addr;

    // std::string strFromAddr;
    std::cout << "Please confirm your addr:" << std::endl;
    // std::cin >> strFromAddr;
    std::cout << strFromAddr << std::endl;
    if (!CheckBase58Addr(strFromAddr))
    {
        ERRORLOG("Input addr error!");
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    std::string strToAddr = strFromAddr;
    std::cout << "Please confirm the addr you want to invest to:" << std::endl;
    std::cout << strToAddr << std::endl;
    // std::cin >> strToAddr;
    if (!CheckBase58Addr(strToAddr))
    {
        ERRORLOG("Input addr error!");
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    std::string strInvestFee = "23000";
    std::cout << "Please enter the amount to invest:" << std::endl;
    //std::cin >> strInvestFee;
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



void evmAddrConversion()
{
    std::string strInput;
    std::cout << "Please enter non-checksummed version addr:" << std::endl;
    std::cin >> strInput;
    bool need0x = false;
    if (strInput.substr(0, 2) == "0x")
    {
        strInput = strInput.substr(2);
        need0x = true;
    }

    std::string checksum_addr = evm_utils::EvmAddrToChecksum(strInput);
    if (need0x)
    {
        checksum_addr = "0x" + checksum_addr;
    }

    std::cout << checksum_addr << std::endl;
}


static bool benchmark_automic_write_switch = false;
void printBenchmarkToFile()
{
    if(benchmark_automic_write_switch)
    {
        benchmark_automic_write_switch = false;
        std::cout << "benchmark automic write has stoped" << std::endl;
        return;
    }
    std::cout << "enter write time interval (unit second) :";
    int interval = 0;
    std::cin >> interval;
    if(interval <= 0)
    {
         std::cout << "time interval less or equal to 0" << std::endl;
         return;
    }
    benchmark_automic_write_switch = true;
    auto benchmark_automic_write_thread = std::thread(
            [interval]()
            {
                while (benchmark_automic_write_switch)
                {
                    MagicSingleton<DONbenchmark>::GetInstance()->PrintBenchmarkSummary(true);
                    MagicSingleton<DONbenchmark>::GetInstance()->PrintBenchmarkSummary_DoHandleTx(true);
                    sleep(interval);
                }
            }
    );
    benchmark_automic_write_thread.detach();


    return;
}


void get_balance_by_utxo()
{
    std::cout << "Inquiry address:";
    std::string addr;
    std::cin >> addr;

    DBReader reader;
    std::vector<std::string> utxoHashs;
    reader.GetUtxoHashsByAddress(addr, utxoHashs);

    auto utxoOutput = [addr, utxoHashs, &reader](ostream &stream)
    {
        stream << "account:" << addr << " utxo list " << std::endl;

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

        stream << "address: " << addr << " UTXO total: " << utxoHashs.size() << " UTXO gross value:" << total << std::endl;
    };

    if (utxoHashs.size() < 10)
    {
        utxoOutput(std::cout);
    }
    else
    {
        std::string fileName = "utxo_" + addr + ".txt";
        ofstream file(fileName);
        if (!file.is_open())
        {
            ERRORLOG("Open file failed!");
            return;
        }
        utxoOutput(file);
        file.close();
    }
}

int imitate_create_tx_struct()
{
    Account acc;
    EVP_PKEY_free(acc.pkey);
    if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(acc) != 0)
    {
        return -1;
    }

    //Check whether the Genesis account is in the address list
    std::vector<std::string> base58_list;
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(base58_list);
    if(std::find(base58_list.begin(), base58_list.end(), global::ca::kInitAccountBase58Addr) == base58_list.end())
    {
        std::cout << "The Genesis account is not in the node list !" << std::endl;
        return -2;
    }

    //Get the filled account number and amount from the file and store it in the map
    //std::map<std::string, int> addr_value = readMapFromFile("addr_value.txt");
    //std::cout << addr_value["112orBGwM7uFm3GoHGriMdwmjY7XWjVbDb"] << std::endl;
    const std::string addr = acc.base58Addr;
    uint64_t time = global::ca::kGenesisTime;

    CTransaction tx;
    tx.set_version(0);
    tx.set_time(time);
    tx.set_n(0);
    tx.set_identity(addr);
    tx.set_type(global::ca::kGenesisSign);

    CTxUtxo *utxo = tx.mutable_utxo();
    utxo->add_owner(addr);
    {
        CTxInput *txin = utxo->add_vin();
        CTxPrevOutput *prevOut = txin->add_prevout();
        prevOut->set_hash(std::string(64, '0'));
        prevOut->set_n(0);
        txin->set_sequence(0);

        std::string serVinHash = getsha256hash(txin->SerializeAsString());
        std::string signature;
        std::string pub;

        if (acc.Sign(serVinHash, signature) == false)
        {
            std::cout << "tx sign fail !" << std::endl;
            return -5;
        }

        CSign *sign = txin->mutable_vinsign();
        sign->set_sign(signature);
        sign->set_pub(acc.pubStr);
    }

    {
        //Traversing this map and filling the account and amount into utxo's vout requires special processing
        CTxOutput *txout = utxo->add_vout();
        txout->set_value(10000000000000000);
        txout->set_addr(addr);
        
        // for(auto & obj : addr_value)
        // {
        //     CTxOutput *new_txout = utxo->add_vout();
        //     new_txout->set_value(obj.second * 100);
        //     new_txout->set_addr(obj.first);
        // }
    }

    {
        //Multi-sign processing logic
        std::string serUtxo = getsha256hash(utxo->SerializeAsString());
        std::string signature;
        if (acc.Sign(serUtxo, signature) == false)
        {
            std::cout << "multiSign fail !" << std::endl;
            return -6;
        }

        CSign *multiSign = utxo->add_multisign();
        multiSign->set_sign(signature);
        multiSign->set_pub(acc.pubStr);
    }
    
    tx.set_txtype((uint32)global::ca::TxType::kTxTypeGenesis);

    tx.set_hash(getsha256hash(tx.SerializeAsString()));

    CBlock block;
    block.set_time(time);
    block.set_version(0);
    block.set_prevhash(std::string(64, '0'));
    block.set_height(0);

    CTransaction *tx0 = block.add_txs();
    *tx0 = tx;

    nlohmann::json blockData;
    blockData["Name"] = "Transformers";
    blockData["Type"] = "Genesis";
    block.set_data(blockData.dump());

    block.set_merkleroot(ca_algorithm::CalcBlockMerkle(block));
    block.set_hash(getsha256hash(block.SerializeAsString()));

    std::string hex = Str2Hex(block.SerializeAsString());

    //Change the hexadecimal of the block from screen output to output to file
    std::ofstream filestream;
    filestream.open("blockHex.txt");
    if(!filestream)
    {
       std::cout << "open blockHex.txt fail" << std::endl;
        return -7;
    }
    
    filestream << hex;
    filestream.close();

    return 0;
}

void multi_tx()
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
        std::cout << "amount : ";
        std::cin >> amt;
        toAddr.insert(make_pair(addr, amt * global::ca::kDecimalNum));
    }

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    TxMsgReq txMsg;
    TxHelper::vrfAgentType isNeedAgent_flag;
    CTransaction outTx;
    Vrf info_;
    int ret = TxHelper::CreateTxTransaction(fromAddr, toAddr, top + 1, outTx,isNeedAgent_flag,info_);
    if (ret != 0)
	{
		ERRORLOG("CreateTxTransaction error!!");
		return;
	}


	txMsg.set_version(global::kVersion);
    TxMsgInfo * txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf){
        Vrf * new_info = txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);
    }

    auto msg = make_shared<TxMsgReq>(txMsg);

    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if (isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {

        ret = DropshippingTx(msg, outTx);
    }
    else
    {
        ret = DoHandleTx(msg, outTx);
    }
    DEBUGLOG("Transaction result, ret:{}  txHash: {}", ret, outTx.hash());
}

void get_all_pledge_addr()
{
    DBReader reader;
    std::vector<std::string> addressVec;
    reader.GetStakeAddress(addressVec);

    auto allPledgeOutput = [addressVec](ostream &stream)
    {
        stream << std::endl
               << "---- Pledged address start ----" << std::endl;
        for (auto &addr : addressVec)
        {
            uint64_t pledgeamount = 0;
            SearchStake(addr, pledgeamount, global::ca::StakeType::kStakeType_Node);
            stream << addr << " : " << pledgeamount << std::endl;
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

void auto_tx()
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

void get_blockinfo_by_txhash()
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


void get_tx_hash_by_height()
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

    std::string fileName = "TPS_INFO_" + std::to_string(start) + "_" + std::to_string(end) + ".txt";
    std::ofstream filestream;
    filestream.open(fileName);
    if (!filestream)
    {
        std::cout << "Open file failed!" << std::endl;
        return;
    }
    filestream << "TPS_INFO:" << std::endl;
    DBReader db_reader;
    uint64_t tx_total = 0;
    uint64_t block_total = 0;
    for (int64_t i = end; i >= start; --i)
    {

        std::vector<std::string> tmp_block_hashs;
        if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(i, tmp_block_hashs))
        {
            ERRORLOG("(get_tx_hash_by_height) GetBlockHashsByBlockHeight  Failed!!");
            return;
        }

        int tx_hash_count = 0;
        for (auto &blockhash : tmp_block_hashs)
        {
            std::string blockstr;
            db_reader.GetBlockByBlockHash(blockhash, blockstr);
            CBlock block;
            block.ParseFromString(blockstr);

            tx_hash_count += block.txs_size();
        }
        tx_total += tx_hash_count;
        block_total += tmp_block_hashs.size();
        filestream << GREEN << "height: " << i << " block: " << tmp_block_hashs.size() << " tx: " << tx_hash_count << RESET << std::endl;
    }

    filestream << GREEN << "block sum " << block_total << RESET << std::endl;
    filestream << GREEN << "tx sum " << tx_total  << RESET << std::endl;

    std::vector<std::string> start_hashes;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(start, start_hashes))
    {
        ERRORLOG("GetBlockHashsByBlockHeight fail  top = {} ", start);
        return;
    }
    //Take out the blocks at the starting height and sort them from the smallest to the largest in time
    std::vector<CBlock> start_blocks;
    for (auto &hash : start_hashes)
    {
        std::string blockStr;
        db_reader.GetBlockByBlockHash(hash, blockStr);
        CBlock block;
        block.ParseFromString(blockStr);
        start_blocks.push_back(block);
    }
    std::sort(start_blocks.begin(), start_blocks.end(), [](const CBlock &x, const CBlock &y)
              { return x.time() < y.time(); });

    std::vector<std::string> end_hashes;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(end, end_hashes))
    {
        ERRORLOG("GetBlockHashsByBlockHeight fail  top = {} ", end);
        return;
    }
    //Take out the blocks at the end height and sort them from small to large in time
    std::vector<CBlock> end_blocks;
    for (auto &hash : end_hashes)
    {
        std::string blockStr;
        db_reader.GetBlockByBlockHash(hash, blockStr);
        CBlock block;
        block.ParseFromString(blockStr);
        end_blocks.push_back(block);
    }
    std::sort(end_blocks.begin(), end_blocks.end(), [](const CBlock &x, const CBlock &y)
              { return x.time() < y.time(); });

    uint64_t time_diff = 0;
    if (end_blocks[end_blocks.size() - 1].time() - start_blocks[0].time() != 0)
    {
        time_diff = (end_blocks[end_blocks.size() - 1].time() - start_blocks[0].time()) / 1000000;
    }
    else
    {
        time_diff = 1;
    }
    uint64_t tx_conut = tx_total ;
    uint64_t tps = tx_conut / time_diff;
    filestream << "TPS : " << tps << std::endl;
}


void get_investedNodeBlance()
{
    std::string addr;
    std::cout << "Please enter the address you need to inquire: " << std::endl;
    std::cin >> addr;

    std::shared_ptr<GetAllInvestAddressReq> req = std::make_shared<GetAllInvestAddressReq>();
    req->set_version(global::kVersion);
    req->set_addr(addr);

    GetAllInvestAddressAck ack;
    GetAllInvestAddressReqImpl(req, ack);
    if (ack.code() != 0)
    {
        std::cout << "code: " << ack.code() << std::endl;
        ERRORLOG("get_investedNodeBlance failed!");
        return;
    }

    std::cout << "------------" << ack.addr() << "------------" << std::endl;

    for (int i = 0; i < ack.list_size(); i++)
    {
        const InvestAddressItem info = ack.list(i);
        std::cout << "addr:" << info.addr() << "\tamount:" << info.value() << std::endl;
    }
}
void print_database_block()
{
    DBReader dbReader;
    std::string str = printBlocks(100, false);
    std::cout << str << std::endl;
}

void ThreadTest::TestCreateTx_2(const std::string &from, const std::string &to)
{
    // int intPart = rand() % 10;
    std::cout << "from:" << from << std::endl;
    std::cout << "to:" << to << std::endl;

    uint64_t start_time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    bool Initiate = false;
    ON_SCOPE_EXIT{
        if(!Initiate)
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

    DBReader data_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != data_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }
    
    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    int ret = TxHelper::CreateTxTransaction(fromAddr, toAddrAmount, top + 1, outTx,isNeedAgent_flag,info_);
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
    txMsgInfo->set_height(top);


    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf){
        Vrf * new_info = txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }

    auto msg = make_shared<TxMsgReq>(txMsg);

    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if (isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {

        ret = DropshippingTx(msg, outTx);
        MagicSingleton<BlockMonitor>::GetInstance()->addDropshippingTxVec(outTx.hash());
    }
    else
    {
        ret = DoHandleTx(msg, outTx);
        MagicSingleton<BlockMonitor>::GetInstance()->addDoHandleTxTxVec(outTx.hash());
    }

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
    Initiate = true;
    MagicSingleton<DONbenchmark>::GetInstance()->AddTransactionInitiateMap(start_time, MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
    
    std::cout << "=====Transaction initiator:" << from << std::endl;
    std::cout << "=====Transaction recipient:" << to << std::endl;
    std::cout << "=====Transaction amount:" << amountStr << std::endl;
    std::cout << "=======================================================================" << std::endl
              << std::endl
              << std::endl;
}

bool bStopTx_2 = true;
bool bIsCreateTx_2 = false;
static int i = -1;
static int i_count = 1;
static int count_wheel = 0;
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
    return i;
}
void ThreadTest::set_StopTx_flag(const bool &flag)
{
    bStopTx_2 = flag;
}



void ThreadTest::get_StopTx_flag(bool &flag)
{
   flag =  bStopTx_2 ;
}



void ThreadTest::test_createTx(uint32_t tranNum, std::vector<std::string> addrs_,int timeout)
{
    DEBUGLOG("test_createTx start at {}", MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
    Cycliclist<std::string> addrs;

    for (auto &U : addrs_)
    {
        addrs.push_back(U);
    }

    if(addrs.isEmpty())
    {
        std::cout << "account list is empty" << std::endl;
        return;
    }
    auto iter=addrs.begin();
    while (bStopTx_2==false)
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

void Create_multi_thread_automatic_transaction()
{
    std::cout << "1. tx " << std::endl;
    std::cout << "2. close" << std::endl;

    int check=0;
     std::cout << "chose:" ;
     std::cin >> check;

     if(check==1){
       if(bStopTx_2==true){
            //No concurrency
            bStopTx_2=false;
       }else {
            //Concurrency in progress
            std::cout << "has run" << std::endl;
            return;
       }
     }else if(check ==2){
        bStopTx_2=true;
        return;
     }else{
        std::cout<< " invalui" << std::endl;
        return;
     }
     if(bStopTx_2)
     {
        return;
     }

    int TxNum = 0;
    int timeout = 0;
    //Transaction interval
    std::cout << "Interval time (seconds):";
    std::cin >> timeout;
    //Number of transactions issued each time
    std::cout << "Interval frequency :" ;

    std:: cin >> TxNum;
    std::vector<std::string> addrs_;

    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(addrs_);

    std::thread th(ThreadTest::test_createTx,TxNum, addrs_, timeout);
    th.detach();
}

void TestCreateStake_2(const std::string &from)
{
    TxHelper::PledgeType pledgeType = TxHelper::PledgeType::kPledgeType_Node;
    uint64_t stake_amount = 10  * global::ca::kDecimalNum ;

    DBReader data_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != data_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }


    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    std::vector<TxHelper::Utxo> outVin;
    if(TxHelper::CreateStakeTransaction(from, stake_amount, top + 1, pledgeType, outTx, outVin,isNeedAgent_flag,info_) != 0)
    {
        return;
    }
    std::cout << " from: " << from << " amout: " << stake_amount << std::endl;
    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo * txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info = txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);
    }
    auto msg = std::make_shared<TxMsgReq>(txMsg);
    int ret = 0;
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if (isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
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


void Create_multi_thread_automatic_stake_transaction()
{
    std::vector<std::string> addrs;

    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(addrs);

    std::vector<std::string>::iterator it = std::find(addrs.begin(), addrs.end(), MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
    if (it != addrs.end())
    {
        addrs.erase(it);
    }

    for (int i = 0; i <= addrs.size(); ++i)
    {
        std::thread th(TestCreateStake_2, addrs[i]);
        th.detach();
    }
}

void TestCreateInvestment(const std::string &strFromAddr, const std::string &strToAddr, const std::string &amountStr)
{

    TxHelper::InvestType investType = TxHelper::InvestType::kInvestType_NetLicence;

    uint64_t invest_amount = std::stod(amountStr) * global::ca::kDecimalNum;

    DBReader data_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != data_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }


    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    int ret = TxHelper::CreateInvestTransaction(strFromAddr, strToAddr, invest_amount, top + 1, investType,outTx, outVin,isNeedAgent_flag,info_);
	if(ret != 0)
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

    if (isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);
    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);

    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();

    if (isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {

        ret = DropshippingTx(msg, outTx);
    }
    else
    {
        ret = DoHandleTx(msg, outTx);
    }

    std::cout << "=====Transaction initiator:" << strFromAddr << std::endl;
    std::cout << "=====Transaction recipient:" << strToAddr << std::endl;
    std::cout << "=====Transaction amount:" << amountStr << std::endl;
    std::cout << "=======================================================================" << std::endl
              << std::endl
              << std::endl
              << std::endl;
}

void Auto_investment()
{

    std::cout << "input aummot: ";
    std::string aummot;
    std::cin >> aummot;

    std::string addrs;

    // MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();
    // MagicSingleton<AccountManager>::GetInstance()->GetAccountList(addrs);

    // std::vector<std::string>::iterator it = std::find(addrs.begin(), addrs.end(), MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
    // if (it != addrs.end())
    // {
    //     addrs.erase(it);
    // }
    addrs = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();

    // int i = 0;
    // while (i < addrs.size())
    // {
    //     std::string from;
    //     std::string to;
    //     from = addrs[i];
    //     if ((i + 1) >= addrs.size())
    //     {
    //         i = 0;
    //     }
    //     else
    //     {
    //         i += 1;
    //     }

    //     to = addrs[i];

    //     if (from != "")
    //     {
    //         if (!MagicSingleton<AccountManager>::GetInstance()->IsExist(from))
    //         {
    //             DEBUGLOG("Illegal account.");
    //             return;
    //         }
    //     }
    //     else
    //     {
    //         DEBUGLOG("Illegal account. from base58addr is null !");
    //         return;
    //     }
    std::thread th(TestCreateInvestment, addrs, addrs, aummot);
    th.detach();
    //     if (i == 0)
    //     {
    //         return;
    //     }
    //     sleep(1);
    // }
}

void print_verify_node()
{
    std::vector<Node> nodelist = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();

    vector<Node> result_node;
    for (const auto &node : nodelist)
    {
        if(CheckVerifyNodeQualification(node.base58address) == 0)
        {
            result_node.push_back(node);
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
    for (auto &i : result_node)
    {
        filestream
            << "  base58(" << i.base58address << ")"
            << std::endl;
    }
    filestream << "------------------------------------------------------------------------------------------------------------" << std::endl;
    filestream << "PeerNode size is: " << result_node.size() << std::endl;
}

void print_block_cache()
{
    std::cout << "input height :";
    int height;
    std::cin >> height;
    std::map<uint64_t, std::set<CBlock, CBlockCompare>> _cache;
    MagicSingleton<CBlockCache>::GetInstance()->GetCache(_cache);
    auto iter = _cache.begin();
    for (; iter != _cache.end(); ++iter)
    {
        if (iter->first == height)
        {
            for (auto block : iter->second)
            {
                std::cout << block.hash() << std::endl;
            }
        }
    }
}

std::map<std::string, int> readMapFromFile(const std::string& filename) {
    std::map<std::string, int> myMap;
    std::ifstream file(filename);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            // Remove leading and trailing whitespaces from the line
            line.erase(line.find_last_not_of(" \t\r\n") + 1);

            // Find the position of the separator
            std::size_t separatorPos = line.find(",");

            // Extract the key and value from the line
            if (separatorPos != std::string::npos) {
                std::string key = line.substr(1, separatorPos - 2);
                int value = std::stoi(line.substr(separatorPos + 1));
                myMap[key] = value;
            }
        }
        file.close();
    } else {
        std::cout << "Unable to open file for reading.\n";
    }
    return myMap;
}


void GetTxHashByHeight(int64_t start,int64_t end,std::ofstream& filestream)
{
    int64_t localStart = start;
    int64_t localEnd = end;

    // std::cout << "Please input start height:";
    // std::cin >> start;

    // std::cout << "Please input end height:";
    // std::cin >> end;

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
        filestream  << "Height >: " << i << " Blocks >: " << tmpBlockHashs.size() << " Txs >: " << txHashCount  << std::endl;
        for(auto &blockhash : tmpBlockHashs)
        {
            std::string blockstr;
            dbReader.GetBlockByBlockHash(blockhash, blockstr);
            CBlock block;
            block.ParseFromString(blockstr);
            std::string tmpBlockHash = block.hash();
            tmpBlockHash = tmpBlockHash.substr(0,6);
            int tmpHashSize = block.txs_size();
            filestream << " BlockHash: " << tmpBlockHash << " TxHashSize: " << tmpHashSize << std::endl;
        }
    }

    filestream  << "Total block sum >:" << blockTotal  << std::endl;
    filestream  << "Total tx sum >:" << txTotal   << std::endl;
    //debugL("..............");
    std::vector<std::string> startHashes;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockHashsByBlockHeight(localStart, startHashes))
    {
        ERRORLOG("GetBlockHashsByBlockHeight fail  top = {} ", localStart);
        return;
    }

    //Take out the blocks at the starting height and sort them from the smallest to the largest in time
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

    //Take out the blocks at the end height and sort them from small to large in time
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
    uint64_t tx_conut = txTotal ;
    float tps = float(tx_conut) / float(timeDiff);
    filestream << "TPS : " << tps << std::endl;
}

void TpsCount(){
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
    std::string fileName =  "TPS_INFO_" +StartW +"_"+ EndW+".txt";
    std::ofstream filestream;
    filestream.open(fileName);
    GetTxHashByHeight(start,end,filestream);

     
}

void rocksdbSaveBlock()
{
    //read rocksdbSaveBlock
    DBReader db_reader;
    uint64_t top;
    nlohmann::json block;
    db_reader.GetBlockTop(top);
    for (auto i = top; i <= 1; i++) {
    std::vector<std::string> vBlockHashs;

    if (db_reader.GetBlockHashsByBlockHeight(i, vBlockHashs) !=
        DBStatus::DB_SUCCESS) {
      return;
    }

    for (auto hash : vBlockHashs) {
      string strHeader;
      if (db_reader.GetBlockByBlockHash(hash, strHeader) !=
          DBStatus::DB_SUCCESS) {
        return;
      }
      CBlock cblock;
      cblock.ParseFromString(block);
      std::string blockHash;
      global::ca::BlockObtainMean obtain_mean = global::ca::BlockObtainMean::Normal;
      static global::ca::SaveType sync_type = global::ca::SaveType::Unknow;
      DBReadWriter* db_writer_ptr = new DBReadWriter();
      for(int i = 1;i <= 1000;i++)
      {
        ca_algorithm::SaveBlock(*db_writer_ptr,cblock,sync_type,obtain_mean);
      }
      
    }
  }
}

void ThreadTest::SetStopTxFlag(const bool &flag)
{
    bStopTx_2 = flag;
}

void ThreadTest::GetStopTxFlag(bool &flag)
{
   flag =  bStopTx_2 ;
}

void ThreadTest::TestCreateTx(uint32_t tranNum, std::vector<std::string> addrs_,int timeout)
{
    DEBUGLOG("TestCreateTx start at {}", MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
    Cycliclist<std::string> addrs;

    for (auto &U : addrs_)
    {
        addrs.push_back(U);
    }

    if(addrs.isEmpty())
    {
        std::cout << "account list is empty" << std::endl;
        return;
    }
    auto iter=addrs.begin();
    while (bStopTx_2==false)
    {
        //MagicSingleton<TFSbenchmark>::GetInstance()->SetTransactionInitiateBatchSize(tranNum);
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

