#include "api/http_api.h"
#include "../include/ScopeGuard.h"
#include "../include/net_interface.h"
#include "../net/global.h"
#include "../net/httplib.h"
#include "../net/net_api.h"
#include "../net/peer_node.h"
#include "../utils/base64.h"
#include "../utils/json.hpp"
#include "../utils/string_util.h"
#include "./interface/tx.h"
#include "block.pb.h"
#include "ca/ca.h"
#include "ca/ca_AdvancedMenu.h"
#include "ca/ca_algorithm.h"
#include "ca_global.h"
#include "ca_protomsg.pb.h"
#include "ca_transaction.h"
#include "ca_txhelper.h"
// #include "db/cache.h"
#include "db/db_api.h"
#include "google/protobuf/stubs/status.h"
#include "interface.pb.h"
#include "transaction.pb.h"
#include "utils/AccountManager.h"
#include "utils/Envelop.h"
#include "utils/MagicSingleton.h"
#include "utils/base64_2.h"
#include "utils/tmp_log.h"
#include <algorithm>
#include <algorithm> //transform
#include <boost/math/constants/constants.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <cctype> //toupper/tolower
#include <sstream>
#include <string>

#include "api/interface/RSA_TEXT.h"
#include "api/interface/tx.h"
#include "ca/ca_interface.h"
#include "api/interface/rpc_error.h"
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <google/protobuf/util/json_util.h>
#include <sys/types.h>
#include <boost/threadpool.hpp>
#include <evmc/evmc.hpp>
#include <utils/ContractUtils.h>


static bool flag = true;
static bool autoTxFlag = true;
#define CHECK_VALUE(value)\
        std::regex pattern("(^[1-9]\\d*\\.\\d+$|^0\\.\\d+$|^[1-9]\\d*$|^0$)");\
        if (!std::regex_match(value, pattern))\
        {\
            ack_t.ErrorCode="-3004";\
            ack_t.ErrorMessage=Sutil::Format("input value error:",value);\
            res.set_content(ack_t.paseToString(), "application/json");\
            return;\
        }


#define CHECK_PASE_REQ_T\
    std::string PaseRet = req_t.paseFromJson(req.body);\
    if(PaseRet != "OK") {\
        errorL("bad error pase fail");\
        ack_t.ErrorCode="9090";\
        ack_t.ErrorMessage=Sutil::Format("pase fail:%s",PaseRet);\
        res.set_content(ack_t.paseToString(), "application/json");\
        return ;\
    }

void ca_register_http_callbacks() {
#ifndef NDEBUG // The debug build compiles these functions
  HttpServer::registerCallback("/", api_jsonrpc);
  HttpServer::registerCallback("/block", api_print_block);
  HttpServer::registerCallback("/info", api_info);
  //    HttpServer::registerCallback("/info_queue", api_info_queue);
  HttpServer::registerCallback("/get_block", api_get_block);
  //    HttpServer::registerCallback("/get_block_hash", api_get_block_hash);
  //    HttpServer::registerCallback("/get_block_by_hash",
  //    api_get_block_by_hash); HttpServer::registerCallback("/get_tx_owner",
  //    api_get_tx_owner); HttpServer::registerCallback("/test_create_multi_tx",
  //    test_create_multi_tx); HttpServer::registerCallback("/get_db_key",
  //    api_get_db_key); HttpServer::registerCallback("/add_block_callback",
  //    add_block_callback_test); HttpServer::registerCallback("/rollbackblock",
  //    rollback_block_callback_test);
  //    HttpServer::registerCallback("/cache_info", api_cache_info);
  //
  HttpServer::registerCallback("/pub", api_pub);
  HttpServer::registerCallback("/startautotx", api_start_autotx);
  HttpServer::registerCallback("/endautotx", api_end_autotx);
  HttpServer::registerCallback("/autotxstatus", api_status_autotx);
  HttpServer::registerCallback("/filterheight", api_filter_height);

  HttpServer::registerCallback("/block_info", api_get_block_info);
  HttpServer::registerCallback("/get_tx_info", api_get_tx_info);
  HttpServer::registerCallback("/ip", ApiIp);
  HttpServer::registerCallback("/printHundredHash",ApiPrintHundredSumHash);
#endif // #ifndef NDEBUG
  HttpServer::registerCallback("/ip", ApiIp);
  HttpServer::registerCallback("/get_rates_info", api_get_rates_info);
  //
  //    //json rpc=========
  //    HttpServer::registerJsonRpcCallback("jsonrpc_test", jsonrpc_test);
  HttpServer::registerCallback("/get_height", jsonrpc_get_height);
  HttpServer::registerCallback("/get_balance", jsonrpc_get_balance);
  HttpServer::registerCallback("/rpc_get_utxo",jsonrpc_get_utxo);
  HttpServer::registerCallback("/get_utxo",api_get_utxo);
  HttpServer::registerCallback("/get_gas", jsonrpc_get_gas);

  HttpServer::registerCallback("/get_transaction_req", get_transaction);
  HttpServer::registerCallback("/get_stakeutxo_req", get_stakeutxo);
  HttpServer::registerCallback("/get_disinvestutxo_req", get_disinvestutxo);
  HttpServer::registerCallback("/get_stake_req", get_stake);
  HttpServer::registerCallback("/get_unstake_req", get_unstake);
  HttpServer::registerCallback("/get_invest_req", get_invest);
  HttpServer::registerCallback("/get_disinvest_req", get_disinvest);
  HttpServer::registerCallback("/get_declare_req", get_declare);
  HttpServer::registerCallback("/get_bonus_req", get_bonus);
  HttpServer::registerCallback("/get_rsa_req", get_rsa_pub);
  HttpServer::registerCallback("/deploy_contract_req", deploy_contract);
  HttpServer::registerCallback("/call_contract_req", call_contract);
  HttpServer::registerCallback("/send_message", send_message);
  HttpServer::registerCallback("/get_isonchain", get_isonchain);
  
  HttpServer::registerCallback("/SendContractMessage",SendContractMessage);

  HttpServer::registerCallback("/deployers_req", get_deployer);

  HttpServer::registerCallback("/deploy_utxo_req", get_deployerutxo);

  HttpServer::registerCallback("/get_restinverst_req", get_restinvest);
  HttpServer::registerCallback("/get_all_stake_node_list_ack",get_all_stake_node_list_ack);
  HttpServer::registerCallback("/confirm_transaction",confirm_transaction);

  
  HttpServer::registerCallback("/test_thread_contract",test_contact_thread);
  HttpServer::registerCallback("/test_success",test_success);
  HttpServer::start();
}

// void add_block_callback_test(const Request &req, Response &res)
//{
//     DEBUGLOG("Receive callback request from Client: {}", req.body);
//     res.set_content(req.body, "text/plain"); // "application/json"
// }
//
// void rollback_block_callback_test(const Request &req, Response &res)
//{
//     DEBUGLOG("Receive callback request from Client: {}", req.body);
//     cout << "Receive callback request from Client: {}" << endl;
//
//     {
//         cout << "req.body=" << req.body << endl;
//     }
//
//     res.set_content(req.body, "text/plain"); // "application/json"
// }
//
// nlohmann::json jsonrpc_test(const nlohmann::json &param)
//{
//     std::string param1 = param["param1"].get<std::string>();
//     nlohmann::json ret;
//     ret["result"]["echo param"] = param1;
//     return ret;
// }
//
////-------
void api_pub(const Request &req, Response &res) {
  std::ostringstream oss;
  MagicSingleton<ProtobufDispatcher>::GetInstance()->task_info(oss);
  oss << "queue_read:" << global::queue_read.msg_queue_.size() << std::endl;
  oss << "queue_work:" << global::queue_work.msg_queue_.size() << std::endl;
  oss << "queue_write:" << global::queue_write.msg_queue_.size() << std::endl;
  oss << "\n" << std::endl;

  double total = .0f;
  uint64_t n64Count = 0;
  oss << "------------------------------------------" << std::endl;
  for (auto &item : global::reqCntMap) {
    total += (double)item.second.second; // Data Size
    oss.precision(3);                    // Retain 3 decimal places
    // Type of data				Number of calls							 Convert
    // MB
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
  std::vector<std::string> baselist;

  MagicSingleton<AccountManager>::GetInstance()->GetAccountList(baselist);
  for (auto &i : baselist) {
    uint64_t amount = 0;
    GetBalanceByUtxo(i, amount);
    oss << i + ":" + std::to_string(amount) << std::endl;
  }

  oss << std::endl << std::endl;

  std::vector<Node> pubNodeList =
      MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
  oss << "Public PeerNode size is: " << pubNodeList.size() << std::endl;
  oss << MagicSingleton<PeerNode>::GetInstance()->nodelist_info(
      pubNodeList); // Convert all public network node data to string for saving
  res.set_content(oss.str(), "text/plain");
}
//
//
void api_jsonrpc(const Request &req, Response &res) {
  nlohmann::json ret;
  ret["jsonrpc"] = "2.0";
  try {
    auto json = nlohmann::json::parse(req.body);

    std::string method = json["method"];

    auto p = HttpServer::rpc_cbs.find(method);
    if (p == HttpServer::rpc_cbs.end()) {
      ret["error"]["code"] = -32601;
      ret["error"]["message"] = "Method not found";
      ret["id"] = "";
    } else {
      auto params = json["params"];
      ret = HttpServer::rpc_cbs[method](params);
      try {
        ret["id"] = json["id"].get<int>();
      } catch (const std::exception &e) {
        ret["id"] = json["id"].get<std::string>();
      }
      ret["jsonrpc"] = "2.0";
    }
  } catch (const std::exception &e) {
    ret["error"]["code"] = -32700;
    ret["error"]["message"] = "Internal error";
    ret["id"] = "";
  }
  res.set_content(ret.dump(4), "application/json");
}
//
// void api_get_db_key(const Request &req, Response &res)
//{
//    std::string key;
//    if (req.has_param("key"))
//    {
//        key = req.get_param_value("key");
//    }
//
//    std::string value;
//    DBReader().ReadData(key, value);
//    res.set_content(value, "text/plain");
//}
//
void api_print_block(const Request &req, Response &res) {
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
    str = printBlocksHash(num, req.has_param("pre_hash_flag"));
    res.set_content(str, "text/plain");
    return;
  }

  if (startNum == 0)
    str = printBlocks(num, req.has_param("pre_hash_flag"));
  else
    str = printRangeBlocks(startNum, num, req.has_param("pre_hash_flag"));

  res.set_content(str, "text/plain");
}
//
// void api_info_queue(const Request &req, Response &res)
//{
//    std::ostringstream oss;
//    oss << "queue_read:" << global::queue_read.msg_queue_.size() << std::endl;
//    oss << "queue_work:" << global::queue_work.msg_queue_.size() << std::endl;
//    oss << "queue_write:" << global::queue_write.msg_queue_.size() <<
//    std::endl; oss << "\n"
//        << std::endl;
//
//    double total = .0f;
//    oss << "------------------------------------------" << std::endl;
//    for (auto &item : global::reqCntMap)
//    {
//        total += (double) item.second.second;
//        oss.precision(3);
//        oss << item.first << ": " << item.second.first << " size: " <<
//        (double) item.second.second / 1024 / 1024
//            << " MB" << std::endl;
//    }
//    oss << "------------------------------------------" << std::endl;
//    oss << "Total: " << total / 1024 / 1024 << " MB" << std::endl;
//
//    res.set_content(oss.str(), "text/plain");
//}
//
void api_info(const Request &req, Response &res) {

  std::ostringstream oss;

  oss << "queue:" << std::endl;
  oss << "queue_read:" << global::queue_read.msg_queue_.size() << std::endl;
  oss << "queue_work:" << global::queue_work.msg_queue_.size() << std::endl;
  oss << "queue_write:" << global::queue_write.msg_queue_.size() << std::endl;
  oss << "\n" << std::endl;

  oss << "amount:" << std::endl;
  std::vector<std::string> baselist;

  MagicSingleton<AccountManager>::GetInstance()->GetAccountList(baselist);
  for (auto &i : baselist) {
    uint64_t amount = 0;
    GetBalanceByUtxo(i, amount);
    oss << i + ":" + std::to_string(amount) << std::endl;
  }
  oss << "\n" << std::endl;

  std::vector<Node> nodeList =
      MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
  oss << "Public PeerNode size is: " << nodeList.size() << std::endl;
  oss << MagicSingleton<PeerNode>::GetInstance()->nodelist_info(nodeList);

  oss << std::endl << std::endl;

  res.set_content(oss.str(), "text/plain");
}
//
//
void api_get_block(const Request &req, Response &res) {
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

  num = num > 2000 ? 2000 : num;

  if (top < 0 || num < 0) {
    ERRORLOG("api_get_block top < 0||num < 0");
    return;
  }

  DBReader db_reader;
  uint64_t mytop = 0;
  db_reader.GetBlockTop(mytop);
  if (top > (int)mytop) {
    ERRORLOG("api_get_block begin > mytop");
    return;
  }
  int k = 0;
  uint64_t countNum = top + num;
  if (countNum > mytop) {
    countNum = mytop;
  }
  for (auto i = top; i <= countNum; i++) {
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
      BlockInvert(strHeader, block);
      // blocks[k++] = httplib::detail::base64_encode(strHeader);
      blocks[k++] = block;
    }
  }
  std::string str = blocks.dump();
  res.set_content(str, "application/json");
}

void api_filter_height(const Request &req, Response &res) {
  std::ostringstream oss;

  DBReader db_reader;
  uint64_t myTop = 0;
  db_reader.GetBlockTop(myTop);

  std::vector<Node> nodeList =
      MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
  std::vector<Node> filterNodes;

  for (auto &node : nodeList) {
    if (node.height == myTop) {
      filterNodes.push_back(node);
    }
  }

  oss << "My Top : " << myTop << std::endl;
  oss << "Public PeerNode size is: " << filterNodes.size() << std::endl;
  oss << MagicSingleton<PeerNode>::GetInstance()->nodelist_info(filterNodes);

  oss << std::endl << std::endl;

  res.set_content(oss.str(), "text/plain");
}

void api_start_autotx(const Request &req, Response &res) {
  // std::ostringstream oss;
  // oss << "end auto tx:" << std::endl;
  if (!flag) {
    std::cout << "flag =" << flag << std::endl;
    std::cout << "api_start_autotx is going " << std::endl;
    return;
  }

  // int tranNum = 0;
  // if (req.has_param("tranNum"))
  // {
  //     tranNum = atol(req.get_param_value("tranNum").c_str());
  // }
  int Interval = 0;
  if (req.has_param("Interval")) {
    Interval = atol(req.get_param_value("Interval").c_str());
  }
  int Interval_frequency = 0;
  if (req.has_param("Interval_frequency")) {
    Interval_frequency =
        atol(req.get_param_value("Interval_frequency").c_str());
  }

  std::cout << "Interval =" << Interval << std::endl;
  std::cout << "Interval_frequency =" << Interval_frequency << std::endl;
  std::vector<std::string> addrs;

  // MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();
  MagicSingleton<AccountManager>::GetInstance()->GetAccountList(addrs);

  std::vector<std::string>::iterator it = std::find(
      addrs.begin(), addrs.end(),
      MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
  if (it != addrs.end()) {
    addrs.erase(it);
  }

  // std::random_shuffle(addrs.begin(),addrs.end());

  flag = false;

  ThreadTest::set_StopTx_flag(flag);
  std::thread th(&ThreadTest::test_createTx, Interval_frequency, addrs,
                 Interval);
  th.detach();
  return;
}
void api_status_autotx(const Request &req, Response &res) {
  std::ostringstream oss;
  bool flag = false;
  ThreadTest::get_StopTx_flag(flag);
  if (!flag) {
    oss << "auto tx is going :" << std::endl;
  } else {
    oss << "auto tx is end!:" << std::endl;
  }
  res.set_content(oss.str(), "text/plain");
}

void api_end_autotx(const Request &req, Response &res) {
  std::ostringstream oss;
  oss << "end auto tx:" << std::endl;

  flag = true;
  ThreadTest::set_StopTx_flag(flag);
  res.set_content(oss.str(), "text/plain");
}

void jsonrpc_get_height(const Request &req, Response &res) {
  the_top ack_t;
  DBReader db_reader;
  uint64_t top = 0;
  db_reader.GetBlockTop(top);
  ack_t.top = std::to_string(top);

  res.set_content(ack_t.paseToString(), "application/json");
}

void jsonrpc_get_balance(const Request &req, Response &res) {
  balance_req req_t;
  balance_ack ack_t;
  req_t.paseFromJson(req.body);
  std::string address = req_t.addr;

  if (!CheckBase58Addr(address)) {
    ack_t.ErrorCode = "-1";
    ack_t.ErrorMessage = "address is invalid ";
  }

  uint64_t balance = 0;
  if (GetBalanceByUtxo(address.c_str(), balance) != 0) {

    ack_t.ErrorCode = "-2";
    ack_t.ErrorMessage = "search balance failed";
  }
  ack_t.balance = std::to_string(balance);
  res.set_content(ack_t.paseToString(), "application/json");
}

void jsonrpc_get_gas(const Request &req, Response &res)
{

      gas_req req_t;
      gas_ack ack_t;
      req_t.paseFromJson(req.body);

      // Find utxo
      uint64_t total = 0;
      std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
      std::vector<std::string> fromAddr;
      fromAddr.push_back(req_t.fromaddr);
      int ret = TxHelper::FindUtxo(fromAddr, TxHelper::kMaxVinSize, total, setOutUtxos);
      if (ret != 0)
      {
          ack_t.ErrorCode = "-1";
          ack_t.ErrorMessage = "FindUtxo failed!";
      }
      if (setOutUtxos.empty())
      {
          ack_t.ErrorCode = "-2";
          ack_t.ErrorMessage = "utxo is empty!";
      }

      CTransaction outTx;
      outTx.Clear();

      CTxUtxo * txUtxo = outTx.mutable_utxo();
      
      // Fill Vin
      std::set<string> setTxowners;
      for (auto & utxo : setOutUtxos)
      {
        setTxowners.insert(utxo.addr);
      }
      if (setTxowners.empty())
      {
          ack_t.ErrorCode = "-3";
          ack_t.ErrorMessage = "Tx owner is empty!";
      }

      uint32_t n = 0;
      for (auto & owner : setTxowners)
      {
        txUtxo->add_owner();
        CTxInput * vin = txUtxo->add_vin();
        for (auto & utxo : setOutUtxos)
        {
          if (owner == utxo.addr)
          {
            CTxPrevOutput * prevOutput = vin->add_prevout();
            prevOutput->set_hash(utxo.hash);
            prevOutput->set_n(utxo.n);
          }
        }
        vin->set_sequence(n++);
      }

      outTx.set_data("");
      outTx.set_type(global::ca::kTxSign);

      uint64_t gas = 0;
      uint64_t expend = 0;
      std::map<std::string, int64_t> targetAddrs;
      targetAddrs.insert(make_pair(req_t.toaddr, 0));
      targetAddrs.insert(make_pair(*fromAddr.rbegin(), total - expend));
      targetAddrs.insert(make_pair(global::ca::kVirtualBurnGasAddr,gas));
      if(GenerateGas(outTx, targetAddrs.size(), gas) != 0)
      {
          ack_t.ErrorCode = "-4";
          ack_t.ErrorMessage = "Generate gas fail!";
      }

      ack_t.gas = gas;
      res.set_content(ack_t.paseToString(), "application/json");
}


void api_get_block_info(const Request &req, Response &res) {
  std::string block_hash;
  if (req.has_param("block_hash")) {
    block_hash = req.get_param_value("block_hash").c_str();
  }
  if (block_hash.empty()) {
    res.set_content("get block_hash error", "text/plain");
    return;
  }

  DBReader db_reader;
  std::string strHeader;

  if (DBStatus::DB_SUCCESS !=
      db_reader.GetBlockByBlockHash(block_hash, strHeader)) {
    res.set_content("block_hash error", "text/plain");
    return;
  }
  CBlock block;

  if (!block.ParseFromString(strHeader)) {
    res.set_content("block ParseFromString error", "text/plain");
    return;
  }

  std::ostringstream ss;
  printBlock(block, false, ss);

  res.set_content(ss.str(), "text/plain");
}

void api_get_tx_info(const Request &req, Response &res) {

  get_tx_info_req req_t;
  get_tx_info_ack ack_t;
  req_t.paseFromJson(req.body);

  DBReader db_reader;
  std::string BlockHash;
  std::string strHeader;
  unsigned int BlockHeight;
  if (DBStatus::DB_SUCCESS !=
      db_reader.GetTransactionByHash(req_t.txhash, strHeader)) {
    ack_t.ErrorCode = "-1";
    ack_t.ErrorMessage = "txhash error";
    res.set_content(ack_t.paseToString(), "application/json");
    return;
  }

  if (DBStatus::DB_SUCCESS !=
      db_reader.GetBlockHashByTransactionHash(req_t.txhash, BlockHash)) {
    ack_t.ErrorCode = "-2";
    ack_t.ErrorMessage = "Block error";
    res.set_content(ack_t.paseToString(), "application/json");
    return;
  }

  if (DBStatus::DB_SUCCESS !=
      db_reader.GetBlockHeightByBlockHash(BlockHash, BlockHeight)) {
    ack_t.ErrorCode = "-3";
    ack_t.ErrorMessage = "Block error";
    res.set_content(ack_t.paseToString(), "application/json");
    return;
  }

  CTransaction tx;
  if (!tx.ParseFromString(strHeader)) {
    ack_t.ErrorCode = "-4";
    ack_t.ErrorMessage = "tx ParseFromString error";
    res.set_content(ack_t.paseToString(), "application/json");
    return;
  }

  std::string txStr;
  google::protobuf::util::Status status =
      google::protobuf::util::MessageToJsonString(tx, &txStr);
  ack_t.tx = txStr;
  ack_t.blockhash = BlockHash;
  ack_t.blockheight = BlockHeight;
  res.set_content(ack_t.paseToString(), "application/json");
}

uint64_t get_circulation_before_yesterday(uint64_t cur_time) {
  DBReadWriter db_writer;
  std::vector<std::string> utxos;
  std::string strTx;
  CTransaction tx;
  {
    uint64_t Period =
        MagicSingleton<TimeUtil>::GetInstance()->getPeriod(cur_time);
    auto ret = db_writer.GetBonusUtxoByPeriod(Period, utxos);
    if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret) {
      return -2;
    }
  }
  uint64_t Claim_Vout_amount = 0;
  uint64_t TotalClaimDay = 0;
  for (auto utxo = utxos.rbegin(); utxo != utxos.rend(); utxo++) {
    if (db_writer.GetTransactionByHash(*utxo, strTx) != DBStatus::DB_SUCCESS) {
      return -3;
    }
    if (!tx.ParseFromString(strTx)) {
      return -4;
    }
    uint64_t claim_amount = 0;
    if ((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx) {
      nlohmann::json data_json = nlohmann::json::parse(tx.data());
      nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
      tx_info["BonusAmount"].get_to(claim_amount);
      TotalClaimDay += claim_amount;
    }
  }

  return TotalClaimDay;
}

void api_get_rates_info(const Request &req, Response &res) {
  typedef boost::multiprecision::cpp_bin_float_50 cpp_bin_float;
  uint64_t cur_time =
      MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
  uint64_t TotalCirculationYesterday = 0;
  uint64_t TotalinvestYesterday = 0;
  uint64_t TotalCirculation = 0;
  DBReadWriter db_writer;
  nlohmann::json jsObject;
  int ret = 0;

  do {
    ret = GetTotalCirculationYesterday(cur_time, TotalCirculationYesterday);
    if (ret < 0) {
      jsObject["Code"] = std::to_string(ret -= 100);
      jsObject["Message"] = "GetTotalCirculation error";
      break;
    }


    uint64_t TotalBrunYesterday = 0;
    ret = GetTotalBurnYesterday(cur_time, TotalBrunYesterday);
    if (ret < 0) {
      jsObject["Code"] = std::to_string(ret -= 200);
      jsObject["Message"] = "GetTotalBurn error";
      break;
    }

    TotalCirculationYesterday = TotalCirculationYesterday - TotalBrunYesterday;
    uint64_t ClaimReward = get_circulation_before_yesterday(cur_time);
    jsObject["LastClaimReward"] = std::to_string(ClaimReward);
    jsObject["TotalCirculatingSupply"] = std::to_string(TotalCirculationYesterday);
    jsObject["TotalBurn"] = std::to_string(TotalBrunYesterday);
    ret = GetTotalInvestmentYesterday(cur_time, TotalinvestYesterday);
    if (ret < 0) {
      jsObject["Code"] = std::to_string(ret -= 400);
      jsObject["Message"] = "GetTotalInvestment error";
      break;
    }
    jsObject["TotalStaked"] = std::to_string(TotalinvestYesterday);

    uint64_t StakeRate =
        ((double)TotalinvestYesterday / TotalCirculationYesterday + 0.005) *
        100;
    if (StakeRate <= 25) {
      StakeRate = 25;
    } else if (StakeRate >= 90) {
      StakeRate = 90;
    }

    jsObject["StakingRate"] = std::to_string((double)TotalinvestYesterday /
                                             TotalCirculationYesterday);

    double InflationRate = .0f;
    ret =
        ca_algorithm::GetInflationRate(cur_time, StakeRate - 1, InflationRate);
    if (ret < 0) {
      jsObject["Code"] = std::to_string(ret -= 500);
      jsObject["Message"] = "GetInflationRate error";
      break;
    }

    std::stringstream ss;
    ss << std::setprecision(8) << InflationRate;
    std::string InflationRateStr = ss.str();
    ss.str(std::string());
    ss.clear();
    ss << std::setprecision(2) << (StakeRate / 100.0);
    std::string StakeRateStr = ss.str();
    cpp_bin_float EarningRate0 =
        static_cast<cpp_bin_float>(std::to_string(global::ca::kDecimalNum)) *
        (static_cast<cpp_bin_float>(InflationRateStr) /
         static_cast<cpp_bin_float>(StakeRateStr));
    ss.str(std::string());
    ss.clear();
    ss << std::setprecision(8) << EarningRate0;

    uint64_t EarningRate1 = std::stoi(ss.str());

    double EarningRate2 = (double)EarningRate1 / global::ca::kDecimalNum;
    if (EarningRate2 > 0.34) {
      jsObject["Code"] = std::to_string(-5);
      jsObject["Message"] = "EarningRate2 error";
      break;
    }
    jsObject["CurrentAPR"] = std::to_string(EarningRate2);

    jsObject["Code"] = "0";
    jsObject["Message"] = "";

  } while (0);

  res.set_content(jsObject.dump(), "application/json");
}

bool tool_encode(const std::string &source, std::string &dest) {
  std::shared_ptr<envelop> enve = MagicSingleton<envelop>::GetInstance();
  bool bret = RSADeCode(source, enve.get(), dest);
  if (bret == false) {
    return false;
  }
  return true;
}

void deploy_contract(const Request &req, Response &res) {
  deploy_contract_req req_t;
  contract_ack ack_t;
  //CHECK_PASE_REQ_T

  bool ret_ = req_t.paseFromJson(req.body);
  if (ret_ == false) {
    return;
  }

  std::string ret = handle__deploy_contract_rpc((void *)&req_t, &ack_t);
  
  ack_t.type = "deploy_contract_req";
  ack_t.ErrorCode = "0";
  
    if (ret != "0") {
        auto rpcError=GetRpcError();
        if(rpcError.first!="0"){
            ack_t.ErrorMessage = rpcError.second;
            ack_t.ErrorCode = rpcError.first;
        }else{
            ack_t.ErrorMessage = ret;
            ack_t.ErrorCode = "-1";
        }
    }
  res.set_content(ack_t.paseToString(), "application/json");
}

void get_stakeutxo(const Request &req, Response &res) {
  get_stakeutxo_ack ack_t;
  get_stakeutxo_req req_t;

  ack_t.ErrorCode = "0";

  if (!req_t.paseFromJson(req.body)) {
    errorL("bad error pase fail");
    ack_t.ErrorCode = "-1";
    ack_t.ErrorMessage = "bad error pase fail";
    res.set_content(ack_t.paseToString(), "application/json");
    return;
  }

  DBReader db_reader;
  std::vector<string> utxos;
  db_reader.GetStakeAddressUtxo(req_t.fromAddr, utxos);
  std::reverse(utxos.begin(), utxos.end());
  std::map<std::string, uint64_t> output;
  // std::cout << "-- Current pledge amount: -- " << std::endl;
  for (auto &utxo : utxos) {
    std::string txRaw;
    db_reader.GetTransactionByHash(utxo, txRaw);
    CTransaction tx;
    tx.ParseFromString(txRaw);
    uint64_t value = 0;
    for (auto &vout : tx.utxo().vout()) {
      if (vout.addr() == global::ca::kVirtualStakeAddr) {
        value = vout.value();
        // break;
      }
      output[utxo] = value;
    }
    // std::cout << "utxo: " << utxo << " value: " << value << std::endl;
  }
  ack_t.utxos = output;
  res.set_content(ack_t.paseToString(), "application/json");
  // debugL(ack_t.paseToString());
}

void get_disinvestutxo(const Request &req, Response &res) {
  get_disinvestutxo_ack ack_t;
  get_disinvestutxo_req req_t;
  // std::string text;
  // bool bret= tool_encode(req.body,text);
  // if(bret==false){
  //     errorL("error ras error");
  //     ack_t.ErrorCode="-1";
  //     ack_t.ErrorMessage="error ras fail";
  //     res.set_content(ack_t.paseToString(), "application/json");
  //     return ;
  // }

  ack_t.ErrorCode = "0";

  if (!req_t.paseFromJson(req.body)) {
    errorL("bad error pase fail");
    ack_t.ErrorCode = "-1";
    ack_t.ErrorMessage = "bad error pase fail";
    res.set_content(ack_t.paseToString(), "application/json");
    return;
  }

  DBReader db_reader;
  std::vector<string> vecUtxos;
  db_reader.GetBonusAddrInvestUtxosByBonusAddr(req_t.toAddr, req_t.fromAddr,
                                               vecUtxos);
  std::reverse(vecUtxos.begin(), vecUtxos.end());
  // std::cout << "======================================= Current invest
  // amount: =======================================" << std::endl;
  //  for (auto &utxo : vecUtxos)
  //  {
  //      std::cout << "Utxo: " << utxo << std::endl;
  //  }
  // std::cout <<
  // "======================================================================================================"
  // << std::endl;

  ack_t.utxos = vecUtxos;
  res.set_content(ack_t.paseToString(), "application/json");
}

void get_transaction(const Request &req, Response &res) {
  tx_ack ack_t;
  tx_req req_t;

  ack_t.ErrorCode = "0";
  bool bret = req_t.paseFromJson(req.body);

  
  //debugL(req.body);
  DEBUGLOG(req.body);
  if (bret == false) {
    errorL("bad error pase fail");
    ack_t.ErrorCode = "-1";
    ack_t.ErrorMessage = "bad error pase fail";
    res.set_content(ack_t.paseToString(), "application/json");
    return;
  }
  std::map<std::string, int64_t> toAddr;

  for (auto iter = req_t.toAddr.begin(); iter != req_t.toAddr.end(); iter++) {
    
    toAddr[iter->first]=(std::stod(iter->second) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
    
  }

  std::string strError =
      TxHelper::ReplaceCreateTxTransaction_test(req_t.fromAddr, toAddr, &ack_t);
  if (strError != "0") {
    ack_t.ErrorMessage = strError;
    ack_t.ErrorCode = "-5";
  }
  res.set_content(ack_t.paseToString(), "application/json");
}

void get_stake(const Request &req, Response &res) {
  get_stake_req req_t;
  // rpc_ack ack_t;
  tx_ack ack_t;

  req_t.paseFromJson(req.body);

  std::string fromAddr = req_t.fromAddr;

   
  uint64_t stake_amount = (std::stod(req_t.stake_amount) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
  
  int32_t PledgeType = std::stoll(req_t.PledgeType);

  ack_t.type = "getStake_ack";
  ack_t.ErrorCode = "0";

  std::string strError = TxHelper::ReplaceCreateStakeTransaction_test(
      fromAddr, stake_amount, PledgeType, &ack_t);
  if (strError != "0") {
    ack_t.ErrorMessage = strError;
    ack_t.ErrorCode = "-1";
  }

  res.set_content(ack_t.paseToString(), "application/json");
}

void get_unstake(const Request &req, Response &res) {
  get_unstake_req req_t;
  tx_ack ack_t;

  // std::string text;
  // bool bret= tool_encode(req.body,text);
  // if(bret==false){
  //     errorL("error ras error");
  //     ack_t.ErrorCode="-1";
  //     ack_t.ErrorMessage="error ras fail";
  //     res.set_content(ack_t.paseToString(), "application/json");
  //     return ;
  // }

  req_t.paseFromJson(req.body);

  std::string fromAddr = req_t.fromAddr;
  std::string utxo_hash = req_t.utxo_hash;

  ack_t.type = "getUnstake_ack";
  ack_t.ErrorCode = "0";

  std::string strError = TxHelper::ReplaceCreatUnstakeTransaction_test(
      fromAddr, utxo_hash, &ack_t);
  if (strError != "0") {
    ack_t.ErrorMessage = strError;
    ack_t.ErrorCode = "-1";
  }

  res.set_content(ack_t.paseToString(), "application/json");
}

void get_invest(const Request &req, Response &res) {
  get_invest_req req_t;
  tx_ack ack_t;

  req_t.paseFromJson(req.body);

  std::string fromAddr = req_t.fromAddr;
  std::string toAddr = req_t.toAddr;

  uint64_t invest_amout = (std::stod(req_t.invest_amount) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;

  int32_t investType = std::stoll(req_t.investType);

  ack_t.type = "getInvest_ack";
  ack_t.ErrorCode = "0";

  std::string strError = TxHelper::ReplaceCreateInvestTransaction_test(
      fromAddr, toAddr, invest_amout, investType, &ack_t);
  if (strError != "0") {
    ack_t.ErrorMessage = strError;
    ack_t.ErrorCode = "-1";
  }

  res.set_content(ack_t.paseToString(), "application/json");
}

void get_disinvest(const Request &req, Response &res) {
  get_disinvest_req req_t;
  tx_ack ack_t;

  req_t.paseFromJson(req.body);

  std::string fromAddr = req_t.fromAddr;
  std::string toAddr = req_t.toAddr;
  std::string utxo_hash = req_t.utxo_hash;

  ack_t.type = "getDisInvest_ack";
  ack_t.ErrorCode = "0";

  std::string strError = TxHelper::ReplaceCreateDisinvestTransaction_test(
      fromAddr, toAddr, utxo_hash, &ack_t);
  if (strError != "0") {
    ack_t.ErrorMessage = strError;
    ack_t.ErrorCode = "-1";
  }

  res.set_content(ack_t.paseToString(), "application/json");
}

void get_declare(const Request &req, Response &res) {
  get_declare_req req_t;
  tx_ack ack_t;

  // std::string text;
  // bool bret= tool_encode(req.body,text);
  // if(bret==false){
  //     errorL("error ras error");
  //     ack_t.ErrorCode="-1";
  //     ack_t.ErrorMessage="error ras fail";
  //     res.set_content(ack_t.paseToString(), "application/json");
  //     return ;
  // }

  req_t.paseFromJson(req.body);

  std::string fromAddr = req_t.fromAddr;
  std::string toAddr = req_t.toAddr;
  uint64_t amount = std::stoll(req_t.amount) * global::ca::kDecimalNum;

  std::string multiSignPub;
  Base64 base_;
  multiSignPub = base_.Decode((const char *)req_t.multiSignPub.c_str(),
                              req_t.multiSignPub.size());

  std::vector<std::string> signAddrList = req_t.signAddrList;
  uint64_t signThreshold = std::stoll(req_t.signThreshold);

  ack_t.type = "get_declare_req";
  ack_t.ErrorCode = "0";

  std::string strError = TxHelper::ReplaceCreateDeclareTransaction_test(
      fromAddr, toAddr, amount, multiSignPub, signAddrList, signThreshold,
      &ack_t);
  if (strError != "0") {
    ack_t.ErrorMessage = strError;
    ack_t.ErrorCode = "-1";
  }

  res.set_content(ack_t.paseToString(), "application/json");
}

void get_bonus(const Request &req, Response &res) {
  get_bonus_req req_t;
  tx_ack ack_t;

  // std::string text;
  // bool bret= tool_encode(req.body,text);
  // if(bret==false){
  //     errorL("error ras error");
  //     ack_t.ErrorCode="-1";
  //     ack_t.ErrorMessage="error ras fail";
  //     res.set_content(ack_t.paseToString(), "application/json");
  //     return ;
  // }

  req_t.paseFromJson(req.body);

  std::string Addr = req_t.Addr;

  ack_t.ErrorCode = "0";

  std::string strError =
      TxHelper::ReplaceCreateBonusTransaction_test(Addr, &ack_t);
  if (strError != "0") {
    ack_t.ErrorMessage = strError;
    ack_t.ErrorCode = "-1";
  }

  res.set_content(ack_t.paseToString(), "application/json");
}

void call_contract(const Request &req, Response &res) {
  RpcErrorClear();
  call_contract_req req_t;
  contract_ack ack_t;
  //CHECK_PASE_REQ_T;

  bool ret = req_t.paseFromJson(req.body);
  if (ret == false) {
    return;
  }

  ack_t.type = "call_contract_ack";
  ack_t.ErrorCode = "0";

  std::string ret_ = handle__call_contract_rpc((void *)&req_t, &ack_t);
      if (ret_ != "0") {
      auto rpcError=GetRpcError();
      if(rpcError.first!="0"){
          ack_t.ErrorMessage = rpcError.second;
          ack_t.ErrorCode = rpcError.first;
      }else{
          ack_t.ErrorMessage = ret_;
          ack_t.ErrorCode = "-1";
      }
  }
  res.set_content(ack_t.paseToString(), "application/json");
}

void send_message(const Request &req, Response &res) {
  tx_ack ack_t;
  rpc_ack ack_nn;
  ack_t.paseFromJson(req.body);
  CTransaction tx;
  Vrf info;
  int height;
  TxHelper::vrfAgentType type;
  google::protobuf::util::Status status =
      google::protobuf::util::JsonStringToMessage(ack_t.txJson, &tx);
  status = google::protobuf::util::JsonStringToMessage(ack_t.vrfJson, &info);
  height = std::stoi(ack_t.height);
  type = (TxHelper::vrfAgentType)std::stoi(ack_t.txType);
  std::string txHash = getsha256hash(tx.SerializeAsString());
  ack_nn.txhash = txHash;
  int ret = TxHelper::sendMessage(tx, height, info, type);
  ack_nn.ErrorCode = std::to_string(ret);

  res.set_content(ack_nn.paseToString(), "application/json");
}

void get_rsa_pub(const Request &req, Response &res) {
  rsa_pubstr_ack ack_t;
  std::shared_ptr<envelop> enve = MagicSingleton<envelop>::GetInstance();
  std::string pubstr = enve->getPubstr();
  Base64 base_;
  ack_t.rsa_pubstr =
      base_.Encode((const unsigned char *)pubstr.c_str(), pubstr.size());
  res.set_content(ack_t.paseToString(), "application/json");
}

void get_isonchain(const Request &req, Response &res) {
  get_isonchain_req req_j;
  req_j.paseFromJson(req.body);
  IsOnChainAck ack;
  std::shared_ptr<IsOnChainReq> req_t = std::make_shared<IsOnChainReq>();
  req_t->add_txhash(req_j.txhash);
  req_t->set_version(global::kVersion);
  auto current_time =
      MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
  req_t->set_time(current_time);

  int ret = 0;
  ret = SendCheckTxReq(req_t, ack);
  std::string debug_value;
  google::protobuf::util::Status status =
      google::protobuf::util::MessageToJsonString(ack, &debug_value);

  get_isonchain_ack ack_t;
  auto sus = ack.percentage();
  auto rate = sus.at(0);
  ack_t.txhash = rate.hash();
  ack_t.pro = std::to_string(rate.rate());
  ack_t.ErrorCode = std::to_string(ret);
  res.set_content(ack_t.paseToString(), "application/json");
}

void get_deployer(const Request &req, Response &res) {
  deployers_ack ack_t;
  DBReader data_reader;
  std::vector<std::string> vecDeployers;
  data_reader.GetAllDeployerAddr(vecDeployers);
  std::cout << "=====================deployers====================="
            << std::endl;
  for (auto &deployer : vecDeployers) {
    std::cout << "deployer: " << deployer << std::endl;
  }
  ack_t.deployers = vecDeployers;

  res.set_content(ack_t.paseToString(), "application/json");
}

void get_deployerutxo(const Request &req, Response &res) {
  deploy_utxo_req req_t;
  deploy_utxo_ack ack_t;
  req_t.paseFromJson(req.body);

  DBReader data_reader;
  std::vector<std::string> vecDeployUtxos;
  data_reader.GetDeployUtxoByDeployerAddr(req_t.addr, vecDeployUtxos);
  std::cout << "=====================deployed utxos====================="
            << std::endl;
  for (auto &deploy_utxo : vecDeployUtxos) {
    std::cout << "deployed utxo: " << deploy_utxo << std::endl;
  }
  std::cout << "=====================deployed utxos====================="
            << std::endl;
  ack_t.utxos = vecDeployUtxos;
  res.set_content(ack_t.paseToString(), "application/json");
}

void get_all_stake_node_list_ack(const Request & req,Response & res){
    int ret;
   GetAllStakeNodeListAck ack;
   std::shared_ptr<GetAllStakeNodeListReq> req_t;
    ret = GetAllStakeNodeListReqImpl(req_t, ack);
    if(ret!=0){
        ack.set_code(ret);
    }
    std::string jsonstr;
    google::protobuf::util::Status status =
    google::protobuf::util::MessageToJsonString(ack, &jsonstr);
       if(!status.ok()){
            errorL("protobuff to json fail");
            jsonstr="protobuff to json fail";
       }
    res.set_content(jsonstr.c_str(),"application/json");
}

void get_restinvest(const Request &req, Response &res) {
    GetRestInvestAmountAck ack;
    get_restinverst_req req_c;
    req_c.paseFromJson(req.body);
    std::shared_ptr<GetRestInvestAmountReq> req_t =
        std::make_shared<GetRestInvestAmountReq>();
    req_t->set_base58(req_c.addr);
    req_t->set_version(global::kVersion);
    int ret = GetRestInvestAmountReqImpl(req_t, ack);
    get_restinverst_ack ack_t;
    ack_t.addr = ack.base58();
    ack_t.amount = std::to_string(ack.amount());

    res.set_content(ack_t.paseToString(), "application/json");
}

void confirm_transaction(const Request &req, Response &res) 
{
    confirm_transaction_req req_j;
    confirm_transaction_ack ack_t;
    req_j.paseFromJson(req.body);

    uint64_t height = std::stoll(req_j.height);
    ConfirmTransactionAck ack;
    std::shared_ptr<ConfirmTransactionReq> req_t = std::make_shared<ConfirmTransactionReq>();
    req_t->add_txhash(req_j.txhash);
    req_t->set_version(global::kVersion);
    req_t->set_height(height);
    auto currentTime =
        MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    req_t->set_time(currentTime);

    int ret = 0;
    ret = SendConfirmTransactionReq(req_t, ack);
    if(ret != 0)
    {
        ERRORLOG("sussize is empty{}",ret);
        ack_t.ErrorMessage = ack.message();
        ack_t.ErrorCode = std::to_string(ret);
        res.set_content(ack_t.paseToString(),"application/json");
        return;
    }
    std::string debugValue;
    google::protobuf::util::Status status =
        google::protobuf::util::MessageToJsonString(ack, &debugValue);
     DEBUGLOG("http_api.cpp:ConfirmTransaction ack_T.paseToString {}",debugValue);

   
    auto sus = ack.percentage();
    auto susSize = sus.size();
    if(susSize == 0)
    {
        ERRORLOG("sussize is empty{}",susSize);
        ack_t.ErrorMessage = "susSize node list is empty";
        ack_t.ErrorCode = "-6";
        res.set_content(ack_t.paseToString(),"application/json");
        return;
    }
    std::string received_size = std::to_string(ack.received_size());
    int receivedSizeNum = stoi(received_size);

    std::vector<Node> nodelist = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
    int sendsize = nodelist.size();
    if(receivedSizeNum < sendsize * 0.5)
    {
      ack_t.ErrorMessage = "The amount received was too small to verify transaction on-chain";
      ack_t.ErrorCode = "-7";
      res.set_content(ack_t.paseToString(),"application/json");
      return;
    }
    //Generally，the rate mustn't less than 70 % for receivedSizeNum
    auto rate = sus.at(0);
    ack_t.txhash = rate.hash();
    ack_t.percent = std::to_string(rate.rate());
    ack_t.ErrorCode = std::to_string(ret);
    ack_t.sendsize = std::to_string(ack.send_size());
    ack_t.receivedsize = std::to_string(ack.received_size());
    
    res.set_content(ack_t.paseToString(), "application/json");
}

void ApiIp(const Request &req, Response &res) 
{
    std::ostringstream oss;
    std::map<uint64_t,std::map<std::string, int>> stakeResult;
    std::map<uint64_t,std::map<std::string, int>> unStakeResult;
    MagicSingleton<UnregisterNode>::GetInstance()->GetIpMap(stakeResult,unStakeResult);
    oss << "total size:" << stakeResult.size() + unStakeResult.size() << std::endl;
    oss << "stake size: " << stakeResult.size() << std::endl;
    for (auto &item : stakeResult) 
    {
        oss << "---------------------------------------------------------------"
               "----------------------"
            << std::endl;
        oss << MagicSingleton<TimeUtil>::GetInstance()->formatUTCTimestamp(
                   item.first)
            << std::endl;
        for (auto i : item.second) 
        {
            oss << "Addr: " << i.first
                << "  Count: " << i.second << std::endl;
        }
    }

    oss << "unstake size: " << unStakeResult.size() << std::endl;
    for (auto &item : unStakeResult) 
    {
        oss << "---------------------------------------------------------------"
               "----------------------"
            << std::endl;
        oss << MagicSingleton<TimeUtil>::GetInstance()->formatUTCTimestamp(
                   item.first)
            << std::endl;
        for (auto i : item.second) 
        {
            oss << "Addr: " << i.first
                << "  Count: " << i.second << std::endl;
        }
    }

    res.set_content(oss.str(), "text/plain");
}

void SendContractMessage(const Request & req,Response & res){
    contract_ack ack;
    rpc_ack ack_t;
    //debugL(req.body);
    DEBUGLOG(req.body);
    if(ack.paseFromJson(req.body)!= true)
    {
        errorL("pase fail");
        return;
    }
    ContractTxMsgReq ContractMsg;
    CTransaction tx;
    google::protobuf::util::JsonStringToMessage(ack.contractJs, &ContractMsg);
    google::protobuf::util::JsonStringToMessage(ack.txJs, &tx);

    std::string txHash = getsha256hash(tx.SerializeAsString());
    tx.set_hash(txHash);
    
    ack_t.txhash=txHash;
    ack_t.type = "SendContractMessage";
    ack_t.ErrorCode = "0";
  
   ContractTempTxMsgReq txReq= ContractMsg.txmsgreq();
   TxMsgInfo info=txReq.txmsginfo();
   info.set_tx(tx.SerializeAsString());
   txReq.clear_txmsginfo();
   TxMsgInfo *info_p=txReq.mutable_txmsginfo();
   info_p->CopyFrom(info);
   ContractMsg.clear_txmsgreq();
   ContractTempTxMsgReq * txReq_p=ContractMsg.mutable_txmsgreq();
   txReq_p->CopyFrom(txReq);
    auto msg = make_shared<ContractTxMsgReq>(ContractMsg);
   DropCallShippingTx(msg,tx);
    res.set_content(ack_t.paseToString(), "application/json");
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
    
}
namespace RprContract{
struct ContractJob{
    std::string fromAddr;
    std::string deployer;
    std::string deployutxo;
    std::string arg;
    std::string tip;
    std::string money;
};

std::vector<ContractJob> jobs;
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
            ContractJob job;
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
void ContrackInvke(ContractJob job){
    

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
}

//
void test_contact_thread(const Request &req, Response &res) {
  nlohmann::json block;
  nlohmann::json blocks;

  int time = 0;
  if (req.has_param("time")) {
    time = atol(req.get_param_value("time").c_str());
  }
  int second = 0;
  if (req.has_param("second")) {
    second = atol(req.get_param_value("second").c_str());
  }
  int much = 0;
  if (req.has_param("much")) {
    much = atol(req.get_param_value("much").c_str());
  }

    RprContract::ReadContract_json("contract.json");
    std::vector<std::string> acccountlist;
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(acccountlist);

    RprContract::jobs_index=0;
    RprContract::perrnode_index=0;

    int oneSecond=0;
    int count = 1;
    while(time){
        oneSecond++;
        std::cout <<"count" <<count << std::endl;
        RprContract::jobs[RprContract::jobs_index].fromAddr=acccountlist[RprContract::perrnode_index];
        RprContract::test_pool.schedule(boost::bind(RprContract::ContrackInvke, RprContract::jobs[RprContract::jobs_index]));
        std::thread th=std::thread(RprContract::ContrackInvke,RprContract::jobs[RprContract::jobs_index]);
        th.detach();
        RprContract::jobs_index=++RprContract::jobs_index%RprContract::jobs.size();
        RprContract::perrnode_index=++RprContract::perrnode_index%acccountlist.size();
        ::usleep(second *1000 *1000 / much);
        if(oneSecond == much){
            time--;
            oneSecond=0;
        }
        count++;
    }
}



void test_success(const Request &req, Response &res)
{
  MagicSingleton<BlockMonitor>::GetInstance()->checkTxSuccessRate();
}

void ApiStartAutoTx(const Request &req, Response &res) {
    if (!autoTxFlag) {
        ApiEndAutoTxTest(res);
        autoTxFlag = true;
        return;
    }

    if (!flag) {
        std::cout << "flag =" << flag << std::endl;
        std::cout << "ApiStartAutoTx is going " << std::endl;
        return;
    }

    int Interval = 0;
    if (req.has_param("Interval")) 
    {
        Interval = atol(req.get_param_value("Interval").c_str());
    }
    int Interval_frequency = 0;
    if (req.has_param("Interval_frequency")) 
    {
        Interval_frequency =
            atol(req.get_param_value("Interval_frequency").c_str());
    }

    std::cout << "Interval =" << Interval << std::endl;
    std::cout << "Interval_frequency =" << Interval_frequency << std::endl;
    std::vector<std::string> addrs;

    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(addrs);

    std::vector<std::string>::iterator it = std::find(
        addrs.begin(), addrs.end(),
        MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
    if (it != addrs.end()) 
    {
        addrs.erase(it);
    }

    flag = false;

    ThreadTest::SetStopTxFlag(flag);
    std::thread th(&ThreadTest::TestCreateTx, Interval_frequency, addrs,
                   Interval);
    th.detach();

    sleep(1);
    if (ApiStatusAutoTxTest(res)) 
    {
        autoTxFlag = false;
    }

    return;
}

void ApiStatusAutoTx(const Request &req, Response &res) 
{
    ApiStatusAutoTxTest(res);
}

void ApiEndAutotx(const Request &req, Response &res) 
{
    ApiEndAutoTxTest(res);
}

bool ApiStatusAutoTxTest(Response &res) 
{
    std::ostringstream oss;
    bool flag = false;
    bool stopTx = false;
    ThreadTest::GetStopTxFlag(flag);
    if (!flag) {
        oss << "auto tx is going :" << std::endl;
        stopTx = true;
    } else {
        oss << "auto tx is end!:" << std::endl;
    }
    res.set_content(oss.str(), "text/plain");
    return stopTx;
}

void ApiEndAutoTxTest(Response &res) {
    std::ostringstream oss;
    oss << "end auto tx:" << std::endl;

    flag = true;
    ThreadTest::SetStopTxFlag(flag);
    res.set_content(oss.str(), "text/plain");
}

void jsonrpc_get_utxo(const Request &req, Response &res) 
{
  utxo_req req_t;
  utxo_ack ack_t;
  req_t.paseFromJson(req.body);
  std::string address = req_t.addr;
  std::vector<std::string> utxoHashs;
  std::string balance;
  if (!CheckBase58Addr(address)) {
    ack_t.ErrorCode = "-1";
    ack_t.ErrorMessage = "address is invalid ";
    DEBUGLOG("address is invalid");
  }
  DBReader dbreader;
  if(DBStatus::DB_SUCCESS != dbreader.GetUtxoHashsByAddress(address, utxoHashs))
  {
    ack_t.ErrorCode = "-1";
    ack_t.ErrorMessage = "GetUtxoHashsByAddress error";
    DEBUGLOG("GetUtxoHashsByAddress error");
    std::cout <<"GetUtxoHashsByAddress error";
  }
    
    //Get utxo hash value from utxo hash
  nlohmann::json utxo;
  for(auto &i : utxoHashs)
  {
  if(DBStatus::DB_SUCCESS != dbreader.GetUtxoValueByUtxoHashs(i, address, balance))
  {
    ack_t.ErrorCode = "-2";
    ack_t.ErrorMessage = "GetUtxoValueByUtxoHashs error";
    DEBUGLOG("GetUtxoValueByUtxoHashs error");
     std::cout <<"GetUtxoValueByUtxoHashs error";
  }
  ack_t.utxo  = i;
  ack_t.balance = balance;
  }
  ack_t.ErrorCode = "0";
  ack_t.ErrorMessage = "No Error";
  ack_t.type = "utxo_ack";
  res.set_content(ack_t.paseToString(), "application/json");
}

void api_get_utxo(const Request &req, Response &res) 
{
  utxo_ack ack_t;
  std::string address;
  std::string str ;
  if (req.has_param("address")) {
    address = req.get_param_value("address");
  }


  std::vector<std::string> utxoHashs;
  std::string balance;
  if (!CheckBase58Addr(address)) {
    DEBUGLOG("address is invalid");
  }
  DBReader dbreader;
  if(DBStatus::DB_SUCCESS != dbreader.GetUtxoHashsByAddress(address, utxoHashs))
  {
    DEBUGLOG("GetUtxoHashsByAddress error");
    std::cout <<"GetUtxoHashsByAddress error";
  }
    
  //Get utxo hash value from utxo hash
  nlohmann::json utxo;
  for(auto &i : utxoHashs)
  {
  if(DBStatus::DB_SUCCESS != dbreader.GetUtxoValueByUtxoHashs(i, address, balance))
  {
    DEBUGLOG("GetUtxoValueByUtxoHashs error");
    std::cout <<"GetUtxoValueByUtxoHashs error";
  }
  ack_t.utxo  = i;
  ack_t.balance = balance;
  }
  ack_t.ErrorCode = "0";
  ack_t.ErrorMessage = "No Error";
  
  res.set_content(ack_t.paseToString(), "application/json");
}