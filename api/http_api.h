/*
 * @Author: lyw 15035612538@163.com
 * @Date: 2024-03-26 15:27:30
 * @LastEditors: lyw 15035612538@163.com
 * @LastEditTime: 2024-04-11 15:03:27
 * @FilePath: /don/api/http_api.h
 
 */
#include "../net/http_server.h"
#include "ca_test.h"



void ca_register_http_callbacks();


#ifndef NDEBUG  //The debug build compiles these functions
void api_start_autotx(const Request & req, Response & res);

void api_end_autotx(const Request & req, Response & res);
void api_status_autotx(const Request & req, Response & res);

void api_jsonrpc(const Request & req, Response & res);

void api_print_block(const Request & req, Response & res);
void api_info(const Request & req, Response & res);
void api_info_queue(const Request & req, Response & res);
void api_get_block(const Request & req, Response & res);
void api_get_block_hash(const Request & req, Response & res);
void api_get_block_by_hash(const Request & req, Response & res);

void api_get_tx_owner(const Request & req, Response & res);
void api_cache_info(const Request & req, Response & res);

void api_pub(const Request & req, Response & res);
void api_filter_height(const Request &req, Response &res);

void test_create_multi_tx(const Request & req, Response & res);
void api_get_db_key(const Request & req, Response & res);
void add_block_callback_test(const Request & req, Response & res);

void api_get_block_info(const Request &req, Response &res);
void api_get_tx_info(const Request &req,Response &res);
void api_get_rates_info(const Request &req,Response &res);

void rollback_block_callback_test(const Request & req, Response & res);
void ApiIp(const Request &req, Response & res);

void ApiIp(const Request &req, Response & res);
void ApiPrintHundredSumHash(const Request & req, Response & res);

nlohmann::json jsonrpc_test(const nlohmann::json & param);


nlohmann::json jsonrpc_get_txids_by_height(const nlohmann::json & param);
nlohmann::json jsonrpc_get_tx_by_txid(const nlohmann::json & param);
nlohmann::json jsonrpc_create_tx_message(const nlohmann::json & param);
nlohmann::json jsonrpc_send_tx(const nlohmann::json & param);
nlohmann::json jsonrpc_send_multi_tx(const nlohmann::json & param);
nlohmann::json jsonrpc_generate_wallet(const nlohmann::json & param);
nlohmann::json jsonrpc_generate_sign(const nlohmann::json & param);
nlohmann::json jsonrpc_get_pending_transaction(const nlohmann::json & param);
nlohmann::json jsonrpc_get_failure_transaction(const nlohmann::json & param);
nlohmann::json jsonrpc_get_block_info_list(const nlohmann::json & param);
nlohmann::json jsonrpc_confirm_transaction(const nlohmann::json & param);
nlohmann::json jsonrpc_get_tx_by_addr_and_height(const nlohmann::json & param);

void ApiStartAutoTx(const Request & req, Response & res);
void ApiEndAutotx(const Request & req, Response & res);
void ApiStatusAutoTx(const Request & req, Response & res);
void ApiEndAutoTxTest(Response & res);
bool ApiStatusAutoTxTest(Response & res);
void test_contact_thread(const Request & req, Response & res);
void test_success(const Request & req, Response & res);

#endif  //#ifndef NDEBUG




void jsonrpc_get_height(const Request &req,Response &res);

void jsonrpc_get_balance(const Request &req,Response &res);
void jsonrpc_get_utxo(const Request &req, Response &res);
void jsonrpc_get_gas(const Request &req,Response &res);
void api_get_utxo(const Request &req, Response &res);
void api_get_rates_info(const Request &req,Response &res);
bool jsonrpc_get_sigvalue(const std::string& addr, const std::string& message, std::string & signature, std::string& pub);
void get_stakeutxo(const Request & req, Response & res);
void get_disinvestutxo(const Request & req, Response & res);

void get_transaction(const Request & req, Response & res);
void get_stake(const Request & req, Response & res);
void get_unstake(const Request & req, Response & res);
void get_invest(const Request & req, Response & res);
void get_disinvest(const Request & req, Response & res);
void get_declare(const Request & req, Response & res);
void get_bonus(const Request & req, Response & res);
void get_rsa_pub(const Request & req, Response & res);
void deploy_contract(const Request & req, Response & res);
void call_contract(const Request & req, Response & res);


void get_restinvest(const Request &req, Response &res);
void send_message(const Request & req, Response & res);

void get_isonchain(const Request & req, Response & res);


void confirm_transaction(const Request & req, Response & res);

void get_deployer(const Request & req, Response & res);

void get_deployerutxo(const Request & req, Response & res);

void SendContractMessage(const Request & req,Response & res);
void get_all_stake_node_list_ack(const Request & req,Response & res);