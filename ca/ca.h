#ifndef DON_CA_H
#define DON_CA_H

#include <iostream>
#include <thread>
#include <shared_mutex>
#include <string>
#include <vector>
#include <map>
#include "proto/transaction.pb.h"

#include "proto/transaction.pb.h"

extern bool bStopTx;
extern bool bIsCreateTx;

void RegisterCallback();
void TestCreateTx(const std::vector<std::string> & addrs, const int & sleepTime);
std::string PrintTime(uint64_t time);
void CreateMultiThreadAutomaticDeployContract();
void printJson();

/**
*@ Description: CA initialization
*@ param none
*@ return: return true for success and false for failure
*/
bool ca_init();




/**
*@ Description: CA cleanup function
*@ param none
*@ return: none
 */
void ca_cleanup();

/**
*@ Description: CA menu
*@ param none
*@ return: none
 */
void ca_print();



/**
 * @description: Related implementation functions used in the main menu
 * @create: 20201104   LiuMingLiang
 */
void ca_print_basic_info();
void handle_transaction();
void handle_declaration();
void handle_stake();
void handle_unstake();
void handle_invest();
void handle_disinvest();
void handle_bonus();
void handle_AccountManger();
void handle_SetdefaultAccount();
void handle_deploy_contract();

void handle_call_contract();

void handle_delegates_transaction();



void handle_export_private_key();
void handle_export_all_private_key();





//==================rpc======================
std::string handle__deploy_contract_rpc(void * arg,void *ack);

std::string handle__call_contract_rpc(void * arg,void *ack);

//NTPcheckout
int checkNtpTime();

bool isPublicIp(const std::string& ip);

int get_chain_height(unsigned int & chainHeight);

void title_version();

int SigTx(CTransaction &tx,const std::string & addr);

#endif
