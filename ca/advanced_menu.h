/**
 * *****************************************************************************
 * @file        advanced_menu.h
 * @brief       So the implementation of the menu function
 * @date        2023-09-25
 * @copyright   don
 * *****************************************************************************
 */

#ifndef __CA_ADVANCEDMENU_H_
#define __CA_ADVANCEDMENU_H_

#include <string>
#include <cstdint>
#include "db/db_api.h"




/**
 * @brief       
 */
void GenKey();

/**
 * @brief       Rollback block from Height or Rollback block from Hash 
 */
void RollBack();

/**
 * @brief       Get the stake list
 */
void GetStakeList();

/**
 * @brief      Get a list of addresses that can claim bonuses
 */
int GetBonusAddrInfo();


/**
 * @brief       
 */
void SendMessageToUser();

/**
 * @brief       
 */
void ShowMyKBucket();

/**
 * @brief       
 */
void KickOutNode();

/**
 * @brief       
 */
void TestEcho();

/**
 * @brief       
 */
void PrintReqAndAck();

#pragma region ThreeLevelMenu
/**
 * @brief       blockinfoMenu
 */
void MenuBlockInfo();

/**
 * @brief       Get the tx block info object
 * 
 * @param       top: block height
 */
void getTxBlockInfo(uint64_t& top);

/**
 * @brief       
 */
void GenMnemonic();

/**
 * @brief       
 */
void GetBalanceByUtxo();

/**
 * @brief       
 */
int ImitateCreateTxStruct();

/**
 * @brief       
 */
void TestsHandleInvest();

/**
 * @brief       
 */
void MultiTransaction();

/**
 * @brief       
 */
void GetAllPledgeAddr();

/**
 * @brief       
 */
void AutoTx();

/**
 * @brief       
 */
void GetBlockinfoByTxhash();

/**
 * @brief       
 */
void CreateMultiThreadAutomaticTransaction();

/**
 * @brief       
 */
void CreateMultiThreadAutomaticStakeTransaction();

/**
 * @brief       
 */
void AutoInvestment();

/**
 * @brief       
 */
void PrintVerifyNode();


/**
 * @brief       
 */
void TpsCount();

/**
 * @brief       
 */
void Get_InvestedNodeBlance();

/**
 * @brief       
 */
void PrintDatabaseBlock();

/**
 * @brief       
 */
void PrintTxData();

/**
 * @brief       
 */
void MultiTx();

/**
 * @brief       
 */
void testNewAddr();

/**
 * @brief       
 */
void getContractAddr();

/**
 * @brief       
 */
void PrintBenchmarkToFile();

/**
 * @brief       
 */
void GetRewardAmount();

/**
 * @brief  
 */
void TestManToOneDelegate();

/**
 * @brief  open log
 */
void OpenLog();

/**
 * @brief  close log
 */
void CloseLog();

void TestSign();
namespace ThreadTest
{
    /**
     * @brief       
     * 
     * @param       from: 
     * @param       to: 
     */
    void TestCreateTx_2(const std::string& from,const std::string& to);

    /**
     * @brief       
     * 
     * @param       tranNum: 
     * @param       addrs: 
     * @param       sleepTime: 
     */
    void TestCreateTx(uint32_t tranNum, std::vector<std::string> addrs, int sleepTime);

    /**
     * @brief       Set the Stop Tx Flag object
     * 
     * @param       flag: 
     */
    void SetStopTxFlag(const bool &flag);

    /**
     * @brief       Get the Stop Tx Flag object
     * 
     * @param       flag: 
     */
    void GetStopTxFlag(bool &flag);

}

#pragma endregion
#endif
