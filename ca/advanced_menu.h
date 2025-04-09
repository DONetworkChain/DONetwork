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
#include "proto/sync_block.pb.h"
#include "common/global_data.h"
#include "net/msg_queue.h"


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

void SetRpcConTxFlag(const bool flag);
void GetRpcConTxFlag(bool& flag);
void TestRpcContactThread(int TxNum, int timeout);

void SeekLog();
int HandleLogReq(const std::shared_ptr<GetLogReq> &msg, const MsgData &msgdata);
int HandleLogAck(const std::shared_ptr<GetLogAck> &msg, const MsgData &msgdata);
int HandleRpcBlockReq(const std::shared_ptr<GetRpcBlockReq> &msg, const MsgData &msgdata);
int HandleRpcBlockAck(const std::shared_ptr<GetRpcBlockAck> &msg, const MsgData &msgdata);
int HandleRpcSySInfoReq(const std::shared_ptr<GetRpcSySInfoReq> &msg, const MsgData &msgdata);
int HandleRpcSySInfoAck(const std::shared_ptr<GetRpcSySInfoAck> &msg, const MsgData &msgdata);
int HandleRpcPubReq(const std::shared_ptr<GetRpcPubReq> &msg, const MsgData &msgdata);
int HandleRpcPubAck(const std::shared_ptr<GetRpcPubAck> &msg, const MsgData &msgdata);
int HandleRpcBlockInfoReq(const std::shared_ptr<GetRpcBlockInfoReq> &msg, const MsgData &msgdata);
int HandleRpcBlockInfoAck(const std::shared_ptr<GetRpcBlockInfoAck> &msg, const MsgData &msgdata);

int SendLogAck(const std::string &startTime, const std::string &endTime, const int &lines,const std::string &addr, const std::string &msgId, const std::string &fileName);
int SendRpcBlockAck(const std::string &addr, int num, int height, const bool &hash, const bool &prehashflag, const std::string &msgId);
int SendRpcSySInfoAck(const std::string &addr, const std::string &msgId);
int SendRpcPubAck(const std::string &addr, const std::string &msgId);
int SendRpcBlockInfoAck(const std::string &addr, int num, int top, const std::string &msgId);
std::string ReadLastNLines(const std::string &inputFile, size_t n);
void SeekLogByTime();
void SeekLogByLines();
void SeekInfo();
void SendRpcBlock();
void SendRpcSySInfo();
void SendRpcPub();
void SendRpcBlockInfo();
std::string ReplaceThirdDashWithSpace(const std::string &input);
std::string CleanInvalidUtf8(const std::string &input);
bool IsValidUtf8(const std::string &data);
std::string ReplaceSpacesWithUnderscores(const std::string &input);
// new get logs
std::string FileSeekFilterLogs(const char *input_file,std::string start_time,std::string end_time);
std::string LogToDateTime(std::string strlog);
int64_t TimePointToTimeStamp(std::string dateTime);
std::chrono::time_point<std::chrono::system_clock> StringToTimePoint(const std::string &dateTime);
int FindPreviousLine(FILE *infile, long &offset, std::string &line_str,int &line_length);
int FindPreviousLine(FILE *infile, long &offset, std::string &line_str);
int FindCurrentLine(FILE *infile, long &offset, std::string &line_str, int &line_length);
int FindCurrentLine(FILE *infile, long &offset, std::string &line_str);
int FindNextLine(FILE *infile, long &offset, std::string &line_str, int &line_length);
int FindNextLine(FILE *infile, long &offset, std::string &line_str);
std::string GetExactLine(int64_t currentTimeStamp, const char *input_file,long line,const std::string &endTime);
long FindOffsetAndLowerOffset(long lowerBound, long upperBound, int mid, long upper_offset, long lower_offset,long mid_offset, FILE *infile, int64_t currentTimeStamp,long last_offset,long loop_mid_num);
//database
int GetDataBaseInitVersion(DBReadWriter *dbReadWriter);
int64_t GetLastLineTimestamp(FILE* infile);
int64_t GetFirstLineTimestamp(FILE* infile);
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
