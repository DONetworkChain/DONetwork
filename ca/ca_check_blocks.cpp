// #include <cstdint>
// #include <fstream> 
// #include <mutex>
// #include <string>
// #include <utility>

// #include "ca/ca_algorithm.h"
// #include "ca/ca_transaction.h"
// // #include "ca/ca_check_blocks.h"
// #include "ca/ca_blockhelper.h"
// #include "net/peer_node.h"
// #include "include/logging.h"
// #include "common/global_data.h"

// CheckBlocks::CheckBlocks()
// {
//     _Init();
//     _checkRuning = false;
// }

// void CheckBlocks::_Init()
// {
//     DBReader dbReader;
//     auto ret = dbReader.GetBlockComHashHeight(this->_topBlockHeight);
//     if(ret != DBStatus::DB_SUCCESS)
//     {
//         this->_topBlockHeight = 0;
//         this->_topBlockHash = "";
//     }

//     _SetTempTopData(0, "");
// }

// void CheckBlocks::StartTimer()
// {
// 	_timer.AsyncLoop(30000, [this](){
//         int ret = _ToCheck();
//         if(ret != 0)
//         {
//             ERRORLOG("_ToCheck error, error num: {}", ret);
//         }
// 	});
// }

// //get stake and invested addr
// int CheckBlocks::GetPledgeAddr(DBReadWriter& dbReader, std::vector<std::string>& pledgeAddr)
// {
//     std::vector<std::string> stakeAddr;
//     auto status = dbReader.GetStakeAddress(stakeAddr);
//     if (DBStatus::DB_SUCCESS != status && DBStatus::DB_NOT_FOUND != status)
//     {
//         ERRORLOG("GetStakeAddress error, error num:{}", -1);
//         return -1;
//     }

//     for(const auto& addr : stakeAddr)
//     {
//         if(VerifyBonusAddr(addr) != 0)
//         {
//             DEBUGLOG("{} doesn't get invested, skip", addr);
//             continue;
//         }
//         pledgeAddr.push_back(addr);
//     }
//     return 0;
// }

// std::pair<uint64_t, std::string> CheckBlocks::GetTempTopData()
// {
//     std::unique_lock<std::mutex> lock(_tempTopDateMutex);
//     return this->_tempTopDate;
// }

// void CheckBlocks::_SetTempTopData(uint64_t height, std::string hash)
// {
//     std::unique_lock<std::mutex> lock(_tempTopDateMutex);
//     _tempTopDate.first = height;
//     _tempTopDate.second = hash;
// }

// int CheckBlocks::_ToCheck()
// {
//     if(_checkRuning)
//     {
//         DEBUGLOG("_ToCheck is running");
//         return 0;
//     }

//     //ON_SCOPE_EXIT{
//     //    _checkRuning = false;
//     //};

//     _checkRuning = true;

//     _Init();
    
//     uint64_t selfNodeHeight = 0;
//     DBReadWriter dbReaderWrite;
//     auto status = dbReaderWrite.GetBlockTop(selfNodeHeight);
//     if (DBStatus::DB_SUCCESS != status)
//     {
//         ERRORLOG("GetBlockTop error, error num:{}", -1);
//         return -1;
//     }

//     if(_topBlockHeight == 0 && selfNodeHeight < 1100)
//     {
//         DEBUGLOG("Currently less than 1100 height");
//         return 0;
//     }
//     else if(selfNodeHeight < _topBlockHeight + 1100) 
//     {
//         DEBUGLOG("selfNodeHeight:{} less than top_block_height + 100:{}", selfNodeHeight, _topBlockHeight + 1100);
//         return 0;
//     }

//     while(true)
//     {
//         std::string tempHash;
//         ca_algorithm::Calc1000HeightsSumHash(_topBlockHeight + 1000, dbReaderWrite, tempHash);
//         DEBUGLOG("self tempHash: {}", tempHash);
//         if(tempHash.empty())
//         {
//             ERRORLOG("Calc1000HeightsSumHash error, error num:{}", -1);
//             return -2;
//         }
//         _SetTempTopData(_topBlockHeight + 1000, tempHash);

//         std::vector<std::string> pledgeAddr;
//         int ret = GetPledgeAddr(dbReaderWrite, pledgeAddr);
//         if(ret != 0)
//         {
//             ERRORLOG("GetPledgeAddr error, error num:{}", -2);
//             return -3;
//         }

//         std::vector<std::string> sendNodeIds;
//         int peerNodeSize = MagicSingleton<PeerNode>::GetInstance()->get_nodelist_size();
//         ret = MagicSingleton<SyncBlock>::GetInstance()->GetNewSyncNode(peerNodeSize, _topBlockHeight + 1000, pledgeAddr, sendNodeIds);
//         if(ret != 0)
//         {
//             ERRORLOG("_GetSyncNode error, error num:{}", ret);
//             return -4;
//         }

//         std::string msgId;
//         size_t sendNum = sendNodeIds.size();
//         if (!GLOBALDATAMGRPTR.CreateWait(90, sendNum * 0.9, msgId))
//         {
//             return -5;
//         }
//         for (auto &nodeId : sendNodeIds)
//         {
//             if(!GLOBALDATAMGRPTR.AddResNode(msgId, nodeId))
//             {
//                 return -6;
//             }
//             SendGetCheckSumHashReq(nodeId, msgId, _topBlockHeight + 1000);
//         }

//         std::vector<std::string> retDatas;
//         if (!GLOBALDATAMGRPTR.WaitData(msgId, retDatas))
//         {
//             if (retDatas.empty() || retDatas.size() < sendNum / 2)
//             {
//                 ERRORLOG("wait sync height time out send:{} recv:{}", sendNum, retDatas.size());
//                 return -7;
//             }
//         }

//         std::map<std::string, uint64_t> consensusMap;
//         GetCheckSumHashAck ack;
//         uint64_t successNum = 0;
//         for (auto &ret_data : retDatas)
//         {
//             ack.Clear();
//             if (!ack.ParseFromString(ret_data))
//             {
//                 continue;
//             }

//             if(ack.success() == false)
//             {
//                 continue;
//             }

//             if(ack.hash().empty())
//             {
//                 continue;
//             }

//             auto find = consensusMap.find(ack.hash());
//             if(find == consensusMap.end())
//             {
//                 consensusMap.insert(std::make_pair(ack.hash(), 1));
//             }
//             else
//             {
//                 ++find->second;
//             }

//             ++successNum;
//         }

//         bool back = successNum >= retDatas.size() * 0.8;
//         if(!back)
//         {
//             ERRORLOG("success num:{} less than retDatas.size() * 0.8:{}", successNum, retDatas.size() * 0.8);
//             return -8;
//         }

//         auto compare = [](const std::pair<std::string, uint64_t>& a, const std::pair<std::string, uint64_t>& b) {
//             return a.second < b.second;
//         };

//         auto maxIterator = std::max_element(consensusMap.begin(), consensusMap.end(), compare);

//         if (maxIterator != consensusMap.end())
//         {
//             DEBUGLOG("maxIterator hash: {}", maxIterator->first);
//             bool byzantine = maxIterator->second >= successNum * 0.9;
//             if(byzantine)
//             {
//                 auto [timpHeight, timpHash] = GetTempTopData();
//                 if(maxIterator->first == timpHash)
//                 {
//                     DBReadWriter dbWriter;
//                     if (DBStatus::DB_SUCCESS !=  dbWriter.SetCheckBlockHashsByBlockHeight(timpHeight, timpHash))
//                     {
//                         ERRORLOG("SetCheckBlockHashsByBlockHeight failed !");
//                         return -9;
//                     }

//                     uint64_t lastHeight;
//                     if(DBStatus::DB_SUCCESS != dbWriter.GetBlockComHashHeight(lastHeight))
//                     {
//                         ERRORLOG("GetBlockComHashHeight failed !");
//                         lastHeight = 0;
//                     }

//                     if(lastHeight != timpHeight - 1000)
//                     {
//                         ERRORLOG("lastHeight is: {} != timpHeight - 1000, timpHeight is: {} !", lastHeight, timpHeight);
//                         return -10;
//                     }

//                     if ( DBStatus::DB_SUCCESS != dbWriter.SetBlockComHashHeight(timpHeight))
//                     {
//                         return -11; 
//                     }
//                     if (DBStatus::DB_SUCCESS != dbWriter.TransactionCommit())
//                     {
//                         ERRORLOG("(rocksdb init) TransactionCommit failed !");
//                         return -12;
//                     }
//                     return 0;
//                 }
//                 else 
//                 {     
//                     int res = DoNewSync(sendNodeIds,pledgeAddr, selfNodeHeight);
//                     DEBUGLOG("first DoNewSync return num: {}", res);
//                     continue;
//                 }
//             }
//             int res = DoNewSync(sendNodeIds, pledgeAddr, selfNodeHeight);
//             DEBUGLOG("second DoNewSync return num: {}", res);
//             continue;
//         }

//     }

// }


// int CheckBlocks::DoNewSync(std::vector<std::string> sendNodeIds, std::vector<std::string>& pledgeAddr, uint64_t selfNodeHeight)
// {
//     std::vector<uint64_t> heights;
//     for(int i = 1; i <= 10; i++)
//     {
//         heights.push_back(_topBlockHeight + i * 100); 
//     }

//     std::vector<uint64_t> needSyncHeights;
//     int ret = ByzantineSumHash(sendNodeIds, heights, needSyncHeights);
//     if(ret != 0)
//     {
//         ERRORLOG("ByzantineSumHash fail:{}", ret);
//         return -1;
//     }

//     uint64_t chain_height = 0;
//     if(!MagicSingleton<BlockHelper>::GetInstance()->ObtainChainHeight(chain_height))
//     {
//         return -2;
//     }
//     for(const auto& sync_heiht: needSyncHeights)
//     {
//         DEBUGLOG("needSyncHeights: {}",sync_heiht);
//         ret = MagicSingleton<SyncBlock>::GetInstance()->RunNewSyncOnce(pledgeAddr, chain_height, selfNodeHeight, sync_heiht - 100, sync_heiht, 99999);
//         sleep(10); 
//         if(ret != 0)
//         {
//             ERRORLOG("_RunNewSyncOnce fail:{}", ret);
//             return -3;
//         }
//     }
//     return 0;
// }


// int CheckBlocks::ByzantineSumHash(const std::vector<std::string> &sendNodeIds, const std::vector<uint64_t>& sendHeights, std::vector<uint64_t>& needSyncHeights)
// {
//     needSyncHeights.clear();
//     std::string msgId;
//     size_t sendNum = sendNodeIds.size();

//     double acceptance_rate = 0.9;

//     if (!GLOBALDATAMGRPTR.CreateWait(90, sendNum * acceptance_rate, msgId))
//     {
//         return -1;
//     }

//     for (auto &nodeId : sendNodeIds)
//     {
//         if(!GLOBALDATAMGRPTR.AddResNode(msgId, nodeId))
//         {
//             return -2;
//         }
//         DEBUGLOG("get from zero sync sum hash from {}", nodeId);
//         SendFromZeroSyncGetSumHashReq(nodeId, msgId, sendHeights);
//     }
//     std::vector<std::string> retDatas;
//     if (!GLOBALDATAMGRPTR.WaitData(msgId, retDatas))
//     {
//         if (retDatas.empty() || retDatas.size() < sendNum / 2)
//         {
//             ERRORLOG("wait sync height time out send:{} recv:{}", sendNum, retDatas.size());
//             return -3;
//         }
//     }
    
//     std::map<uint64_t/*height*/, std::map<std::string/*sumhash*/, uint64_t/*num*/>>sumHashDatas;

//     int successCount = 0;
//     for (auto &ret_data : retDatas)
//     {
//         SyncFromZeroGetSumHashAck ack;
//         if (!ack.ParseFromString(ret_data))
//         {
//             continue;
//         }
//         if (ack.code() == 0)
//         {
//             ++successCount;
//             continue;
//         }
//         ++successCount;
//         auto retSumHashes = ack.sum_hashes();
//         for(const auto& sum_hash : retSumHashes)
//         {
//             const auto hash = sum_hash.hash();
//             auto height = sum_hash.height();
            
//             auto found = sumHashDatas.find(height);
//             if (found == sumHashDatas.end())
//             {
//                 std::map<std::string, uint64_t> temp;
//                 temp.insert(make_pair(hash, 1));
//                 sumHashDatas.insert(std::make_pair(height, temp));
//                 continue;
//             }
//             auto& content = found->second;
//             auto findHash = content.find(hash);
//             if(findHash == content.end())
//             {
//                 content.insert(make_pair(hash, 1));
//                 continue;
//             }
//             findHash->second++;
//         }

//     }

//     uint64_t backNum = sendNum * 0.8;
//     bool byzantineSuccess = successCount >= backNum;
//     if(!byzantineSuccess)
//     {
//         ERRORLOG("checkByzantine error, sendNum = {} , successCount = {}", sendNum, successCount);
//         return -4;
//     }

//     DBReader dbReader;

//     auto compare = [](const std::pair<std::string, uint64_t>& a, const std::pair<std::string, uint64_t>& b) {
//         return a.second < b.second;
//     };

//     for(const auto& sum_hashdata: sumHashDatas)
//     {
//         std::string shelf_sum_hash;
//         if (DBStatus::DB_SUCCESS != dbReader.GetSumHashByHeight(sum_hashdata.first, shelf_sum_hash))
//         {
//             DEBUGLOG("fail to get sum hash height at height {}", sum_hashdata.first);
//             needSyncHeights.push_back(sum_hashdata.first);
//             continue;
//         }

//         auto maxIterator = std::max_element(sum_hashdata.second.begin(), sum_hashdata.second.end(), compare);

//         if (maxIterator != sum_hashdata.second.end())
//         {
//            bool byzantineSuccess = maxIterator->second >= successCount * 0.85;
//            if(byzantineSuccess)
//            {
//                 if(shelf_sum_hash == maxIterator->first)
//                 {
//                     continue;
//                 }
//            }
//            needSyncHeights.push_back(sum_hashdata.first);
//         }
//         else 
//         {
//             needSyncHeights.push_back(sum_hashdata.first);
//         }
//     }

//     return 0;
// }

// void SendGetCheckSumHashReq(const std::string &nodeId, const std::string &msgId, uint64_t height)
// {
//     GetCheckSumHashReq req;
//     req.set_height(height);
//     req.set_self_node_id(net_get_self_node_id());
//     req.set_msg_id(msgId);
//     net_send_message<GetCheckSumHashReq>(nodeId, req, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
// }

// void SendGetCheckSumHashAck(const std::string &nodeId, const std::string &msgId, uint64_t height)
// {
//     GetCheckSumHashAck ack;
//     DBReader dbReader;
//     std::string hash;
//     bool success = true;
//     ack.set_height(height);
//     ack.set_msg_id(msgId);
//     ack.set_self_node_id(net_get_self_node_id());
//     if(DBStatus::DB_SUCCESS != dbReader.GetCheckBlockHashsByBlockHeight(height, hash))
//     {
//         auto [timpHeight, timpHash] = MagicSingleton<CheckBlocks>::GetInstance()->GetTempTopData();
//         if(timpHeight == height)
//         {
//             ack.set_success(success);
//             ack.set_hash(timpHash);
//             net_send_message<GetCheckSumHashAck>(nodeId, ack, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
//             return;
//         }

//         ERRORLOG("GetCheckBlockHashsByBlockHeight Error");
//         success = false;
//     }
//     ack.set_success(success);
//     ack.set_hash(hash);
//     net_send_message<GetCheckSumHashAck>(nodeId, ack, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
// }

// int HandleGetCheckSumHashReq(const std::shared_ptr<GetCheckSumHashReq> &msg, const MsgData &msgdata)
// {
//     if(!MagicSingleton<PeerNode>::GetInstance()->PeerNodeVerifyNodeId(msgdata.fd, msg->self_node_id()))
//     {
//         return -1;
//     }
//     SendGetCheckSumHashAck(msg->self_node_id(), msg->msg_id(),msg->height());
//     return 0;
// }

// int HandleGetCheckSumHashAck(const std::shared_ptr<GetCheckSumHashAck> &msg, const MsgData &msgdata)
// {
//      if(!MagicSingleton<PeerNode>::GetInstance()->PeerNodeVerifyNodeId(msgdata.fd, msg->self_node_id()))
//     {
//         return -1;
//     }

//     //GLOBALDATAMGRPTR.NewAddWaitData(msg->msg_id(), msg->self_node_id(), msg->SerializeAsString());
//     return 0;
// }
