/*
 * @Author: lyw 15035612538@163.com
 * @Date: 2024-03-24 14:58:14
 * @LastEditors: lyw 15035612538@163.com
 * @LastEditTime: 2024-04-15 00:35:57
 * @FilePath: /don/net/handle_event.h
 */
#ifndef _HANDLE_EVENT_H_
#define _HANDLE_EVENT_H_

#include <memory>
#include "net.pb.h"
#include "./msg_queue.h"
#include "ca_protomsg.pb.h"
#include "proto/interface.pb.h"

int handlePrintMsgReq(const std::shared_ptr<PrintMsgReq> &printMsgReq, const MsgData &from);
int handleRegisterNodeReq(const std::shared_ptr<RegisterNodeReq> &registerNode, const MsgData &from);
int handleRegisterNodeAck(const std::shared_ptr<RegisterNodeAck> &registerNodeAck, const MsgData &from);
int VerifyRegisterNode(const NodeInfo &nodeinfo, uint32_t &from_ip, uint32_t &from_port);
int handleBroadcastMsgReq(const std::shared_ptr<BroadcastMsgReq> &broadcaseMsgReq, const MsgData &from);

int handlePingReq(const std::shared_ptr<PingReq> &pingReq, const MsgData &from);
int handlePongReq(const std::shared_ptr<PongReq> &pongReq, const MsgData &from);
int handleSyncNodeReq(const std::shared_ptr<SyncNodeReq> &syncNodeReq, const MsgData &from);
int handleSyncNodeAck(const std::shared_ptr<SyncNodeAck> &syncNodeAck, const MsgData &from);
int handleEchoReq(const std::shared_ptr<EchoReq> &echoReq, const MsgData &from);
int handleEchoAck(const std::shared_ptr<EchoAck> &echoAck, const MsgData &from);

int handleNodeHeightChangedReq(const std::shared_ptr<NodeHeightChangedReq>& req, const MsgData& from);
int handleNodeBase58AddrChangedReq(const std::shared_ptr<NodeBase58AddrChangedReq>& req, const MsgData& from);

int handleCheckTxReq(const std::shared_ptr<CheckTxReq>& req, const MsgData& from);
int handleCheckTxAck(const std::shared_ptr<CheckTxAck>& ack, const MsgData& from);

int handleBroadcastMsg( const std::shared_ptr<BuildBlockBroadcastMsg>& msg, const MsgData& msgdata);
// int handleContractBroadcastMsg(const std::shared_ptr<BuildContractBlockBroadcastMsg>& msg,const MsgData& msgdata);

#endif
