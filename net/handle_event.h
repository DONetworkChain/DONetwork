#ifndef _HANDLE_EVENT_H_
#define _HANDLE_EVENT_H_

#include <memory>
#include "net.pb.h"
#include "./msg_queue.h"

int handlePrintMsgReq(const std::shared_ptr<PrintMsgReq> &printMsgReq, const MsgData &from);
int handleRegisterNodeReq(const std::shared_ptr<RegisterNodeReq> &registerNode, const MsgData &from);
int handleRegisterNodeAck(const std::shared_ptr<RegisterNodeAck> &registerNodeAck, const MsgData &from);
int handleConnectNodeReq(const std::shared_ptr<ConnectNodeReq> &connectNodeReq, const MsgData &from);
int handleBroadcastNodeReq(const std::shared_ptr<BroadcastNodeReq> &broadcastNodeReq, const MsgData &from);
int handleTransMsgReq(const std::shared_ptr<TransMsgReq> &transMsgReq, const MsgData &from);
int handleBroadcastMsgReq(const std::shared_ptr<BroadcaseMsgReq> &broadcaseMsgReq, const MsgData &from);
int handleNotifyConnectReq(const std::shared_ptr<NotifyConnectReq> &transMsgReq, const MsgData &from);

int handlePingReq(const std::shared_ptr<PingReq> &pingReq, const MsgData &from);
int handlePongReq(const std::shared_ptr<PongReq> &pongReq, const MsgData &from);
int handleSyncNodeReq(const std::shared_ptr<SyncNodeReq> &syncNodeReq, const MsgData &from);
int handleSyncNodeAck(const std::shared_ptr<SyncNodeAck> &syncNodeAck, const MsgData &from);
int handleEchoReq(const std::shared_ptr<EchoReq> &echoReq, const MsgData &from);
int handleEchoAck(const std::shared_ptr<EchoAck> &echoAck, const MsgData &from);

int handleUpdateFeeReq(const std::shared_ptr<UpdateFeeReq> &updateFeeReq, const MsgData &from);
int handleUpdatePackageFeeReq(const std::shared_ptr<UpdatePackageFeeReq> &updatePackageFeeReq, const MsgData &from);

int handleGetTransInfoReq(const std::shared_ptr<GetTransInfoReq> &transInfoReq, const MsgData &from);
int handleGetTransInfoAck(const std::shared_ptr<GetTransInfoAck> &transInfoAck, const MsgData &from);

int handleNodeHeightChangedReq(const std::shared_ptr<NodeHeightChangedReq>& req, const MsgData& from);

#endif
