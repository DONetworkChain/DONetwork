#ifndef _TRAN_STROAGE_
#define _TRAN_STROAGE_

#include "ca_txhelper.h"
#include "ca_global.h"
#include "proto/transaction.pb.h"
#include "proto/ca_protomsg.pb.h"
#include "net/msg_queue.h"
#include "utils/time_util.h"
#include "ca/ca_transaction_cache.h"
#include "ca/ca_tranmonitor.h"
#include <net/if.h>
#include <unistd.h>
#include <map>


class TranStroage
{
public:
    TranStroage(){ Start_Timer(); };
    ~TranStroage() = default;
    TranStroage(TranStroage &&) = delete;
    TranStroage(const TranStroage &) = delete;
    TranStroage &operator=(TranStroage &&) = delete;
    TranStroage &operator=(const TranStroage &) = delete;

public:
	int Add(const TxMsgReq &msg);
	int Update(const TxMsgReq &msg);


private:
	void Start_Timer();
	void Check();
	void Remove(const std::string &hash);
	void composeEndmsg(std::vector<TxMsgReq> &msgvec);




private:
	std::mutex _TranMap_mutex_;

	std::map<std::string, std::vector<TxMsgReq>> _TranMap;
	std::map<std::string, std::set<std::string>> TxSignMap;
	CTimer _timer;
};

#endif