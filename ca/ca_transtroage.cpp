#include "ca/ca_transtroage.h" 
#include "db/db_api.h"
#include "ca_transaction.h"
#include "utils/AccountManager.h"
#include "utils/DONbenchmark.h"
#include "common/time_report.h"
#include "utils/tmp_log.h"

/*********************************Broadcast circulation**************************************/
void TranStroage::Start_Timer()
{
	//Notifications for inspections at regular intervals
	
	_timer.AsyncLoop(100, [this](){
		Check();
	});
}

void TranStroage::Check()
{
	std::unique_lock<std::mutex> lck(_TranMap_mutex_);

	std::vector<std::string> hashKey;
	for(auto &i : _TranMap)
	{
			TxMsgReq copyendmsg_ = i.second.at(0);//Spelled TxMsgReq
			CTransaction tx;
			if (!tx.ParseFromString(copyendmsg_.txmsginfo().tx()))
			{
				ERRORLOG("Failed to deserialize transaction body! time = {}",tx.hash());
				continue;
			}
			
			if(tx.hash() != i.first)
			{
				hashKey.push_back(tx.hash());
				continue;
			}
			
			int64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
			const int64_t kTenSecond = (int64_t)1000000 * 10;
			
			if( abs(nowTime - (int64_t)tx.time()) >= kTenSecond)
			{
				ERRORLOG("Transaction flow time timeout");
				hashKey.push_back(tx.hash());
				copyendmsg_.Clear();
			}
			else if(tx.verifysign_size() == global::ca::kConsensus)
			{
				DEBUGLOG("begin add cache ");

				CTransaction copyTx = tx;
				copyTx.clear_hash();
				copyTx.clear_verifysign();
				std::string tx_hash = getsha256hash(copyTx.SerializeAsString());
				uint64_t start_time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
				auto start_t2 = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
				
				if(MagicSingleton<TranMonitor>::GetInstance()->isConfirmHash(tx_hash))
				{
					DEBUGLOG("tx Verify <success>, tx_hash:{}", tx_hash);
				}
				else
				{
					ERRORLOG("tx Verify <fail>, tx_hash:{}", tx_hash);
					continue;
				}
				auto ret = CheckVerifysign(tx);
				if (ret < 0)
				{
					ERRORLOG("CheckVerifysign Transaction error ,ret:{}", ret);
					continue;
				}
				auto end_t2 = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
				auto t2 = end_t2 - start_t2;
				
				MagicSingleton<DONbenchmark>::GetInstance()->SetByTxHash(tx_hash, &t2, 2);
				
				std::string blockHash;
				DBReader db_reader;
				auto db_status = db_reader.GetBlockHashByTransactionHash(tx.hash(), blockHash);
				if (db_status != DBStatus::DB_SUCCESS && db_status != DBStatus::DB_NOT_FOUND)
				{
					hashKey.push_back(tx.hash());
					DEBUGLOG("GetBlockHashByTransactionHash failed! ");
					continue;
				}

				if(!blockHash.empty() || MagicSingleton<CtransactionCache>::GetInstance()->exist_in_cache(tx.hash()))
				{
					// If it is found, it indicates that the block has been added or in the block cache
					hashKey.push_back(tx.hash());
					DEBUGLOG("Already in cache!");
					continue;
				}

				ret = MagicSingleton<CtransactionCache>::GetInstance()->add_cache(tx, copyendmsg_);	

				if( 0 != ret)
				{
					ret -= 900;
					ERRORLOG("HandleTx BuildBlock failed! ret = {} , time = {}",ret,tx.hash());
				}
				
				hashKey.push_back(tx.hash());
				copyendmsg_.Clear();
			}

	}
	if(!hashKey.empty())
	{
		for (auto &hash : hashKey)
		{
			DEBUGLOG("hashKey is {}",hash);
			Remove(hash);
		}
	}
	hashKey.clear();

}



int TranStroage::Add(const TxMsgReq &msg )
{
	
	CTransaction tx;
	if (!tx.ParseFromString(msg.txmsginfo().tx()))
	{
		ERRORLOG("Failed to deserialize transaction body!");
		return -1;
	}
	DEBUGLOG("tx add hash is {}",tx.hash());

	std::vector<TxMsgReq> msgVec;
	msgVec.push_back(msg);
	std::unique_lock<std::mutex> lck(_TranMap_mutex_);
	_TranMap.insert(std::pair<std::string,std::vector<TxMsgReq>>(tx.hash(),msgVec));
	DEBUGLOG("add TranStroage _TranMap {}",tx.hash());
	if(tx.verifysign_size() != 1)
	{
		ERRORLOG("tx.verifysign_size() != 1");
		return -2;
	}
	TxSignMap[tx.hash()].insert(GetBase58Addr(tx.verifysign(0).pub()));

	DEBUGLOG("add TranStroage TxSignMap {}",tx.hash());

	return 0;
}


int TranStroage::Update(const TxMsgReq &msg )
{
	std::unique_lock<std::mutex> lck(_TranMap_mutex_);

	DEBUGLOG("TranStroage::Update1");
	
	CTransaction tx;
	if (!tx.ParseFromString(msg.txmsginfo().tx()))
	{
		ERRORLOG("Failed to deserialize transaction body!");
		return -1;
	}

	if(tx.verifysign_size() != 2)
	{
		ERRORLOG("tx.verifysign_size() != 2");
		return -2;
	}

	if(TxSignMap.find(tx.hash()) != TxSignMap.end())
	{
		auto signSet = TxSignMap[tx.hash()];
		if(signSet.find(GetBase58Addr(tx.verifysign(1).pub())) != signSet.end())
		{
			ERRORLOG("2 nodes can Transaction continue");
			return -3;
		}
	}
	else
	{
		DEBUGLOG("Transaction does not exist");
		return -4;
	}
	TxSignMap[tx.hash()].insert(GetBase58Addr(tx.verifysign(1).pub()));
	DEBUGLOG("TxSignMap update{}",tx.hash());
	MagicSingleton<DONbenchmark>::GetInstance()->AddTransactionSignReceiveMap(tx.hash());

	if(_TranMap.find(tx.hash()) != _TranMap.end())
	{
		auto& Tran = _TranMap[tx.hash()];
		DEBUGLOG("TranMap size is {}",_TranMap.size());
		Tran.push_back(msg);
		if(Tran.size() == global::ca::kConsensus)
		{
			DEBUGLOG("TranStroage::Update");
			//Combined into endTxMsg
			composeEndmsg(Tran);
			CTransaction tx_;
			if (!tx_.ParseFromString(Tran.at(0).txmsginfo().tx()))
			{
				ERRORLOG("Failed to deserialize transaction body!");
				return -4;
			}
			CTransaction copyTx = tx_;
			copyTx.clear_hash();
			copyTx.clear_verifysign();
			uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
			MagicSingleton<DONbenchmark>::GetInstance()->SetByTxHash(getsha256hash(copyTx.SerializeAsString()), &nowTime, 4);
			MagicSingleton<DONbenchmark>::GetInstance()->CalculateTransactionSignReceivePerSecond(tx.hash(), MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
			
		}
	}
	lck.unlock();

	return 0;
}

void TranStroage::Remove(const std::string &hash)
{
	try
	{
		/* code */
		_TranMap.erase(_TranMap.find(hash));
		DEBUGLOG("_TranMap {}",hash);
		TxSignMap.erase(TxSignMap.find(hash));
		DEBUGLOG("TxSignMap {}",hash);
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		ERRORLOG("_TranMap.erase or TxSignMap.erase fail!!!!");
	}
}



void TranStroage::composeEndmsg( std::vector<TxMsgReq> &msgvec)
{
	DEBUGLOG("TranStroage::composeEndmsg");

	for(auto &i : msgvec)
	{

		

		CTransaction tx_compose;
		if (!tx_compose.ParseFromString(i.txmsginfo().tx()))
		{
			ERRORLOG("Failed to deserialize transaction body!");
			return ;
		}
		DEBUGLOG("TranStroage::composeEndmsg1 {}", tx_compose.hash());
		if(tx_compose.verifysign_size() == 1 || i.prevblkhashs_size() == 0 )
		{
			continue;
		}

		if(tx_compose.verifysign_size() != 2 )
		{
			continue;
		}

		CTransaction tx_end;
		if (!tx_end.ParseFromString(msgvec[0].txmsginfo().tx()))
		{
			ERRORLOG("Failed to deserialize transaction body!");
			return ;
		}

		CSign * end_sign =  tx_end.add_verifysign();
		end_sign->set_sign(tx_compose.verifysign(1).sign());
		end_sign->set_pub(tx_compose.verifysign(1).pub());

		for(int j = 0 ; j < i.prevblkhashs_size() ; j++)
		{
			msgvec[0].add_prevblkhashs(i.prevblkhashs(j));
		}

		CTransaction copyTx = tx_end;
		copyTx.clear_hash();
		copyTx.clear_verifysign();

		tx_end.set_hash(getsha256hash(copyTx.SerializeAsString()));
		msgvec[0].mutable_txmsginfo()->set_tx(tx_end.SerializeAsString());
	}
}


