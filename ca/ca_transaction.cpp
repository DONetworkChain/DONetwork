#include "ca_transaction.h"

#include <assert.h>
#include <cstdint>
#include <exception>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>

#include <iostream>
#include <set>
#include <algorithm>
#include <shared_mutex>
#include <mutex>


#include "interface.pb.h"
#include "proto/ca_protomsg.pb.h"
#include "db/db_api.h"
#include "db/cache.h"
#include "common/config.h"
#include "utils/time_util.h"
#include "utils/base64.h"
#include "utils/string_util.h"
#include "utils/MagicSingleton.h"
#include "utils/util2.h"
#include "utils/hexcode.h"
#include "include/logging.h"
#include "include/net_interface.h"
#include "common/global.h"
#include "ca.h"
#include "ca_global.h"
#include "utils/console.h"
#include "utils/base64_2.h"
#include "ca_block_http_callback.h"
#include "ca/ca_algorithm.h"
#include "ca/ca_blockcache.h"
#include "ca/ca_transaction_cache.h"
#include "ca/ca_txhelper.h"
#include "utils/time_util.h"
#include "utils/ReturnAckCode.h"
#include "include/ScopeGuard.h"
#include "ca/ca_tranmonitor.h"
#include "ca_blockhelper.h"
#include "utils/AccountManager.h"
#include "utils/Cycliclist.hpp"
#include "utils/VRF.hpp"
#include "utils/DONbenchmark.h"
#include "mpt/trie.h"
#include "ca/ca_dispatchtx.h"
#include "utils/json.hpp"
#include "ca/failed_transaction_cache.h"
#include "common/task_pool.h"
#include "utils/ContractUtils.h"
#include "api/interface/rpc_error.h"


int GetBalanceByUtxo(const std::string &address, uint64_t &balance)
{
	if (address.size() == 0)
	{
		return -1;
	}

	DBReader db_reader;
	std::vector<std::string> addr_utxo_hashs;
	if(DBStatus::DB_SUCCESS != db_reader.GetUtxoHashsByAddress(address, addr_utxo_hashs))
	{
		return -2;
	}

	std::sort(addr_utxo_hashs.begin(), addr_utxo_hashs.end());
	addr_utxo_hashs.erase(std::unique(addr_utxo_hashs.begin(), addr_utxo_hashs.end()), addr_utxo_hashs.end()); 

	for (const auto &utxo_hash : addr_utxo_hashs)
	{
		std::string address_balance;
		if (DBStatus::DB_SUCCESS != db_reader.GetUtxoValueByUtxoHashs(utxo_hash, address, address_balance))
		{
			return -3;
		}
		//If I get the pledged utxo, I will use it together
		uint64_t stakeValue = 0;
		std::string underline = "_";
		std::vector<std::string> utxo_values;

		if(address_balance.find(underline) != string::npos)
		{
			StringUtil::SplitString(address_balance, "_", utxo_values);
			
			for(int i = 0; i < utxo_values.size(); ++i)
			{
				stakeValue += std::stol(utxo_values[i]);
			}

			balance += stakeValue;
		}
		else
		{
			balance +=  std::stol(address_balance);
		}

	}

	return 0;
}


void setVrf(Vrf &dest, const std::string &proof, const std::string &pub, const std::string &data)
{
	CSign *sign = dest.mutable_vrfsign();
	sign->set_pub(pub);
	sign->set_sign(proof);
	dest.set_data(data);
}


void SetNewVrf(NewVrf &dest, const std::string &proof, const std::string &pub)
{
	CSign *sign = dest.mutable_vrfsign();
	sign->set_pub(pub);
	sign->set_sign(proof);

}
int getVrfdata(const Vrf &vrf, std::string &hash, int &range , double &percentage)
{
	try
	{
		auto json = nlohmann::json::parse(vrf.data());
		hash = json["hash"];
		range = json["range"];
		percentage = json["percentage"];
	}
	catch (...)
	{
		ERRORLOG("getVrfdata json parse fail !");
		return -1;
	}

	return 0;
}

int getNewVrfdata(const NewVrf &vrf, std::string &hash, int &range , double &percentage)
{
	try
	{
		hash = vrf.vrfdata().hash();
		range = vrf.vrfdata().range();
		percentage=vrf.vrfdata().percentage();
	}
	catch (...)
	{
		ERRORLOG("getNewVrfdata json parse fail !");
		return -1;
	}

	return 0;
}

int getVrfdata(const Vrf &vrf, std::string &hash, int &range)
{
	try
	{
		auto json = nlohmann::json::parse(vrf.data());
		hash = json["hash"];
		range = json["range"];
	}
	catch (...)
	{
		ERRORLOG("getVrfdata json parse fail !");
		return -1;
	}

	return 0;
}
int getNewVrfdata(const NewVrf &vrf, std::string &hash, int &range)
{
	try
	{
		hash = vrf.vrfdata().hash();
		range = vrf.vrfdata().range();
	}
	catch (...)
	{
		ERRORLOG("getVrfdata json parse fail !");
		return -1;
	}

	return 0;
}

TransactionType GetTransactionType(const CTransaction &tx)
{
	if (tx.type() == global::ca::kGenesisSign)
	{
		return kTransactionType_Genesis;
	}
	if (tx.type() == global::ca::kTxSign)
	{
		return kTransactionType_Tx;
	}
	return kTransactionType_Unknown;
}

bool checkTop(int top)
{
	// CBlockDataApi data_reader;
	uint64_t mytop = 0;
	DBReader db_reader;
	db_reader.GetBlockTop(mytop);

	if (top < (int)mytop - 4)
	{
		ERRORLOG("checkTop fail other top:{} my top:{}", top, (int)mytop);
		return false;
	}
	else if (top > (int)mytop + 1)
	{
		ERRORLOG("checkTop fail other top:{} my top:{}", top, (int)mytop);
		return false;
	}
	else
	{
		return true;
	}
}

bool ContainSelfVerifySign(const CTransaction &tx)
{
	bool isContainSelfVerifySign = false;

	if (tx.verifysign_size() == 0)
	{
		return isContainSelfVerifySign;
	}

	std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	int index = defaultBase58Addr != tx.identity() ? 0 : 1;

	for (; index != tx.verifysign_size(); index++)
	{
		const CSign &sign = tx.verifysign(index);
		if (defaultBase58Addr == GetBase58Addr(sign.pub()))
		{
			isContainSelfVerifySign = true;
			break;
		}
	}
	return isContainSelfVerifySign;
}

int HandleBuildBlockBroadcastMsg(const std::shared_ptr<BuildBlockBroadcastMsg> &msg, const MsgData &msgdata)
{
	DEBUGLOG("HandleBuildBlockBroadcastMsg begin");
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("HandleBuildBlockBroadcastMsg IsVersionCompatible");
		return -1;
	}

	std::string serBlock = msg->blockraw();
	CBlock block;
	if (!block.ParseFromString(serBlock))
	{
		ERRORLOG("HandleBuildBlockBroadcastMsg block ParseFromString failed");
		return -2;
	}

	if(block.sign_size() != global::ca::kConsensus)
	{
		return -3;
	}

	bool isVerify = false;
	
	for (auto &tx : block.txs())
	{
		bool txConsensusStatus = CheckTxConsensusStatus(tx);
		if(!txConsensusStatus)
		{
			isVerify = true;
			break;
		}
	}
	DBReader reader;
	uint64_t newTop = 0;
	static const uint64_t block_pool_cache_height = 10000;
	if (reader.GetBlockTop(newTop) == DBStatus::DB_SUCCESS)
	{
		if (block.height() >= newTop && block.height() - newTop > block_pool_cache_height)
		{
			return -6;
		}
	}
	DEBUGLOG("isVerify:{}, top:{}", isVerify, newTop);
	if(isVerify)
	{
		for (auto &sign : block.sign())
		{
			//Verification of investment and pledge
			int ret = VerifyBonusAddr(GetBase58Addr(sign.pub()));
			if(ret != 0)
			{
				return -4;
			}
		}
	}

	int ret = VerifyBlockSign(block);
	if (ret != 0)
	{
		ERRORLOG("VerifyBlockSign fail, ret: {}", ret);
		return -5;
	}



	std::string proof;
	std::string result;

	
	if(IsContractBlock(block))
	{
	NewVrf vrf = msg->contractvrf();
	
	int range_ = 0;

	std::string hash;
	if(getNewVrfdata(vrf, hash, range_) != 0)
	{
		ERRORLOG("vrf data error");
		return -7;
	}

	EVP_PKEY *pkey = nullptr;
	if (!GetEDPubKeyByBytes(vrf.vrfsign().pub(), pkey))
	{
		ERRORLOG(RED "HandleBuildBlockBroadcastMsg Get public key from bytes failed!" RESET);
		return -8;
	}

	
	result = hash;
	proof = vrf.vrfsign().sign();
	if (MagicSingleton<VRF>::GetInstance()->VerifyVRF(pkey, block.hash(), result, proof) != 0)
	{
		ERRORLOG(RED "HandleBuildBlockBroadcastMsg Verify VRF Info fail" RESET);
		return -9;
	}
	}
	else
	{
		Vrf vrf = msg->vrfinfo();

	int range_ = 0;

	std::string hash;
	if(getVrfdata(vrf, hash, range_) != 0)
	{
		ERRORLOG("vrf data error");
		return -10;
	}

	EVP_PKEY *pkey = nullptr;
	if (!GetEDPubKeyByBytes(vrf.vrfsign().pub(), pkey))
	{
		ERRORLOG(RED "HandleBuildBlockBroadcastMsg Get public key from bytes failed!" RESET);
		return -11;
	}

	
	result = hash;
	proof = vrf.vrfsign().sign();
	if (MagicSingleton<VRF>::GetInstance()->VerifyVRF(pkey, block.hash(), result, proof) != 0)
	{
		ERRORLOG(RED "HandleBuildBlockBroadcastMsg Verify VRF Info fail" RESET);
		return -12;
	}
	}

	double rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(result);

	//Circular linked list
	Cycliclist<std::string> list;
	for (auto &iter : block.txs())
	{
		for (auto &sign_node : iter.verifysign())
		{
			list.push_back(GetBase58Addr(sign_node.pub()));
		}
	} //The signing nodes for all transactions in the block are added to the loop list

	int rand_pos = list.size() * rand_num;
	const int sign_threshold = global::ca::KSign_node_threshold / 2;

	auto end_pos = rand_pos - sign_threshold;
	std::vector<std::string> target_addr;
	for (; target_addr.size() < global::ca::KSign_node_threshold; end_pos++)
	{
		target_addr.push_back(list[end_pos]);
	}

	std::vector<std::string> sign_addr;
	for (auto iter = list.begin(); iter != list.end(); iter++)
	{
		sign_addr.push_back(iter->data);
	}
	sign_addr.push_back(list.end()->data);

	//Determine whether the random signature node of VRF is consistent with the circulation signature node
	for (auto &item : target_addr)
	{
		if (std::find(sign_addr.begin(), sign_addr.end(), item) == sign_addr.end())
		{
			DEBUGLOG("HandleBuildBlockBroadcastMsg sign addr error !");
			return -13;
		}
	}

	MagicSingleton<BlockMonitor>::GetInstance()->AddBlockMonitor(block.hash(), msg->id(), msg->flag());
	MagicSingleton<BlockHelper>::GetInstance()->AddBroadcastBlock(block);
	std::cout << "block Add succeed" << std::endl;
	return 0;
}

// int HandleBuildContractBlockBroadcastMsg(const std::shared_ptr<BuildContractBlockBroadcastMsg> &msg, const MsgData &msgdata)
// {
// 	DEBUGLOG("HandleBuildBlockBroadcastMsg begin");
// 	if (0 != Util::IsVersionCompatible(msg->version()))
// 	{
// 		ERRORLOG("HandleBuildBlockBroadcastMsg IsVersionCompatible");
// 		return -1;
// 	}

// 	std::string serBlock = msg->blockraw();
// 	CBlock block;
// 	if (!block.ParseFromString(serBlock))
// 	{
// 		ERRORLOG("HandleBuildBlockBroadcastMsg block ParseFromString failed");
// 		return -2;
// 	}

// 	DBReader reader;
// 	uint64_t newTop = 0;
// 	static const uint64_t block_pool_cache_height = 10000;
// 	if (reader.GetBlockTop(newTop) == DBStatus::DB_SUCCESS)
// 	{
// 		if (block.height() >= newTop && block.height() - newTop > block_pool_cache_height)
// 		{
// 			return -3;
// 		}
// 	}

// 	NewVrf vrf = msg->vrfinfo();

// 	int range_ = 0;

// 	std::string hash;
// 	if(getNewVrfdata(vrf, hash, range_) != 0)
// 	{
// 		ERRORLOG("vrf data error");
// 		return -4;
// 	}

// 	EVP_PKEY *pkey = nullptr;
// 	if (!GetEDPubKeyByBytes(vrf.vrfsign().pub(), pkey))
// 	{
// 		ERRORLOG(RED "HandleBuildBlockBroadcastMsg Get public key from bytes failed!" RESET);
// 		return -5;
// 	}

// 	std::string result = hash;
// 	std::string proof = vrf.vrfsign().sign();
// 	if (MagicSingleton<VRF>::GetInstance()->VerifyVRF(pkey, block.hash(), result, proof) != 0)
// 	{
// 		ERRORLOG(RED "HandleBuildBlockBroadcastMsg Verify VRF Info fail" RESET);
// 		return -6;
// 	}

// 	double rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(result);

// 	//Circular linked list
// 	Cycliclist<std::string> list;
// 	for (auto &iter : block.txs())
// 	{
// 		for (auto &sign_node : iter.verifysign())
// 		{
// 			list.push_back(GetBase58Addr(sign_node.pub()));
// 		}
// 	} //The signing nodes for all transactions in the block are added to the loop list

// 	int rand_pos = list.size() * rand_num;
// 	const int sign_threshold = global::ca::KSign_node_threshold / 2;

// 	auto end_pos = rand_pos - sign_threshold;
// 	std::vector<std::string> target_addr;
// 	for (; target_addr.size() < global::ca::KSign_node_threshold; end_pos++)
// 	{
// 		target_addr.push_back(list[end_pos]);
// 	}

// 	std::vector<std::string> sign_addr;
// 	for (auto iter = list.begin(); iter != list.end(); iter++)
// 	{
// 		sign_addr.push_back(iter->data);
// 	}
// 	sign_addr.push_back(list.end()->data);

// 	//Determine whether the random signature node of VRF is consistent with the circulation signature node
// 	for (auto &item : target_addr)
// 	{
// 		if (std::find(sign_addr.begin(), sign_addr.end(), item) == sign_addr.end())
// 		{
// 			DEBUGLOG("HandleBuildBlockBroadcastMsg sign addr error !");
// 			return -7;
// 		}
// 	}

// 	MagicSingleton<BlockMonitor>::GetInstance()->AddBlockMonitor(block.hash(), msg->id(), msg->flag());
// 	MagicSingleton<BlockHelper>::GetInstance()->AddBroadcastBlock(block);
// 	std::cout << "block Add succeed" << std::endl;
// 	return 0;
// }

int SendTxMsg(const CTransaction &tx, const std::shared_ptr<TxMsgReq> &msg)
{
	std::set<std::string> sendid;
	const int signNodeNumber = global::ca::KSign_node_threshold;
	int ret = FindSignNode(tx, msg, signNodeNumber, sendid);
	if (ret < 0)
	{
		ret -= 100;
		ERRORLOG("SendTxMsg failed, ret:{} sendid size: {}", ret, sendid.size());
		return ret;
	}
	if (sendid.empty())
	{
		ERRORLOG("SendTxMsg failed, sendid size is empty");
		return -1;
	}

	if (sendid.size() < global::ca::kConsensus)
	{
		ERRORLOG("The number of nodes is less than the consensus number, sendid.size:{}", sendid.size());
		return -2;
	}

	std::vector<std::string> randomSignAddrs;
	for (auto &addr : sendid)
	{
		randomSignAddrs.push_back(addr);
	}
	std::random_shuffle(randomSignAddrs.begin(),randomSignAddrs.end());

	uint64_t handleTxHeight = msg->txmsginfo().height();
	TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);

	for (auto id : randomSignAddrs)
	{
		DEBUGLOG("sendid id = {} tx time = {} , type = {}", id, tx.time(), type);
		net_send_message<TxMsgReq>(id.c_str(), *msg, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
	}

	return 0;
}

int CheckVerifyNodeQualification(const std::string & base58)
{
	uint64_t pledgeamount = 0;
    if(SearchStake(base58, pledgeamount, global::ca::StakeType::kStakeType_Node) != 0)
	{
		ERRORLOG("{} No pledge", base58);
		return -1;
	}

	uint64_t invest_amount;
	auto ret = MagicSingleton<BounsAddrCache>::GetInstance()->get_amount(base58, invest_amount);
	if (ret < 0)
	{
		ERRORLOG("invest BonusAddr: {}, ret:{}", base58, ret);
		return -2;
	}
	if(pledgeamount + invest_amount < global::ca::kMinSignAmt)
	{
		ERRORLOG("pledgeamount + invest_amount = {} less than {}",(pledgeamount + invest_amount), global::ca::kMinSignAmt);
		return -3;
	}
	return 0;
}

int CheckVerifysign(const CTransaction & tx)
{
	// Is the transaction hash length 64
    if (tx.hash().size() != 64)
    {
        return -1;
    }

    // Verify whether the transaction hash is consistent
    if (tx.hash() != ca_algorithm::CalcTransactionHash(tx))
    {
        return -2;
    }
	
	// check tx sign
    if (tx.verifysign_size() != global::ca::kConsensus)
    {
        return -3;
    }

    if (tx.verifysign_size() > 0 && GetBase58Addr(tx.verifysign(0).pub()) != tx.identity())
    {
        ERRORLOG("tx verify sign size = {} " , tx.verifysign_size());
        ERRORLOG("addr = {} , tx identity = {} ", GetBase58Addr(tx.verifysign(0).pub()), tx.identity());
        return -4;
    }

	auto VerifySignLambda = [](const CSign & sign, const std::string & serHash)->int {
        
        if (sign.sign().size() == 0 || sign.pub().size() == 0)
		{
			return -5;
		}
        if (serHash.size() == 0)
        {
            return -6;
        }

        EVP_PKEY* eckey = nullptr;
        if(GetEDPubKeyByBytes(sign.pub(), eckey) == false)
        {
            EVP_PKEY_free(eckey);
            ERRORLOG(RED "Get public key from bytes failed!" RESET);
            return -7;
        }

        if(ED25519VerifyMessage(serHash, eckey, sign.sign()) == false)
        {
            EVP_PKEY_free(eckey);
            ERRORLOG(RED "Public key verify sign failed!" RESET);
            return -8;
        }
        EVP_PKEY_free(eckey);
        return 0;
    };

	CTransaction copyTx = tx;
	copyTx.clear_hash();
	copyTx.clear_verifysign();
	std::string serTxHash = getsha256hash(copyTx.SerializeAsString());

	for (auto & verifySign : tx.verifysign())
	{
		if (!CheckBase58Addr(GetBase58Addr(verifySign.pub()), Base58Ver::kBase58Ver_Normal))
		{
			return -9;
		}

        int verifySignRet = VerifySignLambda(verifySign, serTxHash);
        if (verifySignRet != 0)
        {
            return -10;
        }
	}

	std::set<std::string> vin_addrs;
	bool isMultiSign = IsMultiSign(tx);
	Base58Ver ver = isMultiSign ? Base58Ver::kBase58Ver_MultiSign : Base58Ver::kBase58Ver_Normal;
	for (auto &vin : tx.utxo().vin())
    {
		std::string addr = GetBase58Addr(vin.vinsign().pub(), ver);
		vin_addrs.insert(addr);
	}
	std::set<std::string> vout_addrs;
	for (int i = 0; i < tx.utxo().vout_size(); i++)
    {
        auto &vout = tx.utxo().vout(i);
		vout_addrs.insert(vout.addr());
	}
	bool is_bonus = false;
	global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();
	if (global::ca::TxType::kTxTypeBonus == tx_type)
	{
		is_bonus = true;
	}

	// The initiator and receiver of the transaction are not allowed to sign for mining
    if(!is_bonus)
    {
        std::vector<std::string> v_union;
        std::set_union(vin_addrs.cbegin(), vin_addrs.cend(), vout_addrs.cbegin(), vout_addrs.cend(), std::back_inserter(v_union));
        std::vector<std::string> v_sign_addr;
        std::string sign_addr;
        for (int i = 1; i < tx.verifysign_size(); ++i)
        {
            auto &tx_sign_pre_hash = tx.verifysign(i);
			if (tx_sign_pre_hash.pub().size() == 0)
			{
				return -11;
			}
            sign_addr = GetBase58Addr(tx_sign_pre_hash.pub());
            if (!CheckBase58Addr(sign_addr))
            {
                ERRORLOG(RED "Check Base58Addr failed!" RESET);
                return -12;
            }
            v_sign_addr.push_back(sign_addr);
        }
        std::vector<std::string> v_intersection;
        std::sort(v_union.begin(), v_union.end());
        std::sort(v_sign_addr.begin(), v_sign_addr.end());
        std::set_intersection(v_union.cbegin(), v_union.cend(), v_sign_addr.cbegin(), v_sign_addr.cend(), std::back_inserter(v_intersection));
        if (!v_intersection.empty())
        {
            ERRORLOG(RED "The initiator and receiver of the transaction are not allowed to sign for mining!" RESET);
            return -13;
        }
    }
	return 0;
}

int AddContractPreHash(const std::shared_ptr<ContractTempTxMsgReq> &msg, CTransaction &tx)
{
	Account defaultAccount;
	EVP_PKEY_free(defaultAccount.pkey);
	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount) != 0)
	{
		ERRORLOG("get default account fail");
		return -1;
	}

	DBReader db_reader;
	// CBlockDataApi data_reader;
	std::vector<std::string> pre_block_hashs;
	if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(msg->txmsginfo().height(), pre_block_hashs))
	{
		return -2;
	}

	std::string ownBaseaddr = defaultAccount.base58Addr;
	for (int i = 0; i < pre_block_hashs.size(); ++i)
	{
		if (ownBaseaddr != GetBase58Addr(tx.verifysign(0).pub()))
		{
			msg->add_prevblkhashs(pre_block_hashs[i]);
		}
	}

	TxMsgInfo *txMsgInfo = msg->mutable_txmsginfo();
	CTransaction copyTx = tx;
	copyTx.clear_hash();
	copyTx.clear_verifysign();

	tx.set_hash(getsha256hash(copyTx.SerializeAsString()));
	txMsgInfo->set_tx(tx.SerializeAsString());
	return 0;
}

int AddPreHash(const std::shared_ptr<TxMsgReq> &msg, CTransaction &tx)
{
	Account defaultAccount;
	EVP_PKEY_free(defaultAccount.pkey);
	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount) != 0)
	{
		ERRORLOG("get default account fail");
		return -1;
	}

	DBReader db_reader;
	// CBlockDataApi data_reader;
	std::vector<std::string> pre_block_hashs;
	if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(msg->txmsginfo().height(), pre_block_hashs))
	{
		return -2;
	}

	std::string ownBaseaddr = defaultAccount.base58Addr;
	for (int i = 0; i < pre_block_hashs.size(); ++i)
	{
		if (ownBaseaddr != GetBase58Addr(tx.verifysign(0).pub()))
		{
			msg->add_prevblkhashs(pre_block_hashs[i]);
		}
	}

	TxMsgInfo *txMsgInfo = msg->mutable_txmsginfo();
	CTransaction copyTx = tx;
	copyTx.clear_hash();
	copyTx.clear_verifysign();

	tx.set_hash(getsha256hash(copyTx.SerializeAsString()));
	txMsgInfo->set_tx(tx.SerializeAsString());
	return 0;
}

int HandleDoHandleTxAck(const std::shared_ptr<TxMsgAck> &msg, const MsgData &msgdata)
{
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("HandleBuildBlockBroadcastMsg IsVersionCompatible");
		return -1;
	}

	return 0;
}

std::map<int32_t, std::string> TxMsgReqCode()
{
	std::map<int32_t, std::string> errInfo = {std::make_pair(0, "Success "),
											  std::make_pair(-1, "Incompatible version!"),
											  std::make_pair(-2, "Unreasonable height!"),
											  std::make_pair(-3, "Failed to deserialize transaction body!"),
											  std::make_pair(-4, "Already verify signed this transaction"),
											  std::make_pair(-5, "catch json prase exception."),
											  std::make_pair(-6, "SearchStake failed!"),
											  std::make_pair(-7, "stake amount less than kMinStakeAmt"),
											  std::make_pair(-9, "Calculate gas failed!!"),
											  std::make_pair(-10, "pay gas doesn't equal to calculate gas!"),
											  std::make_pair(-11, "json parse fail"),
											  std::make_pair(-12, "TranStroage Update."),
											  std::make_pair(-13, "TranStroage Add."),
											  std::make_pair(-14, "defaultBase58Addr != tx.identity()"),
											  std::make_pair(-15, "number of sign is not equal to number of consensus"),
											  std::make_pair(-16, "GetBlockHashByTransactionHash failed!"),
											  std::make_pair(-17, "Already in cache!"),
											  std::make_pair(-1001, "The transaction version is not equal to zero."),
											  std::make_pair(-1002, "The transaction type is not a normal transaction"),
											  std::make_pair(-1003, "The transaction time is less than the time of Genesis block."),
											  std::make_pair(-1004, "The hash length of transaction is not equal 64."),
											  std::make_pair(-1005, "The hash of transaction not equal to calculation hash."),
											  std::make_pair(-1006, "Extension field is empty."),
											  std::make_pair(-1007, "The identity of the transaction is equal to zero."),
											  std::make_pair(-1008, "The identity was not verified successfully."),
											  std::make_pair(-1009, "The size of UTXO is equal to zero."),
											  std::make_pair(-1010, "The number of vins must be less than or equal to 100!"),
											  std::make_pair(-1011, "The size of VOUT is less than 2"),
											  std::make_pair(-1012, "The multisign_size is equal to zero."),
											  std::make_pair(-1013, "Catch parse JSON exception."),
											  std::make_pair(-1014, "The consenus number is not equal to kConsensus."),
											  std::make_pair(-1015, "The transaction of height is less then 1."),
											  std::make_pair(-1016, "The sign_gas is not equal to gas."),
											  std::make_pair(-1017, "Stake type can only be online stake and public network stake!"),
											  std::make_pair(-1018, "The hash length of redeem_utxo_hash is not equal to 64."),
											  std::make_pair(-1019, "The BonusAddr was not verified successfully"),
											  std::make_pair(-1020, "the invest type can only be invest licence and reserve invest licence!"),
											  std::make_pair(-1021, "The size of divest_utxo_hash is not equal to 64."),
											  std::make_pair(-1022, "The bonusAddrList is not equal to tx.utxo().vout_size()."),
											  std::make_pair(-1023, "The size of the VOUT is not equal to 2 and vout().addr() is not equal to multiSignAddr."),
											  std::make_pair(-1024, "The signAddrList.size() is less than 2 0r greater than 100."),
											  std::make_pair(-1025, "Verify whether the base58 address of the signature is valid."),
											  std::make_pair(-1026, "The setSignAddr size is not equal to signAddrList size."),
											  std::make_pair(-1027, "The SignThreshold is greater than signAddrList.size()."),
											  std::make_pair(-1028, "Unknown tx type!"),
											  std::make_pair(-1029, "catch exception."),
											  std::make_pair(-1030, "The number of vouts must be equal to 2!"),
											  std::make_pair(-1031, "The owner_addrs is equal to zero."),
											  std::make_pair(-1032, "Verify whether the kBase58Ver_MultiSign address is valid."),
											  std::make_pair(-1033, "Verify whether the kBase58Ver_All address is valid."),
											  std::make_pair(-1034, "The owner size of the following five types of transactions must be 1!"),
											  std::make_pair(-1035, "Txowner does not allow duplicate!"),
											  std::make_pair(-1036, "The multiSignOwners is greater than 1. "),
											  std::make_pair(-1037, "The pub size of vin is equal to zero. "),
											  std::make_pair(-1038, "Check Base58Addr failed!"),
											  std::make_pair(-1039, "The prevout_size of VIN is equal to zero."),
											  std::make_pair(-1040, "The prevout.hash() size is not equal to 64."),
											  std::make_pair(-1041, "Txowner and VIN signers are not consistent!"),
											  std::make_pair(-1042, "The sequence of VIN is not consistent!"),
											  std::make_pair(-1043, "Vin cannot be repeated except for the redeem or divest transaction!"),
											  std::make_pair(-1044, "Vin cannot be repeated except for the redeem or divest transaction!"),
											  std::make_pair(-1045, "The tx.utxo().vout_size() is equal to zero or greater than 1000."),
											  std::make_pair(-1046, "The pledge amount should be consistent with the output!"),
											  std::make_pair(-1047, "Check Base58Addr failed!"),
											  std::make_pair(-1048, "tx.utxo().vout_size() is greater than 2."),
											  std::make_pair(-1049, "The invest amount should be consistent with the output!"),
											  std::make_pair(-1050, "Check Base58Addr failed!"),
											  std::make_pair(-1051, "tx.utxo().vout_size() is greater than 2."),
											  std::make_pair(-1052, "kBase58Ver_MultiSign Check Base58Addr failed!"),
											  std::make_pair(-1053, "kBase58Ver_Normal Check Base58Addr failed!"),
											  std::make_pair(-1054, "tx.utxo().vout_size() is greater than 2."),
											  std::make_pair(-1055, "Check Base58Addr failed!"),
											  std::make_pair(-1056, "The amount in the output must be Greater than 0!"),
											  std::make_pair(-1057, "Multi-to-Multi transaction is not allowed!"),
											  std::make_pair(-1058, "sign.sign() or sign.pub().size() is equal to zero."),
											  std::make_pair(-1059, "serialize hash size is equal zero."),
											  std::make_pair(-1060, "Get public key from bytes failed!"),
											  std::make_pair(-1061, "Public key verify sign failed!"),
											  std::make_pair(-1062, "serVinHash VerifySignLambda failed."),
											  std::make_pair(-1063, "tx.utxo().multisign_size() is equal to zero."),
											  std::make_pair(-1064, "serUtxoHash VerifySignLambda failed."),
											  std::make_pair(-1065, "Determine whether the multi signature address is correct."),
											  std::make_pair(-1066, "Txowner and multi sign signers are not consistent!"),
											  std::make_pair(-1067, "The verifysign_size() is less than zero or greater than kConsensus."),
											  std::make_pair(-1068, "tx.identity() are not consistent!"),
											  std::make_pair(-1069, "Check Base58Addr failed!"),
											  std::make_pair(-1070, "serTxHash VerifySignLambda failed"),
											  std::make_pair(-1071, "tx.info().size() is not equal to zero."),
											  std::make_pair(-1072, "tx.reserve0().size()  or tx.reserve1().size()  is not equal to zero ."),
											  std::make_pair(-1073, "tx_sign_pre_hash.pub().size() is equal to zero."),
											  std::make_pair(-1074, "Check Base58Addr failed!"),
											  std::make_pair(-1075, "The initiator and receiver of the transaction are not allowed to sign for mining!"),
											  std::make_pair(-2000, "Verify TransactionTx fail"),
											  std::make_pair(-2001, "JSON failed to parse data field!"),
											  std::make_pair(-2002, "GetUtxoHashsByAddress failed!"),
											  std::make_pair(-2003, "GetStakeAddressUtxo failed!"),
											  std::make_pair(-2004, "The utxo used exists and is used!"),
											  std::make_pair(-2005, "GetBonusAddrInvestUtxosByBonusAddr failed!"),
											  std::make_pair(-2006, "The utxo used exists and is used!"),
											  std::make_pair(-2007, "The utxo used exists and is used!"),
											  std::make_pair(-2008, "Errors are not allowed for subscripts of pre utxo array!"),
											  std::make_pair(-2009, "Subscript out of bounds!"),
											  std::make_pair(-2010, "The Vout of the corresponding subscript of utxo used is incorrect!"),
											  std::make_pair(-2011, "The Vout of the corresponding subscript of utxo used is incorrect!"),
											  std::make_pair(-2012, "The Vout of the corresponding subscript of utxo used is incorrect!"),
											  std::make_pair(-2013, "Failed to obtain the amount claimed by the investor"),
											  std::make_pair(-2014, "The TotalClaim is not equal to the claimed amount"),
											  std::make_pair(-2015, "Input is not equal to output + packaging fee + handling fee!"),
											  std::make_pair(-2016, "get tx failed"),
											  std::make_pair(-2017, "The prevTx.hash() size is equal to zero."),
											  std::make_pair(-2018, "Found vinAddr in the prevTx.utxo().vout()."),
											  std::make_pair(-2019, "Utxo owner of transaction is not equal to 1"),
											  std::make_pair(-2201, "Get all stake address failed!"),
											  std::make_pair(-2202, "The account number has not staked assets!"),
											  std::make_pair(-2203, "Get stake utxo from address failed!"),
											  std::make_pair(-2204, "The utxo to be de staked is not in the staked utxo!"),
											  std::make_pair(-2205, "The staked utxo is not more than 30 days"),
											  std::make_pair(-2206, "Stake tx not found!"),
											  std::make_pair(-2208, "Stake value is zero!"),
											  std::make_pair(-2020, "The address of the withdrawal utxo is incorrect!"),
											  std::make_pair(-2021, "The value of the withdrawal utxo is incorrect!"),
											  std::make_pair(-2301, "The investor have already invested in a node!"),
											  std::make_pair(-2302, "The investment amount is less than 99"),
											  std::make_pair(-2303, "The account to be invested has not spent 500 to access the Internet!"),
											  std::make_pair(-2304, "Get invest addrs by node failed!"),
											  std::make_pair(-2305, "The account number to be invested have been invested by 999 people!"),
											  std::make_pair(-2306, "GetBonusAddrInvestUtxosByBonusAddr failed!"),
											  std::make_pair(-2307, "GetTransactionByHash failed!"),
											  std::make_pair(-2309, "The total amount invested in a single node will be more than 100000!"),
											  std::make_pair(-2022, "Utxo owner of transaction is not equal to 1"),
											  std::make_pair(-2023, "Utxo owner of transaction is not equal to 1"),
											  std::make_pair(-2401, "GetBonusAddrByInvestAddr failed!"),
											  std::make_pair(-2402, "The account has not invested assets to node!"),
											  std::make_pair(-2403, "GetBonusAddrInvestUtxosByBonusAddr failed!"),
											  std::make_pair(-2404, "The utxo to divest is not in the utxos that have been invested!"),
											  std::make_pair(-2405, "The invested utxo is not more than 1 day!"),
											  std::make_pair(-2406, "Invest tx not found!"),
											  std::make_pair(-2408, "The node to be divested is not invested!"),
											  std::make_pair(-2409, "The invested value is zero!"),
											  std::make_pair(-2024, "The address of the withdrawal utxo is incorrect!"),
											  std::make_pair(-2025, "The value of the withdrawal utxo is incorrect!"),
											  std::make_pair(-2026, "Failed to obtain multi sign address"),
											  std::make_pair(-2027, "No multi sign address found"),
											  std::make_pair(-2028, "Time to initiate claim > 1:00 a.m. & < my time"),
											  std::make_pair(-2029, "Failed to get bonus utxo."),
											  std::make_pair(-2030, "Set missing utxo"),
											  std::make_pair(-2031, "Claim time is not within the range."),
											  std::make_pair(-2032, "Failed to obtain investment address."),
											  std::make_pair(-2033, "Investment address is between 1 and 999."),
											  std::make_pair(-2034, "Failed to get bonusaddrinvestutxos."),
											  std::make_pair(-2035, "Failed to get transaction through hash."),
											  std::make_pair(-2036, "The total investment amount is less than kMinInvestAmt."),
											  std::make_pair(-2037, "Failed to obtain the total bonus amount."),
											  std::make_pair(-2038, "The difference between the total dividend amount and the node dividend is not equal to the value of Vout."),
											  std::make_pair(-2039, "The difference between the total dividend amount and the node dividend is equal to the value of Vout."),
											  std::make_pair(-2040, "LastVoutAmount given tx.utxo().vout(i.value)is not equal."),
											  std::make_pair(-2041, "Failed to obtain pledge address."),
											  std::make_pair(-2042, "Utxo owner of transaction is not equal to 1."),
											  std::make_pair(-2043, "Check base58 address."),
											  std::make_pair(-2044, "VerifyBonusAddr error."),
											  std::make_pair(-2045, "It is judged that the pledge time is less than 0."),
											  std::make_pair(-2046, "Height is not equal to transaction height."),
											  std::make_pair(-3000, "Failed to check the transaction body information."),
											  std::make_pair(-3001, "Failed to parse transaction body."),
											  std::make_pair(-3002, "Compare the signers in the transaction body."),
											  std::make_pair(-3003, "catch parse json exception."),
											  std::make_pair(-3004, "Failed to obtain the pledge address of the whole network."),
											  std::make_pair(-3005, "Judge whether the pledge time is less than zero."),
											  std::make_pair(-3006, "Failed to check the transaction body information."),
											  std::make_pair(-3007, "Failed to get public key."),
											  std::make_pair(-3008, "Signature information error of verification transaction."),
											  std::make_pair(-4000, "not a verify node"),
											  std::make_pair(-4001, "Failed to obtain investment address."),
											  std::make_pair(-4002, "Failed to get utxo of investment address."),
											  std::make_pair(-4003, "Failed to get transaction through hash."),
											  std::make_pair(-5000, "stake_time <= 0"),
											  std::make_pair(-5001, "unknow pledge type"),
											  std::make_pair(-5002, "fail to query addr pledge"),
											  std::make_pair(-5003, "faile to query trasaction"),
											  std::make_pair(-5004, "get pledge trasaction fail"),
											  std::make_pair(-6000, "Add verify sign fail"),
											  std::make_pair(-6001, "illegal address"),
											  std::make_pair(-6002, "fail to serialize trasaction"),
											  std::make_pair(-6003, "fail to sign message"),
											  std::make_pair(-7000, "Add node sign fail"),
											  std::make_pair(-7001, "get default account fail"),
											  std::make_pair(-7002, "sign info fail"),
											  std::make_pair(-7004, "Failed to get block hash by height."),
											  std::make_pair(-8000, "Send TxMsgReq failed"),
											  std::make_pair(-8011, "Failed to find signature node."),
											  std::make_pair(-8001, "SendTxMsg failed, sendid size is empty"),
											  std::make_pair(-9000, "HandleTx BuildBlock failed!"),
											  std::make_pair(-10001, "The transaction version is not equal to zero."),
											  std::make_pair(-10002, "The transaction type is not a normal transaction"),
											  std::make_pair(-10003, "The transaction time is less than the time of Genesis block."),
											  std::make_pair(-10004, "The hash length of transaction is not equal 64."),
											  std::make_pair(-10005, "The hash of transaction not equal to calculation hash."),
											  std::make_pair(-10006, "Extension field is empty."),
											  std::make_pair(-10007, "The identity of the transaction is equal to zero."),
											  std::make_pair(-10008, "The identity was not verified successfully."),
											  std::make_pair(-10009, "The size of UTXO is equal to zero."),
											  std::make_pair(-10010, "The number of vins must be less than or equal to 100!"),
											  std::make_pair(-10011, "The size of VOUT is less than 2"),
											  std::make_pair(-10012, "The multisign_size is equal to zero."),
											  std::make_pair(-10013, "Catch parse JSON exception."),
											  std::make_pair(-10014, "The consenus number is not equal to kConsensus."),
											  std::make_pair(-10015, "The transaction of height is less then 1."),
											  std::make_pair(-10016, "The sign_gas is not equal to gas."),
											  std::make_pair(-10017, "Stake type can only be online stake and public network stake!"),
											  std::make_pair(-10018, "The hash length of redeem_utxo_hash is not equal to 64."),
											  std::make_pair(-10019, "The BonusAddr was not verified successfully"),
											  std::make_pair(-10020, "the invest type can only be invest licence and reserve invest licence!"),
											  std::make_pair(-10021, "The size of divest_utxo_hash is not equal to 64."),
											  std::make_pair(-10022, "The bonusAddrList is not equal to tx.utxo().vout_size()."),
											  std::make_pair(-10023, "The size of the VOUT is not equal to 2 and vout().addr() is not equal to multiSignAddr."),
											  std::make_pair(-10024, "The signAddrList.size() is less than 2 0r greater than 100."),
											  std::make_pair(-10025, "Verify whether the base58 address of the signature is valid."),
											  std::make_pair(-10026, "The setSignAddr size is not equal to signAddrList size."),
											  std::make_pair(-10027, "The SignThreshold is greater than signAddrList.size()."),
											  std::make_pair(-10028, "Unknown tx type!"),
											  std::make_pair(-10029, "catch exception."),
											  std::make_pair(-10030, "The number of vouts must be equal to 2!"),
											  std::make_pair(-10031, "The owner_addrs is equal to zero."),
											  std::make_pair(-10032, "Verify whether the kBase58Ver_MultiSign address is valid."),
											  std::make_pair(-10033, "Verify whether the kBase58Ver_All address is valid."),
											  std::make_pair(-10034, "The owner size of the following five types of transactions must be 1!"),
											  std::make_pair(-10035, "Txowner does not allow duplicate!"),
											  std::make_pair(-10036, "The multiSignOwners is greater than 1. "),
											  std::make_pair(-10037, "The pub size of vin is equal to zero. "),
											  std::make_pair(-10038, "Check Base58Addr failed!"),
											  std::make_pair(-10039, "The prevout_size of VIN is equal to zero."),
											  std::make_pair(-10040, "The prevout.hash() size is not equal to 64."),
											  std::make_pair(-10041, "Txowner and VIN signers are not consistent!"),
											  std::make_pair(-10042, "The sequence of VIN is not consistent!"),
											  std::make_pair(-10043, "Vin cannot be repeated except for the redeem or divest transaction!"),
											  std::make_pair(-10044, "Vin cannot be repeated except for the redeem or divest transaction!"),
											  std::make_pair(-10045, "The tx.utxo().vout_size() is equal to zero or greater than 1000."),
											  std::make_pair(-10046, "The pledge amount should be consistent with the output!"),
											  std::make_pair(-10047, "Check Base58Addr failed!"),
											  std::make_pair(-10048, "tx.utxo().vout_size() is greater than 2."),
											  std::make_pair(-10049, "The invest amount should be consistent with the output!"),
											  std::make_pair(-10050, "Check Base58Addr failed!"),
											  std::make_pair(-10051, "tx.utxo().vout_size() is greater than 2."),
											  std::make_pair(-10052, "kBase58Ver_MultiSign Check Base58Addr failed!"),
											  std::make_pair(-10053, "kBase58Ver_Normal Check Base58Addr failed!"),
											  std::make_pair(-10054, "tx.utxo().vout_size() is greater than 2."),
											  std::make_pair(-10055, "Check Base58Addr failed!"),
											  std::make_pair(-10056, "The amount in the output must be Greater than 0!"),
											  std::make_pair(-10057, "Multi-to-Multi transaction is not allowed!"),
											  std::make_pair(-10058, "sign.sign() or sign.pub().size() is equal to zero."),
											  std::make_pair(-10059, "serialize hash size is equal zero."),
											  std::make_pair(-10060, "Get public key from bytes failed!"),
											  std::make_pair(-10061, "Public key verify sign failed!"),
											  std::make_pair(-10062, "serVinHash VerifySignLambda failed."),
											  std::make_pair(-10063, "tx.utxo().multisign_size() is equal to zero."),
											  std::make_pair(-10064, "serUtxoHash VerifySignLambda failed."),
											  std::make_pair(-10065, "Determine whether the multi signature address is correct."),
											  std::make_pair(-10066, "Txowner and multi sign signers are not consistent!"),
											  std::make_pair(-10067, "The verifysign_size() is less than zero or greater than kConsensus."),
											  std::make_pair(-10068, "tx.identity() are not consistent!"),
											  std::make_pair(-10069, "Check Base58Addr failed!"),
											  std::make_pair(-10070, "serTxHash VerifySignLambda failed"),
											  std::make_pair(-10071, "tx.info().size() is not equal to zero."),
											  std::make_pair(-10072, "tx.reserve0().size()  or tx.reserve1().size()  is not equal to zero ."),
											  std::make_pair(-10073, "tx_sign_pre_hash.pub().size() is equal to zero."),
											  std::make_pair(-10074, "Check Base58Addr failed!"),
											  std::make_pair(-10075, "The initiator and receiver of the transaction are not allowed to sign for mining!"),
											  std::make_pair(-11001, "JSON failed to parse data field!"),
											  std::make_pair(-11002, "GetUtxoHashsByAddress failed!"),
											  std::make_pair(-11003, "GetStakeAddressUtxo failed!"),
											  std::make_pair(-11004, "The utxo used exists and is used!"),
											  std::make_pair(-11005, "GetBonusAddrInvestUtxosByBonusAddr failed!"),
											  std::make_pair(-11006, "The utxo used exists and is used!"),
											  std::make_pair(-11007, "The utxo used exists and is used!"),
											  std::make_pair(-11008, "Errors are not allowed for subscripts of pre utxo array!"),
											  std::make_pair(-11009, "Subscript out of bounds!"),
											  std::make_pair(-11010, "The Vout of the corresponding subscript of utxo used is incorrect!"),
											  std::make_pair(-11011, "The Vout of the corresponding subscript of utxo used is incorrect!"),
											  std::make_pair(-11012, "The Vout of the corresponding subscript of utxo used is incorrect!"),
											  std::make_pair(-11013, "Failed to obtain the amount claimed by the investor"),
											  std::make_pair(-11014, "The TotalClaim is not equal to the claimed amount"),
											  std::make_pair(-11015, "Input is not equal to output + packaging fee + handling fee!"),
											  std::make_pair(-11016, "get tx failed"),
											  std::make_pair(-11017, "The prevTx.hash() size is equal to zero."),
											  std::make_pair(-11018, "Found vinAddr in the prevTx.utxo().vout()."),
											  std::make_pair(-11019, "Utxo owner of transaction is not equal to 1"),
											  std::make_pair(-11201, "Get all stake address failed!"),
											  std::make_pair(-11202, "The account number has not staked assets!"),
											  std::make_pair(-11203, "Get stake utxo from address failed!"),
											  std::make_pair(-11204, "The utxo to be de staked is not in the staked utxo!"),
											  std::make_pair(-11205, "The staked utxo is not more than 30 days"),
											  std::make_pair(-11206, "Stake tx not found!"),
											  std::make_pair(-11208, "Stake value is zero!"),
											  std::make_pair(-11020, "The address of the withdrawal utxo is incorrect!"),
											  std::make_pair(-11021, "The value of the withdrawal utxo is incorrect!"),
											  std::make_pair(-11301, "The investor have already invested in a node!"),
											  std::make_pair(-11302, "The investment amount is less than 99"),
											  std::make_pair(-11303, "The account to be invested has not spent 500 to access the Internet!"),
											  std::make_pair(-11304, "Get invest addrs by node failed!"),
											  std::make_pair(-11305, "The account number to be invested have been invested by 999 people!"),
											  std::make_pair(-11306, "GetBonusAddrInvestUtxosByBonusAddr failed!"),
											  std::make_pair(-11307, "GetTransactionByHash failed!"),
											  std::make_pair(-11309, "The total amount invested in a single node will be more than 100000!"),
											  std::make_pair(-11022, "Utxo owner of transaction is not equal to 1"),
											  std::make_pair(-11023, "Utxo owner of transaction is not equal to 1"),
											  std::make_pair(-11401, "GetBonusAddrByInvestAddr failed!"),
											  std::make_pair(-11402, "The account has not invested assets to node!"),
											  std::make_pair(-11403, "GetBonusAddrInvestUtxosByBonusAddr failed!"),
											  std::make_pair(-11404, "The utxo to divest is not in the utxos that have been invested!"),
											  std::make_pair(-11405, "The invested utxo is not more than 1 day!"),
											  std::make_pair(-11406, "Invest tx not found!"),
											  std::make_pair(-11408, "The node to be divested is not invested!"),
											  std::make_pair(-11409, "The invested value is zero!"),
											  std::make_pair(-11024, "The address of the withdrawal utxo is incorrect!"),
											  std::make_pair(-11025, "The value of the withdrawal utxo is incorrect!"),
											  std::make_pair(-11026, "Failed to obtain multi sign address"),
											  std::make_pair(-11027, "No multi sign address found"),
											  std::make_pair(-11028, "Time to initiate claim > 1:00 a.m. & < my time"),
											  std::make_pair(-11029, "Failed to get bonus utxo."),
											  std::make_pair(-11030, "Set missing utxo"),
											  std::make_pair(-11031, "Claim time is not within the range."),
											  std::make_pair(-11032, "Failed to obtain investment address."),
											  std::make_pair(-11033, "Investment address is between 1 and 999."),
											  std::make_pair(-11034, "Failed to get bonusaddrinvestutxos."),
											  std::make_pair(-11035, "Failed to get transaction through hash."),
											  std::make_pair(-11036, "The total investment amount is less than kMinInvestAmt."),
											  std::make_pair(-11037, "Failed to obtain the total bonus amount."),
											  std::make_pair(-11038, "The difference between the total dividend amount and the node dividend is not equal to the value of Vout."),
											  std::make_pair(-11039, "The difference between the total dividend amount and the node dividend is equal to the value of Vout."),
											  std::make_pair(-11040, "LastVoutAmount given tx.utxo().vout(i.value)is not equal."),
											  std::make_pair(-11041, "Failed to obtain pledge address."),
											  std::make_pair(-11042, "Utxo owner of transaction is not equal to 1."),
											  std::make_pair(-11043, "Check base58 address."),
											  std::make_pair(-11044, "VerifyBonusAddr error."),
											  std::make_pair(-11045, "It is judged that the pledge time is less than 0."),
											  std::make_pair(-11046, "Height is not equal to transaction height."),
											  std::make_pair(-12001, "Transaction  number is not equal to 0."),
											  std::make_pair(-12002, "The signers number is not equal to kConsensus."),
											  std::make_pair(-12003, "The number of reward addresses is inconsistent."),
											  std::make_pair(-12000, "mistake verifyCount"),
											  std::make_pair(-13000, "msg txmsginfo type error")};

	return errInfo;
}
int HandleTx(const std::shared_ptr<TxMsgReq> &msg, const MsgData &msgdata)
{
	MagicSingleton<DONbenchmark>::GetInstance()->AddAgentTransactionReceiveMap(msg);

	auto errInfo = TxMsgReqCode();
	TxMsgAck ack;

	int ret = 0;
	ON_SCOPE_EXIT
	{
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, ack, ret);
	};

	CTransaction tx;

	ret = DoHandleTx(msg, tx);
	if (ret != 0)
	{
		ERRORLOG("trasaction {} turnover fail {}", tx.hash(), ret);
	}
	ack.set_tx(tx.SerializeAsString());
	return ret;
}

int DoHandleContractTx( const std::shared_ptr<ContractTempTxMsgReq>& msg, CTransaction & outTx){
	// Judge whether the version is compatible
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("Incompatible version!");
		return -1;
	}

	// Judge whether the height is reasonable
	uint64_t txheight = msg->txmsginfo().height();
	CTransaction tx;
	if (!tx.ParseFromString(msg->txmsginfo().tx()))
	{
		ERRORLOG("Failed to deserialize transaction body!");
		return -2;
	}

	DEBUGLOG("Start DoHandleTx txHash:{}",tx.hash().substr(0,6));

	ON_SCOPE_EXIT
	{
		outTx = tx;
	};


	int64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	MagicSingleton<DONbenchmark>::GetInstance()->SetByTxHash(tx.hash(), &nowTime, 1);

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return -3;
    }

	int ret = VerifyTxTimeOut(tx);
	if(txheight > top && ret == 0)
	{
		DEBUGLOG("TTT txHeight:{} > top:{}, repeat commit tx, txhash:{}",txheight, top, tx.hash());
		MagicSingleton<FailedTransactionCache>::GetInstance()->Add(txheight, *msg);
		return -4;
	}

	if(ret != 0)
	{
		ERRORLOG("tx timeout:{}", nowTime - (int64_t)tx.time());
		return -5;
	}

	if (!checkTop(txheight))
	{
		ERRORLOG("Unreasonable height!");
		return -6;
	}

	MagicSingleton<BlockStroage>::GetInstance()->CommitSeekTask(txheight);
	if (msg->txmsginfo().type() != 0)
	{
		ERRORLOG("type Error!");
		return -7;
	}

	ret = VerifyContractTxMsgReq(*msg);
	if (ret != 0)
	{
		ERRORLOG("Verify fail");
		return ret -10000;
	}

	std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	if (TxHelper::AddVerifySign(defaultBase58Addr, tx) != 0)
	{
		ERRORLOG("DoHandle Contract tx Add verify sign fail");
		return -8;
	}
	TxHelper::vrfAgentType type;
	//Gets the type of transaction initiated
	global::ca::TxType txType = (global::ca::TxType)tx.txtype();
	if(global::ca::TxType::kTxTypeCallContract == txType || global::ca::TxType::kTxTypeDeployContract == txType)
	{
		type = TxHelper::vrfAgentType_vrf;
	}
	else 
	{
		TxHelper::GetContractTxStartIdentity(txheight + 1, tx.time(), type);
	}

	if (type == TxHelper::vrfAgentType::vrfAgentType_vrf)
	{

		if(global::ca::TxType::kTxTypeCallContract != txType && global::ca::TxType::kTxTypeDeployContract != txType)
		{
			ret = IsVrfVerifyContractNode(defaultBase58Addr, msg);
			if(ret == -5)
			{
				DEBUGLOG("TTT block not found, repeat commit tx ,txHeight:{}, txhash:{}",txheight, tx.hash());
				MagicSingleton<FailedTransactionCache>::GetInstance()->Add(txheight, *msg);
				return -9;
			}
		}
		else
		{
			ret = VerifyContractDistributionManager(tx, txheight, msg->vrfinfo());
		}

		if (ret != 0)
		{
			ERRORLOG("TTT I am not a transaction issuing node = {} , tx hash = {}, ret = {}", defaultBase58Addr, tx.hash(), ret);
			return -10;
		}
	}

	ret = UpdateTxMsg(tx, msg);
	if (0 != ret)
	{
		if( ret == -103 || ret == -105 || ret == -106)
		{
			DEBUGLOG("TTT NodelistHeight discontent, repeat commit tx ,txHeight:{}, txhash:{}, ret:{}",txheight, tx.hash(), ret);
			MagicSingleton<FailedTransactionCache>::GetInstance()->Add(txheight, *msg);
			return 0;
		}
		ERRORLOG("UpdateTxMsg failed");
		return  -11;
	}

	ret = MagicSingleton<CtransactionCache>::GetInstance()->contract_add_cache(tx, txheight,{msg->txmsginfo().contractstoragelist().begin(), msg->txmsginfo().contractstoragelist().end()});
	if (ret != 0)
	{
		ERRORLOG("add to TransactionCache fail");
		return -12;
	}
	DEBUGLOG("End DoHandleTx txHash:{}",tx.hash().substr(0,6));
	return 0;
}

int DoHandleTx(const std::shared_ptr<TxMsgReq> &msg, CTransaction &outTx)
{
	// Judge whether the version is compatible
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("Incompatible version!");
		return -1;
	}

	// Judge whether the height is reasonable
	uint64_t txheight = msg->txmsginfo().height();
	if (!checkTop(txheight))
	{
		ERRORLOG("Unreasonable height!");
		return -2;
	}

	CTransaction tx;
	if (!tx.ParseFromString(msg->txmsginfo().tx()))
	{
		ERRORLOG("Failed to deserialize transaction body!");
		return -3;
	}

	ON_SCOPE_EXIT
	{
		outTx = tx;
	};

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return -4;
    }

	std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	if (msg->txmsginfo().type() != 0)
	{
		ERRORLOG("type Error!");
		return -5;
	}

	int verifyCount = tx.verifysign_size();
	std::vector<std::string> owners(tx.utxo().owner().begin(), tx.utxo().owner().end());
	if (verifyCount == 2 && defaultBase58Addr == tx.identity())
	{
		//Determine whether the transaction initiator is a type of local payment, local payment on behalf or agent payment of vrf
		TxHelper::vrfAgentType type;
		TxHelper::GetTxStartIdentity(owners, txheight + 1, tx.time(), type);
		if (type == TxHelper::vrfAgentType::vrfAgentType_vrf)
		{
			std::pair<std::string, std::vector<std::string>> nodes_pair;
			MagicSingleton<VRF>::GetInstance()->getVerifyNodes(tx.hash(), nodes_pair);
			std::vector<std::string> nodes = nodes_pair.second;
			auto id_ = GetBase58Addr(tx.verifysign(1).pub());
			auto iter = std::find(nodes.begin(), nodes.end(), id_);
			if (iter == nodes.end())
			{
				ERRORLOG("vrf sign node = {} info fail", id_);
				return -6;
			}
		}
		int update_num = MagicSingleton<TranStroage>::GetInstance()->Update(*msg);
		if (update_num != 0)
		{
			ERRORLOG("Update error is {}",update_num);
			ERRORLOG("Update fail");
			return -7;
		}
	}
	else
	{

		int ret = VerifyTxMsgReq(*msg);
		if (ret != 0)
		{
			ERRORLOG("Verify fail");
			return ret -10000;
		}

		if (TxHelper::AddVerifySign(defaultBase58Addr, tx) != 0)
		{
			ERRORLOG("Add verify sign fail");
			return -8;
		}

		if (AddPreHash(msg, tx) != 0)
		{
			ERRORLOG("AddPreHash fail");
			return -9;
		}

		if (verifyCount == 0)
		{
			TxHelper::vrfAgentType type;
			TxHelper::GetTxStartIdentity(owners, txheight + 1, tx.time(), type);
			TxMsgInfo *txmsginfo_ = msg->mutable_txmsginfo();

			if (type == TxHelper::vrfAgentType::vrfAgentType_vrf)
			{
				CTransaction copyTx = tx;
				copyTx.clear_hash();
				copyTx.clear_verifysign();
				
				tx.set_hash(getsha256hash(copyTx.SerializeAsString()));
				txmsginfo_->set_tx(tx.SerializeAsString());

				if (IsVrfVerifyNode(defaultBase58Addr, msg) != 0)
				{
					ERRORLOG("I am not a transaction issuing node = {} , tx hash = {}", defaultBase58Addr, tx.hash());
					return -10;
				}
			}
			ret = (MagicSingleton<TranStroage>::GetInstance()->Add(*msg));
			if (ret != 0)
			{
				
				ERRORLOG("add to TranStroage fail");
				return - 11;
			}

			CTransaction copyTx = tx;
			copyTx.clear_hash();
			copyTx.clear_verifysign();
			uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
			MagicSingleton<DONbenchmark>::GetInstance()->SetByTxHash(getsha256hash(copyTx.SerializeAsString()),&nowTime, 1);
			
			// send to other node
			ret = SendTxMsg(tx, msg);
			if (0 != ret)
			{
				ERRORLOG("Send ContractTempTxMsgReq failed");
				return ret - 20000;
			}

			if (GetBase58Addr(tx.verifysign(0).pub()) == defaultBase58Addr)
			{
				CTransaction copyTx = tx;
				copyTx.clear_hash();
				copyTx.clear_verifysign();
				tx.set_hash(getsha256hash(copyTx.SerializeAsString()));
				txmsginfo_->set_tx(tx.SerializeAsString());
				MagicSingleton<TranMonitor>::GetInstance()->AddTxHash(tx.hash());
			}
		}
		else if (verifyCount == 1)
		{
			uint64_t handleTxHeight = msg->txmsginfo().height();

			//Check whether you are the signature node specified by VRF
			auto CheckVrfVerify = [](const std::shared_ptr<TxMsgReq> &msg) -> int
			{
				double proportion = 0.0;

				Vrf vrfinfo = msg->txvrfinfo();
				EVP_PKEY *pkey = nullptr;
				std::string pub_str = vrfinfo.vrfsign().pub();
				if (!GetEDPubKeyByBytes(pub_str, pkey))
				{
					ERRORLOG(RED "Get public key from bytes failed!" RESET);
					return -1;
				}

				std::string hash;
				int range = 0;
				if(getVrfdata(vrfinfo, hash, range, proportion) != 0)
				{
					return -2;
				}
				std::string output;
				std::string proof = vrfinfo.vrfsign().sign();
				MagicSingleton<VRF>::GetInstance()->VerifyVRF(pkey, hash, output, proof);
				double seletRandom = MagicSingleton<VRF>::GetInstance()->GetRandNum(output); //Get VRF random number

				int radius = global::ca::KSign_node_threshold / proportion;

				DEBUGLOG("the range radius: {}", radius);
				DEBUGLOG("The Random :{}", seletRandom);
				DEBUGLOG("The proportion is:{}", proportion);

				//Filter transaction parties
				std::vector<Node> nodelist;

				CTransaction tx;
				if (!tx.ParseFromString(msg->txmsginfo().tx()))
				{
					ERRORLOG("Failed to deserialize transaction body!");
					return -3;
				}

				filterNodeList(tx, nodelist);
				nodelist.push_back(tx.identity());

				std::sort(nodelist.begin(), nodelist.end(), [&](const Node &n1, const Node &n2)
						  { return n1.base58address < n2.base58address; });

				vector<Node> stakeNodes;
				for (const auto &node : nodelist)
				{
					if(CheckVerifyNodeQualification(node.base58address) == 0)
					{
						stakeNodes.push_back(node);
					}
				}

				std::vector<std::string> eligible_addrs;
				if (stakeNodes.size() < global::ca::kNeed_node_threshold)
				{
					for (const auto &node : nodelist)
					{
						eligible_addrs.push_back(node.base58address);
					}
				}
				else
				{
					for (const auto &node : stakeNodes)
					{
						eligible_addrs.push_back(node.base58address);
					}
				}

				if (msg->txmsginfo().height() > global::ca::kMinUnstakeHeight)
				{
					if (proportion * stakeNodes.size() < global::ca::kNeed_node_threshold)
					{
						ERRORLOG(" stake nodes less than: {}", global::ca::kNeed_node_threshold);
						return -4;
					}
				}
				std::sort(eligible_addrs.begin(), eligible_addrs.end(), [](const std::string &addr1, const std::string &addr2)
						  { return addr1 < addr2; });


				Cycliclist<std::string> all_list;

				for (auto &addr : eligible_addrs)
				{
					all_list.push_back(addr);
				}

				//Take out all nodes in the vrf range to determine whether they are in it
				int target_pos = eligible_addrs.size() * seletRandom;

				auto begin = all_list.begin();
				auto target = begin + target_pos;
				auto begin_pos = target - radius;
				auto end_pos = target + radius;

				std::string base58_default = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
				for (; begin_pos != end_pos; begin_pos++)
				{
					if (base58_default == begin_pos->data)
					{
						return 0;
					}
				}

				if (begin_pos->data == base58_default)
				{

					return 0;
				}

				return -5;
			};

			TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);
			if (type == TxHelper::vrfAgentType::vrfAgentType_vrf)
			{
				//Check whether the dropshipping node is a VP-specified node
				ret = IsVrfVerifyNode(tx.identity(), msg);
				if (ret != 0)
				{
					ERRORLOG("The issuing node = {} is not the specified node, ret: {}", tx.identity(), ret);
					// write_tmplog("Issuing transaction " + tx.hash() + " The specified issuing node is inconsistent with the actual issuing node");
					return ret - 200;
				}
				int _ret = CheckVrfVerify(msg);
				if (_ret != 0)
				{
					ERRORLOG("The signature node is not selected by vrf : {}", _ret);
					return _ret - 300;
				}
			}

			TxMsgInfo *txmsginfo_ = msg->mutable_txmsginfo();
			CTransaction copyTx = tx;
			copyTx.clear_hash();
			copyTx.clear_verifysign();
			tx.set_hash(getsha256hash(copyTx.SerializeAsString()));

			txmsginfo_->set_tx(tx.SerializeAsString());
			// send to origin node
			if (defaultBase58Addr != tx.identity() && tx.verifysign_size() == 2)
			{
				net_send_message<TxMsgReq>(tx.identity(), *msg, net_com::Priority::kPriority_High_1);
				DEBUGLOG("TX Send to ip[{}] to Create Block ...", tx.identity().c_str());
			}
		}
		else
		{
			// error
			ERRORLOG("unknow type!");
			return -12;
		}
	}

	return 0;
}

int IsVrfVerifyContractNode(const std::string identity, const std::shared_ptr<ContractTempTxMsgReq> &msg){
	CTransaction tx;
	if (!tx.ParseFromString(msg->txmsginfo().tx()))
	{
		ERRORLOG("Failed to deserialize transaction body!");
		return -1;
	}
	DEBUGLOG("Issuing transaction verification tx hash = {}", tx.hash());
	EVP_PKEY *pkey = nullptr;
	int range;
	std::string hash;
	NewVrf vrfInfo = msg->vrfinfo();
	if(getNewVrfdata(vrfInfo, hash, range) != 0)
	{
		return -2;
	}

	std::string pub_str = msg->vrfinfo().vrfsign().pub();
	if (!GetEDPubKeyByBytes(pub_str, pkey))
	{
		ERRORLOG("vrf pub str is empty = {} ", pub_str.size());
		return -3;
	}

	std::string proof = msg->vrfinfo().vrfsign().sign();

	auto getUtxoHash = [](CTransaction &tx) -> std::string
	{
		std::string AllHash;
		auto utxo_ = tx.utxo();
		for (int i = 0; i < utxo_.vin_size(); i++)
		{
			auto vin = utxo_.vin(i);
			for (int j = 0; j < vin.prevout_size(); j++)
			{
				auto CTxPrevOutput_ = vin.prevout(j);
				AllHash += CTxPrevOutput_.hash();
			}
		}
		AllHash += std::to_string(tx.time());
		return AllHash;
	};
	std::string result;
	if (MagicSingleton<VRF>::GetInstance()->VerifyVRF(pkey, getUtxoHash(tx), result, proof) != 0)
	{
		ERRORLOG(RED "Verify VRF Info fail" RESET);
		return -4;
	}

	std::string block;
	DBReader db_reader;
	std::string block_hash = hash;
	if (DBStatus::DB_SUCCESS != db_reader.GetBlockByBlockHash(block_hash, block))
	{
		ERRORLOG("GetBlockByBlockHash block hash = {} ", block_hash);
		return -5;
	}
	CBlock cblock;
	if (!cblock.ParseFromString(block))
	{
		ERRORLOG("block parse string fail !");
		return -6;
	}

	std::vector<std::string> target_addrs;
	for (int i = 2; i < 5; ++i)
	{
		target_addrs.push_back(GetBase58Addr(cblock.sign(i).pub()));
	}

	if (target_addrs.size() < 3)
	{
		ERRORLOG("target addrs block sign size = {} ", target_addrs.size());
		return -7;
	}

	int rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(result, 3);

	std::string target_addr = target_addrs[rand_num];
	if (identity != target_addr)
	{
		ERRORLOG("Issuing node = {} not equal target node = {}", target_addr, identity);
		return -8;
	}

	return 0;

}

int IsVrfVerifyNode(const CTransaction& tx, const NewVrf& vrfInfo)
{
	DEBUGLOG("Issuing transaction verification tx hash = {}", tx.hash());
	EVP_PKEY *pkey = nullptr;
	int range;
	std::string hash;
	if(getNewVrfdata(vrfInfo, hash, range) != 0)
	{
		return -1;
	}

	std::string pubStr = vrfInfo.vrfsign().pub();
	if (!GetEDPubKeyByBytes(pubStr, pkey))
	{
		ERRORLOG("vrf pub str is empty = {} ", pubStr.size());
		return -2;
	}

	std::string proof = vrfInfo.vrfsign().sign();

	auto getUtxoHash = [](const CTransaction &tx) -> std::string
	{
		std::string allHash;
		auto txUtxo = tx.utxo();
		for (int i = 0; i < txUtxo.vin_size(); i++)
		{
			auto vin = txUtxo.vin(i);
			for (int j = 0; j < vin.prevout_size(); j++)
			{
				auto CTxPrevOutput_ = vin.prevout(j);
				allHash += CTxPrevOutput_.hash();
			}
		}
		allHash += std::to_string(tx.time());
		return allHash;
	};
	std::string result;
	if (MagicSingleton<VRF>::GetInstance()->VerifyVRF(pkey, getUtxoHash(tx), result, proof) != 0)
	{
		ERRORLOG(RED "Verify VRF Info fail" RESET);
		return -3;
	}

	std::string block;
	DBReader dbReader;
	std::string blockHash = hash;
	if (DBStatus::DB_SUCCESS != dbReader.GetBlockByBlockHash(blockHash, block))
	{
		ERRORLOG("GetBlockByBlockHash block hash = {} ", blockHash);
		return -4;
	}
	CBlock cblock;
	if (!cblock.ParseFromString(block))
	{
		ERRORLOG("block parse string fail !");
		return -5;
	}

	//Take 3, 4, 5, 6 and 7 of the signature array of the block. Use vrf to randomly find an address as the packing node in the five addresses
	// 0 1 2 3 4 5 6
	std::vector<std::string> targetAddrs;
	for (int i = 2; i < 7; ++i)
	{
		targetAddrs.push_back(GetBase58Addr(cblock.sign(i).pub()));
	}

	if (targetAddrs.size() < global::ca::KSign_node_threshold)
	{
		ERRORLOG("target addrs block sign size = {} ", targetAddrs.size());
		return -6;
	}

	int randNum = MagicSingleton<VRF>::GetInstance()->GetRandNum(result, global::ca::KSign_node_threshold);

	std::string targetAddr = targetAddrs[randNum];
	if (tx.identity() != targetAddr)
	{
		ERRORLOG("Issuing node = {} not equal target node = {}", targetAddr, tx.identity());
		return -7;
	}

	return 0;
}

int IsVrfVerifyNode(const std::string identity, const std::shared_ptr<TxMsgReq> &msg)
{
	CTransaction tx;
	if (!tx.ParseFromString(msg->txmsginfo().tx()))
	{
		ERRORLOG("Failed to deserialize transaction body!");
		return -1;
	}
	DEBUGLOG("Issuing transaction verification tx hash = {}", tx.hash());
	EVP_PKEY *pkey = nullptr;
	int range;
	std::string hash;
	Vrf vrfInfo = msg->vrfinfo();
	if(getVrfdata(vrfInfo, hash, range) != 0)
	{
		return -2;
	}

	std::string pub_str = msg->vrfinfo().vrfsign().pub();
	if (!GetEDPubKeyByBytes(pub_str, pkey))
	{
		ERRORLOG("vrf pub str is empty = {} ", pub_str.size());
		return -3;
	}

	std::string proof = msg->vrfinfo().vrfsign().sign();

	auto getUtxoHash = [](CTransaction &tx) -> std::string
	{
		std::string AllHash;
		auto utxo_ = tx.utxo();
		for (int i = 0; i < utxo_.vin_size(); i++)
		{
			auto vin = utxo_.vin(i);
			for (int j = 0; j < vin.prevout_size(); j++)
			{
				auto CTxPrevOutput_ = vin.prevout(j);
				AllHash += CTxPrevOutput_.hash();
			}
		}
		AllHash += std::to_string(tx.time());
		return AllHash;
	};
	std::string result;
	if (MagicSingleton<VRF>::GetInstance()->VerifyVRF(pkey, getUtxoHash(tx), result, proof) != 0)
	{
		ERRORLOG(RED "Verify VRF Info fail" RESET);
		return -4;
	}

	std::string block;
	DBReader db_reader;
	std::string block_hash = hash;
	if (DBStatus::DB_SUCCESS != db_reader.GetBlockByBlockHash(block_hash, block))
	{
		ERRORLOG("GetBlockByBlockHash block hash = {} ", block_hash);
		return -5;
	}
	CBlock cblock;
	if (!cblock.ParseFromString(block))
	{
		ERRORLOG("block parse string fail !");
		return -6;
	}

	std::vector<std::string> target_addrs;
	for (int i = 2; i < 5; ++i)
	{
		target_addrs.push_back(GetBase58Addr(cblock.sign(i).pub()));
	}

	if (target_addrs.size() < 3)
	{
		ERRORLOG("target addrs block sign size = {} ", target_addrs.size());
		return -7;
	}

	int rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(result, 3);

	std::string target_addr = target_addrs[rand_num];
	if (identity != target_addr)
	{
		ERRORLOG("Issuing node = {} not equal target node = {}", target_addr, identity);
		return -8;
	}

	return 0;
}

int SearchNodeToSendContractMsg(ContractBlockMsg &msg)
{
	CBlock cblock;
	cblock.ParseFromString(msg.block());

	// Circular linked list
	Cycliclist<std::string> list;
    std::unordered_set<std::string> addrList;
	for (auto &iter : cblock.txs())
	{
		auto transaction_type = GetTransactionType(iter);
		if (kTransactionType_Tx == transaction_type)
		{
			for (auto &sign_node : iter.verifysign())
			{
				addrList.insert(GetBase58Addr(sign_node.pub()));
			}
		}
	}

	// if( addrList.size() < global::ca::KSign_node_threshold )  
    // {
    //     DEBUGLOG("size = {},Less than {} ==============================================================", addrList.size(), global::ca::KSign_node_threshold);
	// 	return -7;
    // }

	for(auto & addr : addrList)
    {
        list.push_back(addr);
    }
	
	//The signature nodes of all transactions in the block are stored in a circular linked list

	std::string output, proof;
	Account defaultAccount;
	EVP_PKEY_free(defaultAccount.pkey);
	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount) != 0)
	{
		ERRORLOG("Failed to get the default account");
		return -1;
	}

	int ret = MagicSingleton<VRF>::GetInstance()->CreateVRF(defaultAccount.pkey, cblock.hash(), output, proof);
	if (ret != 0)
	{
		std::cout << "error create:" << ret << std::endl;
		ERRORLOG("generate VRF info fail");
		return -2;
	}

	double rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(output);
	int rand_pos = list.size() * rand_num;

	const int sign_threshold = global::ca::KSign_node_threshold / 2;
	// Stores the signature node randomly found by VRF
	std::vector<std::string> target_addr;

	auto end_pos = rand_pos - sign_threshold;

	ret = filterSendContractList(end_pos,list,target_addr);
	if(ret != 0)
	{
		ERRORLOG("filter send node faile !");
		return -3;
	}

	// for (; target_addr.size() < global::ca::KSign_node_threshold; end_pos++)
	// {
	// 	target_addr.push_back(list[end_pos]);
	// }

	// // Determine whether the number of signatures found by VRF and the number of consensus are consistent
	// if (global::ca::KSign_node_threshold != target_addr.size())
	// {
	// 	ERRORLOG("Insufficient signature nodes = {}, global::ca::KSign_node_threshold = {}", target_addr.size(), global::ca::KSign_node_threshold);
	// 	return -3;
	// }

	std::vector<std::string> sign_addr;
	for (auto ite = list.begin(); ite != list.end(); ite++)
	{
		sign_addr.push_back(ite->data);
	}
	sign_addr.push_back(list.end()->data);

	// Determine whether the random signature node of VRF is in the transaction signature node in the block
	for (auto &item : target_addr)
	{
		if (std::find(sign_addr.begin(), sign_addr.end(), item) == sign_addr.end())
		{
			ERRORLOG("sign addr = {} error !", item);
			return -4;
		}
	}

	// Fill in the block flow information into the VRF cache
	// nlohmann::json data;
	// data["hash"] = cblock.hash();
	// data["range"] = 0;
	// data["percentage"] = 0;

	//std::string dataStr = data.dump();
	NewVrf info;
	auto vrfData = info.mutable_vrfdata();
	vrfData->set_hash(cblock.hash());
	vrfData->set_range(0);
	SetNewVrf(info, proof, defaultAccount.pubStr);

	MagicSingleton<VRF>::GetInstance()->addNewVrfInfo(cblock.hash(), info);
	MagicSingleton<VRF>::GetInstance()->addVerifyNodes(cblock.hash(), target_addr);

	for (auto &iter : target_addr)
	{
		//std::cout <<"contrac block msg search node to send contract msg";
		DEBUGLOG("block verify broadcast addr = {} ", iter);
		net_send_message<ContractBlockMsg>(iter, msg, net_com::Priority::kPriority_High_1);
	}

	return 0;
}

int SearchNodeToSendMsg(BlockMsg &msg)
{
	CBlock cblock;
	cblock.ParseFromString(msg.block());

	// Circular linked list
	Cycliclist<std::string> list;
    std::unordered_set<std::string> addrList;
	for (auto &iter : cblock.txs())
	{
		auto transaction_type = GetTransactionType(iter);
		if (kTransactionType_Tx == transaction_type)
		{
			for (auto &sign_node : iter.verifysign())
			{
				addrList.insert(GetBase58Addr(sign_node.pub()));
			}
		}
	}

	for(auto & addr : addrList)
    {
        list.push_back(addr);
    }
	
	//	The signature node for all transactions in the }// block is stored in a circular linked list

	std::string output, proof;
	Account defaultAccount;
	EVP_PKEY_free(defaultAccount.pkey);
	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount) != 0)
	{
		ERRORLOG("Failed to get the default account");
		return -1;
	}

	int ret = MagicSingleton<VRF>::GetInstance()->CreateVRF(defaultAccount.pkey, cblock.hash(), output, proof);
	if (ret != 0)
	{
		std::cout << "error create:" << ret << std::endl;
		ERRORLOG("generate VRF info fail");
		return -2;
	}

	double rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(output);
	int rand_pos = list.size() * rand_num;

	const int sign_threshold = global::ca::KSign_node_threshold / 2;
	// Stores the signature node randomly found by VRF
	std::vector<std::string> target_addr;

	auto end_pos = rand_pos - sign_threshold;

	ret = filterSendList(end_pos,list,target_addr);
	if(ret != 0)
	{
		ERRORLOG("filter send node faile !");
		return -3;
	}

	// for (; target_addr.size() < global::ca::KSign_node_threshold; end_pos++)
	// {
	// 	target_addr.push_back(list[end_pos]);
	// }

	// // Determine whether the number of signatures found by VRF and the number of consensus are consistent
	// if (global::ca::KSign_node_threshold != target_addr.size())
	// {
	// 	ERRORLOG("Insufficient signature nodes = {}, global::ca::KSign_node_threshold = {}", target_addr.size(), global::ca::KSign_node_threshold);
	// 	return -3;
	// }

	std::vector<std::string> sign_addr;
	for (auto ite = list.begin(); ite != list.end(); ite++)
	{
		sign_addr.push_back(ite->data);
	}
	sign_addr.push_back(list.end()->data);

	// Determine whether the random signature node of VRF is in the transaction signature node in the block
	for (auto &item : target_addr)
	{
		if (std::find(sign_addr.begin(), sign_addr.end(), item) == sign_addr.end())
		{
			ERRORLOG("sign addr = {} error !", item);
			return -4;
		}
	}

	// Fill in the block flow information into the VRF cache
	nlohmann::json data;
	data["hash"] = cblock.hash();
	data["range"] = 0;
	data["percentage"] = 0;

	std::string dataStr = data.dump();
	Vrf info;
	setVrf(info, proof, defaultAccount.pubStr, dataStr);

	MagicSingleton<VRF>::GetInstance()->addVrfInfo(cblock.hash(), info);
	MagicSingleton<VRF>::GetInstance()->addVerifyNodes(cblock.hash(), target_addr);

	for (auto &iter : target_addr)
	{
		DEBUGLOG("block verify broadcast addr = {} ", iter);
		net_send_message<BlockMsg>(iter, msg, net_com::Priority::kPriority_High_1);
	}

	return 0;
}

int SearchStake(const std::string &address, uint64_t &stakeamount, global::ca::StakeType stakeType)
{
	DBReader db_reader;
	// CBlockDataApi data_reader;
	std::vector<string> utxos;
	auto status = db_reader.GetStakeAddressUtxo(address, utxos);
	if (DBStatus::DB_SUCCESS != status)
	{
		ERRORLOG("GetStakeAddressUtxo fail db_status:{}", status);
		return -1;
	}
	uint64_t total = 0;
	for (auto &item : utxos)
	{
		std::string strTxRaw;
		if (DBStatus::DB_SUCCESS != db_reader.GetTransactionByHash(item, strTxRaw))
		{
			continue;
		}
		CTransaction utxoTx;
		utxoTx.ParseFromString(strTxRaw);

		nlohmann::json data;
		if(!utxoTx.data().empty())
		{
			data = nlohmann::json::parse(utxoTx.data());
		}
		else
		{
			ERRORLOG("data is empty");
			return -1;
		}

		nlohmann::json txInfo;
		if(!data["TxInfo"].empty())
		{
			txInfo = data["TxInfo"].get<nlohmann::json>();
		}
		else
		{
			ERRORLOG("TxInfo is get error");
			return -2;
		}

		std::string txStakeTypeNet;
		if(!txInfo["StakeType"].empty())
		{
			txStakeTypeNet = txInfo["StakeType"].get<std::string>();
		}
		else
		{
			ERRORLOG("StakeType is error");
			return -3;	
		}

		if (stakeType == global::ca::StakeType::kStakeType_Node && txStakeTypeNet != global::ca::kStakeTypeNet)
		{
			continue;
		}

		for (int i = 0; i < utxoTx.utxo().vout_size(); i++)
		{
			CTxOutput txout = utxoTx.utxo().vout(i);
			if (txout.addr() == global::ca::kVirtualStakeAddr)
			{
				total += txout.value();
			}
		}
	}
	stakeamount = total;
	return 0;
}


static void SignNodeFilter(Cycliclist<Node>::iterator &start, Cycliclist<Node>::iterator &end, const std::vector<Node> &filter_addrs, const int &sign_node_threshold, std::set<std::string> &target_nodes, uint64_t &top)
{
	for (; start != end; start++)
	{
		auto node = start->data;
		auto find_result = std::find_if(filter_addrs.begin(), filter_addrs.end(), [node](const Node &findNode)
										{ return node.base58address == findNode.base58address; });

		if (find_result != filter_addrs.end())
		{
			if (sign_node_threshold > target_nodes.size() && node.height >= top)
			{
				target_nodes.insert(node.base58address);
				DEBUGLOG("node {} meets the requirements of sign node", node.base58address);
			}
		}
		else
		{
			DEBUGLOG("node {} doesn't meet the requirements of sign node", node.base58address);
		}
	}
}

static void RandomSelectNode(const std::vector<Node> &nodes, const double &rand_num, const int &sign_node_threshold, const bool &flag, std::set<std::string> &out_nodes, int &range , uint64_t & top)
{
	// Select the range of nodes from the node cache
	int target_pos = nodes.size() * rand_num;

	Cycliclist<Node> list;

	for (auto &node : nodes)
	{
		list.push_back(node);
	}

	auto begin = list.begin();
	auto target = begin + target_pos;
	auto start_pos = target - range;
	auto end_pos = target + range;

	
	int iter_count = range * 2;
	if (nodes.size() < iter_count)
	{
		DEBUGLOG("peer node cache size = {} less than target num = {}", nodes.size(), iter_count);
		return;
	}

	std::string ownerID = net_get_self_node_id();
	//Find the nodes within the range of the circular linked list that match the node height and filter their own nodes to add to the collection
	for (; start_pos != end_pos; start_pos++)
	{
		
		if(start_pos->data.height >= top)
		{
			if(out_nodes.size() > sign_node_threshold)
			{
				return;
			}

			if(start_pos->data.base58address == ownerID)
			{
				continue;
			}
			out_nodes.insert(start_pos->data.base58address);
			
		}
	}

	return;
}

// Random select node from list, 20211207  Liu
static void RandomSelectNode(const vector<Node> &nodes, size_t selectNumber, std::set<std::string> &outNodes)
{
	if (nodes.empty())
		return;

	vector<Node> tmp_nodes = nodes;

	std::random_device device;
	std::mt19937 engine(device());
	std::uniform_int_distribution<size_t> dist(0, tmp_nodes.size() - 1);

	const size_t randomCount = std::min(tmp_nodes.size(), selectNumber);
	std::unordered_set<size_t> randomIndexs;
	while (randomIndexs.size() < randomCount)
	{
		size_t random = dist(engine);
		randomIndexs.insert(random);
	}

	for (const auto &i : randomIndexs)
	{
		outNodes.insert(tmp_nodes[i].base58address);
	}
}
// Random select node from list, 20211207  Liu
static void RandomContractSelectNode(const vector<Node> &nodes, size_t selectNumber, std::unordered_set<std::string> &outNodes)
{
	if (nodes.empty())
		return;

	vector<Node> tmp_nodes = nodes;

	std::random_device device;
	std::mt19937 engine(device());
	std::uniform_int_distribution<size_t> dist(0, tmp_nodes.size() - 1);

	const size_t randomCount = std::min(tmp_nodes.size(), selectNumber);
	std::unordered_set<size_t> randomIndexs;
	while (randomIndexs.size() < randomCount)
	{
		size_t random = dist(engine);
		randomIndexs.insert(random);
	}

	for (const auto &i : randomIndexs)
	{
		outNodes.insert(tmp_nodes[i].base58address);
	}
}

static void filterContractNodeList(const CTransaction & tx, const bool & isBonus, const uint64_t &top, std::vector<Node> &outAddrs)
{
	std::vector<Node> conNodeList = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
	std::string ownerID = net_get_self_node_id();

	//Take out both sides of the transaction
	std::vector<std::string> txAddrs;
	if (!isBonus)
	{
		for (int i = 0; i < tx.utxo().vout_size(); ++i)
		{
			CTxOutput txout = tx.utxo().vout(i);
			txAddrs.push_back(txout.addr());
		}
	}
	else
	{
		CTxOutput txout = tx.utxo().vout(tx.utxo().vout_size() - 1);
		txAddrs.push_back(txout.addr());
	}

	std::vector<Node> nodeListTmp;
	for (auto iter = conNodeList.begin(); iter != conNodeList.end(); ++iter)
	{
		if(ownerID == iter->base58address)
		{
			DEBUGLOG("ownerID filter");
		}
		
		// Delete both sides of the transaction node
		if (txAddrs.end() != find(txAddrs.begin(), txAddrs.end(), iter->base58address))
		{
			DEBUGLOG("FindSignNode filter: exchanger {}", iter->base58address);
			continue;
		}

		if (iter->height < top)
		{
			DEBUGLOG("FindSignNode filter: height {} less than top {}", iter->height, top);
			continue;
		}
		
		if (tx.identity() == iter->base58address)
		{
			DEBUGLOG("FindSignNode filter: identity addr");
			continue;
		}

		nodeListTmp.push_back(*iter);
	}

	outAddrs = nodeListTmp;
	std::sort(outAddrs.begin(), outAddrs.end(), [&](const Node &n1, const Node &n2)
			  { return n1.base58address < n2.base58address; });

}

static void filterNodeList(const CTransaction & tx, std::vector<Node> &outAddrs)
{
	std::vector<Node> nodelist = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
	//Recipient address
	std::vector<std::string> txAddrs;
	global::ca::TxType txType = (global::ca::TxType)tx.txtype();
	if(txType == global::ca::TxType::kTxTypeBonus)
	{
		CTxOutput txout = tx.utxo().vout(tx.utxo().vout_size() - 1);
		txAddrs.push_back(txout.addr());
	}
	else
	{
		for (int i = 0; i < tx.utxo().vout_size(); ++i)
		{
			CTxOutput txout = tx.utxo().vout(i);
			txAddrs.push_back(txout.addr());
		}
	}	

	std::vector<std::string> txOwners(tx.utxo().owner().begin(), tx.utxo().owner().end());


	for (auto iter = nodelist.begin(); iter != nodelist.end(); ++iter)
	{
		//Delete initiator node
		if (txOwners.end() != find(txOwners.begin(), txOwners.end(), iter->base58address))
		{
			DEBUGLOG("filterNodeList filter: from addr {}", iter->base58address);
			continue;
		}
		//Delete Recipient Node
		if (txAddrs.end() != find(txAddrs.begin(), txAddrs.end(), iter->base58address))
		{
			DEBUGLOG("filterNodeList filter: to addr {}", iter->base58address);
			continue;
		}
		//Delete the identity of the transaction
		if (tx.identity() == iter->base58address)
		{
			DEBUGLOG("filterNodeList filter: identity addr {}", iter->base58address);
			continue;
		}
		outAddrs.push_back(*iter);
	}
	outAddrs.push_back(MagicSingleton<PeerNode>::GetInstance()->get_self_node());
}


static void filterNonVrfSignatureNodes(const std::vector<Node> & nodeList, const bool txConsensusStatus, std::unordered_set<std::string> & nextNodes)
{
	std::vector<Node> stakeNodes, unstakeNodes;
	for (const auto &node : nodeList)
	{
		int ret = VerifyBonusAddr(node.base58address);
		int64_t stakeTime = ca_algorithm::GetPledgeTimeByAddr(node.base58address, global::ca::StakeType::kStakeType_Node);
		if (stakeTime > 0 && ret == 0)
		{
			stakeNodes.push_back(node);
		}
		else
		{
			unstakeNodes.push_back(node);
		}
	}
	if (!stakeNodes.empty())
	{
		RandomContractSelectNode(stakeNodes, global::ca::KSign_node_threshold, nextNodes);
	}

	if ((stakeNodes.size() < global::ca::KSign_node_threshold) && txConsensusStatus && !unstakeNodes.empty())
	{
		size_t leftCount = global::ca::KSign_node_threshold - stakeNodes.size();
		RandomContractSelectNode(unstakeNodes, leftCount, nextNodes);
	}

	std::unordered_set<std::string> sendid;
	if (nextNodes.size() <= (uint32_t)global::ca::KSign_node_threshold)
	{
		for (auto &nodeid : nextNodes)
		{
			sendid.insert(nodeid);
		}
	}
	else
	{
		std::vector<std::string> excessiveAddrs;
		for (auto &addr : nextNodes)
		{
			excessiveAddrs.push_back(addr);
		}

		std::random_device device;
		std::mt19937 engine(device());
		std::uniform_int_distribution<size_t> dist(0, excessiveAddrs.size() - 1);

		std::unordered_set<size_t> randomIndexs;
		while (randomIndexs.size() < global::ca::KSign_node_threshold)
		{
			size_t random = dist(engine);
			randomIndexs.insert(random);
		}

		for (const auto &i : randomIndexs)
		{
			sendid.insert(excessiveAddrs[i]);
		}
	}
	nextNodes = sendid;
}	

static int filterSendList(int & end_pos,Cycliclist<std::string> &list, std::vector<std::string> &target_addrs)
{
	bool falg = false;
	if(list.size() < global::ca::kConsensus)
	{
		ERRORLOG("cycliclist size is >:{}",list.size());
		return -1;
	}
	else if (global::ca::kConsensus <= list.size() && list.size() < global::ca::KSign_node_threshold)
	{
		for(auto iter = list.begin(); iter != list.end(); iter++)
		{
			target_addrs.push_back(iter->data);
		}
		target_addrs.push_back(list.end()->data);
		falg  = true;
	}
	else
	{
		for (; target_addrs.size() < global::ca::KSign_node_threshold; end_pos++)
		{
			target_addrs.push_back(list[end_pos]);
		}

	}

	std::sort(target_addrs.begin(), target_addrs.end());
	target_addrs.erase(std::unique(target_addrs.begin(), target_addrs.end()), target_addrs.end());

	if(falg == true)
	{
		if(target_addrs.size() < global::ca::kConsensus)
		{
			ERRORLOG("target addr size is >:{} , less than >:{}",target_addrs.size(), global::ca::KSign_node_threshold);
			return -2;
		}
	}
	else
	{
		if(target_addrs.size() != global::ca::KSign_node_threshold)
		{
			ERRORLOG("target addr size is >:{} != {}",target_addrs.size(), global::ca::KSign_node_threshold);
			return -3;
		}
	}
	 
	
	return 0;
}

static int filterSendContractList(int & endPos,Cycliclist<std::string> &list, std::vector<std::string> &targetAddrs)
{
	bool falg = false;
	if(list.size() < global::ca::kConsensus)
	{
		ERRORLOG("cycliclist size is >:{}",list.size());
		return -1;
	}
	else if (global::ca::kConsensus <= list.size() && list.size() < global::ca::KSign_node_threshold)
	{
		for(auto iter = list.begin(); iter != list.end(); iter++)
		{
			targetAddrs.push_back(iter->data);
		}
		targetAddrs.push_back(list.end()->data);
		falg  = true;
	}
	else
	{
		for (; targetAddrs.size() < global::ca::KSign_node_threshold; endPos++)
		{
			targetAddrs.push_back(list[endPos]);
		}
	}

	std::sort(targetAddrs.begin(), targetAddrs.end());
	targetAddrs.erase(std::unique(targetAddrs.begin(), targetAddrs.end()), targetAddrs.end());

	if(falg == true)
	{
		if(targetAddrs.size() < global::ca::kConsensus)
		{
			ERRORLOG("target addr size is >:{} , less than >:{}",targetAddrs.size(), global::ca::KSign_node_threshold);
			return -2;
		}
	}
	else
	{
		if(targetAddrs.size() < global::ca::KSign_node_threshold)
		{
			ERRORLOG("target addr size is >:{} != {}",targetAddrs.size(), global::ca::KSign_node_threshold);
			return -3;
		}
	}
	return 0;

}


int FindContractSignNode(const CTransaction & tx, const std::shared_ptr<ContractTempTxMsgReq> &msg, std::unordered_set<std::string> & nextNodes){
	bool isBonus = false;
	global::ca::TxType txType = (global::ca::TxType)tx.txtype();
	if(txType == global::ca::TxType::kTxTypeBonus)
	{
		isBonus = true;
	}
	uint64_t top = msg->txmsginfo().height();
	TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, top);

	bool txConsensusStatus = CheckTxConsensusStatus(tx);
	if (type == TxHelper::vrfAgentType_vrf)
	{
		return filterVrfSignatureNodes(tx, msg, txConsensusStatus, nextNodes);
	}

	std::vector<Node> nodeList;
	filterContractNodeList(tx, isBonus, top, nodeList);
	filterNonVrfSignatureNodes(nodeList, txConsensusStatus, nextNodes);

	return 0;

}

static void insertOutNodes(Cycliclist<Node>::iterator & currPos, Cycliclist<Node>::iterator & endPos, int & count, std::unordered_set<std::string> &outNodes, bool isVerify)
{
	DEBUGLOG("insertOutNodes start pos : {}, end pos : {} ", currPos->data.base58address, endPos->data.base58address);
	//Add the nodes in the range to the container
	std::string ownerID = net_get_self_node_id();
	for(; currPos != endPos; currPos++)
	{
		++count;
		if(outNodes.size() > global::ca::KSign_node_threshold)
		{
			DEBUGLOG("outNodes size = {} > signNodeThreshold = {}, count = {}", outNodes.size(), global::ca::KSign_node_threshold, count);
			return;
		}

		if(!isVerify && currPos->data.base58address == ownerID)
		{
			DEBUGLOG("currPos->data.base58address == ownerID:{}", ownerID);
			continue;
		}
		DEBUGLOG("outNodes.insert(currPos->data.base58address) lower_bound = {}, count = {}", currPos->data.base58address, count);
		outNodes.insert(currPos->data.base58address);
	}
}

int FindSignNode(const CTransaction & tx, const std::shared_ptr<TxMsgReq> &msg,  const int nodeNumber, std::set<std::string> & nextNodes)
{
	// Parameter judgment
	if (nodeNumber <= 0)
	{
		return -1;
	}
	TxMsgReq *data_ = msg.get();
	uint64_t top = msg->txmsginfo().height();

	bool isStake = false;
	bool isInvest = false;
	bool isBonus = false;

	global::ca::TxType txType = (global::ca::TxType)tx.txtype();
	if (txType == global::ca::TxType::kTxTypeStake)
	{
		isStake = true;
	}
	else if (txType == global::ca::TxType::kTxTypeInvest)
	{
		isInvest = true;
	}
	else if (txType == global::ca::TxType::kTxTypeBonus)
	{
		isBonus = true;
	}
	//Judge whether it is a transaction initiated by the initial account
	bool isInitAccount = false;
	std::vector<std::string> vTxowners = TxHelper::GetTxOwner(tx);
	if (vTxowners.size() == 1 && vTxowners.end() != find(vTxowners.begin(), vTxowners.end(), global::ca::kInitAccountBase58Addr))
	{
		isInitAccount = true;
	}

	std::vector<Node> nodelist = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
	std::string ownerID = net_get_self_node_id();

	//Take out both sides of the transaction
	std::vector<std::string> txAddrs;
	if (!isBonus)
	{
		for (int i = 0; i < tx.utxo().vout_size(); ++i)
		{
			CTxOutput txout = tx.utxo().vout(i);
			txAddrs.push_back(txout.addr());
		}
	}
	else
	{
		CTxOutput txout = tx.utxo().vout(tx.utxo().vout_size() - 1);
		txAddrs.push_back(txout.addr());
	}

	std::vector<Node> nodeListTmp;
	for (auto iter = nodelist.begin(); iter != nodelist.end(); ++iter)
	{
		if(ownerID == iter->base58address)
		{
			DEBUGLOG("ownerID filter");
		}
		
		//Delete both sides of the transaction node
		if (txAddrs.end() != find(txAddrs.begin(), txAddrs.end(), iter->base58address))
		{
			DEBUGLOG("FindSignNode filter: exchanger {}", iter->base58address);
			continue;
		}


		if (iter->height < top)
		{
			DEBUGLOG("FindSignNode filter: height {} less than top {}", iter->height, top);
			continue;
		}
		
		if (tx.identity() == iter->base58address)
		{
			DEBUGLOG("FindSignNode filter: identity addr");
			continue;
		}

		nodeListTmp.push_back(*iter);
	}

	nodelist = nodeListTmp;
	std::sort(nodelist.begin(), nodelist.end(), [&](const Node &n1, const Node &n2)
			  { return n1.base58address < n2.base58address; });

	TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, top);
	if (type == TxHelper::vrfAgentType_vrf)
	{
		std::string output, proof;
		Account defaultAccount;
		EVP_PKEY_free(defaultAccount.pkey);
		if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount) != 0)
		{
			return -2;
		}

		CTransaction copyTx = tx;
		copyTx.clear_hash();
		copyTx.clear_verifysign();
		std::string tx_hash = getsha256hash(copyTx.SerializeAsString());

		int ret = MagicSingleton<VRF>::GetInstance()->CreateVRF(defaultAccount.pkey, tx_hash, output, proof);
		if (ret != 0)
		{
			std::cout << "error create:" << ret << std::endl;
			return -3;
		}

		std::vector<Node> outnodelist;
		filterNodeList(tx, outnodelist);

		std::sort(outnodelist.begin(), outnodelist.end(), [&](const Node &n1, const Node &n2)
			  { return n1.base58address < n2.base58address; });

		std::vector<Node> SatisfiedAddrs;//L
		for(auto & node : outnodelist)
		{
			//Verification of investment and pledge
			if(CheckVerifyNodeQualification(node.base58address) == 0)
			{
				SatisfiedAddrs.push_back(node);
			}
		}

		std::vector<Node> suitableAddrs;//N
		for(auto & item : SatisfiedAddrs)
		{
			if(item.height >= top)
			{
				suitableAddrs.push_back(item);
			}
		}
		double percentage = 0;//R
		if(suitableAddrs.size() < global::ca::kNeed_node_threshold)
		{
			if(top < global::ca::kMinUnstakeHeight)
			{
				percentage = double(global::ca::kNeed_node_threshold) / double(outnodelist.size());
			}
			else
			{
				percentage = double(global::ca::kNeed_node_threshold) / double(SatisfiedAddrs.size());
			}

		}
		else
		{
			percentage = double(suitableAddrs.size()) / double(SatisfiedAddrs.size());
		}

		double newRange =  global::ca::KSign_node_threshold  / percentage;
		DEBUGLOG("SatisfiedAddrs.size = {},suitableAddrs.size() = {}, percentage = {}",SatisfiedAddrs.size(), suitableAddrs.size(), percentage);

		double rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(output);
		DEBUGLOG("rand_num = {}", rand_num);
		int range = (int)newRange;
		//If the number of current pledge nodes meets the threshold, it will be found in 45 satisfied nodes. If not, it will be found randomly
		bool hasPledge = ((isStake || isInvest || isInitAccount) && (top < global::ca::kMinUnstakeHeight));
		if (SatisfiedAddrs.size() >= global::ca::kNeed_node_threshold)//45
		{
			RandomSelectNode(SatisfiedAddrs, rand_num, nodeNumber, true, nextNodes, range, top);
		}
		else if (SatisfiedAddrs.size() < global::ca::kNeed_node_threshold && hasPledge)
		{
			RandomSelectNode(outnodelist, rand_num, nodeNumber, false, nextNodes, range, top);
		}
		else
		{
			DEBUGLOG("Insufficient qualified signature nodes");
			return -4;
		}
		//Add to the vrfifo cache
		std::vector<std::string> excessiveAddrs;
		for (auto &addr : nextNodes)
		{
			excessiveAddrs.push_back(addr);
		}
		MagicSingleton<VRF>::GetInstance()->addVerifyNodes(tx_hash, excessiveAddrs);
		//Judge whether the number of filtered nodes is equal to the threshold number
		if (nextNodes.size() < global::ca::kConsensus)
		{
			DEBUGLOG("Insufficient number of nodes = {}", nextNodes.size());
			return -5;
		}

		Vrf info;
		nlohmann::json data;
		data["hash"] = tx_hash;
		data["range"] = range;
		data["percentage"] = percentage;
		std::string dataStr = data.dump();
		setVrf(info, proof, defaultAccount.pubStr, dataStr);

		Vrf * new_info = data_->mutable_txvrfinfo();
		new_info->CopyFrom(info);

		MagicSingleton<VRF>::GetInstance()->addVrfInfo(tx_hash, info);
		return 0;
	}

	vector<Node> stakeNodes;
	vector<Node> unstakeNodes;
	for (const auto &node : nodelist)
	{
		if(CheckVerifyNodeQualification(node.base58address) == 0)
		{
			stakeNodes.push_back(node);
		}
		else
		{
			unstakeNodes.push_back(node);
		}
	}


	if (!stakeNodes.empty())
	{
		RandomSelectNode(stakeNodes, nodeNumber, nextNodes);
	}
	bool hasPledge = ((isStake || isInvest || isInitAccount) && (top < global::ca::kMinUnstakeHeight));
	if ((stakeNodes.size() < nodeNumber) && hasPledge && !unstakeNodes.empty())
	{
		size_t leftCount = nodeNumber - stakeNodes.size();
		RandomSelectNode(unstakeNodes, leftCount, nextNodes);
	}

	std::set<std::string> sendid;
	if (nextNodes.size() <= (uint32_t)nodeNumber)
	{
		for (auto &nodeid : nextNodes)
		{
			sendid.insert(nodeid);
		}
	}
	else
	{
		std::vector<std::string> excessiveAddrs;
		for (auto &addr : nextNodes)
		{
			excessiveAddrs.push_back(addr);
		}

		std::random_device device;
		std::mt19937 engine(device());
		std::uniform_int_distribution<size_t> dist(0, excessiveAddrs.size() - 1);

		std::unordered_set<size_t> randomIndexs;
		while (randomIndexs.size() < nodeNumber)
		{
			size_t random = dist(engine);
			randomIndexs.insert(random);
		}

		for (const auto &i : randomIndexs)
		{
			sendid.insert(excessiveAddrs[i]);
		}
	}
	nextNodes = sendid;
	return 0;
}

int GetBlockPackager(std::string &packager, const std::string &hash_utxo, Vrf &info)
{
	DBReader db_reader;
	uint64_t top;
	if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
	{
		return -1;
	}
	std::vector<std::string> hashes;
	//Take the current height within 50 height and take the current height outside 50 height - 10 height
	uint64_t block_height = top;
	if (top >= 50)
	{
		block_height = top - 10;
	}

	if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(block_height, hashes))
	{
		return -2;
	}

	std::vector<CBlock> blocks;
	for (auto &hash : hashes)
	{
		std::string blockStr;
		db_reader.GetBlockByBlockHash(hash, blockStr);
		CBlock block;
		block.ParseFromString(blockStr);
		blocks.push_back(block);
	}
	std::sort(blocks.begin(), blocks.end(), [](const CBlock &x, const CBlock &y)
			  { return x.time() < y.time(); });

	CBlock RandomBlock = blocks[0];
	std::string output, proof;
	Account defaultAccount;
	EVP_PKEY_free(defaultAccount.pkey);
	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount) != 0)
	{
		return -3;
	}
	int ret = MagicSingleton<VRF>::GetInstance()->CreateVRF(defaultAccount.pkey, hash_utxo, output, proof);
	if (ret != 0)
	{
		std::cout << "error create:" << ret << std::endl;
		return -4;
	}
	//Take 3, 4, and 5 of the signature array of the block. Use vrf to randomly find an address as the packing node in these 3 addresses
	std::vector<std::string> BlockSignInfo;
	for (int i = 2; i < 5; ++i)
	{
		BlockSignInfo.push_back(GetBase58Addr(RandomBlock.sign(i).pub()));
	}

	if (BlockSignInfo.size() < 3)
	{
		return -5;
	}

	uint32_t rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(output, 3);
	packager = BlockSignInfo[rand_num];
	if (packager == MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr())
	{
		ERRORLOG("Packager = {} cannot be the transaction initiator", packager);
		std::cout << "Packager cannot be the transaction initiator " << std::endl;
		return -6;
	}
	std::cout << "block rand_num: " << rand_num << std::endl;
	std::cout << "packager: " << packager << std::endl;
	nlohmann::json data_string;
	data_string["hash"] = RandomBlock.hash();
	data_string["range"] = 0;
	data_string["percentage"] = 0;
	setVrf(info, proof, defaultAccount.pubStr, data_string.dump());
	std::cout << "**********VRF Generated the number end**********************" << std::endl;

	return 0;
}

int VerifyContractTxMsgReq(const ContractTempTxMsgReq & msg){
	CTransaction tx;
	if (!tx.ParseFromString(msg.txmsginfo().tx()))
	{
		ERRORLOG("Failed to deserialize transaction body!");
		return -1;
	}
	int ret = ca_algorithm::MemVerifyTransactionTx(tx);
	if (ret != 0)
	{
		ERRORLOG("Verify MemTransactionTx fail ret: {}", ret);
		return ret -= 1000;
	}

	//add condition of height and version
	uint64_t selfNodeHeight = 0;
	DBReader dbReader;
	auto status = dbReader.GetBlockTop(selfNodeHeight);
	if (DBStatus::DB_SUCCESS != status)
	{
		ERRORLOG("Get block top error");
		return -2000;
	}
	ret = ca_algorithm::VerifyContractTransactionTx(tx, msg.txmsginfo().height() + 1);

	if(ret < 0)
	{
		ERRORLOG("Verify TransactionTx fail ret: {}", ret);
		ret -= 3000;
		ERRORLOG("The error code for verifying the transaction body in memory is:{}", ret);
		return ret;
	}
		// Judge whether it is a stake transaction
	bool isStakeTx = false;
	bool isInvestTx = false;
	bool isBonus = false;
	bool isUnStake = false;
	bool isDisInvest = false;

	try
	{
		global::ca::TxType txType = (global::ca::TxType)tx.txtype();

		if (txType == global::ca::TxType::kTxTypeStake)
		{
			isStakeTx = true;
		}
		if (txType == global::ca::TxType::kTxTypeInvest)
		{
			isInvestTx = true;
		}
		if (txType == global::ca::TxType::kTxTypeBonus)
		{
			isBonus = true;
		}
		if (txType == global::ca::TxType::kTxTypeUnstake)
		{
			isUnStake = true;
		}
		if (txType == global::ca::TxType::kTxTypeDisinvest)
		{
			isDisInvest = true;
		}
	}
	catch (...)
	{
		return -2;
	}

	// Judge whether it is a transaction initiated by the initial account number
	bool isInitAccountTx = false;

	for (auto &vin : tx.utxo().vin())
	{
		if (GetBase58Addr(vin.vinsign().pub()) == global::ca::kInitAccountBase58Addr)
		{
			isInitAccountTx = true;
			break;
		}
	}

	/*If the account number is not pledged,	it is not allowed to sign the transfer transaction,
	but it is allowed to sign the pledge transaction.
	When verifyprehashcount == 0, the signature is allowed for the transaction initiated by yourself.
	When verifyprehashcount == needConsensus, the signature is enough to start building blocks*/
	std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	if (!isInvestTx && !isStakeTx && !isInitAccountTx)
	{
		// If it is unpledged, it is directly judged whether he has pledged or not
		if (isUnStake)
		{
			uint64_t amount = 0;
			if (SearchStake(defaultBase58Addr, amount, global::ca::StakeType::kStakeType_Node) != 0)
			{
				return -3;
			}

			if (amount < global::ca::kMinStakeAmt)
			{
				ERRORLOG("stake amount less than kMinStakeAmt");
				return -4;
			}

			int64_t stakeTime = ca_algorithm::GetPledgeTimeByAddr(defaultBase58Addr, global::ca::StakeType::kStakeType_Node);
			if (stakeTime <= 0)
			{
				return ret - 5000;
			}
		}
		else if (isDisInvest) // If it is to solve the investment, directly judge whether he has invested
		{
			//bool isSponsorNode = msg.signnodemsg().empty() || msg.signnodemsg(0).id() == defaultBase58Addr;
			bool isSponsorNode = tx.verifysign().empty() || GetBase58Addr(tx.verifysign(0).pub()) == defaultBase58Addr;
			if (isSponsorNode || (isSponsorNode && isBonus))
			{
				auto ret = VerifyBonusAddr(defaultBase58Addr);
				if (ret < 0)
				{
					DEBUGLOG("not a verify node");
					return ret - 4000;
				}
			}
		}
		else
		{
			uint64_t amount = 0;
			if (SearchStake(defaultBase58Addr, amount, global::ca::StakeType::kStakeType_Node) != 0)
			{
				ERRORLOG("SearchStake error! defaultBase58Addr:{}");
				return -5;
			}

			if (amount < global::ca::kMinStakeAmt)
			{
				ERRORLOG("stake amount less than kMinStakeAmt");
				return -6;
			}

			//bool isSponsorNode = msg.signnodemsg().empty() || msg.signnodemsg(0).id() == defaultBase58Addr;
			bool isSponsorNode = tx.verifysign().empty() || GetBase58Addr(tx.verifysign(0).pub()) == defaultBase58Addr;
			if (isSponsorNode || (isSponsorNode && isBonus))
			{
				auto ret = VerifyBonusAddr(defaultBase58Addr);
				if (ret < 0)
				{
					DEBUGLOG("not a verify node");
					return ret - 6000;
				}
			}

			int64_t stakeTime = ca_algorithm::GetPledgeTimeByAddr(defaultBase58Addr, global::ca::StakeType::kStakeType_Node);
			if (stakeTime <= 0)
			{
				return ret - 7000;
			}
		}
	}
	return 0;
}

int VerifyTxMsgReq(const TxMsgReq &msg)
{
	CTransaction tx;
	if (!tx.ParseFromString(msg.txmsginfo().tx()))
	{
		ERRORLOG("Failed to deserialize transaction body!");
		return -1;
	}

	int ret = ca_algorithm::MemVerifyTransactionTx(tx);
	if (ret != 0)
	{
		ERRORLOG("Verify MemTransactionTx fail ret: {}", ret);
		return ret -= 1000;
	}

	ret = ca_algorithm::VerifyTransactionTx(tx, msg.txmsginfo().height() + 1);
	if (ret < 0)
	{
		ERRORLOG("Verify TransactionTx fail ret: {}", ret);
		ret -= 2000;
		ERRORLOG("The error code for verifying the transaction body in memory is:{}", ret);
		return ret;
	}

	if (ContainSelfVerifySign(tx))
	{
		INFOLOG("Already verify signed this transaction");
		return -2;
	}

	std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();

	if(CheckVerifyNodeQualification(defaultBase58Addr) != 0 && msg.txmsginfo().height() > global::ca::kMinUnstakeHeight)
	{
		DEBUGLOG("The node is not eligible to sign");
		return -3;
	}
 
	return 0;
}

int IsQualifiedToUnstake(const std::string &fromAddr,
						 const std::string &utxo_hash,
						 uint64_t &staked_amount)
{
	// Query whether the account number has stake assets
	DBReader db_reader;
	// CBlockDataApi data_reader;
	std::vector<string> addresses;
	if (db_reader.GetStakeAddress(addresses) != DBStatus::DB_SUCCESS)
	{
		ERRORLOG(RED "Get all stake address failed!" RESET);
		return -1;
	}
	if (std::find(addresses.begin(), addresses.end(), fromAddr) == addresses.end())
	{
		ERRORLOG(RED "The account number has not staked assets!" RESET);
		return -2;
	}

	// Query whether the utxo to be de stake is in the staked utxo
	std::vector<string> utxos;
	if (db_reader.GetStakeAddressUtxo(fromAddr, utxos) != DBStatus::DB_SUCCESS)
	{
		ERRORLOG(RED "Get stake utxo from address failed!" RESET);
		return -3;
	}
	if (std::find(utxos.begin(), utxos.end(), utxo_hash) == utxos.end())
	{
		ERRORLOG(RED "The utxo to be de staked is not in the staked utxo!" RESET);
		return -4;
	}

	// Check whether the stake exceeds 30 days
	if (IsMoreThan30DaysForUnstake(utxo_hash) != true)
	{
		ERRORLOG(RED "The staked utxo is not more than 30 days" RESET);
		return -5;
	}

	std::string strStakeTx;
	if (DBStatus::DB_SUCCESS != db_reader.GetTransactionByHash(utxo_hash, strStakeTx))
	{
		ERRORLOG(RED "Stake tx not found!" RESET);
		return -6;
	}

	CTransaction StakeTx;
	if (!StakeTx.ParseFromString(strStakeTx))
	{
		ERRORLOG(RED "Failed to parse transaction body!" RESET);
		return -7;
	}
	for (int i = 0; i < StakeTx.utxo().vout_size(); i++)
	{
		if (StakeTx.utxo().vout(i).addr() == global::ca::kVirtualStakeAddr)
		{
			staked_amount = StakeTx.utxo().vout(i).value();
			break;
		}
	}
	if (staked_amount == 0)
	{
		ERRORLOG(RED "Stake value is zero!" RESET);
		return -8;
	}

	return 0;
}

int CheckInvestQualification(const std::string &fromAddr,
							 const std::string &toAddr,
							 uint64_t invest_amount)
{
	// Each investor can only invest once
	DBReader db_reader;
	// CBlockDataApi data_reader;
	std::vector<string> nodes;
	auto status = db_reader.GetBonusAddrByInvestAddr(fromAddr, nodes);
	if (status == DBStatus::DB_SUCCESS && !nodes.empty())
	{
		SetRpcError("-72016", "The investor have already invested in a node!");
		ERRORLOG(RED "The investor have already invested in a node!" RESET);
		return -1;
	}

	// Each investor shall not invest less than 200 yuan
	if (invest_amount < global::ca::kMinInvestAmt)
	{
		SetRpcError("-72021", "The investment amount is less than 35");
		ERRORLOG(RED "The investment amount is less than 200" RESET);
		return -2;
	}

	// The node to be invested must have spent 999 to access the Internet
	int64_t stake_time = ca_algorithm::GetPledgeTimeByAddr(toAddr, global::ca::StakeType::kStakeType_Node);
	if (stake_time <= 0)
	{
		SetRpcError("-72022", "The account to be invested has not spent 500 to access the Internet!");
		ERRORLOG(RED "The account to be invested has not spent 20000 to access the Internet!" RESET);
		return -3;
	}

	// The node to be invested can only be invested by 999 people at most
	std::vector<string> addresses;
	status = db_reader.GetInvestAddrsByBonusAddr(toAddr, addresses);
	if (status != DBStatus::DB_SUCCESS && status != DBStatus::DB_NOT_FOUND)
	{
		SetRpcError("-72023", "Get invest addrs by node failed!");
		ERRORLOG(RED "Get invest addrs by node failed!" RESET);
		return -4;
	}
	if (addresses.size() + 1 > 999)
	{
		SetRpcError("-72024", "The account number to be invested have been invested by 999 people!");
		ERRORLOG(RED "The account number to be invested have been invested by 999 people!" RESET);
		return -5;
	}

	// The node to be invested can only be be invested 100000 DON at most
	uint64_t sum_invest_amount = 0;
	for (auto &address : addresses)
	{
		std::vector<string> utxos;
		if (db_reader.GetBonusAddrInvestUtxosByBonusAddr(toAddr, address, utxos) != DBStatus::DB_SUCCESS)
		{
			SetRpcError("-72025", "GetBonusAddrInvestUtxosByBonusAddr failed!");
			ERRORLOG("GetBonusAddrInvestUtxosByBonusAddr failed!");
			return -6;
		}

		for (const auto &utxo : utxos)
		{
			std::string strTx;
			if (db_reader.GetTransactionByHash(utxo, strTx) != DBStatus::DB_SUCCESS)
			{
				SetRpcError("-72026", "GetTransactionByHash failed!");
				ERRORLOG("GetTransactionByHash failed!");
				return -7;
			}

			CTransaction tx;
			if (!tx.ParseFromString(strTx))
			{
				SetRpcError("-72027", "Failed to parse transaction body!");
				ERRORLOG("Failed to parse transaction body!");
				return -8;
			}
			for (auto &vout : tx.utxo().vout())
			{
				if (vout.addr() == global::ca::kVirtualInvestAddr)
				{
					sum_invest_amount += vout.value();
					break;
				}
			}
		}
	}
	if (sum_invest_amount + invest_amount > global::ca::kMaxInvertAmt)
	{
		SetRpcError("-72017", "The total amount invested in a single node will be more than 65000!");
		ERRORLOG(RED "The total amount invested in a single node will be more than {}!", global::ca::kMaxInvertAmt, RESET);
		return -9;
	}
	return 0;
}

int IsQualifiedToDisinvest(const std::string &fromAddr,
						   const std::string &toAddr,
						   const std::string &utxo_hash,
						   uint64_t &invested_amount)
{
	// Query whether the account has invested assets to node
	DBReader db_reader;
	// CBlockDataApi data_reader;
	std::vector<string> nodes;
	if (db_reader.GetBonusAddrByInvestAddr(fromAddr, nodes) != DBStatus::DB_SUCCESS)
	{
		SetRpcError("-72016", "The investor have already invested in a node!");
		ERRORLOG("GetBonusAddrByInvestAddr failed!");
		return -1;
	}
	if (std::find(nodes.begin(), nodes.end(), toAddr) == nodes.end())
	{
		ERRORLOG(RED "The account has not invested assets to node!" RESET);
		return -2;
	}

	// Query whether the utxo to divest is in the utxos that have been invested
	std::vector<std::string> utxos;
	if (db_reader.GetBonusAddrInvestUtxosByBonusAddr(toAddr, fromAddr, utxos) != DBStatus::DB_SUCCESS)
	{
		ERRORLOG("GetBonusAddrInvestUtxosByBonusAddr failed!");
		return -3;
	}
	if (std::find(utxos.begin(), utxos.end(), utxo_hash) == utxos.end())
	{
		ERRORLOG(RED "The utxo to divest is not in the utxos that have been invested!" RESET);
		return -4;
	}

	// Query whether the investment exceeds one day
	if (IsMoreThan1DayForDivest(utxo_hash) != true)
	{
		SetRpcError("-72015", "The invested utxo is not more than 1 day!");
		ERRORLOG(RED "The invested utxo is not more than 1 day!" RESET);
		return -5;
	}

	// The amount to be divested must be greater than 0
	std::string strInvestTx;
	if (DBStatus::DB_SUCCESS != db_reader.GetTransactionByHash(utxo_hash, strInvestTx))
	{
		ERRORLOG("Invest tx not found!");
		return -6;
	}
	CTransaction InvestedTx;
	if (!InvestedTx.ParseFromString(strInvestTx))
	{
		ERRORLOG("Failed to parse transaction body!");
		return -7;
	}

	nlohmann::json data_json = nlohmann::json::parse(InvestedTx.data());
	nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
	std::string invested_addr = tx_info["BonusAddr"].get<std::string>();
	if (toAddr != invested_addr)
	{
		ERRORLOG(RED "The node to be divested is not invested!" RESET);
		return -8;
	}

	for (int i = 0; i < InvestedTx.utxo().vout_size(); i++)
	{
		if (InvestedTx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr)
		{
			invested_amount = InvestedTx.utxo().vout(i).value();
			break;
		}
	}
	if (invested_amount == 0)
	{
		ERRORLOG(RED "The invested value is zero!" RESET);
		return -9;
	}

	return 0;
}

int CheckBonusQualification(const std::string& BonusAddr, const uint64_t& txTime, bool verify_abnormal)
{
	DBReader db_reader;

	uint64_t cur_time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	uint64_t zero_time = MagicSingleton<TimeUtil>::GetInstance()->getMorningTime(cur_time)*1000000;//Convert to subtle
	uint64_t error_time = cur_time + (10 * 1000000);
	if(verify_abnormal) //broadcast
	{
		//Time to initiate claim > 1:00 a.m. & < my time
		if(txTime > error_time || txTime < (zero_time + (uint64_t)60 * 60 * 1000000))
		{
			return -1;
		}
	}
	else //sync
	{
		if(txTime > error_time)
		{
			return -2;
		}
	}

	std::vector<std::string> utxos;
	uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(txTime);
	auto status =  db_reader.GetBonusUtxoByPeriod(Period, utxos);
	if (status != DBStatus::DB_SUCCESS && status != DBStatus::DB_NOT_FOUND)
	{
		return -3;
	}
	
	if(status == DBStatus::DB_SUCCESS)
	{
		std::string strTx;
		CTransaction Claimtx;
		
		for(auto utxo = utxos.rbegin(); utxo != utxos.rend(); utxo++)
		{
			if (db_reader.GetTransactionByHash(*utxo, strTx) != DBStatus::DB_SUCCESS)
			{
				MagicSingleton<BlockHelper>::GetInstance()->PushMissUTXO(*utxo);
				return -4;
			}	
			if(!Claimtx.ParseFromString(strTx))
			{
				return -5;
			}
			std::string ClaimAddr = GetBase58Addr(Claimtx.utxo().vin(0).vinsign().pub());
			if(BonusAddr == ClaimAddr)//Application completed
			{
				return -6;
			}
		}
	}

	// The total number of investors must be more than 10 before they can apply for it
	auto ret = VerifyBonusAddr(BonusAddr);
	if(ret < 0)
	{
		return -7;
	}

	int64_t stake_time = ca_algorithm::GetPledgeTimeByAddr(BonusAddr, global::ca::StakeType::kStakeType_Node);
	if (stake_time <= 0)
	{
		return -8;
	}
	
	return 0;
}

// Check time of the unstake, unstake time must be more than 30 days, add 20201208   LiuMingLiang
bool IsMoreThan30DaysForUnstake(const std::string &utxo)
{
	DBReader db_reader;

	std::string strTransaction;
	DBStatus status = db_reader.GetTransactionByHash(utxo, strTransaction);
	if (status != DBStatus::DB_SUCCESS)
	{
		return false;
	}

	CTransaction utxoStake;
	utxoStake.ParseFromString(strTransaction);
	uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();


	return (nowTime - utxoStake.time()) >= global::ca::kUnstakeTime;
}

static void updateCentralNodeInterval(const std::string targetAddr, const std::string centerNode, Cycliclist<Node>::iterator & targetPos, Cycliclist<Node>::iterator & startPos, Cycliclist<Node>::iterator & endPos)
{
	//Whether the central node is within the prescribed range is judged, and if it is, the central node is modified
	if(targetAddr != centerNode)
	{
		auto currNode = startPos;
		for(; currNode != endPos; currNode++)
		{
			if(currNode->data.base58address == centerNode)
			{
				DEBUGLOG("updateCentralNodeInterval startPos : {} , endPos : {} ", startPos->data.base58address, endPos->data.base58address);
				//Correct the center node to exit the loop
				targetPos = currNode;
				startPos = targetPos - 2;
				endPos = targetPos + 3;
				return;
			}
		}
	}
}

// Check time of the redeem, redeem time must be more than 30 days, add 20201208   LiuMingLiang
bool IsMoreThan1DayForDivest(const std::string &utxo)
{
	DBReader db_reader;

	std::string strTransaction;
	DBStatus status = db_reader.GetTransactionByHash(utxo, strTransaction);
	if (status != DBStatus::DB_SUCCESS)
	{
		return -1;
	}
	CTransaction utxoStake;
	utxoStake.ParseFromString(strTransaction);
	uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	return (nowTime - utxoStake.time()) >= global::ca::kDisinvestTime;
}

int VerifyBonusAddr(const std::string &BonusAddr)
{
	uint64_t invest_amount;
	auto ret = MagicSingleton<BounsAddrCache>::GetInstance()->get_amount(BonusAddr, invest_amount);
	if (ret < 0)
	{
		ERRORLOG("invest BonusAddr: {}, ret:{}", BonusAddr, ret);
		return -99;
	}
	
	return invest_amount >= global::ca::kMinInvestAmt ? 0 : -99;
}

int GetInvestmentAmountAndDuration(const std::string &bonusAddr, const uint64_t &cur_time, const uint64_t &zero_time, std::map<std::string, std::pair<uint64_t, uint64_t>> &mpInvestAddr2Amount)
{
	DBReadWriter db_writer;
	std::string strTx;
	CTransaction tx;
	std::vector<string> addresses;

	time_t t = cur_time;
	t = t / 1000000;
	struct tm *tm = gmtime(&t);
	tm->tm_hour = 23;
	tm->tm_min = 59;
	tm->tm_sec = 59;
	uint64_t end_time = mktime(tm);
	end_time *= 1000000;

	uint64_t invest_amount = 0;
	uint64_t invest_amountDay = 0;
	if (db_writer.GetInvestAddrsByBonusAddr(bonusAddr, addresses) != DBStatus::DB_SUCCESS)
	{
		return -1;
	}
	for (auto &address : addresses)
	{
		std::vector<std::string> utxos;
		if (db_writer.GetBonusAddrInvestUtxosByBonusAddr(bonusAddr, address, utxos) != DBStatus::DB_SUCCESS)
		{
			return -2;
		}

		if(utxos.size() > 1 || utxos.size() <= 0)
		{
			return -3;
		}

		invest_amount = 0;
		invest_amountDay = 0;
		for (const auto &hash : utxos)
		{
			tx.Clear();
			if (db_writer.GetTransactionByHash(hash, strTx) != DBStatus::DB_SUCCESS)
			{
				return -4;
			}
			if (!tx.ParseFromString(strTx))
			{
				return -5;
			}

			if(cur_time <= tx.time())
			{
				return -6;
			}
			if(cur_time - tx.time() <= 24ull * 60 * 60 * 1000000)
			{
				DEBUGLOG("Investment time is less than 24 hours, waiting time:{}", (cur_time - tx.time()) / (60ull * 60 * 1000000));
				break;
			}

			if (tx.time() >= zero_time && tx.time() <= end_time)
			{
				for (int i = 0; i < tx.utxo().vout_size(); i++)
				{
					if (tx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr)
					{
						invest_amountDay += tx.utxo().vout(i).value();
						invest_amount += tx.utxo().vout(i).value();
						break;
					}
				}
			}
			else
			{
				for (int i = 0; i < tx.utxo().vout_size(); i++)
				{
					if (tx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr)
					{
						invest_amount += tx.utxo().vout(i).value();
						break;
					}
				}
				break;
			}
		}
		invest_amount = (invest_amount - invest_amountDay);
		if (invest_amount == 0)
		{
			continue;
		}
		mpInvestAddr2Amount[address].first = invest_amount;
	}
	if (mpInvestAddr2Amount.empty())
	{
		return -7;
	}
	return 0;
}

int GetTotalCirculationYesterday(const uint64_t &cur_time, uint64_t &TotalCirculation)
{
	DBReadWriter db_writer;
	std::vector<std::string> utxos;
	std::string strTx;
	CTransaction tx;
	{
		std::lock_guard<std::mutex> lock(global::ca::kBonusMutex);
		if (DBStatus::DB_SUCCESS != db_writer.GetM2(TotalCirculation))
		{
			return -1;
		}
		uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(cur_time);
		auto ret = db_writer.GetBonusUtxoByPeriod(Period, utxos);
		if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
		{
			return -2;
		}
	}
	uint64_t Claim_Vout_amount = 0;
	uint64_t TotalClaimDay = 0;
	for (auto utxo = utxos.rbegin(); utxo != utxos.rend(); utxo++)
	{
		if (db_writer.GetTransactionByHash(*utxo, strTx) != DBStatus::DB_SUCCESS)
		{
			return -3;
		}
		if (!tx.ParseFromString(strTx))
		{
			return -4;
		}
		uint64_t claim_amount = 0;
		if ((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
		{
			nlohmann::json data_json = nlohmann::json::parse(tx.data());
			nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
			tx_info["BonusAmount"].get_to(claim_amount);
			TotalClaimDay += claim_amount;
		}
	}
	TotalCirculation -= TotalClaimDay;
	return 0;
}

int GetTotalInvestmentYesterday(const uint64_t &cur_time, uint64_t &Totalinvest)
{
	DBReadWriter db_writer;
	std::vector<std::string> utxos;
	std::string strTx;
	CTransaction tx;
	{
		std::lock_guard<std::mutex> lock(global::ca::kInvestMutex);
		auto ret = db_writer.GetTotalInvestAmount(Totalinvest);
		if (DBStatus::DB_SUCCESS != ret)
		{
			if (DBStatus::DB_NOT_FOUND != ret)
			{
				return -1;
			}
			else
			{
				Totalinvest = 0;
			}
		}
		uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(cur_time);
		ret = db_writer.GetInvestUtxoByPeriod(Period, utxos);
		if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
		{
			return -2;
		}
	}
	uint64_t Invest_Vout_amount = 0;
	uint64_t TotalInvestmentDay = 0;
	for (auto utxo = utxos.rbegin(); utxo != utxos.rend(); utxo++)
	{
		Invest_Vout_amount = 0;
		if (db_writer.GetTransactionByHash(*utxo, strTx) != DBStatus::DB_SUCCESS)
		{
			return -3;
		}
		if (!tx.ParseFromString(strTx))
		{
			return -4;
		}
		for (auto &vout : tx.utxo().vout())
		{
			if (vout.addr() == global::ca::kVirtualInvestAddr)
			{
				Invest_Vout_amount += vout.value();
				break;
			}
		}
		TotalInvestmentDay += Invest_Vout_amount;
	}
	Totalinvest -= TotalInvestmentDay;
	return 0;
}

int GetTotalBurnYesterday(const uint64_t &cur_time, uint64_t &Totalburn)
{
	DBReadWriter db_writer;
	uint64_t burnAmountDay = 0;
	{
		std::lock_guard<std::mutex> lock(global::ca::kBurnMutex);
		if (DBStatus::DB_SUCCESS != db_writer.GetDM(Totalburn))
		{
			return -1;
		}
		uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(cur_time);
		auto ret = db_writer.GetburnAmountByPeriod(Period, burnAmountDay);
		if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
		{
			return -2;
		}
	}
	DEBUGLOG("burnAmountDay:{}, Totalburn:{}", burnAmountDay, Totalburn);
	if(burnAmountDay > Totalburn)	return -3;
	Totalburn -= burnAmountDay;
	return 0;
}

void NotifyNodeHeightChange()
{
	net_send_node_height_changed();
}

std::map<int32_t, std::string> GetMultiSignTxReqCode()
{
	std::map<int32_t, std::string> errInfo = {
		std::make_pair(0, ""),
		std::make_pair(-1, ""),
		std::make_pair(-2, ""),
		std::make_pair(-3, ""),
		std::make_pair(-4, ""),
		std::make_pair(-5, ""),
		std::make_pair(-6, ""),
	};

	return errInfo;
}
int HandleMultiSignTxReq(const std::shared_ptr<MultiSignTxReq> &msg, const MsgData &msgdata)
{
	std::cout << "HandleMultiSignTxReq" << std::endl;

	auto errInfo = GetMultiSignTxReqCode();
	MultiSignTxAck ack;
	int ret = 0;

	ON_SCOPE_EXIT
	{
		ReturnAckCode<MultiSignTxAck>(msgdata, errInfo, ack, ret);
	};

	CTransaction tx;
	tx.ParseFromString(msg->txraw());

	ret = ca_algorithm::MemVerifyTransactionTx(tx);
	if (ret != 0)
	{
		return ret -= 100;
	}

	ret = ca_algorithm::VerifyTransactionTx(tx, msg->height() + 1);
	if (ret != 0)
	{
		return ret -= 200;
	}
	// Find all signable accounts that do not have signatures in the multi-signature list
	std::set<std::string> dataSignAddr;
	uint64_t threshold = 0;
	std::string multiSignPub;
	try
	{
		if (tx.utxo().owner_size() == 0)
		{
			return -1;
		}
		std::string owner = tx.utxo().owner(0);
		if (CheckBase58Addr(owner, Base58Ver::kBase58Ver_MultiSign) == false)
		{
			return -2;
		}

		DBReader db_reader;
		std::vector<std::string> multiSignAddrs;
		auto db_status = db_reader.GetMutliSignAddress(multiSignAddrs);
		if (DBStatus::DB_SUCCESS != db_status)
		{
			if (DBStatus::DB_NOT_FOUND != db_status)
			{
				return -3;
			}
		}

		if (std::find(multiSignAddrs.begin(), multiSignAddrs.end(), owner) == multiSignAddrs.end())
		{
			return -4;
		}

		std::vector<std::string> utxos;
		db_status = db_reader.GetMutliSignAddressUtxo(owner, utxos);
		if (DBStatus::DB_SUCCESS != db_status)
		{
			return -5;
		}
		if (utxos.size() != 1)
		{
			return -6;
		}

		std::string declareTxRaw;
		db_status = db_reader.GetTransactionByHash(utxos[0], declareTxRaw);
		if (DBStatus::DB_SUCCESS != db_status)
		{
			return -7;
		}
		CTransaction declareTx;
		if (!declareTx.ParseFromString(declareTxRaw))
		{
			ERRORLOG("TxHelper FindUtxo: GetTransactionByHash failed!");
			return -8;
		}
		nlohmann::json data_json = nlohmann::json::parse(declareTx.data());
		nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
		multiSignPub = tx_info["MultiSignPub"].get<std::string>();
		multiSignPub = Base64Decode(multiSignPub);
		threshold = tx_info["SignThreshold"].get<uint64_t>();
		nlohmann::json signAddrList = tx_info["SignAddrList"].get<nlohmann::json>();

		for (auto &addr : signAddrList)
		{
			if (CheckBase58Addr(addr, Base58Ver::kBase58Ver_Normal) == false)
			{
				return -9;
			}
			dataSignAddr.insert(std::string(addr));
		}

		if (signAddrList.size() != dataSignAddr.size())
		{
			return -10;
		}

		if (threshold > signAddrList.size())
		{
			return -11;
		}
	}
	catch (const std::exception &e)
	{
		std::cerr << e.what() << '\n';
	}

	std::set<std::string> setMultiSign;
	const CTxUtxo &utxo = tx.utxo();
	for (int i = 1; i < utxo.multisign_size(); ++i)
	{
		const CSign &sign = utxo.multisign(i);

		setMultiSign.insert(GetBase58Addr(sign.pub()));
	}

	if ((utxo.multisign_size() - 1) != threshold)
	{
		return ret = -12;
	}

	uint64_t count = 0;
	for (auto &mSignAddr : setMultiSign)
	{
		for (auto &dSignAddr : dataSignAddr)
		{
			if (dSignAddr == mSignAddr)
			{
				count++;
			}
		}
	}

	if (count != setMultiSign.size())
	{
		return ret -= 13;
	}

	std::string identity = tx.identity();

	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr() == identity)
	{
		uint64_t top = 0;
		{
			// CBlockDataApi data_reader;
			DBReader db_reader;
			if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
			{
				ERRORLOG("db get top failed!!");
				return ret = -14;
			}
		}

		TxMsgReq txMsg;
		txMsg.set_version(global::kVersion);
		TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
		txMsgInfo->set_type(0);
		txMsgInfo->set_tx(tx.SerializeAsString());
		txMsgInfo->set_height(top);

		auto msg = make_shared<TxMsgReq>(txMsg);

		CTransaction outTx;
		ret = DoHandleTx(msg, outTx);
		DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
		return ret;
	}
	else
	{
		MultiSignTxReq anotherReq;
		anotherReq.set_version(global::kVersion);
		anotherReq.set_txraw(tx.SerializeAsString());

		net_send_message<MultiSignTxReq>(identity, anotherReq, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
		return ret = 1;
	}

	return ret = 0;
}

bool IsMultiSign(const CTransaction &tx)
{
	global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();

	return tx.utxo().owner_size() == 1 &&
		   (CheckBase58Addr(tx.utxo().owner(0), Base58Ver::kBase58Ver_MultiSign) &&
			(tx.utxo().vin_size() == 1) &&
			global::ca::TxType::kTxTypeTx == tx_type);
}

int HandleAddBlockAck(const std::shared_ptr<BuildBlockBroadcastMsgAck> &msg, const MsgData &msgdata)
{
	// Determine if the version is compatible
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("HandleBuildBlockBroadcastMsg IsVersionCompatible");
		return -1;
	}
	MagicSingleton<BlockMonitor>::GetInstance()->HandleBroadcastAddBlockAck(*msg);

	return 0;
}

bool AddBlockSign(CBlock &block)
{
	CBlock cblock = block;
	cblock.clear_sign();
	std::string serblockHash = getsha256hash(cblock.SerializeAsString());
	std::string signature;
	std::string pub;
	std::string defalutaddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	if (TxHelper::Sign(defalutaddr, serblockHash, signature, pub) != 0)
	{
		ERRORLOG("Block flow signature failed");
		return false;
	}

	CSign *cblocksign = block.add_sign();
	cblocksign->set_sign(signature);
	cblocksign->set_pub(pub);

	return true;
}

int VerifyBlockSign(const CBlock &block)
{		
	CBlock cblock = block;
	cblock.clear_sign();
	std::string serblockHash = getsha256hash(cblock.SerializeAsString());

	for (auto &blocksignmsg : block.sign())
	{
		std::string pub = blocksignmsg.pub();
		std::string sign = blocksignmsg.sign();


		if (pub.size() == 0 ||
			sign.size() == 0 ||
			serblockHash.size() == 0)
		{
			ERRORLOG("block flow info fail!");
			return -1;
		}

		EVP_PKEY *eckey = nullptr;
		if (GetEDPubKeyByBytes(pub, eckey) == false)
		{
			EVP_PKEY_free(eckey);
			ERRORLOG(RED "Get public key from bytes failed!" RESET);
			return -2;
		}

		if (ED25519VerifyMessage(serblockHash, eckey, sign) == false)
		{
			EVP_PKEY_free(eckey);
			ERRORLOG(RED "Public key verify sign failed!" RESET);
			return -3;
		}
		EVP_PKEY_free(eckey);
	}

	return 0;
}

int HandleBlock(const std::shared_ptr<BlockMsg> &msg, const MsgData &msgdata)
{
	auto errInfo = TxMsgReqCode();
	BlockMsg ack;

	int ret = 0;
	DEBUGLOG("Hand Block enter ");
	ret = DoHandleBlock(msg);
	if (ret != 0)
	{
		DEBUGLOG("DoHandleBlock failed The error code is {}", ret);
	}

	return ret;
}

int HandleContractBlock(const std::shared_ptr<ContractBlockMsg>& msg,const MsgData& msgdata)
{
	Node node;
    if(!MagicSingleton<PeerNode>::GetInstance()->find_node_by_fd(msgdata.fd, node))
    {
        ERRORLOG("Invalid message ");
        return -1;
    }

	int ret = DoHandleContractBlock(msg);
	if (ret != 0)
	{
		CBlock cblock;
	    if (!cblock.ParseFromString(msg->block()))
	    {
		    ERRORLOG("fail to serialization!!");   
	    }
		DEBUGLOG("DoHandleBlock failed The error code is {} , block hash :{} ", ret, cblock.hash().substr(0, 6));
	}

	return ret;
}

int verifyTxVrfInfo(const std::shared_ptr<ContractBlockMsg> &msg, const std::map<std::string, CTransaction> & txMap,const CBlock &cblock)
{
	for(const auto& vrf : msg->txvrfinfo())
	{
		const VrfData& txvrfData = vrf.vrfdata();
		std::string txVrfHash = txvrfData.txvrfinfohash();

		auto found = txMap.find(txVrfHash);
		if(found == txMap.end())
		{
			return -99;
		}

		uint64_t handleTxHeight = cblock.height() - 1;
		global::ca::TxType txType = (global::ca::TxType)found->second.txtype();
		int ret = 0;
		if(global::ca::TxType::kTxTypeCallContract != txType && global::ca::TxType::kTxTypeDeployContract != txType)
		{
			//Check whether the dropshipping node is a VP-specified node
			ret = IsVrfVerifyNode(found->second, vrf);
		}
		else
		{
			ret = VerifyContractDistributionManager(found->second, handleTxHeight, vrf);
		}
		if (ret != 0)
		{
			ERRORLOG("The issuing node = {} is not the specified node, ret: {}", found->second.identity(), ret);
			return ret - 40;
		}
	}	
	return 0;
}

int verifyVrfInfo(const std::shared_ptr<ContractBlockMsg> &msg, const std::map<std::string, CTransaction> & txMap)
{
	for(const auto& vrf : msg->vrfinfo())
	{
		const VrfData& vrfData = vrf.vrfdata();
		std::string hash = vrfData.hash();

		auto found = txMap.find(hash);
		if(found == txMap.end())
		{
			return -99;
		}
		std::vector<Node> vrfNodelist;
		std::string targetAddr = vrfData.targetaddr();
		const google::protobuf::RepeatedPtrField<std::string>& _vrfStringList = vrfData.vrflist();
		uint64_t vrfTxHeight = vrfData.height();

		for(const auto& id : _vrfStringList)
		{
			Node node;
			node.base58address = id;
			vrfNodelist.push_back(node);
			DEBUGLOG("vrfNodelist, id:{}", id);
		}

		// Check that the selected nodes for VRFs for all transactions in the block are correct
		EVP_PKEY *pkey = nullptr;
		std::string pubStr = vrf.vrfsign().pub();
		if (!GetEDPubKeyByBytes(pubStr, pkey))
		{
			ERRORLOG(RED "Get public key from bytes failed!" RESET);
			return -17;
		}

		std::string proof = vrf.vrfsign().sign();
		std::string result;
		if (MagicSingleton<VRF>::GetInstance()->VerifyVRF(pkey, found->first, result, proof) != 0)
		{
			ERRORLOG(RED "Verify VRF Info fail" RESET);
			return -18;
		}

		double randNum = MagicSingleton<VRF>::GetInstance()->GetRandNum(result);
		int ret = VerifyContractTxFlowSignNode(vrfNodelist, vrfTxHeight, found->second, randNum, targetAddr) ;
		if (ret != 0)
		{
			ERRORLOG("vrf Failed to verify nodes in the interval : tx hash : {}, ret = {}" , found->first, ret);
			return -19;
		}
	}
	return 0;
}

int DoHandleContractBlock(const std::shared_ptr<ContractBlockMsg>& msg)
{
	// Verify the version
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("Incompatible version!");
		return -1;
	}

	std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	CBlock cblock;
	if (!cblock.ParseFromString(msg->block()))
	{
		ERRORLOG("fail to serialization!!");
		return -2;
	}

	int verifyCount = cblock.sign_size();
	if (verifyCount == 2 && defaultBase58Addr == GetBase58Addr(cblock.sign(0).pub()))
	{
		std::pair<std::string, std::vector<std::string>> nodes_pair;
		MagicSingleton<VRF>::GetInstance()->getVerifyNodes(cblock.hash(), nodes_pair);

		std::vector<std::string> nodes = nodes_pair.second;
		auto id_ = GetBase58Addr(cblock.sign(1).pub());
		
		// if(node != nullptr && id_ != node->base58address)
		// {
		// 	ERRORLOG("Invalid message peerNode_id:{}, node.base58address:{}", id_, node->base58address);
		// 	return -3;
		// }

		auto iter = std::find(nodes.begin(), nodes.end(), id_);
		if (iter == nodes.end())
		{
			ERRORLOG("Validation node not found = {} block hash = {}", id_, cblock.hash());
			return -4;
		}
		if (MagicSingleton<BlockStroage>::GetInstance()->UpdateContractBlock(*msg))
		{
			ERRORLOG("UpdataBlock fail");
			return -5;
		}
	}
	else
	{

		int ret = VerifyBlockSign(cblock);
		if (ret != 0)
		{
			ERRORLOG("VerifyBlockSign fail");
			return -6;
		}

		

		BlockStatus blockStatus;

		ret = MagicSingleton<BlockHelper>::GetInstance()->ContractVerifyFlowedBlock(cblock, &blockStatus, &*msg);
		DEBUGLOG("VerifyFlowedBlock blockHash:{}, ret:{}", cblock.hash().substr(0,6), ret);
		
		if (ret != 0)
		{
			if(verifyCount != 0)
			{
				blockStatus.set_blockhash(cblock.hash());
				blockStatus.set_status(ret);
				blockStatus.set_id(net_get_self_node_id());
				std::string destNode = GetBase58Addr(cblock.sign(0).pub());
				if(destNode != defaultBase58Addr)
				{
					DEBUGLOG("AAAC DoProtoBlockStatus, destNode:{}, ret:{}, blockHash:{}", destNode, ret, cblock.hash().substr(0,6));
					//DoProtoBlockStatus(blockStatus, destNode);
				}
			}
			
			ERRORLOG("Verify Flowed Block fail BlockHash:{}", cblock.hash().substr(0,6));
			return ret -= 30;
		}


		// Block flow plus signature
		if(AddBlockSign(cblock) == false)
		{
			ERRORLOG("Add Block Sign fail");
			return -7;
		}

		msg->set_block(cblock.SerializeAsString());
		if (verifyCount == 0)
		{

			if (MagicSingleton<BlockStroage>::GetInstance()->AddContractBlock(*msg))
			{
				ERRORLOG("Add Block  fail)");
				return -9;
			}
			auto S = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();

			// VRF looks for nodes to send block flows

			ret = SearchNodeToSendContractMsg(*msg);
			if (ret != 0)
			{
				ERRORLOG("Search Node To SendMsg fail");
				return ret -= 300;
			}
			auto E = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
			uint64_t searchNodeTime = E - S;
    		MagicSingleton<DONbenchmark>::GetInstance()->SetByBlockHash(cblock.hash(), &searchNodeTime, 7, &E);
		}
		else if (verifyCount == 1)
		{

			ContractBlockMsg _cpMsg = *msg;
			_cpMsg.clear_sign();
    		_cpMsg.clear_block();

			std::string blockMsgHash = getsha256hash(_cpMsg.SerializeAsString());
			
			int verifySignRet = ca_algorithm::VerifySign(msg->sign(), blockMsgHash);
			if (verifySignRet != 0)
			{
				ERRORLOG("blockMsgHash VerifySign fail!!!");
				return -12;
			}

			if(GetBase58Addr(cblock.sign(0).pub()) != GetBase58Addr(msg->sign().pub()))
			{
				return -13;
			}

			std::map<std::string, CTransaction> txMap;
			std::vector<std::string> verifySign;

			for (auto &tx : cblock.txs())
			{
				txMap[tx.hash()] = tx;
				// Whether to find the vrf logo
				bool flag = true;

				if (GetTransactionType(tx) != kTransactionType_Tx)
				{
					continue;
				}
				// Not dropshipping


				global::ca::TxType txType = (global::ca::TxType)tx.txtype();
				if(global::ca::TxType::kTxTypeCallContract != txType && global::ca::TxType::kTxTypeDeployContract != txType)
				{

					if(GetBase58Addr(cblock.sign(0).pub()) != tx.identity())
					{
						ERRORLOG("Relay Node Error, cblock.sign(0):{}, tx.identity:{}", GetBase58Addr(cblock.sign(0).pub()), tx.identity());
						return -14;
					}
				}

				if(VerifyTxTimeOut(tx) != 0)
				{
					ERRORLOG("time out tx hash = {}, blockHash:{}",tx.hash(), cblock.hash().substr(0,6));
					return -15;
				}
				CTransaction copyTx = tx;
				copyTx.clear_hash();
				copyTx.clear_verifysign();
				std::string tx_hash = getsha256hash(copyTx.SerializeAsString());
				uint64_t handleTxHeight = cblock.height() - 1;
				TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);
				DEBUGLOG("block verify type = {}", type);
				if (type != TxHelper::vrfAgentType_vrf)
				{
					continue;
				}
			}

			std::map<std::string, future<int>> taskResults;
			{	

				auto taskVrfInfo = std::make_shared<std::packaged_task<int()>>([msg,txMap] { return verifyVrfInfo(msg,txMap);});

				auto taskTxVrfInfo = std::make_shared<std::packaged_task<int()>>([=] { return verifyTxVrfInfo(msg,txMap,cblock);});
				try
				{
					taskResults["vrfinfo"] = taskVrfInfo->get_future();
					taskResults["vrfTxinfo"] = taskTxVrfInfo->get_future();
				}
				catch(const std::exception& e)
				{
					std::cerr << e.what() << '\n';
				}

				MagicSingleton<taskPool>::GetInstance()->commit_work_task([taskVrfInfo](){(*taskVrfInfo)();});

				MagicSingleton<taskPool>::GetInstance()->commit_work_task([taskTxVrfInfo](){(*taskTxVrfInfo)();});
			}


			for (auto& res : taskResults)
			{
				int ret = res.second.get();
				if (ret != 0)
				{
					return -16;
					ERRORLOG("AAAC MemVerifyTransactionTx Error:{}, txHash:{}",ret, res.first);
				}
			}

				
			DEBUGLOG("verify vrf, 3 blockHash:{}", cblock.hash().substr(0,6));
			uint64_t height = cblock.height();
			uint64_t txsize = cblock.txs().size();

			MagicSingleton<DONbenchmark>::GetInstance()->SetByBlockHash(cblock.hash(), &height, 4, &txsize);
			// send to origin node
			if (defaultBase58Addr != GetBase58Addr(cblock.sign(0).pub()) && cblock.sign_size() == 2)
			{
				
				DEBUGLOG("DoHandleBlock net_send_message<BlockMsg> {}", GetBase58Addr(cblock.sign(0).pub()));
				auto base58 = GetBase58Addr(cblock.sign(0).pub());
				std::cout << "base58 is "<< base58;
				net_send_message<ContractBlockMsg>(base58, *msg, net_com::Priority::kPriority_High_1);
			}
		}
		else
		{
			// error
			ERRORLOG("unknow type !");
			return -23;
		}
	}
	return 0;
}

int DoHandleBlock(const std::shared_ptr<BlockMsg> &msg)
{
	DEBUGLOG("DoHandleBlock");
	// Verify the version
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("Incompatible version!");
		return -1;
	}

	std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	CBlock cblock;
	if (!cblock.ParseFromString(msg->block()))
	{
		ERRORLOG("fail to serialization!!");
		return -2;
	}

	int verifyCount = cblock.sign_size();
	if (verifyCount == 2 && defaultBase58Addr == GetBase58Addr(cblock.sign(0).pub()))
	{
		std::pair<std::string, std::vector<std::string>> nodes_pair;
		MagicSingleton<VRF>::GetInstance()->getVerifyNodes(cblock.hash(), nodes_pair);

		std::vector<std::string> nodes = nodes_pair.second;
		auto id_ = GetBase58Addr(cblock.sign(1).pub());
		auto iter = std::find(nodes.begin(), nodes.end(), id_);
		if (iter == nodes.end())
		{
			ERRORLOG("Validation node not found = {} block hash = {}", id_, cblock.hash());
			return -3;
		}

		if (MagicSingleton<BlockStroage>::GetInstance()->UpdateBlock(*msg))
		{
			ERRORLOG("UpdataBlock fail");
			return -4;
		}
	}
	else
	{
		int ret = VerifyBlockSign(cblock);
		if (ret != 0)
		{
			ERRORLOG("VerifyBlockSign fail");
			return ret -= 100;
		}
		ret = MagicSingleton<BlockHelper>::GetInstance()->VerifyFlowedBlock(cblock);
		if (ret != 0)
		{
			ERRORLOG("Verify Flowed Block fail");
			return ret -= 200;
		}
		// Block flow plus signature
		if(AddBlockSign(cblock) == false)
		{
			ERRORLOG("Add Block Sign fail");
			return -5;
		}

		msg->set_block(cblock.SerializeAsString());
		if (verifyCount == 0)
		{
			MagicSingleton<BlockStroage>::GetInstance()->AddBlock(*msg);

			// VRF looks for nodes to send block flows
			ret = SearchNodeToSendMsg(*msg);
			if (ret != 0)
			{
				ERRORLOG("Search Node To SendMsg fail");
				return ret -= 300;
			}
		}
		else if (verifyCount == 1)
		{
			std::vector<std::string> verify_sign;
			for (auto &tx : cblock.txs())
			{
				// Whether to find the vrf logo
				bool flag = true;
				if (GetTransactionType(tx) != kTransactionType_Tx)
				{
					continue;
				}
				DEBUGLOG("dohandleblock tx hash: {}", tx.hash());
				// Not dropshipping

				CTransaction copyTx = tx;
				copyTx.clear_hash();
				copyTx.clear_verifysign();
				std::string tx_hash = getsha256hash(copyTx.SerializeAsString());
				uint64_t handleTxHeight = cblock.height() - 1;
				TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);
				DEBUGLOG("block verify type = {}", type);
				if (type != TxHelper::vrfAgentType_vrf)
				{
					continue;
				}

				for (auto &vrf : msg->vrfinfo())
				{
					int range = 0;
					std::string hash;
					if(getVrfdata(vrf, hash, range) != 0)
					{
						return -6;
					}

					if (hash == tx_hash)
					{
						flag = false;
						// Check that the selected nodes for VRFs for all transactions in the block are correct
						EVP_PKEY *pkey = nullptr;
						std::string pub_str = vrf.vrfsign().pub();
						if (!GetEDPubKeyByBytes(pub_str, pkey))
						{
							ERRORLOG(RED "Get public key from bytes failed!" RESET);
							return -7;
						}

						std::string proof = vrf.vrfsign().sign();
						std::string result;
						if (MagicSingleton<VRF>::GetInstance()->VerifyVRF(pkey, tx_hash, result, proof) != 0)
						{
							ERRORLOG(RED "Verify VRF Info fail" RESET);
							return -8;
						}

						double rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(result);
						if (VerifyTxFlowSignNode(tx, rand_num, range) == false)
						{
							ERRORLOG(RED "vrf Failed to verify nodes in the interval" RESET);
							return -9;
						}

						if(VerifyTxTimeOut(tx) != 0)
						{
							ERRORLOG(" time out tx hash = {}" , tx.hash());
							return -10;
						}
					}
				}

				if (flag)
				{
					ERRORLOG("flag is true Not have VrfInfo!");
					return -11;
				}
			}
			// send to origin node
			if (defaultBase58Addr != GetBase58Addr(cblock.sign(0).pub()) && cblock.sign_size() == 2)
			{
				DEBUGLOG("DoHandleBlock net_send_message<BlockMsg> {}", GetBase58Addr(cblock.sign(0).pub()));
				net_send_message<BlockMsg>(GetBase58Addr(cblock.sign(0).pub()), *msg, net_com::Priority::kPriority_High_1);
			}
		}
		else
		{
			// error
			ERRORLOG("unknow type !");
			return -12;
		}
	}
	return 0;
}

int DropshippingContractTx(const std::shared_ptr<ContractTempTxMsgReq> &txMsg, const CTransaction &tx)
{

	uint64_t handleTxHeight = txMsg->txmsginfo().height();
	TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);
	if (type == TxHelper::vrfAgentType_vrf)
	{
		if (txMsg->vrfinfo().vrfsign().pub().empty())
		{
			ERRORLOG("---------------------------net_send_message vrf pub is empty !!!!!");
		}
	}
	else
	{
		ERRORLOG("---------------------------DropshippingTx vrf pub is error !!!!!");
	}
	bool sRet = net_send_message<ContractTempTxMsgReq>(tx.identity(), *txMsg, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
	if (sRet == false)
	{
		return -12000;
	}
	return 0;
}

static void RandomSelectTxNode(const std::vector<Node> &nodes, const double &randNum, std::unordered_set<std::string> &outNodes, std::string & targetAddr, bool isVerify = false)
{
	// Select the range of nodes from the node cache
	int targetPos = nodes.size() * randNum;

	Cycliclist<Node> list;
	for (auto &node : nodes){list.push_back(node);}

	std::vector<std::string> centerNodes;
	if(isVerify)
	{
		//Split the string to get the central node
		std::string underline = "_";
		if(targetAddr.find(underline) != std::string::npos)
		{
			StringUtil::SplitString(targetAddr, "_", centerNodes);
		}
		//Verify that the number of center points passed by the other party is correct
		int targetNums =  global::ca::KSign_node_threshold / 5;
		if(centerNodes.size() != targetNums)
		{
			ERRORLOG("The correct number of addresses = {}, The number of the addressee = {}", targetNums, centerNodes.size());
			return;
		}
	}

	int range = 1; //The number of skipped nodes
	auto begin = list.begin();
	auto target = begin + targetPos;
	auto startPos = target - 2; //The position of the upper boundary
	auto endPos = target + 3;//The position of the lower boundary

	//Check that the range of a circulately linked list cannot be less than the minimum value
	if(list.size() < global::ca::kNeed_node_threshold)
	{
		ERRORLOG("The number of looping linked lists = {} is less than the threshold number = {}", list.size(), global::ca::kNeed_node_threshold);
		return;
	}

	targetAddr = target->data.base58address;
	if(isVerify)
	{
		//Whether the central node is within the prescribed range is judged, and if it is, the central node is modified
		updateCentralNodeInterval(targetAddr, centerNodes[0], target, startPos, endPos);
	}

	int count = 0; //Control the loop by keeping track of the total number of traversals
	int	centerNodesSubscript = 0;
	auto iterCurr = startPos;
	insertOutNodes(iterCurr, endPos, count, outNodes, isVerify);

	while(count < global::ca::KSign_node_threshold)
	{
		//Updating iterators
		auto currNode = startPos - range;
		//Add the secondary central node to the container
		auto centerNode1 = currNode -3;
		if(!isVerify) {targetAddr += ("_" +   centerNode1->data.base58address);}

		//New upper bound and new lower bound
		auto upperBorder = centerNode1 - 2;
		auto LowerBoundary = centerNode1 + 3;
		if(isVerify)
		{
			++centerNodesSubscript;
			updateCentralNodeInterval(centerNode1->data.base58address, centerNodes[centerNodesSubscript], centerNode1, upperBorder, LowerBoundary);
		}

		//Add the nodes in this region to the array	
		auto currPos = upperBorder;
		insertOutNodes(currPos, LowerBoundary, count, outNodes, isVerify);

		//Iterator updates
		startPos = upperBorder;
		if (count >= global::ca::KSign_node_threshold) {
			break;
		}
		//Updating iterators
		currNode = endPos + range;
		//Add the secondary central node to the container
		auto centerNode2 = currNode + 2;
		if(!isVerify) {targetAddr += ("_" +   centerNode2->data.base58address);}

		//New upper bound and new lower bound
		upperBorder = centerNode2 - 2;
		LowerBoundary = centerNode2 + 3;
		if(isVerify)
		{
			++centerNodesSubscript;
			updateCentralNodeInterval(centerNode2->data.base58address, centerNodes[centerNodesSubscript], centerNode2, upperBorder, LowerBoundary);
		}

		//Add the nodes in this region to the array
		currPos = upperBorder;
		insertOutNodes(currPos, LowerBoundary, count, outNodes, isVerify);
		endPos = LowerBoundary;
	}
	DEBUGLOG("RandomSelectTxNode targetAddr = {}, randNum: {}, range: {}", targetAddr, randNum, range);
}

int VerifyContractTxFlowSignNode(const std::vector<Node>& vrfNodelist, const uint64_t& vrfTxHeight, const CTransaction &tx , const double & randNum, std::string & targetAddr)
{
	auto txConsensusStatus = CheckTxConsensusStatus(tx);
	auto ret = verifyVrfDataSource(vrfNodelist, vrfTxHeight, txConsensusStatus);
	if(ret != 0)
	{
		ERRORLOG("verifyVrfDataSource fail!!!,ret:{}", ret);
		return -1;
	}

	std::vector<Node> outNodes;
	FilterConsensusNodeList(vrfNodelist, tx, outNodes);
	if(outNodes.empty())
	{
		return -2;
	}

	std::sort(outNodes.begin(), outNodes.end(),[](const Node & node1, const Node & node2){
		return node1.base58address < node2.base58address;
	});
	
	std::vector<Node> stakeNodes;
	for (const auto &node : outNodes)
	{
		int ret = VerifyBonusAddr(node.base58address);
		int64_t stakeTime = ca_algorithm::GetPledgeTimeByAddr(node.base58address, global::ca::StakeType::kStakeType_Node);
		if (stakeTime > 0 && ret == 0)
		{
			stakeNodes.push_back(node);
		}
	}

	DEBUGLOG("VerifyTxFlowSignNode base58Addr tx identity : {}: ,randNum : {}, eligible nodes size: {}", tx.identity(), randNum, stakeNodes.size());
	for(auto node : stakeNodes)
	{
		DEBUGLOG("VerifyTxFlowSignNode base58Addr:{}, tx hash:{}", node.base58address, tx.hash().substr(0,6));
	}	
	std::unordered_set<std::string> reseultAddrs;
	if (stakeNodes.size() >= global::ca::kNeed_node_threshold)
	{
		RandomSelectTxNode(stakeNodes, randNum, reseultAddrs, targetAddr, true);
	}
	else if (stakeNodes.size() < global::ca::kNeed_node_threshold && txConsensusStatus)
	{
		RandomSelectTxNode(outNodes, randNum, reseultAddrs, targetAddr, true);
	}
	else
	{
		DEBUGLOG("Insufficient qualified signature nodes");
		return -3;
	}

	for(auto addr : reseultAddrs)
	{
		DEBUGLOG("VerifyTxFlowSignNode base58Addr: {}", addr);
	}

	//Take out the signature node in the transaction flow
	std::vector<std::string> verifySign;
	for (int i = 1; i < tx.verifysign().size(); ++i)
	{
		verifySign.push_back(GetBase58Addr(tx.verifysign(i).pub()));
	}
	//Verify whether the signature node is in the selected range
	for (auto &item : verifySign)
	{
		if (std::find(reseultAddrs.begin(), reseultAddrs.end(), item) == reseultAddrs.end())
		{
			ERRORLOG("vrf verify sign addr = {} error !", item);
			return -4;
		}
	}
	return 0;
}

bool VerifyTxFlowSignNode(const CTransaction &tx, const double &rand_num, const int &range)
{
	//Filter transaction parties
	std::vector<Node> outNodes;
	filterNodeList(tx, outNodes);
	outNodes.push_back(tx.identity());
	
	std::vector<std::string> stakeNodes;
	//When there are no global::ca::kNeed_node_threshold node pledge investments, do not filter peernodes. When there are global::ca::kNeed_node_threshold node pledge investments, filter peernodes
	for (const auto &node : outNodes)
	{
		if(CheckVerifyNodeQualification(node.base58address) == 0)
		{
			stakeNodes.push_back(node.base58address);
		}
	}
	//If there are global::ca::kNeed_node_threshold nodes that meet the criteria, select them from the qualification set. If not, select them from the node list
	std::vector<std::string> eligible_addrs;
	if(stakeNodes.size() < global::ca::kNeed_node_threshold)
	{
		for(const auto & node : outNodes)
		{
			eligible_addrs.push_back(node.base58address);
		}
	}
	else
	{
		eligible_addrs = stakeNodes;
	}
	//Sort by base58 address from small to large
	std::sort(eligible_addrs.begin(), eligible_addrs.end(),[](const std::string & addr1, const std::string & addr2){
		return addr1 < addr2;
	});

	//Get all nodes in the vrf range to the target_ addrs
	int target_pos = eligible_addrs.size() * rand_num;
	Cycliclist<std::string> list;

	for (auto &addr : eligible_addrs)
	{
		list.push_back(addr);
	}

	auto begin = list.begin();
	auto target = begin + target_pos;
	auto start_pos = target - range;
	auto end_pos = target + range;

	DEBUGLOG("dohandleblock range = {} , random = {} ",range, rand_num);
	vector<std::string> target_addrs;
	for (; start_pos != end_pos; start_pos++)
	{
		DEBUGLOG("dohandleblock target_addrs = {} ", start_pos->data);
		target_addrs.push_back(start_pos->data);
	}

	//Take out the signature node in the transaction flow
	vector<std::string> verify_sign;
	for (int i = 1; i < tx.verifysign().size(); ++i)
	{
		DEBUGLOG("dohandleblock verify_sign addr = {} ", GetBase58Addr(tx.verifysign(i).pub()));
		verify_sign.push_back(GetBase58Addr(tx.verifysign(i).pub()));
	}
	//Verify whether the signature node is in the selected range
	for (auto &item : verify_sign)
	{
		if (std::find(target_addrs.begin(), target_addrs.end(), item) == target_addrs.end())
		{
			//write_tmplog("The verification node randomly selected by vrf is not In the transaction signature node: " + item);
			DEBUGLOG("vrf verify sign addr = {} error !", item);
			return false;
		}
	}

	return true;
}


int VerifyTxTimeOut(const CTransaction &tx)
{
    const int64_t kExpireSecond = global::ca::KtxTimeout * 3;
    uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    int64_t expireTime = 0;
    if ((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeCallContract && (global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeDeployContract)
    {
        expireTime = global::ca::KtxTimeout;
    }
    else
    {
        expireTime = kExpireSecond;
    }

	if(tx.time() + expireTime <= nowTime || tx.time() >= nowTime + expireTime)
	{
		return -1;
	}
	return 0;
}

int PreCalcGas(CTransaction &tx)
{

	uint64_t gas = 0;
	CalculateGas(tx, gas);
	std::cout << "The gas for this transaction is:" << gas << std::endl;

	std::string strKey;
	std::cout << "Please input your choice [0](accept) or [1](Unacceptable) >: " << std::endl;
	std::cin >> strKey;
	std::regex pattern("^[0-1]$");
	if (!std::regex_match(strKey, pattern))
	{
		std::cout << "Invalid input." << std::endl;
		return -1;
	}
	int key = std::stoi(strKey);

	if (key == 1)
	{
		return -2;
	}

	auto current_time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	tx.set_time(current_time);
	tx.clear_hash();

	std::string txHash = getsha256hash(tx.SerializeAsString());
	tx.set_hash(txHash);

	return 0;
}

int CalculateGas(const CTransaction &tx, uint64_t &gas)
{
	uint64_t UtxoSize = 0;
	TransactionType tx_type = GetTransactionType(tx);
	if (tx_type == kTransactionType_Genesis || tx_type == kTransactionType_Tx)
	{

		uint64_t utxo_size = 0;
		const CTxUtxo &utxo = tx.utxo();

		utxo_size += utxo.owner_size() * 34;

		for (auto &vin : utxo.vin())
		{
			utxo_size += vin.prevout().size() * 64;
			UtxoSize  += vin.prevout().size();
		}
		utxo_size += utxo.vout_size() * 34;

		gas += utxo_size;
		gas += tx.type().size() + tx.data().size() + tx.info().size();
		gas += tx.reserve0().size() + tx.reserve1().size();
	}

    
	gas *= UtxoSize * 100;

	if (gas == 0)
	{
		ERRORLOG(" gas = 0 !");
		return -1;
	}

	return 0;
}

//Interface used when creating transaction
int GenerateGas(const CTransaction &tx, const uint64_t voutSize, uint64_t &gas)
{
	uint64_t UtxoSize = 0;
	TransactionType txType = GetTransactionType(tx);
	if (txType == kTransactionType_Genesis || txType == kTransactionType_Tx)
	{

		uint64_t utxoSize = 0;
		const CTxUtxo &utxo = tx.utxo();

	
		for (auto &vin : utxo.vin())
		{
			utxoSize += vin.prevout().size() * 64;
			UtxoSize  += vin.prevout().size();
		}

		gas = 0;
		gas += utxo.owner_size() * 34;
		gas += utxoSize;
		gas += voutSize * 34;

		gas += tx.type().size() + tx.data().size() + tx.info().size();
		gas += tx.reserve0().size() + tx.reserve1().size();

	}

	gas *= UtxoSize * 100;

	if (gas == 0)
	{
		ERRORLOG(" gas = 0 !");
		return -1;
	}
	return 0;
}


int GetContractRootHash(const std::string& contractAddress, std::string& rootHash)
{
	if(MagicSingleton<ContractDataCache>::GetInstance()->get(contractAddress + "_" + "rootHash", rootHash))
	{
		return 0;
	}

    DBReader data_reader;
    std::string strPrevTxHash;
    int ret = data_reader.GetLatestUtxoByContractAddr(contractAddress, strPrevTxHash);
    if(ret != DBStatus::DB_SUCCESS)
    {
        ERRORLOG("GetLatestUtxoByContractAddr failed!");
        return -1;
    }

    std::string strPrevBlockHash;
    ret = data_reader.GetBlockHashByTransactionHash(strPrevTxHash, strPrevBlockHash);
    if(ret != DBStatus::DB_SUCCESS)
    {
        ERRORLOG("GetBlockHashByTransactionHash failed!, pretxhash: {}", strPrevTxHash);
        return -2;
    }

    std::string blockRaw;
    ret = data_reader.GetBlockByBlockHash(strPrevBlockHash, blockRaw);
    if(ret != DBStatus::DB_SUCCESS)
    {
        ERRORLOG("GetBlockByBlockHash failed!");
        return -3;
    }

    CBlock Prevblock;
    if(!Prevblock.ParseFromString(blockRaw))
    {
        ERRORLOG("parse failed!");
        return -4;
    }

    bool isDeployContract = false;
    for (const auto& tx : Prevblock.txs())
    {
        if (tx.hash() == strPrevTxHash &&
            (global::ca::TxType)tx.txtype() == global::ca::TxType::kTxTypeDeployContract
            )
        {

            isDeployContract = true;
            break;
        }
    }
    try
    {
        nlohmann::json jPrevData = nlohmann::json::parse(Prevblock.data());
        auto found = jPrevData.find(strPrevTxHash);
        if (found == jPrevData.end())
        {
            return -5;
        }
        nlohmann::json txInfo = found.value();
        nlohmann::json jPrevStorage = txInfo["Storage"];
        if(!jPrevStorage.is_null())
        {
            if(isDeployContract)
            {
                rootHash = jPrevStorage[std::string("_") + "rootHash"].get<std::string>();
            }
            else
            {
                rootHash = jPrevStorage[contractAddress + "_" + "rootHash"].get<std::string>();
            }
        }

    }
    catch(...)
    {
        ERRORLOG("Parsing failed!");
        return -6;
    }
    return 0;
}

int GetContractDistributionManager(const uint64_t& txTime, const uint64_t& txHeight, std::string& packager, NewVrf& info)
{
	std::string proof, txHash;
	int ret = CalculateThePackerByTime(txTime, txHeight, packager, proof, txHash);
	if(ret != 0)
	{
		ERRORLOG("CalculateThePackerByTime ret : {}", ret);
		return -1;
	}

	Account defaultAccount;
	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount) != 0)
	{
		return -2;
	}

	if (packager == defaultAccount.base58Addr)
	{
		DEBUGLOG("The package address is the same as the default address : {}", packager);
	}
	
	std::cout << "packager: " << packager << std::endl;
	DEBUGLOG("GetContractDistributionManager : {} , tx time : {}", packager, MagicSingleton<TimeUtil>::GetInstance()->formatUTCTimestamp(txTime));
	
	auto vrfData = info.mutable_vrfdata();
	vrfData->set_hash(txHash);
	vrfData->set_range(0);
	vrfData->set_percentage(0);

	SetNewVrf(info, proof, defaultAccount.GetPubStr());
	std::cout << "**********VRF Generated the number end**********************" << std::endl;

	return 0;
}

int CalculateThePackerByTime(const uint64_t& txTime, const uint64_t& txHeight, std::string& packager, std::string& proof, std::string &txHash)
{
	std::vector<std::string> targetAddrs;
	int ret = GetVrfDataSourceByTime(txTime, txHeight, txHash, targetAddrs);
	if(ret != 0)
	{
		ERRORLOG("GetTheVrfDataSourceByTime error ret : {}", ret);
		return -1;
	}
	
	std::string timestampStr = std::to_string(MagicSingleton<TimeUtil>::GetInstance()->GetTheTimestampPerUnitOfTime(txTime));
	std::string input = getsha256hash(timestampStr);

	uint32_t randNum = MagicSingleton<VRF>::GetInstance()->GetRandNum(input, global::ca::KRandomNodeGroup);
	packager = targetAddrs[randNum]; 
	return 0;
}


int DropCallShippingTx(const std::shared_ptr<ContractTxMsgReq> & Msg,const CTransaction &tx)
{
	uint64_t handleTxHeight = Msg->mutable_txmsgreq()->txmsginfo().height();
	TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);
	DEBUGLOG("enter in dropcallshipping tx");
	std::string defalutAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	if(tx.identity() == defalutAddr)
	{
    	MsgData msgData;
    	int ret = HandleContractTx( Msg,  msgData );
		if(ret != 0)
		{
			ERRORLOG("HandleContractTx ret :{}" , ret);
			return -1;
		}
	}

	bool sRet = net_send_message<ContractTxMsgReq>(tx.identity(), *Msg, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
	DEBUGLOG("HandleCallContract send id :{}, send tx hash :{} ", tx.identity(), tx.hash());
	if (sRet == false)
	{
		return -2;
	}

	return 0;
}

int HandleContractTx( const std::shared_ptr<ContractTxMsgReq>& msg, const MsgData& msgdata )
{
	TRACELOG("HandleContractTx");
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("Incompatible version!");
		return -1;
	}

	CTransaction contractTx;
	if (!contractTx.ParseFromString(msg->mutable_txmsgreq()->txmsginfo().tx()))
	{
		ERRORLOG("Failed to deserialize transaction body!");
		return -2;
	}

	uint64_t height = msg->mutable_txmsgreq()->txmsginfo().height();
	int ret =  VerifyContractDistributionManager(contractTx, height, msg->mutable_txmsgreq()->vrfinfo());
	if(ret != 0)
	{
		ERRORLOG("VerifyContractDistributionManager error ret :{}", ret);
		return -3;
	}
	uint64_t txBaseLineTime =  MagicSingleton<TimeUtil>::GetInstance()->GetTheTimestampPerUnitOfTime(contractTx.time());
	uint64_t nowTime =  MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    uint64_t timeBaseline = MagicSingleton<TimeUtil>::GetInstance()->GetTheTimestampPerUnitOfTime(nowTime);
	DEBUGLOG("nowTime - (tx time) = {}" ,(nowTime - contractTx.time()));
	if(txBaseLineTime != timeBaseline)
	{
		if(nowTime - contractTx.time() >= 1000000)
		{
			ERRORLOG("different time nowTime : {} , contractTx time : {}",nowTime,contractTx.time());
		}
	}



	MagicSingleton<ContractDispatcher>::GetInstance()->setValue(contractTx.time());
	
	std::vector<std::string> dependentAddress(msg->mutable_txmsgreq()->txmsginfo().contractstoragelist().begin(), msg->mutable_txmsgreq()->txmsginfo().contractstoragelist().end());
	MagicSingleton<ContractDispatcher>::GetInstance()->AddContractInfo(contractTx.hash(),dependentAddress);
	MagicSingleton<ContractDispatcher>::GetInstance()->AddContractMsgReq(contractTx.hash(),*msg);
    DEBUGLOG("@@@@@ Dispenser : txhash = {}  ", contractTx.hash());

	return 0;
}

int VerifyContractDistributionManager(const CTransaction& tx, const uint64_t& height, const NewVrf& vrfInfo)
{
	DEBUGLOG("Issuing transaction verification tx hash = {}", tx.hash());

	int range;
	std::string txHash;
	int ret = getNewVrfdata(vrfInfo, txHash, range);
	if(ret != 0)
	{
		return -1;
	}

	std::vector<std::string> targetAddrs;
	std::string outputHash;
	ret = GetVrfDataSourceByTime(tx.time(), height, outputHash, targetAddrs);
	if(ret != 0)
	{
		ERRORLOG("GetTheVrfDataSourceByTime error ret : {}", ret);
		return -2;
	}

	if(txHash != outputHash)
	{
		ERRORLOG("The transaction hash is inconsistent! hash obtained from vrf data: {}, Computational hash: {}", txHash, outputHash);
		return -3;
	}

	std::string timestampStr = std::to_string(MagicSingleton<TimeUtil>::GetInstance()->GetTheTimestampPerUnitOfTime(tx.time()));
	std::string input = getsha256hash(timestampStr);

	int randNum = MagicSingleton<VRF>::GetInstance()->GetRandNum(input, global::ca::KRandomNodeGroup);
	std::string targetAddr = targetAddrs[randNum];
	if (tx.identity() != targetAddr)
	{
		ERRORLOG("Issuing node = {} not equal target node = {}", targetAddr, tx.identity());
		return -4;
	}
	return 0;
}

int GetVrfDataSourceByTime(const uint64_t& txTime, const uint64_t& txHeight, std::string &txHash, std::vector<std::string>& targetAddrs)
{
	bool isFind = false;
	DBReader dbReader;
	x_uint64_t timestamp = MagicSingleton<TimeUtil>::GetInstance()->GetTheTimestampPerUnitOfTime(txTime);
	x_uint64_t previousTenSecondsTime = timestamp - 10 * 1000000;
	CBlock targetBlock;
	//Finding the target block
	for (int i = txHeight; i >= 0; i--)
	{
		std::vector<std::string> hashes;
		if (DBStatus::DB_SUCCESS != dbReader.GetBlockHashsByBlockHeight(i, hashes))
		{
			continue;
		}
		
		std::vector<CBlock> blocks;
		for (auto &hash : hashes)
		{
			std::string blockStr;
			dbReader.GetBlockByBlockHash(hash, blockStr);
			CBlock block;
			if(!block.ParseFromString(blockStr)){
				return -2;
			}
			blocks.emplace_back(block);
		}
	
		std::sort(blocks.begin(), blocks.end(), [](const CBlock &x, const CBlock &y)
			{ return x.time() > y.time(); });
		for(auto & block : blocks)
		{
			if(block.time() < previousTenSecondsTime)
			{
				targetBlock = block;
				DEBUGLOG("GetVrfDataSourceByTime block hash : {}, timestamp :{} ", block.hash().substr(0,6),  MagicSingleton<TimeUtil>::GetInstance()->formatUTCTimestamp(timestamp));
				isFind = true;
				break;
			}
		}

		if(isFind){
			break;
		}
	}

	if(!isFind)
	{
		ERRORLOG("No target block found");
		return -3;
	}


	//save block is empty
	if(targetBlock.txs_size() == 0)
	{
		ERRORLOG("GetVrfDataSourceByTime The transactions in the block are empty");
		return -4;
	}
	CTransaction tx = targetBlock.txs(0);
	txHash = tx.hash();
	DEBUGLOG("GetVrfDataSourceByTime tx hash : {} ", txHash);
	for(auto& iter : tx.verifysign())
	{
		targetAddrs.emplace_back(GetBase58Addr(iter.pub()));
	}

	if(targetAddrs.size() != global::ca::KRandomNodeGroup)
	{
		ERRORLOG("There are less than 35 data sources");
		return -5;
	}
	return 0;
}

int verifyVrfDataSource(const std::vector<Node>& vrfNodelist, const uint64_t& vrfTxHeight, bool txConsensusStatus)
{
    if(vrfNodelist.empty())
    {
        return -1;
    }
    std::set<std::string> vrfStakeNodelist;
    std::set<std::string> vrfNodeIdlist;
    for(const auto& node : vrfNodelist)
    {
        int ret = VerifyBonusAddr(node.base58address);
		int64_t stakeTime = ca_algorithm::GetPledgeTimeByAddr(node.base58address, global::ca::StakeType::kStakeType_Node);
		if (stakeTime > 0 && ret == 0)
		{
			vrfStakeNodelist.insert(node.base58address);
		}

        vrfNodeIdlist.insert(node.base58address);
    }

    if(vrfStakeNodelist.size() >= global::ca::kNeed_node_threshold)
    {
		std::set<std::string> consensusStakeNodelist;
		std::map<std::string,int> stakeNodeMap;
		MagicSingleton<UnregisterNode>::GetInstance()->GetConsensusStakeNodelist(stakeNodeMap);
		if(stakeNodeMap.empty())
		{
			return -2;
		}
		
		for(const auto& it : stakeNodeMap)
		{
			Node node;
			if(MagicSingleton<PeerNode>::GetInstance()->find_node(it.first, node))
			{
				if(node.height >= vrfTxHeight)
				{
					consensusStakeNodelist.insert(it.first);
				}
				continue;
			}
			consensusStakeNodelist.insert(it.first);
		}
		if(consensusStakeNodelist.empty())
		{
			ERRORLOG("consensusStakeNodelist.empty() == true");
			return -3;
		}

        std::set<std::string> difference;
        std::set_difference(consensusStakeNodelist.begin(), consensusStakeNodelist.end(),
                            vrfStakeNodelist.begin(), vrfStakeNodelist.end(),
                            std::inserter(difference, difference.begin()));

        for(auto& id : difference)
        {
            DEBUGLOG("difference, id:{}", id);
        }

        double differenceRatio = static_cast<double>(difference.size()) / consensusStakeNodelist.size();

        DEBUGLOG("difference size:{}, vrfStakeNodelist size:{}, consensusStakeNodelist size:{}, differenceRatio:{}", difference.size(), vrfStakeNodelist.size(), consensusStakeNodelist.size(), differenceRatio);
        if (differenceRatio <= 0.25)
        {
            return 0;
        }
        else
        {
            return -4;
        }

    }
    else if(txConsensusStatus && vrfNodelist.size() >= global::ca::kConsensus)
    {
		std::map<std::string,int> consensusNodeMap;
		MagicSingleton<UnregisterNode>::GetInstance()->GetConsensusNodelist(consensusNodeMap);
        if(consensusNodeMap.empty())
        {
            return -5;
        }
        std::set<std::string> consensNodelist;
        for(const auto& it : consensusNodeMap)
        {
            Node node;
            if(MagicSingleton<PeerNode>::GetInstance()->find_node(it.first, node))
            {
                if(node.height >= vrfTxHeight)
                {
                    consensNodelist.insert(it.first);
                }
                continue;
            }
            consensNodelist.insert(it.first);
        }

        if(consensNodelist.empty())
        {
            ERRORLOG("consensNodelist.empty() == true");
            return -6;
        }

        std::set<std::string> difference;
        std::set_difference(consensNodelist.begin(), consensNodelist.end(),
                            vrfNodeIdlist.begin(), vrfNodeIdlist.end(),
                            std::inserter(difference, difference.begin()));

        for(auto& id : difference)
        {
            DEBUGLOG("difference, id:{}", id);
        }

        double differenceRatio = static_cast<double>(difference.size()) / consensNodelist.size();

        DEBUGLOG("difference size:{}, vrfNodeIdlist size:{}, consensNodelist size:{}, differenceRatio:{}",difference.size(), vrfNodeIdlist.size(), consensNodelist.size(), differenceRatio);
        if (differenceRatio <= 0.25)
        {
            return 0;
        }
        else
        {
            return -7;
        }
    }
    return -8;
}

int VerifyContractPackNode(const std::string& dispatchNodeAddr, const double& randNum, const std::string& targetAddr,const std::vector<Node> & _vrfNodelist)
{
	DEBUGLOG("VerifyContractPackNode randNum : {}, targetAddr : {}", randNum, targetAddr);
	
	if(_vrfNodelist.empty())
	{
		ERRORLOG("conNodeList.empty()  fail!!!");
		return -1;
	}
	

	std::vector<Node> satisfiedAddrs;
	for(auto & node : _vrfNodelist)
	{
		//Verification of investment and pledge
		int ret = VerifyBonusAddr(node.base58address);
		int64_t stakeTime = ca_algorithm::GetPledgeTimeByAddr(node.base58address, global::ca::StakeType::kStakeType_Node);
		if (stakeTime > 0 && ret == 0)
		{
			satisfiedAddrs.push_back(node);
		}
	}
	

	std::sort(satisfiedAddrs.begin(), satisfiedAddrs.end(),[](const Node & node1, const Node & node2){
		return node1.base58address < node2.base58address;
	});
	std::vector<std::string> targetAddrs;
	auto ret = CalculatePackNode(satisfiedAddrs, randNum, true, targetAddrs);
	if(ret != 0)
	{
		ERRORLOG("VerifyContractPackNode, CalculatePackNode ret : {}", ret);
		return -2;
	}

	for(const auto & addr : targetAddrs)
	{
		DEBUGLOG("VerifyContractPackNode result addr : {}" , addr);
	}

	if(std::find(targetAddrs.begin(), targetAddrs.end(), targetAddr) == targetAddrs.end())
	{
		ERRORLOG("VerifyContractPackNode The current address , not equal contract package address : {} ", targetAddr);
		return -3;
	}
	return 0;
}



int FindContractPackNode(const std::string & txHash, std::string &targetAddr, NewVrf& vrfInfo,std::set<std::string> & out_nodelist)
{
	Account defaultAccount;
	defaultAccount = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	std::string output, proof;
	int ret = MagicSingleton<VRF>::GetInstance()->CreateVRF(defaultAccount.pkey, txHash, output, proof);
	if (ret != 0)
	{
		std::cout << "error create:" << ret << std::endl;
		return -2;
	}

	std::vector<Node> nodeList = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
	if(nodeList.empty())
	{
		ERRORLOG("nodeList.empty()  fail!!!");
		return -3;
	}

	DBReader dbReader;
	uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(top))
    {
        ERRORLOG("GetBlockTop error!");
        return -4;
    }

	std::vector<Node> suitableAddrs;
	for(auto & item : nodeList)
	{
		if(item.height >= top)
		{
			suitableAddrs.push_back(item);
			out_nodelist.insert(item.base58address);
		}
	}

	ret = verifyVrfDataSource(suitableAddrs,top);
    if(ret != 0)
    {
        ERRORLOG("verifyVrfDataSource fail ! ,ret:{}", ret);
        return -5;
    }

	std::vector<Node> satisfiedAddrs;
	for(auto & node : suitableAddrs)
	{
		int ret = VerifyBonusAddr(node.base58address);
		int64_t stakeTime = ca_algorithm::GetPledgeTimeByAddr(node.base58address, global::ca::StakeType::kStakeType_Node);
		if (stakeTime > 0 && ret == 0)
		{
			satisfiedAddrs.push_back(node);
		}
	}
	
	std::sort(satisfiedAddrs.begin(), satisfiedAddrs.end(), [&](const Node &n1, const Node &n2)
		{ return n1.base58address < n2.base58address; });

	double randNum = MagicSingleton<VRF>::GetInstance()->GetRandNum(output);
	std::vector<std::string> targetAddrs;
	CalculatePackNode(satisfiedAddrs, randNum, false, targetAddrs);
    if (targetAddrs.empty())
    {
        ERRORLOG("targetAddrs is empty");
        return -6;
    }

	targetAddr = targetAddrs[0];
	auto vrfData = vrfInfo.mutable_vrfdata();
	vrfData->set_hash(txHash);
	vrfData->set_range(0);
	vrfData->set_height(top);

	SetNewVrf(vrfInfo, proof, defaultAccount.GetPubStr());
	return 0;
}

static int CalculatePackNode(const std::vector<Node> &nodes, const double &randNum, const bool& isVerify, std::vector<std::string>& targetAddrs)
{
	DEBUGLOG("CalculatePackNode nodes size :{} , randNum :{}", nodes.size(), randNum);
	int targetPos = nodes.size() * randNum;
	Cycliclist<Node> list;
	for (auto &node : nodes){
		DEBUGLOG("CalculatePackNode node addr : {}", node.base58address);
		list.push_back(node);
	}

	if(list.size() < global::ca::kNeed_node_threshold)
	{
		ERRORLOG("The number of looping linked lists = {} is less than the threshold number = {}", list.size(), global::ca::kNeed_node_threshold);
		return -1;
	}

	auto begin = list.begin();
	auto target = begin + targetPos;
	std::string targetAddr = target->data.base58address;
	targetAddrs.push_back(targetAddr);

	if(isVerify)
	{
		auto currentPos = target;
		auto startPos = currentPos - 2;
		auto endPos = currentPos + 3;
		for(; startPos != endPos; startPos++)
		{
			if(startPos->data.base58address == targetAddr)
			{
				continue;
			}
			targetAddrs.push_back(startPos->data.base58address);
		}
	}
	// int targetPos = nodes.size() * randNum;
	// std::string targetAddr = target->data.base58address;
	// if(isVerify)
	// {
	// 	auto currentPos = target;
	// 	auto startPos = currentPos - 2;
	// 	auto endPos = currentPos + 3;
	// 	for(; startPos != endPos; startPos++)
	// 	{
	// 		if(startPos->data.base58address == targetAddr)
	// 		{
	// 			continue;
	// 		}
	// 		targetAddrs.push_back(startPos->data.base58address);
	// 		break;
	// 	}
	// }
	
	return 0;
}

static int filterVrfSignatureNodes(const CTransaction & tx, const std::shared_ptr<ContractTempTxMsgReq> &msg, const bool txConsensusStatus, std::unordered_set<std::string> & nextNodes)
{
	ContractTempTxMsgReq *data_ = msg.get();
	std::string output, proof;


	Account defaultAccount;
	defaultAccount = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	CTransaction copyTx = tx;
	copyTx.clear_hash();
	copyTx.clear_verifysign();
	std::string txHash = getsha256hash(copyTx.SerializeAsString());

	int ret = MagicSingleton<VRF>::GetInstance()->CreateVRF(defaultAccount.pkey, txHash, output, proof);
	if (ret != 0)
	{
		std::cout << "error create:" << ret << std::endl;
		return -2;
	}
	std::vector<Node> Nodelist = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();

	uint64_t top = msg->txmsginfo().height();
	std::vector<Node> HeightAddrs;//N
	for(auto & item : Nodelist)
	{
		if(item.height >= top)
		{
			HeightAddrs.push_back(item);
		}
	}

	ret = verifyVrfDataSource(HeightAddrs, top, txConsensusStatus); 
	if(ret != 0)
	{
		DEBUGLOG("local verifyVrfDataSource fail!!!,ret:{}", ret);
		return -3;
	}
	std::vector<std::string> _jsonNodelist;
	for(auto & node : HeightAddrs)
	{
		_jsonNodelist.push_back(node.base58address);
		DEBUGLOG("_jsonNodelist, id:{}", node.base58address);
	}
	std::vector<Node> outnodelist;
	FilterConsensusNodeList(HeightAddrs, tx, outnodelist);
	if(outnodelist.empty())
	{
		return -4;
	}


	std::sort(outnodelist.begin(), outnodelist.end(), [&](const Node &n1, const Node &n2)
			{ return n1.base58address < n2.base58address; });

	std::vector<Node> satisfiedAddrs;//L
	for(auto & node : outnodelist)
	{
		//Verification of investment and pledge
		int ret = VerifyBonusAddr(node.base58address);
		int64_t stakeTime = ca_algorithm::GetPledgeTimeByAddr(node.base58address, global::ca::StakeType::kStakeType_Node);
		if (stakeTime > 0 && ret == 0)
		{
			satisfiedAddrs.push_back(node);
		}
	}

	
	DEBUGLOG("satisfiedAddrs.size = {},HeightAddrs.size() = {}, outnodelist size = {}, txConsensusStatus = {}", satisfiedAddrs.size(), HeightAddrs.size(), outnodelist.size(), txConsensusStatus);
	for(auto & node : satisfiedAddrs)
	{
		DEBUGLOG("RandomSelectTxNode Addr : {} , tx hash : {}", node.base58address, tx.hash().substr(0,6));
	}
	double randNum = MagicSingleton<VRF>::GetInstance()->GetRandNum(output);
	std::string targetAddr;
	if (satisfiedAddrs.size() >= global::ca::kNeed_node_threshold)
	{
		RandomSelectTxNode(satisfiedAddrs, randNum, nextNodes, targetAddr);
	}
	else if (satisfiedAddrs.size() < global::ca::kNeed_node_threshold && txConsensusStatus)
	{
		RandomSelectTxNode(outnodelist, randNum, nextNodes, targetAddr);
	}
	else
	{
		DEBUGLOG("Insufficient qualified signature nodes");
		return -5;
	}

	std::vector<std::string> excessiveAddrs;
	for (auto &addr : nextNodes)
	{
		excessiveAddrs.push_back(addr);
	}
	MagicSingleton<VRF>::GetInstance()->addVerifyNodes(txHash, excessiveAddrs);
	//	Judge whether the number of filtered nodes is equal to the threshold number
	if (nextNodes.size() < global::ca::kConsensus)
	{
		DEBUGLOG("Insufficient number of nodes = {}", nextNodes.size());
		if(HeightAddrs.size() < global::ca::kConsensus)
		{
			ERRORLOG("HeightAddrs = {} Less than Consensus = {}", HeightAddrs.size(), global::ca::kConsensus);
			return -6;
		}
		return -7;
	}

	NewVrf info;
	auto vrfData = info.mutable_vrfdata();
	vrfData->set_hash(txHash);
	vrfData->set_targetaddr(targetAddr);
	for(const auto& it : _jsonNodelist)
	{
		vrfData->add_vrflist(it);
	}
	vrfData->set_height(msg->txmsginfo().height());
	
	// nlohmann::json data;
	// data["hash"] = txHash;
	// data["targetAddr"] = targetAddr;
	// data["vrfList"] = _jsonNodelist;
	// data["vrfTxHeight"] = msg->txmsginfo().height();
	// std::string dataStr = data.dump();
	SetNewVrf(info, proof, defaultAccount.GetPubStr());

	NewVrf * newInfo = data_->mutable_txvrfinfo();
	newInfo->CopyFrom(info);

	MagicSingleton<VRF>::GetInstance()->addNewVrfInfo(txHash, info);
	MagicSingleton<VRF>::GetInstance()->addTxNewVrfInfo(txHash, msg->vrfinfo());
	DEBUGLOG("addVrfInfo txHash : {}", txHash);
    DEBUGLOG("addTxVrfInfo txHash : {}", txHash);
	return 0;
}

static void FilterConsensusNodeList(const vector<Node>& vrfNodelist, const CTransaction & tx, std::vector<Node> &outAddrs)
{
    std::vector<Node> nodeList = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
	if(vrfNodelist.empty()){
		ERRORLOG("vrfNodelist  fail!!!");
		return;
	}

	std::vector<std::string> txAddrs;
	global::ca::TxType txType = (global::ca::TxType)tx.txtype();
	if(txType == global::ca::TxType::kTxTypeBonus)
	{
		CTxOutput txout = tx.utxo().vout(tx.utxo().vout_size() - 1);
		txAddrs.push_back(txout.addr());
	}
	else
	{
		for (int i = 0; i < tx.utxo().vout_size(); ++i)
		{
			CTxOutput txout = tx.utxo().vout(i);
			txAddrs.push_back(txout.addr());
		}
	}	
	std::vector<std::string> txOwners(tx.utxo().owner().begin(), tx.utxo().owner().end());
	for (auto iter = vrfNodelist.begin(); iter != vrfNodelist.end(); ++iter)
	{
		if (txOwners.end() != find(txOwners.begin(), txOwners.end(), iter->base58address))
		{
			DEBUGLOG("FilterConsensusNodeList filter: from addr {}", iter->base58address);
			continue;
		}


		if (txAddrs.end() != find(txAddrs.begin(), txAddrs.end(), iter->base58address))
		{
			DEBUGLOG("FilterConsensusNodeList filter: to addr {}", iter->base58address);
			continue;
		}


		if (tx.identity() == iter->base58address)
		{
			DEBUGLOG("FilterConsensusNodeList filter: identity addr {}", iter->base58address);
			continue;
		}

		outAddrs.push_back(*iter);
	}
	//outAddrs.push_back(MagicSingleton<PeerNode>::GetInstance()->GetSelfNode());
}

int DropshippingTx(const std::shared_ptr<TxMsgReq> &txMsg, const CTransaction &tx)
{

	uint64_t handleTxHeight = txMsg->txmsginfo().height();
	TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);

	bool sRet = net_send_message<TxMsgReq>(tx.identity(), *txMsg, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
	if (sRet == false)
	{
		return -1;
	}
	return 0;
}


bool IsContractBlock(const CBlock & block)
{
    for (const auto& tx : block.txs())
    {
        if ((global::ca::TxType)tx.txtype() == global::ca::TxType::kTxTypeCallContract || (global::ca::TxType)tx.txtype() == global::ca::TxType::kTxTypeDeployContract)
        {
            return true;
        }
    }
    return false;
}


int UpdateTxMsg(CTransaction & tx,const std::shared_ptr<ContractTempTxMsgReq> &msg)
{
	std::unordered_set<std::string> sendid;
	int ret = FindContractSignNode(tx, msg, sendid);
	if (ret < 0)
	{
		ret -= 100;
		ERRORLOG("UpdateTxMsg failed, ret:{} sendid size: {}", ret, sendid.size());
		return ret;
	}
	if (sendid.empty())
	{
		ERRORLOG("UpdateTxMsg failed, sendid size is empty");
		return -1;
	}

	if (sendid.size() < global::ca::KRandomNodeGroup)
	{
		ERRORLOG("The number of nodes is less than the consensus number, sendid.size:{}", sendid.size());
		return -2;
	}

	std::vector<std::string> randomSignAddrs;
	for (auto &addr : sendid)
	{
		randomSignAddrs.push_back(addr);
	}
	std::random_shuffle(randomSignAddrs.begin(),randomSignAddrs.end());
	
	uint64_t handleTxHeight = msg->txmsginfo().height();
	TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);

	for (auto id : randomSignAddrs)
	{
		DEBUGLOG("sendid id = {} tx hash : {} , tx time = {} , type = {}", id, tx.hash().substr(0, 6), MagicSingleton<TimeUtil>::GetInstance()->formatUTCTimestamp(tx.time()), type);

		Node node;
		if (MagicSingleton<PeerNode>::GetInstance()->find_node(id, node))
		{
			tx.add_verifysign()->set_pub(node.identity);
		}
		else
		{
			DEBUGLOG("FindNode fail!!! base58addr:{}", id);
		}

		if(tx.verifysign_size() >= global::ca::KRandomNodeGroup)
		{
			break;
		}
	}
	
	CTransaction copyTx = tx;
	copyTx.clear_hash();
	copyTx.clear_verifysign();

	tx.set_hash(getsha256hash(copyTx.SerializeAsString()));
	return 0;
}

bool CheckTxConsensusStatus(const CTransaction &tx)
{
	bool isStake = false, isInvest = false, isBonus = false;
	global::ca::TxType txType = (global::ca::TxType)tx.txtype();
	switch (txType) {
		case global::ca::TxType::kTxTypeStake:
			isStake = true;
			break;
		case global::ca::TxType::kTxTypeInvest:
			isInvest = true;
			break;
		case global::ca::TxType::kTxTypeBonus:
			isBonus = true;
			break;
		default:
			break;
	}

	bool isInitAccount = false;
	std::vector<std::string> vTxowners = TxHelper::GetTxOwner(tx);
	if (vTxowners.size() == 1 && vTxowners.end() != find(vTxowners.begin(), vTxowners.end(), global::ca::kInitAccountBase58Addr))
	{
		isInitAccount = true;
	}

	DBReader dbReader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return true;
    }

	return ((isStake || isInvest || isInitAccount) && (top < global::ca::kMinUnstakeHeight));
}

std::string GetContractAddr(const CTransaction & tx)
{
	global::ca::TxType txType = (global::ca::TxType)tx.txtype();
	if(txType == global::ca::TxType::kTxTypeDeployContract)
	{
		for (auto &vin : tx.utxo().vin())
		{
			const std::string deployerAddress = GetBase58Addr(vin.vinsign().pub());
			const std::string deployHash = tx.hash();
			return evm_utils::GenerateContractAddr(deployerAddress + deployHash);//Evmone::GenContractAddress(deployerAddress, deployHash);
		}
	}
	else if(txType == global::ca::TxType::kTxTypeCallContract)
	{
		nlohmann::json txInfo;
		try
		{
			nlohmann::json dataJson = nlohmann::json::parse(tx.data());
			txInfo = dataJson["TxInfo"].get<nlohmann::json>();

			auto deployerAddr = txInfo["DeployerAddr"].get<std::string>();
			auto deployHash = txInfo["DeployHash"].get<std::string>();
			return evm_utils::GenerateContractAddr(deployerAddr + deployHash);
		}
		catch(...)
        {
            ERRORLOG(RED "JSON failed to parse data field!" RESET);
            return "";
        }
	}
	
	return "";
}
