#include "ca_txhelper.h"

#include "google/protobuf/stubs/status.h"
#include "include/logging.h"
#include "db/db_api.h"
#include "sign.pb.h"
#include "transaction.pb.h"
#include "utils/MagicSingleton.h"
#include "utils/string_util.h"
#include "utils/time_util.h"
#include "utils/json.hpp"
#include "ca/ca_global.h"
#include "ca/ca_transaction.h"
#include "ca/ca_algorithm.h"
#include "utils/console.h"
#include "ca/ca_tranmonitor.h"
#include "ca_blockhelper.h"
#include "utils/AccountManager.h"
#include "utils/tmp_log.h"
#include <cmath>
#include <string>
#include "utils/DONbenchmark.h"
// #include "db/cache.h"
#include "../api/http_api.h"
#include "api/interface/sig.h"
#include "api/interface/tx.h"
#include <google/protobuf/util/json_util.h>
#include <ca/ca_DonHost.hpp>
#include <ca/ca_contract.h>
#include "api/interface/rpc_error.h"
std::vector<std::string> TxHelper::GetTxOwner(const CTransaction& tx)
{
	std::vector<std::string> address;
	for (int i = 0; i < tx.utxo().vin_size(); i++)
	{
		const CTxInput & txin = tx.utxo().vin(i);
		auto pub = txin.vinsign().pub();
		std::string addr = GetBase58Addr(pub);
		auto res = std::find(std::begin(address), std::end(address), addr);
		if (res == std::end(address))
		{
			address.push_back(addr);
		}
	}

	return address;
}

int TxHelper::GetUtxos(const std::string & address, std::vector<TxHelper::Utxo>& utxos)
{
	if (address.empty())
	{
		return -1;
	}

	utxos.clear();

	DBReader db_reader;
    std::vector<std::string> utxoHashs;
    auto status = db_reader.GetUtxoHashsByAddress(address, utxoHashs);
    if(DBStatus::DB_SUCCESS != status)
    {
        return -2;
    }
    
	// Remove duplication
    std::sort(utxoHashs.begin(), utxoHashs.end());
    utxoHashs.erase(unique(utxoHashs.begin(), utxoHashs.end()), utxoHashs.end());

    for (const auto& hash : utxoHashs)
    {
        std::string strTxRaw;
        if (db_reader.GetTransactionByHash(hash, strTxRaw) != DBStatus::DB_SUCCESS)
        {
            continue ;
        }
        CTransaction utxoTx;
        utxoTx.ParseFromString(strTxRaw);

		TxHelper::Utxo utxo;
		utxo.hash = utxoTx.hash();
		utxo.addr = address;
		utxo.value = 0;

		
        for (int i = 0; i < utxoTx.utxo().vout_size(); i++)
        {
			
            const CTxOutput & txout = utxoTx.utxo().vout(i);
            if (txout.addr() == address)
            {
				utxo.value += txout.value();
				utxo.n = i;
            }
        }
		utxos.push_back(utxo);
    }
	return 0;
}

uint64_t TxHelper::GetUtxoAmount(std::string tx_hash, std::string address)
{
	CTransaction tx;
	{
		//CBlockDataApi data_reader;
		DBReader db_reader;
		std::string strTxRaw;
		if (DBStatus::DB_SUCCESS != db_reader.GetTransactionByHash(tx_hash, strTxRaw))
		{
			return 0;
		}
		tx.ParseFromString(strTxRaw);
	}

	uint64_t amount = 0;
	for (int j = 0; j < tx.utxo().vout_size(); j++)
	{
		CTxOutput txout = tx.utxo().vout(j);
		if (txout.addr() == address)
		{
			amount += txout.value();
		}
	}
	return amount;
}

const uint32_t TxHelper::kMaxVinSize = 100;
int TxHelper::Check(const std::vector<std::string>& fromAddr,
					uint64_t height
					)
{
	// Fromaddr cannot be empty
	if(fromAddr.empty())
	{
		ERRORLOG("Fromaddr is empty!");		
		return -1;
	}

	// Fromaddr cannot have duplicate elements
	std::vector<std::string> tempfromAddr = fromAddr;
	std::sort(tempfromAddr.begin(),tempfromAddr.end());
	auto iter = std::unique(tempfromAddr.begin(),tempfromAddr.end());
	tempfromAddr.erase(iter,tempfromAddr.end());
	if(tempfromAddr.size() != fromAddr.size())
	{
		ERRORLOG("Fromaddr have duplicate elements!");		
		return -2;
	}

	//CBlockDataApi data_reader;
	DBReader db_reader;
	std::map<std::string, std::vector<std::string>> identities;

	// Fromaddr cannot be a non base58 address
	for(auto& from : fromAddr)
	{
		if (!CheckBase58Addr(from))
		{
			ERRORLOG("Fromaddr is a non base58 address!");
			return -3;
		}

		std::vector<std::string> utxo_hashs;
		if (DBStatus::DB_SUCCESS != db_reader.GetUtxoHashsByAddress(from, utxo_hashs))
		{
			ERRORLOG(RED "GetUtxoHashsByAddress failed!" RESET);
			return -4;
		}

		auto found = identities.find(from);
		if (found == identities.end())
		{
			identities[from] = std::vector<std::string>{};
		}

		identities[from] = utxo_hashs;
	}

	if (height == 0)
	{
		ERRORLOG("height is zero!");
		return -6;
	}

	return 0;
}


int TxHelper::FindUtxo(const std::vector<std::string>& fromAddr,
						const uint64_t need_utxo_amount,
						uint64_t& total,
						std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare>& setOutUtxos
						)
{
	// Count all utxo
	std::vector<TxHelper::Utxo> Utxos;

	DBReader db_reader;
	for (const auto& addr : fromAddr)
	{
		std::vector<std::string> vecUtxoHashs;
		if (DBStatus::DB_SUCCESS != db_reader.GetUtxoHashsByAddress(addr, vecUtxoHashs))
		{
			ERRORLOG("GetUtxoHashsByAddress failed!");
			return -1;
		}
		// duplicate removal
		std::sort(vecUtxoHashs.begin(), vecUtxoHashs.end());
		vecUtxoHashs.erase(std::unique(vecUtxoHashs.begin(), vecUtxoHashs.end()), vecUtxoHashs.end()); 

		for (const auto& hash : vecUtxoHashs)
		{
			bool flag = false;

			TxHelper::Utxo utxo;
			utxo.hash = hash;
			utxo.addr = addr;
			utxo.value = 0;
			utxo.n = 0; //At present, the n of utxo is all 0

			std::string balance ;
			if (db_reader.GetUtxoValueByUtxoHashs(hash, addr, balance) != 0)
			{
				ERRORLOG("GetTransactionByHash failed!");
				continue;
			}

			//If I get the pledged utxo, I will use it together

			std::string underline = "_";
			std::vector<std::string> utxo_values;

			if(balance.find(underline) != string::npos)
			{
				StringUtil::SplitString(balance, "_", utxo_values);
				
				for(int i = 0; i < utxo_values.size(); ++i)
				{
					utxo.value += std::stol(utxo_values[i]);
				}

			}
			else
			{
				utxo.value = std::stol(balance);
			}

			if(!flag)
			{
				Utxos.push_back(utxo);
			}
		}

	}

	//Sort from large to small
	std::sort(Utxos.begin(), Utxos.end(),[](const TxHelper::Utxo & u1, const TxHelper::Utxo & u2){
		return u1.value > u2.value;
	});

	total = 0;

	if(setOutUtxos.size() < need_utxo_amount)
	{
		// Fill other positions with non-0
		auto it = Utxos.begin();
		while (it != Utxos.end())
		{
			if (setOutUtxos.size() == need_utxo_amount)
			{
				break;
			}
			total += it->value;

			setOutUtxos.insert(*it);
			++it;
		}
	}
	return 0;
}

int TxHelper::CreateTxTransaction(const std::vector<std::string>& fromAddr,
									const std::map<std::string, int64_t> & toAddr,
									uint64_t height,
									CTransaction& outTx,
									TxHelper::vrfAgentType & type,
									Vrf & info)
{
	MagicSingleton<DONbenchmark>::GetInstance()->IncreaseTransactionInitiateAmount();
	// Check parameters
	int ret = Check(fromAddr, height);
	if (ret != 0)
	{
		ERRORLOG(RED "Check parameters failed! The error code is {}." RESET, ret);
		ret -= 100;
		return ret;
	}

	if(toAddr.empty())
	{
		ERRORLOG("to addr is empty");
		return -1;
	}	

	for (auto& addr : toAddr)
	{
		if (!CheckBase58Addr(addr.first))
		{
			ERRORLOG(RED "To address is not base58 address!" RESET);
			return -2;
		}

		for (auto& from : fromAddr)
		{
			if (addr.first == from)
			{
				ERRORLOG(RED "From address and to address is equal!" RESET);
				return -3;
			}
		}
		
		if (addr.second <= 0)
		{
			ERRORLOG(RED "Value is zero!" RESET);
			return -4;
		}
	}

	uint64_t amount = 0;//Transaction fee
	for (auto& i : toAddr)
	{
		amount += i.second;    
	}
	uint64_t expend = amount;

	// Find utxo
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	ret = FindUtxo(fromAddr, TxHelper::kMaxVinSize, total, setOutUtxos);
	if (ret != 0)
	{
		ERRORLOG(RED "FindUtxo failed! The error code is {}." RESET, ret);
		ret -= 200;
		return ret;
	}
	if (setOutUtxos.empty())
	{
		ERRORLOG(RED "Utxo is empty!" RESET);
		return -5;
	}

	outTx.Clear();

	CTxUtxo * txUtxo = outTx.mutable_utxo();
	
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		ERRORLOG(RED "Tx owner is empty!" RESET);
		return -6;
	}

	uint32_t n = 0;
	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		std::string serVinHash = getsha256hash(vin->SerializeAsString());
		std::string signature;
		std::string pub;
		if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0)
		{
			ERRORLOG("sign fail");
			return -7;
		}

		CSign * vinSign = vin->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
	}

	outTx.set_data("");
	outTx.set_type(global::ca::kTxSign);

	uint64_t gas = 0;
	std::map<std::string, int64_t> targetAddrs = toAddr;
	targetAddrs.insert(make_pair(*fromAddr.rbegin(), total - expend));
	targetAddrs.insert(make_pair(global::ca::kVirtualBurnGasAddr,gas));
	if(GenerateGas(outTx, targetAddrs.size(), gas) != 0)
	{
		ERRORLOG(" gas = 0 !");
		return -8;
	}

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	GetTxStartIdentity(fromAddr,height,current_time,type);
	DEBUGLOG("GetTxStartIdentity current_time = {} type = {}",current_time ,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
		ERRORLOG(" +++++++vrfAgentType_unknow +++++");
		return -300;
	}
	expend +=  gas;
	//Judge whether utxo is enough
	if(total < expend)
	{
		ERRORLOG("The total cost = {} is less than the cost = {}", total, expend);
		return -9;
	}
	//fill vout
	for(auto & to : toAddr)
	{
		CTxOutput * vout = txUtxo->add_vout();
		vout->set_addr(to.first);
		vout->set_value(to.second);
	}
	CTxOutput * voutFromAddr = txUtxo->add_vout();
	voutFromAddr->set_addr(*fromAddr.rbegin());
	voutFromAddr->set_value(total - expend);
	
	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);

	std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	for (auto & owner : setTxowners)
	{		
		if (TxHelper::AddMutilSign(owner, outTx) != 0)
		{
			ERRORLOG("addd mutil sign fail");
			return -10;
		}
	}
	
	outTx.set_time(current_time);
	outTx.set_version(0);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeTx);
	//Determine whether dropshipping is default or local dropshipping
	
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
	}
	else
	{
 
		//Select dropshippers
		std::string allUtxos;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		//Candidate packers are selected based on all utxohashes
		allUtxos += std::to_string(current_time);
		
		std::string id;
    	int ret = GetBlockPackager(id,allUtxos, info);
    	if(ret != 0){
        	return ret;
    	}
		outTx.set_identity(id);

	}

	DEBUGLOG("GetTxStartIdentity tx time = {}, package = {}", outTx.time(), outTx.identity());
	
	std::string txHash = getsha256hash(outTx.SerializeAsString());
	outTx.set_hash(txHash);

	INFOLOG( "Transaction Start Time = {}");
	return 0;
}

int TxHelper::CreateStakeTransaction(const std::string & fromAddr,
										uint64_t stake_amount,
										uint64_t height,
										TxHelper::PledgeType pledgeType,
										CTransaction & outTx,
										std::vector<TxHelper::Utxo> & outVin
										,TxHelper::vrfAgentType &type ,Vrf & info_)
{
	// Check parameters
	std::vector<std::string> vecfromAddr;
	vecfromAddr.push_back(fromAddr);
	int ret = Check(vecfromAddr, height);
	if(ret != 0)
	{
		ERRORLOG(RED "Check parameters failed! The error code is {}." RESET, ret);
		ret -= 100;
		return ret;
	}

	if (!CheckBase58Addr(fromAddr, Base58Ver::kBase58Ver_Normal)) 
	{
		ERRORLOG(RED "From address invlaid!" RESET);
		return -1;
	}

	if(stake_amount == 0 )
	{
		ERRORLOG(RED "Stake amount is zero !" RESET);
		return -2;		
	}
	
	if(stake_amount < global::ca::kMinStakeAmt)
	{
		ERRORLOG("The pledge amount must be greater than {} ",  global::ca::kMinStakeAmt);
		return -3;
	}

	std::string strStakeType;
	if (pledgeType == TxHelper::PledgeType::kPledgeType_Node)
	{
		strStakeType = global::ca::kStakeTypeNet;
	}
	else
	{
		ERRORLOG(RED "Unknown stake type!" RESET);
		return -4;
	}

	DBReader db_reader;
	std::vector<std::string> stake_utxos;
    auto dbret = db_reader.GetStakeAddressUtxo(fromAddr,stake_utxos);
	if(dbret == DBStatus::DB_SUCCESS)
	{
		std::cout << "There has been a pledge transaction before !" << std::endl;
		return -5;
	}

	uint64_t expend = stake_amount;

	// Find utxo
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize, total, setOutUtxos);
	if (ret != 0)
	{
		ERRORLOG(RED "FindUtxo failed! The error code is {}." RESET, ret);
		ret -= 200;
		return ret;
	}

	if (setOutUtxos.empty())
	{
		ERRORLOG(RED "Utxo is empty!" RESET);
		return -6;
	}

	outTx.Clear();

	CTxUtxo * txUtxo = outTx.mutable_utxo();
	
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	
	if (setTxowners.size() != 1)
	{
		ERRORLOG(RED "Tx owner is invalid!" RESET);
		return -7;
	}

	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 0;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		std::string serVinHash = getsha256hash(vin->SerializeAsString());
		std::string signature;
		std::string pub;
		if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0)
		{
			return -8;
		}

		CSign * vinSign = vin->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
	}

	nlohmann::json txInfo;
	txInfo["StakeType"] = strStakeType;
	txInfo["StakeAmount"] = stake_amount;

	nlohmann::json data;
	data["TxInfo"] = txInfo;
	outTx.set_data(data.dump());
	outTx.set_type(global::ca::kTxSign);	

	uint64_t gas = 0;
	// Calculate total expenditure
	std::map<std::string, int64_t> toAddr;
	toAddr.insert(std::make_pair(global::ca::kVirtualStakeAddr, stake_amount));
	toAddr.insert(std::make_pair(fromAddr, total - expend));
	toAddr.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas));
	
	if(GenerateGas(outTx, toAddr.size(), gas) != 0)
	{
		ERRORLOG(" gas = 0 !");
		return -10;
	}

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	GetTxStartIdentity(vecfromAddr,height,current_time,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
	//At this point, it indicates that the current node does not meet the pledge and investment requirements within 30 seconds beyond the height of 50. At this time, the pledge operation can be initiated
		type = TxHelper::vrfAgentType_defalut;
	}

	expend += gas;

	//Judge whether utxo is enough
	if(total < expend)
	{
		ERRORLOG("The total cost = {} is less than the cost = {}", total, expend);
		return -9;
	}

	CTxOutput * vout = txUtxo->add_vout(); //vout[0]
	vout->set_addr(global::ca::kVirtualStakeAddr);
	vout->set_value(stake_amount);

	CTxOutput * voutFromAddr = txUtxo->add_vout();//vout[1]
	voutFromAddr->set_addr(fromAddr);
	voutFromAddr->set_value(total - expend);

	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);

	std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	for (auto & owner : setTxowners)
	{	
		if (TxHelper::AddMutilSign(owner, outTx) != 0)
		{
			return -10;
		}
	}
	outTx.set_version(0);
	outTx.set_time(current_time);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeStake);

	//Determine whether dropshipping is default or local dropshipping
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
	}
	else
	{
		//Select dropshippers
		std::string allUtxos;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;
    	int ret= GetBlockPackager(id,allUtxos,info_);
    	if(ret!=0){
        	return ret;
    	}
		outTx.set_identity(id);
		
	}

	std::string txHash = getsha256hash(outTx.SerializeAsString());
	outTx.set_hash(txHash);
	return 0;
}

int TxHelper::CreatUnstakeTransaction(const std::string& fromAddr,
										const std::string& utxo_hash,
										uint64_t height,
										CTransaction& outTx,
										std::vector<TxHelper::Utxo> & outVin
										,TxHelper::vrfAgentType &type ,Vrf & info_)
{
	// Check parameters
	std::vector<std::string> vecfromAddr;
	vecfromAddr.push_back(fromAddr);
	int ret = Check(vecfromAddr, height);
	if(ret != 0)
	{
		ERRORLOG(RED "Check parameters failed! The error code is {}." RESET, ret);
		ret -= 100;
		return ret;
	}

	if (CheckBase58Addr(fromAddr, Base58Ver::kBase58Ver_MultiSign) == true)
	{
		ERRORLOG(RED "FromAddr is not normal base58 addr." RESET);
		return -1;
	}


	uint64_t stake_amount = 0;
	ret = IsQualifiedToUnstake(fromAddr, utxo_hash, stake_amount);
	if(ret != 0)
	{
		ERRORLOG(RED "FromAddr is not qualified to unstake! The error code is {}." RESET, ret);
		ret -= 200;
		return ret;
	}	

	// Find utxo
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	// The number of utxos to be searched here needs to be reduced by 1 \
	because a VIN to be redeem is from the pledged utxo, so just look for 99
	ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize - 1, total, setOutUtxos); 
	if (ret != 0)
	{
		ERRORLOG(RED "FindUtxo failed! The error code is {}." RESET, ret);
		ret -= 300;
		return ret;
	}

	if (setOutUtxos.empty())
	{
		ERRORLOG(RED "Utxo is empty!" RESET);
		return -2;
	}

	outTx.Clear();

	CTxUtxo * txUtxo = outTx.mutable_utxo();
	
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		ERRORLOG(RED "Tx owner is empty!" RESET);
		return -3;
	}

	{
		// Fill vin
		txUtxo->add_owner(fromAddr);
		CTxInput* txin = txUtxo->add_vin();
		txin->set_sequence(0);
		CTxPrevOutput* prevout = txin->add_prevout();
		prevout->set_hash(utxo_hash);
		prevout->set_n(1);

		std::string serVinHash = getsha256hash(txin->SerializeAsString());
		std::string signature;
		std::string pub;
		if (TxHelper::Sign(fromAddr, serVinHash, signature, pub) != 0)
		{
			return -4;
		}

		CSign * vinSign = txin->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
	}


	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 1;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		std::string serVinHash = getsha256hash(vin->SerializeAsString());
		std::string signature;
		std::string pub;
		if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0)
		{
			return -5;
		}

		CSign * vinSign = vin->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
	}

	nlohmann::json txInfo;
	txInfo["UnstakeUtxo"] = utxo_hash;

	nlohmann::json data;
	data["TxInfo"] = txInfo;
	outTx.set_data(data.dump());
	outTx.set_type(global::ca::kTxSign);	
	outTx.set_version(0);

	uint64_t gas = 0;
	//The filled quantity only participates in the calculation and does not affect others
	std::map<std::string, int64_t> toAddr;
	toAddr.insert(std::make_pair(global::ca::kVirtualStakeAddr, stake_amount));
	toAddr.insert(std::make_pair(fromAddr, total));
	toAddr.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas));
	
	
	if(GenerateGas(outTx, toAddr.size(), gas) != 0)
	{
		ERRORLOG(" gas = 0 !");
		return -6;
	}

	// Calculate total expenditure
	uint64_t gasTtoal =  gas;

	uint64_t cost = 0;//Packing fee

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	GetTxStartIdentity(vecfromAddr,height,current_time,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
	//At this point, it indicates that the current node has not met the pledge within 30 seconds beyond the height of 50 and the investment node can initiate the pledge cancellation operation
		type = TxHelper::vrfAgentType_defalut;
	}

	uint64_t expend = gas;

	//Judge whether there is enough money
	if(total < expend)
	{
		ERRORLOG("The total cost = {} is less than the cost = {}", total, expend);
		return -7;
	}

	// Fill vout
	CTxOutput* txoutToAddr = txUtxo->add_vout();
	txoutToAddr->set_addr(fromAddr);      	// Release the pledge to my account number
	txoutToAddr->set_value(stake_amount);

	txoutToAddr = txUtxo->add_vout();
	txoutToAddr->set_addr(fromAddr);  		// Give myself the rest
	txoutToAddr->set_value(total - expend);

	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);

	std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	for (auto & owner : setTxowners)
	{	
		if (TxHelper::AddMutilSign(owner, outTx) != 0)
		{
			return -8;
		}
	}

	outTx.set_time(current_time);
	outTx.set_version(0);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeUnstake);

	//Determine whether dropshipping is default or local dropshipping
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
	}
	else{
		//Select dropshippers
		std::string allUtxos = utxo_hash;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;
    	int ret= GetBlockPackager(id,allUtxos,info_);
    	if(ret!=0){
        	return ret;
    	}
		outTx.set_identity(id);
	}

	std::string txHash = getsha256hash(outTx.SerializeAsString());
	outTx.set_hash(txHash);

	return 0;
}

int TxHelper::CreateInvestTransaction(const std::string & fromAddr,
										const std::string& toAddr,
										uint64_t invest_amount,
										uint64_t height,
										TxHelper::InvestType investType,
										CTransaction & outTx,
										std::vector<TxHelper::Utxo> & outVin
										,TxHelper::vrfAgentType &type ,Vrf & info_)
{
	// Check parameters
	std::vector<std::string> vecfromAddr;
	vecfromAddr.push_back(fromAddr);
	int ret = Check(vecfromAddr, height);
	if(ret != 0)
	{
		ERRORLOG(RED "Check parameters failed! The error code is {}." RESET, ret);
		ret -= 100;
		return ret;
	}

	// Neither fromaddr nor toaddr can be a virtual account
	if (CheckBase58Addr(fromAddr, Base58Ver::kBase58Ver_MultiSign) == true)
	{
		ERRORLOG(RED "FromAddr is not normal base58 addr." RESET);
		return -1;
	}

	if (CheckBase58Addr(toAddr, Base58Ver::kBase58Ver_MultiSign) == true)
	{
		ERRORLOG(RED "To address is not base58 address!" RESET);
		return -2;
	}

	if(invest_amount < global::ca::kMinInvestAmt){
		ERRORLOG("Invest less = {} !", global::ca::kMinInvestAmt);
		return -3;
	}

	ret = CheckInvestQualification(fromAddr, toAddr, invest_amount);
	if(ret != 0)
	{
		ERRORLOG(RED "FromAddr is not qualified to invest! The error code is {}." RESET, ret);
		ret -= 200;
		return ret;
	}	
	std::string strinvestType;
	if (investType ==  TxHelper::InvestType::kInvestType_NetLicence)
	{
		strinvestType = global::ca::kInvestTypeNormal;
	}
	else
	{
		ERRORLOG(RED "Unknown invest type!" RESET);
		return -4;
	}
	
	// Find utxo
	uint64_t total = 0;
	uint64_t expend = invest_amount;

	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize, total, setOutUtxos);
	if (ret != 0)
	{
		ERRORLOG(RED "FindUtxo failed! The error code is {}." RESET, ret);
		ret -= 300;
		return ret;
	}
	if (setOutUtxos.empty())
	{
		ERRORLOG(RED "Utxo is empty!" RESET);
		return -5;
	}

	outTx.Clear();

	CTxUtxo * txUtxo = outTx.mutable_utxo();
	
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		ERRORLOG(RED "Tx owner is empty!" RESET);
		return -6;
	}

	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 0;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		std::string serVinHash = getsha256hash(vin->SerializeAsString());
		std::string signature;
		std::string pub;
		if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0)
		{
			return -7;
		}

		CSign * vinSign = vin->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
	}

	nlohmann::json txInfo;
	txInfo["InvestType"] = strinvestType;
	txInfo["BonusAddr"] = toAddr;
	txInfo["InvestAmount"] = invest_amount;

	nlohmann::json data;
	data["TxInfo"] = txInfo;
	outTx.set_data(data.dump());
	outTx.set_type(global::ca::kTxSign);

	uint64_t gas = 0;	
	// Calculate total expenditure
	std::map<std::string, int64_t> toAddrs;
	toAddrs.insert(std::make_pair(global::ca::kVirtualStakeAddr, invest_amount));
	toAddrs.insert(std::make_pair(fromAddr, total - expend));
	toAddrs.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas));
	
	
	if(GenerateGas(outTx, toAddrs.size(), gas) != 0)
	{
		std::cout << "GenerateGas gas = " << gas << std::endl;
		ERRORLOG(" gas = 0 !");
		return -8;
	}

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	GetTxStartIdentity(vecfromAddr,height,current_time,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
	//This indicates that the current node has not met the pledge within 30 seconds beyond the height of 50 and the investment node can initiate the investment operation at this time
		type = TxHelper::vrfAgentType_defalut;
	}


	expend += gas;

	if(total < expend)
	{
		ERRORLOG("The total cost = {} is less than the cost = {}", total, expend);
		return -9;
	}

	CTxOutput * vout = txUtxo->add_vout();
	vout->set_addr(global::ca::kVirtualInvestAddr);
	vout->set_value(invest_amount);

	CTxOutput * voutFromAddr = txUtxo->add_vout();//vout[1]
	voutFromAddr->set_addr(fromAddr);
	voutFromAddr->set_value(total - expend);

	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);

	std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	for (auto & owner : setTxowners)
	{	
		if (TxHelper::AddMutilSign(owner, outTx) != 0)
		{
			return -10;
		}
	}
	
	outTx.set_version(0);
	outTx.set_time(current_time);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeInvest);

	//Determine whether dropshipping is default or local dropshipping
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
	}
	else{
		
		//Select dropshippers
		std::string allUtxos;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;
    	int ret= GetBlockPackager(id,allUtxos,info_);
    	if(ret!=0){
        	return ret;
    	}
		outTx.set_identity(id);
	}

	std::string txHash = getsha256hash(outTx.SerializeAsString());
	outTx.set_hash(txHash);
	return 0;
}

int TxHelper::CreateDisinvestTransaction(const std::string& fromAddr,
										const std::string& toAddr,
										const std::string& utxo_hash,
										uint64_t height,
										CTransaction& outTx,
										std::vector<TxHelper::Utxo> & outVin
										,TxHelper::vrfAgentType &type ,Vrf & info_)
{
	// Check parameters
	std::vector<std::string> vecfromAddr;
	vecfromAddr.push_back(fromAddr);
	int ret = Check(vecfromAddr, height);
	if(ret != 0)
	{
		ERRORLOG(RED "Check parameters failed! The error code is {}." RESET, ret);
		ret -= 100;
		return ret;
	}

	if (CheckBase58Addr(fromAddr, Base58Ver::kBase58Ver_MultiSign) == true)
	{
		ERRORLOG(RED "FromAddr is not normal base58 addr." RESET);
		return -1;
	}

	if (CheckBase58Addr(toAddr, Base58Ver::kBase58Ver_MultiSign) == true)
	{
		ERRORLOG(RED "To address is not base58 address!" RESET);
		return -2;
	}

	uint64_t invested_amount = 0;
	if(IsQualifiedToDisinvest(fromAddr, toAddr, utxo_hash, invested_amount) != 0)
	{
		ERRORLOG(RED "FromAddr is not qualified to divest!." RESET);
		return -3;
	}
	// Find utxo
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	// The utxo quantity sought here needs to be reduced by 1
	ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize - 1, total, setOutUtxos); 
	if (ret != 0)
	{
		ERRORLOG(RED "FindUtxo failed! The error code is {}." RESET, ret);
		ret -= 300;
		return ret;
	}
	if (setOutUtxos.empty())
	{
		ERRORLOG(RED "Utxo is empty!" RESET);
		return -4;
	}

	outTx.Clear();
	CTxUtxo * txUtxo = outTx.mutable_utxo();
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		ERRORLOG(RED "Tx owner is empty!" RESET);
		return -5;
	}

	{
		// Fill vin
		txUtxo->add_owner(fromAddr);
		CTxInput* txin = txUtxo->add_vin();
		txin->set_sequence(0);
		CTxPrevOutput* prevout = txin->add_prevout();
		prevout->set_hash(utxo_hash);
		prevout->set_n(1);

		std::string serVinHash = getsha256hash(txin->SerializeAsString());
		std::string signature;
		std::string pub;
		ret = TxHelper::Sign(fromAddr, serVinHash, signature, pub);
		if (ret != 0)
		{
			ERRORLOG("invest utxo_hash Sign error:{}", ret);
			return -6;
		}

		CSign * vinSign = txin->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
	}

	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 1;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		std::string serVinHash = getsha256hash(vin->SerializeAsString());
		std::string signature;
		std::string pub;
		if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0)
		{
			return -7;
		}

		CSign * vinSign = vin->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
	}

	nlohmann::json txInfo;
	txInfo["BonusAddr"] = toAddr;
	txInfo["DisinvestUtxo"] = utxo_hash;

	nlohmann::json data;
	data["TxInfo"] = txInfo;
	outTx.set_data(data.dump());
	outTx.set_type(global::ca::kTxSign);	

	uint64_t gas = 0;
	// Calculate total expenditure
	std::map<std::string, int64_t> targetAddrs;
	targetAddrs.insert(std::make_pair(global::ca::kVirtualStakeAddr, invested_amount));
	targetAddrs.insert(std::make_pair(fromAddr, total ));
	targetAddrs.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas ));
	
	
	if(GenerateGas(outTx, targetAddrs.size(), gas) != 0)
	{
		ERRORLOG(" gas = 0 !");
		return -8;
	}

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	GetTxStartIdentity(vecfromAddr,height,current_time,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
		type = TxHelper::vrfAgentType_defalut;
	}

	uint64_t expend = gas;
	
	if(total < expend)
	{
		ERRORLOG("The total cost = {} is less than the cost = {}", total, expend);
		return -9;
	}	

	//Fill vout
	CTxOutput* txoutToAddr = txUtxo->add_vout();
	txoutToAddr->set_addr(fromAddr);      // Give my account the money I withdraw
	txoutToAddr->set_value(invested_amount);

	txoutToAddr = txUtxo->add_vout();
	txoutToAddr->set_addr(fromAddr);  	  // Give myself the rest
	txoutToAddr->set_value(total - expend);

	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);

	std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	for (auto & owner : setTxowners)
	{	
		if (TxHelper::AddMutilSign(owner, outTx) != 0)
		{
			return -10;
		}
	}

	outTx.set_time(current_time);
	outTx.set_version(0);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeDisinvest);

	//Determine whether dropshipping is default or local dropshipping
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
	}
	else{
		//Select dropshippers
		std::string allUtxos = utxo_hash;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;
    	int ret= GetBlockPackager(id,allUtxos,info_);
    	if(ret!=0){
        	return ret;
    	}
		outTx.set_identity(id);
	}

	std::string txHash = getsha256hash(outTx.SerializeAsString());
	outTx.set_hash(txHash);

	return 0;
}

int TxHelper::CreateBonusTransaction(const std::string& Addr,
										uint64_t height,
										CTransaction& outTx,
										std::vector<TxHelper::Utxo> & outVin,
										TxHelper::vrfAgentType &type,
										Vrf & info_)
{
	std::vector<std::string> vecfromAddr;
	vecfromAddr.push_back(Addr);
	int ret = Check(vecfromAddr, height);
	if(ret != 0)
	{
		ERRORLOG("Check parameters failed");
		ret -= 100;
		return ret;
	}

	if (CheckBase58Addr(Addr, Base58Ver::kBase58Ver_MultiSign) == true)
	{
		ERRORLOG(RED "Default is not normal base58 addr." RESET);
		return -1;
	}

	//CBlockDataApi data_reader;
	DBReader db_reader; 
	std::vector<std::string> utxos;
	uint64_t cur_time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(cur_time);
	uint64_t zero_time = MagicSingleton<TimeUtil>::GetInstance()->getMorningTime(cur_time)*1000000;//Convert to subtle
    auto status = db_reader.GetBonusUtxoByPeriod(Period, utxos);
	if (status != DBStatus::DB_SUCCESS && status != DBStatus::DB_NOT_FOUND)
	{
		ERRORLOG("TxHelper CreatUnstakeTransaction: Get all pledge address failed");
		return -2;
	}
	
	if(cur_time < ( zero_time + 60 * 60 * 1000000ul ))
	{
		std::cout << RED << "Claim after 1 a.m!" << RESET << std::endl;
		return -3;
	}
	//Application completed
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
			if(Addr == ClaimAddr)
			{
				std::cout << RED << "Application completed!" << RESET << std::endl;
				return -6;
			}
		}
	}
	// The total number of investors must be more than 10 before they can apply for it
	ret = VerifyBonusAddr(Addr);
	if(ret < 0)
	{
		return -7;
	}

	std::map<std::string, uint64_t> CompanyDividend;
    ret=ca_algorithm::CalcBonusValue(cur_time, Addr, CompanyDividend);
	if(ret < 0)
	{
		ERRORLOG("Failed to obtain the amount claimed by the investor ret:({})",ret);
		ret-=300;
		return ret;
	}

	uint64_t expend = 0;
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize - 1, total, setOutUtxos);
	if (ret != 0)
	{
		ERRORLOG("TxHelper CreatUnstakeTransaction: FindUtxo failed");
		ret -= 200;
		return ret;
	}
	if (setOutUtxos.empty())
	{
		ERRORLOG("TxHelper CreatUnstakeTransaction: utxo is zero");
		return -8;
	}

	outTx.Clear();

	CTxUtxo * txUtxo = outTx.mutable_utxo();


	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		ERRORLOG(RED "Tx owner is empty!" RESET);
		return -9;
	}

	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 0;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		std::string serVinHash = getsha256hash(vin->SerializeAsString());
		std::string signature;
		std::string pub;
		if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0)
		{
			return -10;
		}

		CSign * vinSign = vin->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
	}

	//Fill data

	uint64_t tempCosto=0;
	uint64_t tempNodeDividend=0;
	uint64_t tempTotalClaim=0;
	for(auto Company : CompanyDividend)
	{
		tempCosto=Company.second * global::ca::kDividendsRate + 0.5;
		tempNodeDividend+=tempCosto;
		std::string addr = Company.first;
		uint64_t award = Company.second - tempCosto;
		tempTotalClaim+=award;		
	}
	tempTotalClaim += tempNodeDividend;

	nlohmann::json txInfo;
	txInfo["BonusAmount"] = tempTotalClaim;
	txInfo["BonusAddrList"] = CompanyDividend.size() + 2;
	nlohmann::json data;
	data["TxInfo"] = txInfo;
	outTx.set_data(data.dump());
	outTx.set_type(global::ca::kTxSign);

	//calculation gas
	uint64_t gas = 0;
	std::map<std::string, int64_t> toAddrs;
	for(const auto & item : CompanyDividend)
	{
		toAddrs.insert(make_pair(item.first, item.second));
	}
	toAddrs.insert(std::make_pair(global::ca::kVirtualStakeAddr, total - expend));
	toAddrs.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas));

	if(GenerateGas(outTx, toAddrs.size(), gas) != 0)
	{
		ERRORLOG(" gas = 0 !");
		return -11;
	}

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	GetTxStartIdentity(vecfromAddr,height,current_time,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
		ERRORLOG(" +++++++vrfAgentType_unknow +++++");
		return -300;
	}

	expend = gas;

	if(total < expend)
	{
		ERRORLOG("The total cost = {} is less than the cost = {}", total, expend);
		return -12;
	}

	outTx.set_time(current_time);
	outTx.set_version(0);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeBonus);

	uint64_t costo=0;
	uint64_t NodeDividend=0;
	uint64_t TotalClaim=0;
	std::cout << YELLOW << "Claim Addr : Claim Amount" << RESET << std::endl;
	for(auto Company : CompanyDividend)
	{
		costo=Company.second * global::ca::kDividendsRate + 0.5;
		NodeDividend+=costo;
		std::string addr = Company.first;
		uint64_t award = Company.second - costo;
		TotalClaim+=award;
		CTxOutput* txoutToAddr = txUtxo->add_vout();	
		txoutToAddr->set_addr(addr); 
		txoutToAddr->set_value(award);		
		std::cout << Company.first << ":" << Company.second << std::endl;		
	}

	CTxOutput* txoutToAddr = txUtxo->add_vout();
	txoutToAddr->set_addr(Addr);
	txoutToAddr->set_value(total - expend + NodeDividend);

	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);


	std::cout << Addr << ":" << NodeDividend << std::endl;
	TotalClaim+=NodeDividend;
	if(TotalClaim == 0)
	{
		ERRORLOG("The claim amount is 0");
		return -13;
	}

	uint64_t MiningBalance=0;
	{
		std::lock_guard<std::mutex> lock(global::ca::kBonusMutex);
		if (DBStatus::DB_SUCCESS != db_reader.GetTotalAwardAmount(MiningBalance))
		{
			return -14;
		}
	}
	if(MiningBalance-TotalClaim < 0) return -15;

	std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	for (auto & owner : setTxowners)
	{	
		if (TxHelper::AddMutilSign(owner, outTx) != 0)
		{
			return -15;
		}
	}

	//Determine whether dropshipping is default or local dropshipping
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
	}
	else{
		
		//Select dropshippers
		std::string allUtxos;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;
    	int ret= GetBlockPackager(id,allUtxos,info_);
    	if(ret!=0){
        	return ret;
    	}
		outTx.set_identity(id);
	}

	std::string txHash = getsha256hash(outTx.SerializeAsString());
	outTx.set_hash(txHash);
	return 0;
}

std::string TxHelper::ReplaceCreateBonusTransaction_test(const std::string& Addr,void * ack)
{
	tx_ack * ack_t=(tx_ack *)ack;
	TxHelper::vrfAgentType type;
	CTransaction outTx;
	Vrf info_;

	DBReader db_reader;
    uint64_t height = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(height))
    {
        return DSTR"-1 db get top failed!!"; 
    }
	height=height+1;

	std::vector<std::string> vecfromAddr;
	vecfromAddr.push_back(Addr);
	int ret = Check(vecfromAddr, height);
	if(ret != 0)
	{
		return DSTR"Check parameters failed"+std::to_string(ret);
		
	}

	if (CheckBase58Addr(Addr, Base58Ver::kBase58Ver_MultiSign) == true)
	{
		return DSTR"Default is not normal base58 addr." ;
		
	}

	//CBlockDataApi data_reader;
	std::vector<std::string> utxos;
	uint64_t cur_time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(cur_time);
	uint64_t zero_time = MagicSingleton<TimeUtil>::GetInstance()->getMorningTime(cur_time)*1000000;//Convert to subtle
    auto status = db_reader.GetBonusUtxoByPeriod(Period, utxos);
	if (status != DBStatus::DB_SUCCESS && status != DBStatus::DB_NOT_FOUND)
	{
		return DSTR"TxHelper CreatUnstakeTransaction: Get all pledge address failed";
	}
	
	if(cur_time < ( zero_time + 60 * 60 * 1000000ul ))
	{
		return DSTR"Claim after 1 a.m!";
	}
	//Application completed
	if(status == DBStatus::DB_SUCCESS)
	{
		std::string strTx;
		CTransaction Claimtx;
		
		for(auto utxo = utxos.rbegin(); utxo != utxos.rend(); utxo++)
		{
			if (db_reader.GetTransactionByHash(*utxo, strTx) != DBStatus::DB_SUCCESS)
			{
				MagicSingleton<BlockHelper>::GetInstance()->PushMissUTXO(*utxo);
				return DSTR std::to_string(-4);
			}	
			if(!Claimtx.ParseFromString(strTx))
			{
				return DSTR std::to_string(-5);
			}
			std::string ClaimAddr = GetBase58Addr(Claimtx.utxo().vin(0).vinsign().pub());
			if(Addr == ClaimAddr)
			{
				std::cout << RED << "Application completed!" << RESET << std::endl;
				return DSTR std::to_string(-6);
			}
		}
	}
	// The total number of investors must be more than 10 before they can apply for it
	ret = VerifyBonusAddr(Addr);
	if(ret < 0)
	{
		//return -7;
		return DSTR std::to_string(-7);
	}

	std::map<std::string, uint64_t> CompanyDividend;
    ret=ca_algorithm::CalcBonusValue(cur_time, Addr, CompanyDividend);
	if(ret < 0)
	{
		return DSTR"Failed to obtain the amount claimed by the investor ret:"+std::to_string(ret);
		//ret-=300;
		//return ret;
	}

	uint64_t expend = 0;
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize - 1, total, setOutUtxos);
	if (ret != 0)
	{
		return DSTR"TxHelper CreatUnstakeTransaction: FindUtxo failed";
		//ret -= 200;
		//return ret;
	}
	if (setOutUtxos.empty())
	{
		return DSTR"TxHelper CreatUnstakeTransaction: utxo is zero";
		//return -8;
	}

	outTx.Clear();

	CTxUtxo * txUtxo = outTx.mutable_utxo();


	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		return DSTR"Tx owner is empty!"+std::to_string(-9);
		//return -9;
	}

	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 0;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		
	}

	//Fill data

	uint64_t tempCosto=0;
	uint64_t tempNodeDividend=0;
	uint64_t tempTotalClaim=0;
	for(auto Company : CompanyDividend)
	{
		tempCosto=Company.second * global::ca::kDividendsRate + 0.5;
		tempNodeDividend+=tempCosto;
		std::string addr = Company.first;
		uint64_t award = Company.second - tempCosto;
		tempTotalClaim+=award;		
	}
	tempTotalClaim += tempNodeDividend;

	nlohmann::json txInfo;
	txInfo["BonusAmount"] = tempTotalClaim;
	txInfo["BonusAddrList"] = CompanyDividend.size() + 2;
	nlohmann::json data;
	data["TxInfo"] = txInfo;
	outTx.set_data(data.dump());
	outTx.set_type(global::ca::kTxSign);

	//calculation gas
	uint64_t gas = 0;
	std::map<std::string, int64_t> toAddrs;
	for(const auto & item : CompanyDividend)
	{
		toAddrs.insert(make_pair(item.first, item.second));
	}
	toAddrs.insert(std::make_pair(global::ca::kVirtualStakeAddr, total - expend));
	toAddrs.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas));

	if(GenerateGas(outTx, toAddrs.size(), gas) != 0)
	{
		return DSTR" gas = 0 !";
		//return -11;
	}

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	GetTxStartIdentity(vecfromAddr,height,current_time,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
		return DSTR" +++++++vrfAgentType_unknow +++++";
		//return -300;
	}

	expend = gas;
	ack_t->gas=std::to_string(gas);
	ack_t->time=std::to_string(current_time);

	if(total < expend)
	{
		//return DSTR"The total cost = {} is less than the cost = {}";
        return "-72013";
		//return -12;
	}

	outTx.set_time(current_time);
	outTx.set_version(0);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeBonus);

	uint64_t costo=0;
	uint64_t NodeDividend=0;
	uint64_t TotalClaim=0;
	std::cout << YELLOW << "Claim Addr : Claim Amount" << RESET << std::endl;
	for(auto Company : CompanyDividend)
	{
		costo=Company.second * global::ca::kDividendsRate + 0.5;
		NodeDividend+=costo;
		std::string addr = Company.first;
		uint64_t award = Company.second - costo;
		TotalClaim+=award;
		CTxOutput* txoutToAddr = txUtxo->add_vout();	
		txoutToAddr->set_addr(addr); 
		txoutToAddr->set_value(award);		
		std::cout << Company.first << ":" << Company.second << std::endl;		
	}

	CTxOutput* txoutToAddr = txUtxo->add_vout();
	txoutToAddr->set_addr(Addr);
	txoutToAddr->set_value(total - expend + NodeDividend);

	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);


	std::cout << Addr << ":" << NodeDividend << std::endl;
	TotalClaim+=NodeDividend;
	if(TotalClaim == 0)
	{
		return DSTR"The claim amount is 0";
		//return -13;
	}

	uint64_t MiningBalance=0;
	{
		std::lock_guard<std::mutex> lock(global::ca::kBonusMutex);
		if (DBStatus::DB_SUCCESS != db_reader.GetTotalAwardAmount(MiningBalance))
		{
			return DSTR "-14";
		}
	}
	if(MiningBalance-TotalClaim < 0) {
		return DSTR "-15";
	}
	

	

	//Determine whether dropshipping is default or local dropshipping
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		std::string id_t=GetEligibleNodes();
		outTx.set_identity(id_t);
	}
	else{
		
		//Select dropshippers
		std::string allUtxos;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;
    	int ret= GetBlockPackager(id,allUtxos,info_);
    	if(ret!=0){
        	//return ret;
    	}
		outTx.set_identity(id);
	}

	std::string txJsonString;
	std::string vrfJsonString;
	google::protobuf::util::Status Gstatus =google::protobuf::util::MessageToJsonString(outTx,&txJsonString);
	Gstatus=google::protobuf::util::MessageToJsonString(info_,&vrfJsonString);

	ack_t->txJson=txJsonString;
	ack_t->vrfJson=vrfJsonString;
	ack_t->ErrorCode="0";
	ack_t->height=std::to_string(height-1);
	ack_t->txType=std::to_string((int)type);
	return "0";
}











int TxHelper::CreateEvmDeployContractTransaction(const std::string &fromAddr, const std::string &OwnerEvmAddr,
                                                 const std::string &code, uint64_t height,
                                                 CTransaction &outTx,
                                                 std::vector<std::string> &dirtyContract,
                                                 TxHelper::vrfAgentType &type, NewVrf &information)
{
    std::string strOutput;
    DonHost host;
    int64_t gasCost = 0;
    int ret = Evmone::DeployContract(fromAddr, OwnerEvmAddr, code, strOutput, host, gasCost);
    if (ret != 0)
    {
		SetRpcError("-72019",Sutil::Format("Evmone failed to call contract! %s  %s",ret, strOutput));
        ERRORLOG("Evmone failed to deploy contract! ret : {}", ret);
        return -1;
    }

    nlohmann::json jTxInfo;
    jTxInfo["Version"] = 0;
    jTxInfo["OwnerEvmAddr"] = OwnerEvmAddr;
    jTxInfo["VmType"] = global::ca::VmType::EVM;
    jTxInfo["Code"] = code;
    jTxInfo["Output"] = strOutput;

    Evmone::GetCalledContract(host, dirtyContract);
    ret = Evmone::FillDeployOutTx(fromAddr,global::ca::kVirtualDeployContractAddr,host.coin_transferrings, jTxInfo, gasCost, height, outTx, type, information);
	if (ret != 0)
    {
		ERRORLOG("FillDeployOutTx fail ret : {}", ret);
		return -2;
	}
    return 0;
}


int TxHelper::CreateEvmCallContractTransaction(const std::string &fromAddr, const std::string &toAddr,
                                               const std::string &txHash,const std::string &strInput,
											   const std::string &OwnerEvmAddr,uint64_t height,
                                               CTransaction &outTx, TxHelper::vrfAgentType &type, NewVrf &info_,
											   const uint64_t contractTip,const uint64_t contractTransfer,
                                               std::vector<std::string> &dirtyContract)
{
    std::string strOutput;
    DonHost host;
    int64_t gasCost = 0;
	nlohmann::json jTxInfo;
    int ret = Evmone::CallContract(fromAddr, OwnerEvmAddr, toAddr, txHash, strInput, strOutput, host, gasCost,contractTransfer);
    if (ret != 0)
    {
		SetRpcError("-72019",Sutil::Format("Evmone failed to call contract! %s  %s",ret, strOutput));
        ERRORLOG("Evmone failed to call contract!");
        ret -= 10;
        return ret;
    }

    
    jTxInfo["Version"] = 0;
    jTxInfo["OwnerEvmAddr"] = OwnerEvmAddr;
    jTxInfo["VmType"] = global::ca::VmType::EVM;
    jTxInfo["DeployerAddr"] = toAddr;
    jTxInfo["DeployHash"] = txHash;
    jTxInfo["Input"] = strInput;
    jTxInfo["Output"] = strOutput;
	jTxInfo["contractTip"] = contractTip;
    jTxInfo["contractTransfer"] = contractTransfer;

    Evmone::GetCalledContract(host, dirtyContract);
    ret = Evmone::FillCallOutTx(fromAddr, toAddr, host.coin_transferrings, jTxInfo, height, gasCost, outTx, type,
                                info_,contractTip);
    if (ret != 0)
    {
        ERRORLOG("FillCallOutTx fail ret: {}", ret);
		return -2;
    }
   
	return 0;
}

int TxHelper::AddMutilSign(const std::string & addr, CTransaction &tx)
{
	if (!CheckBase58Addr(addr))
	{
		return -1;
	}

	CTxUtxo * txUtxo = tx.mutable_utxo();
	CTxUtxo copyTxUtxo = *txUtxo;
	copyTxUtxo.clear_multisign();

	std::string serTxUtxo = getsha256hash(copyTxUtxo.SerializeAsString());
	std::string signature;
	std::string pub;
	if(TxHelper::Sign(addr, serTxUtxo, signature, pub) != 0)
	{
		return -2;
	}

	CSign * multiSign = txUtxo->add_multisign();
	multiSign->set_sign(signature);
	multiSign->set_pub(pub);

	return 0;
}

int TxHelper::AddVerifySign(const std::string & addr, CTransaction &tx)
{
	if (!CheckBase58Addr(addr))
	{
		ERRORLOG("illegal address {}", addr);
		return -1;
	}

	CTransaction copyTx = tx;

	copyTx.clear_hash();
	copyTx.clear_verifysign();

	std::string serTx = copyTx.SerializeAsString();
	if(serTx.empty())
	{
		ERRORLOG("fail to serialize trasaction");
		return -2;
	}

	std::string message = getsha256hash(serTx);

	std::string signature;
	std::string pub;
	if (TxHelper::Sign(addr, message, signature, pub) != 0)
	{
		ERRORLOG("fail to sign message");
		return -3;
	}

	DEBUGLOG("-------------------add verify sign addr = {} --------------------------",addr);

	CSign * verifySign = tx.add_verifysign();
	verifySign->set_sign(signature);
	verifySign->set_pub(pub);
	return 0;
}


int TxHelper::CreateDeclareTransaction(const std::string & fromaddr, 
                                        const std::string & toAddr, 
                                        uint64_t amount, 
                                        const std::string & multiSignPub,
                                        const std::vector<std::string> &signAddrList,
                                        uint64_t signThreshold,
                                        uint64_t height,
                                        CTransaction& outTx,
										TxHelper::vrfAgentType &type,
										Vrf & info_)
{
	// Check parameters	
	std::vector<std::string> VecfromAddr;
	VecfromAddr.emplace_back(fromaddr);
	int ret = Check(VecfromAddr, height);
	if (ret != 0)
	{
		ERRORLOG(RED "Check parameters failed! The error code is {}." RESET, ret);
		ret -= 100;
		return ret;
	}

	if (fromaddr.empty())
	{
		return -1;
	}
	if (!CheckBase58Addr(fromaddr, Base58Ver::kBase58Ver_Normal))
	{
		return -2;
	}

	if (toAddr.empty())
	{
		return -3;
	}

	if (! CheckBase58Addr(toAddr, Base58Ver::kBase58Ver_MultiSign))
	{
		return -4;
	}

	if (amount <= 0)
	{
		return -5;
	}

	if (multiSignPub.empty())
	{
		return -6;
	}

	if (toAddr != GetBase58Addr(multiSignPub, Base58Ver::kBase58Ver_MultiSign))
	{
		return -7;
	}

	if (signAddrList.size() < 2 || signAddrList.size() > 100)
	{
		return -8;
	}

	if (signThreshold > signAddrList.size())
	{
		return -9;
	}

	for (auto & addr : signAddrList)
	{
		if (! CheckBase58Addr(addr, Base58Ver::kBase58Ver_Normal))
		{
			return -10;
		}
	}

	DBReader db_reader;
	std::vector<std::string> multiSignAddrs;
	auto db_status = db_reader.GetMutliSignAddress(multiSignAddrs);
	if (DBStatus::DB_SUCCESS != db_status)
	{
		if (DBStatus::DB_NOT_FOUND != db_status)
		{
			return -11;
		}
	}

	if (std::find(multiSignAddrs.begin(), multiSignAddrs.end(), toAddr) != multiSignAddrs.end())
	{
		return -12;
	}
	
	uint64_t expend = amount;

	// Find utxo
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	ret = FindUtxo(VecfromAddr, TxHelper::kMaxVinSize, total, setOutUtxos);//
	if (ret != 0)
	{
		ERRORLOG(RED "FindUtxo failed! The error code is {}." RESET, ret);
		ret -= 200;
		return ret;
	}
	if (setOutUtxos.empty())
	{
		ERRORLOG(RED "Utxo is empty!" RESET);
		return -13;
	}

	outTx.Clear();

	CTxUtxo * txUtxo = outTx.mutable_utxo();
	
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		ERRORLOG(RED "Tx owner is empty!" RESET);
		return -14;
	}

	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 0;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		std::string serVinHash = getsha256hash(vin->SerializeAsString());
		std::string signature;
		std::string pub;
		if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0)
		{
			return -15;
		}
		
		CSign * vinSign = vin->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
	}

	nlohmann::json txInfo;
	txInfo["SignThreshold"] = signThreshold; // SignThreshold
	txInfo["MultiSignPub"] = Base64Encode(multiSignPub); // MultiSignPub MultiSignAddr
	txInfo["SignAddrList"] = signAddrList; // SignAddr

	nlohmann::json data;
	data["TxInfo"] = txInfo;
	outTx.set_data(data.dump());
	outTx.set_type(global::ca::kTxSign);

	uint64_t gas = 0;
	std::map<std::string, int64_t> targetAddrs ;
	targetAddrs.insert(make_pair(toAddr, amount));
	targetAddrs.insert(make_pair(*VecfromAddr.rbegin(), total - expend));
	targetAddrs.insert(make_pair(global::ca::kVirtualBurnGasAddr, gas));
	if(GenerateGas(outTx, targetAddrs.size(), gas) != 0)
	{
		ERRORLOG(" gas = 0 !");
		return -16;
	}

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();

    GetTxStartIdentity(VecfromAddr, height, current_time, type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
		ERRORLOG(" +++++++vrfAgentType_unknow +++++");
		return -300;
	}

	expend += gas;

	if(total < expend)
	{
		ERRORLOG("The total cost = {} is less than the cost = {}", total, expend);
		return -17;
	}

	{
		CTxOutput * vout = txUtxo->add_vout();
		vout->set_addr(toAddr);
		vout->set_value(amount);
	}
	CTxOutput * voutFromAddr = txUtxo->add_vout();
	voutFromAddr->set_addr(*VecfromAddr.rbegin());
	voutFromAddr->set_value(total - expend);

	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);


	std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	for (auto & owner : setTxowners)
	{
		if (TxHelper::AddMutilSign(owner, outTx) != 0)
		{
			return -18;
		}
	}

	outTx.set_time(current_time);

	//Determine whether dropshipping is default or local dropshipping
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
	}
	else{
		//Select dropshippers
		std::string allUtxos;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;
    	int ret= GetBlockPackager(id,allUtxos,info_);
    	if(ret!=0){
        	return ret;
    	}
		outTx.set_identity(id);
	}

	outTx.set_version(0);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeDeclaration);
	std::string txHash = getsha256hash(outTx.SerializeAsString());
	outTx.set_hash(txHash);

	return 0;
}

int TxHelper::Sign(const std::string & addr, 
					const std::string & message, 
                    std::string & signature, 
					std::string & pub)
{
	if (addr.empty() || message.empty())
	{
		return -1;
	}

	Account account;
	if(MagicSingleton<AccountManager>::GetInstance()->FindAccount(addr ,account) != 0)
	{
		ERRORLOG("account {} doesn't exist", addr);
		return -2;
	}

	if(!account.Sign(message,signature))
	{
		return -3;
	}

	pub = account.GetPubStr();
	return 0;
}

bool TxHelper::IsNeedAgent(const std::vector<std::string> & fromAddr)
{
	bool isNeedAgent = true;
	for(auto& owner : fromAddr)
	{
		// If the transaction owner cannot be found in all accounts of the node, it indicates that it is issued on behalf
		if (owner == MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr())
		{
			isNeedAgent = false;
		}
	}

	return isNeedAgent;

}

bool TxHelper::IsNeedAgent(const CTransaction &tx)
{
	if(std::find(tx.utxo().owner().begin(), tx.utxo().owner().end(),tx.identity()) == tx.utxo().owner().end())
	{
		return true;
	}
	
	return false;
}

bool TxHelper::checkTxTimeOut(const uint64_t & txTime, const uint64_t & timeout,const uint64_t & pre_height)
{
	if(txTime <= 0)
	{
		ERRORLOG("tx time = {} ", txTime);
		return false;
	}
    DBReader db_reader;

    std::vector<std::string> block_hashes;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashesByBlockHeight(pre_height, pre_height, block_hashes))
    {
        ERRORLOG("can't GetBlockHashesByBlockHeight");
        return false;
    }

    std::vector<CBlock> blocks;

    for (auto &hash : block_hashes)
    {
        std::string blockStr;
        if(DBStatus::DB_SUCCESS != db_reader.GetBlockByBlockHash(hash, blockStr))
		{
			ERRORLOG("GetBlockByBlockHash error block hash = {} ", hash);
			return false;
		}

        CBlock block;
        if(!block.ParseFromString(blockStr))
		{
			ERRORLOG("block parse from string fail = {} ", blockStr);
			return false;
		}
        blocks.push_back(block);
    }

	std::sort(blocks.begin(), blocks.end(), [](const CBlock& x, const CBlock& y){ return x.time() < y.time(); });
	CBlock result_block = blocks[blocks.size() - 1];

	if(result_block.time() <= 0)
	{
		ERRORLOG("block time = {}  ", result_block.time());
		return false;
	}

	uint64_t result_time = abs(int64_t(txTime - result_block.time()));
    if (result_time > timeout * 1000000)
    {
		DEBUGLOG("vrf Issuing transaction More than 30 seconds time = {}, tx time= {}, top = {} ", result_time, txTime, pre_height);
        return true;
    }
    return false;
}

TxHelper::vrfAgentType TxHelper::GetVrfAgentType(const CTransaction &tx, uint64_t &pre_height)
{
	global::ca::TxType txType = (global::ca::TxType)tx.txtype();
	if (global::ca::TxType::kTxTypeDeployContract == txType || global::ca::TxType::kTxTypeCallContract == txType)
	{
		return TxHelper::vrfAgentType::vrfAgentType_vrf;
	}
	std::vector<std::string> owners(tx.utxo().owner().begin(), tx.utxo().owner().end());

	//If it is within 30s and you do not find it, it is VRF dropshipping
	if(!TxHelper::checkTxTimeOut(tx.time(),global::ca::TxTimeoutMin, pre_height))//The block is not larger than 30s
	{	
		if(std::find(owners.begin(), owners.end(), tx.identity()) == owners.end())
		{
			return TxHelper::vrfAgentType::vrfAgentType_vrf;
		}
		return TxHelper::vrfAgentType::vrfAgentType_defalut;
	}
	else
	{
		if(std::find(owners.begin(), owners.end(), tx.identity()) == owners.end())
		{
			return TxHelper::vrfAgentType::vrfAgentType_local;
		}
		else
		{
			return TxHelper::vrfAgentType::vrfAgentType_defalut;
		}
	}
	DEBUGLOG("GetVrfAgentType tx vrf agent type is vrfAgentType_defalut");
	return TxHelper::vrfAgentType::vrfAgentType_unknow;
}

void TxHelper::GetContractTxStartIdentity(const uint64_t &height, const uint64_t &currentTime, TxHelper::vrfAgentType &type)
{
	uint64_t preHeight = height -1;
	//The transaction time is verified to distinguish the agent type of the transaction
	if(checkTxTimeOut(currentTime, global::ca::TxTimeoutMin, preHeight) == true)
	{
		type = vrfAgentType_defalut;
		return;
	}
	else
	{
		type = vrfAgentType_vrf;
		return;
	}
}

void TxHelper::GetTxStartIdentity(const std::vector<std::string> &fromaddr,const uint64_t &height,const uint64_t &current_time,TxHelper::vrfAgentType &type)
{
	uint64_t pre_height = height -1;
	
	if(checkTxTimeOut(current_time,global::ca::TxTimeoutMin, pre_height) == true)
	{
		//GetInitiatorType(fromaddr,type);
        type=vrfAgentType_defalut;
		return;
	}
	else
	{
		type = vrfAgentType_vrf;
		return;
	}
	type = vrfAgentType_unknow;
}

void TxHelper::GetInitiatorType(const std::vector<std::string> &fromaddr, TxHelper::vrfAgentType &type)
{
	for(auto &addr : fromaddr)
	{
		if(CheckVerifyNodeQualification(addr) == 0)
		{
			type = vrfAgentType_defalut;
		}
		else
		{
			std::vector<std::string> base58_list;
			MagicSingleton<AccountManager>::GetInstance()->GetAccountList(base58_list);
			for(const auto &item : base58_list)
			{
				if(CheckVerifyNodeQualification(item) != 0)
				{
					continue;
				}
				type = vrfAgentType_local;
				return;
			}
			type = vrfAgentType_unknow;
			return;
		}
	}
}

int testMsag(CTransaction & outTx,int height,Vrf &info,TxHelper::vrfAgentType type);

std::string testSig(CTransaction &tx){
	auto txUtxo=tx.mutable_utxo();
	int index=0;
	auto vin=txUtxo->mutable_vin();
	int ret=0;
	for(auto &owner:txUtxo->owner()){
		auto vin_t=vin->Mutable(index);
		std::string serVinHash = getsha256hash(vin_t->SerializeAsString());
		std::string signature;
		std::string pub;
		ret=TxHelper::Sign(owner, serVinHash, signature, pub);
		if(ret!=0){
			debugL("sign fail " << std::to_string(ret));
			return DSTR "sign fail" + std::to_string(ret);
		}
		

		CSign * vinSign = vin_t->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
		index++;
	}

	for(auto & owner:txUtxo->owner()){
		CTxUtxo * txUtxo=tx.mutable_utxo();
		CTxUtxo copyTxUtxo= *txUtxo;
		std::string serTxUtxo=getsha256hash(copyTxUtxo.SerializeAsString());
		std::string signature;
		std::string pub;
		int ret=TxHelper::Sign(owner, serTxUtxo, signature, pub);
		if(ret!=0){
			debugL("sign fail " << std::to_string(ret));
			return DSTR "sign fail" + std::to_string(ret);
		}
		CSign * multiSign=txUtxo->add_multisign();
		multiSign->set_sign(signature);
		multiSign->set_pub(pub);
	}
	return "0";
}



std::string TxHelper::ReplaceCreateTxTransaction_test(const std::vector<std::string> & fromAddr,const std::map<std::string,int64_t> & toAddr,void * ack)
{
    for(auto & p:toAddr){
        infoL(p.second);
    }
	tx_ack * ack_t=(tx_ack *) ack;
	MagicSingleton<DONbenchmark>::GetInstance()->IncreaseTransactionInitiateAmount();

	DBReader db_reader;
    uint64_t height = 0;
	
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(height))
    {
        return "-1 db get top failed!!"; 
    }

	// Check parameters
	height+=1;
	int ret = Check(fromAddr, height);
	if (ret != 0)
	{
		std::string strError = "-2 Check parameters failed! The error code is " + std::to_string(ret-100);
		return strError; 
	}

	if(toAddr.empty())
	{
		return "-3 to addr is empty";
	}	

	for (auto& addr : toAddr)
	{
		if (!CheckBase58Addr(addr.first))
		{
			return "-4 To address is not base58 address!";
		}

		for (auto& from : fromAddr)
		{
			if (addr.first == from)
			{
				return "-5 From address and to address is equal!";
			}
		}
		
		if (addr.second <= 0)
		{
			return "-6 Value is zero!";
		}
	}

	uint64_t amount = 0;//Transaction fee
	for (auto& i : toAddr)
	{
		amount += i.second;    
	}
	uint64_t expend = amount;




	// Find utxo
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	ret = FindUtxo(fromAddr, TxHelper::kMaxVinSize, total, setOutUtxos);
	if (ret != 0)
	{
		std::string strError = "-7 FindUtxo failed! The error code is " + std::to_string(ret-200);
		return strError; 
	}
	if (setOutUtxos.empty())
	{
		return "-8 Utxo is empty!";
	}

	CTransaction outTx;
	outTx.Clear();
	CTxUtxo * txUtxo = outTx.mutable_utxo();
	
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		return "-9 Tx owner is empty!";
	}

	uint32_t n = 0;
	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		// std::string serVinHash = getsha256hash(vin->SerializeAsString());
		// std::string signature;
		// std::string pub;
		// if(!jsonrpc_get_sigvalue(owner, serVinHash, signature, pub))
		// {
		// 	return "-10 sign fail";
		// }
		// // if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0)
		// // {
		// // 	ERRORLOG("sign fail");
		// // 	return -7;
		// // }

		// CSign * vinSign = vin->mutable_vinsign();
		// vinSign->set_sign(signature);
		// vinSign->set_pub(pub);
	}

	outTx.set_data("");
	outTx.set_type(global::ca::kTxSign);

	uint64_t gas = 0;
	std::map<std::string, int64_t> targetAddrs = toAddr;
	targetAddrs.insert(make_pair(*fromAddr.rbegin(), total - expend));
	targetAddrs.insert(make_pair(global::ca::kVirtualBurnGasAddr,gas));
	if(GenerateGas(outTx, targetAddrs.size(), gas) != 0)
	{
		return " -11 gas = 0 !";
	}

	TxHelper::vrfAgentType type;
	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	GetTxStartIdentity(fromAddr,height,current_time,type);
	DEBUGLOG("GetTxStartIdentity current_time = {} type = {}",current_time ,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
		return "-12 +++++++vrfAgentType_unknow +++++";
	}
	expend +=  gas;

	ack_t->gas = std::to_string(gas);
	ack_t->time = std::to_string(current_time);
	//Judge whether utxo is enough
	if(total < expend)
	{
		std::string strError = "-13 The total cost = " + std::to_string(total) + " is less than the cost =" + std::to_string(expend);
		return "-72013"; 
	}
	//fill vout
	for(auto & to : toAddr)
	{

		CTxOutput * vout = txUtxo->add_vout();
		vout->set_addr(to.first);
		vout->set_value(to.second);
      
	}
	CTxOutput * voutFromAddr = txUtxo->add_vout();
	voutFromAddr->set_addr(*fromAddr.rbegin());
	voutFromAddr->set_value(total - expend);
	
	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);

	//std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	// for (auto & owner : setTxowners)
	// {		
	// 	if (AddMutilSign_rpc(owner, outTx) != 0)
	// 	{
	// 		return "-14 addd mutil sign fail";
	// 	}
	// }
	
	outTx.set_time(current_time);
	outTx.set_version(0);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeTx);


	//Determine whether dropshipping is default or local dropshipping
	Vrf info;
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(TxHelper::GetEligibleNodes());
	}
	else
	{
 
		//Select dropshippers
		std::string allUtxos;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		//Candidate packers are selected based on all utxohashes
		allUtxos += std::to_string(current_time);
		
		std::string id;
		
    	int ret = GetBlockPackager(id,allUtxos, info);
    	if(ret != 0){
			std::string strError = "-15 GetBlockPackager error ,error code is " + std::to_string(ret);
			return strError;
    	}
		outTx.set_identity(id);

	}

	DEBUGLOG("GetTxStartIdentity tx time = {}, package = {}", outTx.time(), outTx.identity());
	std::string txJsonString;
	std::string vrfJsonString;
	google::protobuf::util::Status status =google::protobuf::util::MessageToJsonString(outTx,&txJsonString);
	status=google::protobuf::util::MessageToJsonString(info,&vrfJsonString);

	ack_t->txJson=txJsonString;
	ack_t->vrfJson=vrfJsonString;
	ack_t->ErrorCode="0";
	ack_t->height=std::to_string(height-1);
	ack_t->txType=std::to_string((int)type);
	return "0";
}

int TxHelper::sendMessage(CTransaction & outTx,int height,Vrf &info,TxHelper::vrfAgentType type){
	std::string txHash = getsha256hash(outTx.SerializeAsString());
	outTx.set_hash(txHash);


	TxMsgReq txMsg;
	txMsg.set_version(global::kVersion);
	TxMsgInfo* txMsgInfo = txMsg.mutable_txmsginfo();
	txMsgInfo->set_type(0);
	txMsgInfo->set_tx(outTx.SerializeAsString());
	txMsgInfo->set_height(height);

	if (type == TxHelper::vrfAgentType::vrfAgentType_vrf) {
		Vrf* new_info = txMsg.mutable_vrfinfo();
		new_info->CopyFrom(info);
		
	}
	int ret=0;
	auto msg = make_shared<TxMsgReq>(txMsg);
	std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if (type == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
		infoL("++++++++++++++++++");
        ret = DropshippingTx(msg, outTx);
    }
    else
    {
        //30 after
        ret = DropshippingTx(msg, outTx);
		infoL("------------------------");
    }
	return ret;
}




std::string TxHelper::
ReplaceCreateStakeTransaction_test(const std::string & fromAddr, uint64_t stake_amount, int32_t pledgeType,void *ack)
{

	tx_ack *ack_t=(tx_ack*)ack;
	DBReader db_reader;
    uint64_t height = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(height))
    {
        return "-1 db get top failed!!"; 
    }

	// Check parameters
	height += 1;
	std::vector<std::string> vecfromAddr;
	vecfromAddr.push_back(fromAddr);
	int ret = Check(vecfromAddr, height);
	if(ret != 0)
	{
		std::string strError;
		strError = "-2 Check parameters failed! The error code is " + std::to_string(ret-100);
		return strError;
	}

	if (!CheckBase58Addr(fromAddr, Base58Ver::kBase58Ver_Normal)) 
	{
		return "-3 From address invlaid!";
	}

	if(stake_amount == 0 )
	{
		return "-4 Stake amount is zero !";		
	}
	
	if(stake_amount < global::ca::kMinStakeAmt)
	{
		std::string strError;
		errorL("stake_amount:" << std::to_string(stake_amount));
		strError = DSTR"-5 The pledge amount must be greater than " + std::to_string(global::ca::kMinStakeAmt);
		return strError;
	}

	TxHelper::PledgeType pledgeType_ = (TxHelper::PledgeType)pledgeType;
	std::string strStakeType;
	if (pledgeType_ == TxHelper::PledgeType::kPledgeType_Node)
	{
		strStakeType = global::ca::kStakeTypeNet;
	}
	else
	{
		return "-6 Unknown stake type!";
	}

	std::vector<std::string> stake_utxos;
    auto dbret = db_reader.GetStakeAddressUtxo(fromAddr,stake_utxos);
	if(dbret == DBStatus::DB_SUCCESS)
	{
		return "-7 There has been a pledge transaction before !";
	}

	uint64_t expend = stake_amount;

	// Find utxo
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize, total, setOutUtxos);
	if (ret != 0)
	{
		std::string strError = "-8 FindUtxo failed! The error code is " + std::to_string(ret-200);
		return strError; 
	}

	if (setOutUtxos.empty())
	{
		return "-9 Utxo is empty!";
	}

	CTransaction outTx;
	outTx.Clear();

	CTxUtxo * txUtxo = outTx.mutable_utxo();
	
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	
	if (setTxowners.size() != 1)
	{
		return "-10 Tx owner is invalid!";
	}

	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 0;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		// std::string serVinHash = getsha256hash(vin->SerializeAsString());
		// std::string signature;
		// std::string pub;
		// if(!jsonrpc_get_sigvalue(owner, serVinHash, signature, pub))
		// {
		// 	return "-11 sign fail";
		// }
		// if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0)
		// {
		// 	return -8;
		// }

		// CSign * vinSign = vin->mutable_vinsign();
		// vinSign->set_sign(signature);
		// vinSign->set_pub(pub);
	}

	nlohmann::json txInfo;
	txInfo["StakeType"] = strStakeType;
	txInfo["StakeAmount"] = stake_amount;

	nlohmann::json data;
	data["TxInfo"] = txInfo;
	outTx.set_data(data.dump());
	outTx.set_type(global::ca::kTxSign);	

	uint64_t gas = 0;
	// Calculate total expenditure
	std::map<std::string, int64_t> toAddr;
	toAddr.insert(std::make_pair(global::ca::kVirtualStakeAddr, stake_amount));
	toAddr.insert(std::make_pair(fromAddr, total - expend));
	toAddr.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas));
	
	if(GenerateGas(outTx, toAddr.size(), gas) != 0)
	{
		return "-12 gas = 0 !";
	}

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	TxHelper::vrfAgentType type;
	GetTxStartIdentity(vecfromAddr,height,current_time,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
	//At this point, it indicates that the current node does not meet the pledge and investment requirements within 30 seconds beyond the height of 50. At this time, the pledge operation can be initiated
		type = TxHelper::vrfAgentType_defalut;
	}

	expend += gas;
	ack_t->gas = std::to_string(gas);
	ack_t->time = std::to_string(current_time);

	//Judge whether utxo is enough
	if(total < expend)
	{
		std::string strError = "-13 The total cost = " + std::to_string(total) + " is less than the cost = {}" + std::to_string(expend);
		return "-72013"; 
	}

	CTxOutput * vout = txUtxo->add_vout(); //vout[0]
	vout->set_addr(global::ca::kVirtualStakeAddr);
	vout->set_value(stake_amount);

	CTxOutput * voutFromAddr = txUtxo->add_vout();//vout[1]
	voutFromAddr->set_addr(fromAddr);
	voutFromAddr->set_value(total - expend);

	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);

	// std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	// for (auto & owner : setTxowners)
	// {	
	// 	if (AddMutilSign_rpc(owner, outTx) != 0)
	// 	{
	// 		return "-14 AddMutilSign_rpc(owner, outTx) != 0";
	// 	}
	// }
	outTx.set_version(0);
	outTx.set_time(current_time);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeStake);

	//Determine whether dropshipping is default or local dropshipping
	Vrf info;
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(TxHelper::GetEligibleNodes());
	}
	else
	{
		//Select dropshippers
		std::string allUtxos;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;
		
    	int ret= GetBlockPackager(id,allUtxos,info);
    	if(ret!=0){
			std::string strError = "-15 GetBlockPackager error , error code is " + std::to_string(ret);
			return strError;
    	}
		outTx.set_identity(id);
		
	}

	// std::string txHash = getsha256hash(outTx.SerializeAsString());
	// outTx.set_hash(txHash);


	// TxMsgReq txMsg;
	// txMsg.set_version(global::kVersion);
	// TxMsgInfo* txMsgInfo = txMsg.mutable_txmsginfo();
	// txMsgInfo->set_type(0);
	// txMsgInfo->set_tx(outTx.SerializeAsString());
	// txMsgInfo->set_height(height-1);

	// if (type == TxHelper::vrfAgentType::vrfAgentType_vrf) {
	// 	Vrf* new_info = txMsg.mutable_vrfinfo();
	// 	new_info->CopyFrom(info);
		
	// }
	//  auto msg = make_shared<TxMsgReq>(txMsg);
	// std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    // if (type == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    // {

    //     ret = DropshippingTx(msg, outTx);
    // }
    // else
    // {
    //     ret = DoHandleTx(msg, outTx);
    // }

	// return "0";


	std::string txJsonString;
	std::string vrfJsonString;
	google::protobuf::util::Status status =google::protobuf::util::MessageToJsonString(outTx,&txJsonString);
	status=google::protobuf::util::MessageToJsonString(info,&vrfJsonString);

	ack_t->txJson=txJsonString;
	ack_t->vrfJson=vrfJsonString;
	ack_t->ErrorCode="0";
	ack_t->height=std::to_string(height-1);
	ack_t->txType=std::to_string((int)type);
	return "0";
}



std::string TxHelper::ReplaceCreatUnstakeTransaction_test(const std::string& fromAddr, const std::string& utxo_hash,void*ack)
{
	tx_ack * ack_t=(tx_ack *) ack;
	DBReader db_reader;
    uint64_t height = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(height))
    {
        return "-1 db get top failed!!"; 
    }

	height += 1;
	// Check parameters
	std::vector<std::string> vecfromAddr;
	vecfromAddr.push_back(fromAddr);
	int ret = Check(vecfromAddr, height);
	if(ret != 0)
	{
		std::string strError = "-2 Check parameters failed! The error code is " + std::to_string(ret-100);
		return strError;
	}

	if (CheckBase58Addr(fromAddr, Base58Ver::kBase58Ver_MultiSign) == true)
	{
		return "-3 FromAddr is not normal base58 addr.";
	}


	uint64_t stake_amount = 0;
	ret = IsQualifiedToUnstake(fromAddr, utxo_hash, stake_amount);
	if(ret != 0)
	{
		std::string strError = "-4 FromAddr is not qualified to unstake! The error code is " + std::to_string(ret-200);
		return strError;
	}	

	// Find utxo
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	// The number of utxos to be searched here needs to be reduced by 1 \
	because a VIN to be redeem is from the pledged utxo, so just look for 99
	ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize - 1, total, setOutUtxos); 
	if (ret != 0)
	{
		std::string strError = "-5 FindUtxo failed! The error code is " + std::to_string(ret-300);
		return strError;
	}

	if (setOutUtxos.empty())
	{
		return "-6 Utxo is empty!";
	}

	CTransaction outTx;
	outTx.Clear();
	CTxUtxo * txUtxo = outTx.mutable_utxo();
	
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		return "-7 Tx owner is empty!";
	}

	{
		// Fill vin
		txUtxo->add_owner(fromAddr);
		CTxInput* txin = txUtxo->add_vin();
		txin->set_sequence(0);
		CTxPrevOutput* prevout = txin->add_prevout();
		prevout->set_hash(utxo_hash);
		prevout->set_n(1);

		// std::string serVinHash = getsha256hash(txin->SerializeAsString());
		// std::string signature;
		// std::string pub;
		// if(!jsonrpc_get_sigvalue(fromAddr, serVinHash, signature, pub))
		// {
		// 	return "-8 sign fail";
		// }

		// CSign * vinSign = txin->mutable_vinsign();
		// vinSign->set_sign(signature);
		// vinSign->set_pub(pub);
	}


	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 1;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		// std::string serVinHash = getsha256hash(vin->SerializeAsString());
		// std::string signature;
		// std::string pub;
		// if(!jsonrpc_get_sigvalue(owner, serVinHash, signature, pub))
		// {
		// 	return "-9 sign fail";
		// }

		// CSign * vinSign = vin->mutable_vinsign();
		// vinSign->set_sign(signature);
		// vinSign->set_pub(pub);
	}

	nlohmann::json txInfo;
	txInfo["UnstakeUtxo"] = utxo_hash;

	nlohmann::json data;
	data["TxInfo"] = txInfo;
	outTx.set_data(data.dump());
	outTx.set_type(global::ca::kTxSign);	
	outTx.set_version(0);

	uint64_t gas = 0;
	//The filled quantity only participates in the calculation and does not affect others
	std::map<std::string, int64_t> toAddr;
	toAddr.insert(std::make_pair(global::ca::kVirtualStakeAddr, stake_amount));
	toAddr.insert(std::make_pair(fromAddr, total));
	toAddr.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas));
	
	
	if(GenerateGas(outTx, toAddr.size(), gas) != 0)
	{
		return "-10 gas = 0 !";
	}

	// Calculate total expenditure
	uint64_t gasTtoal =  gas;

	uint64_t cost = 0;//Packing fee

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	TxHelper::vrfAgentType type;
	GetTxStartIdentity(vecfromAddr,height,current_time,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
	//At this point, it indicates that the current node has not met the pledge within 30 seconds beyond the height of 50 and the investment node can initiate the pledge cancellation operation
		type = TxHelper::vrfAgentType_defalut;
	}

	uint64_t expend = gas;

	//Judge whether there is enough money
	if(total < expend)
	{
		std::string strError = "-11 The total cost = " + std::to_string(total) + " is less than the cost = {}" + std::to_string(expend);
		return "-72013"; 
	}

	// Fill vout
	CTxOutput* txoutToAddr = txUtxo->add_vout();
	txoutToAddr->set_addr(fromAddr);      	// Release the pledge to my account number
	txoutToAddr->set_value(stake_amount);

	txoutToAddr = txUtxo->add_vout();
	txoutToAddr->set_addr(fromAddr);  		// Give myself the rest
	txoutToAddr->set_value(total - expend);

	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);

	// std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	// for (auto & owner : setTxowners)
	// {	
	// 	if (AddMutilSign_rpc(owner, outTx) != 0)
	// 	{
	// 		return "-12 AddMutilSign_rpc(owner, outTx) != 0";
	// 	}
	// }

	outTx.set_time(current_time);
	outTx.set_version(0);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeUnstake);

	//Determine whether dropshipping is default or local dropshipping
	Vrf info;
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(TxHelper::GetEligibleNodes());
	}
	else{
		//Select dropshippers
		std::string allUtxos = utxo_hash;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;

    	int ret= GetBlockPackager(id,allUtxos,info);
    	if(ret!=0){
			std::string strError = "-13 GetBlockPackager error , error code is " + std::to_string(ret);
			return strError;
    	}
		outTx.set_identity(id);
	}

	


	std::string txJsonString;
	std::string vrfJsonString;
	google::protobuf::util::Status status =google::protobuf::util::MessageToJsonString(outTx,&txJsonString);
	status=google::protobuf::util::MessageToJsonString(info,&vrfJsonString);

	ack_t->txJson=txJsonString;
	ack_t->vrfJson=vrfJsonString;
	ack_t->ErrorCode="0";
	ack_t->height=std::to_string(height-1);
	ack_t->txType=std::to_string((int)type);


	return "0";
}


std::string TxHelper::ReplaceCreateInvestTransaction_test(const std::string & fromAddr,
								const std::string& toAddr,uint64_t invest_amount, int32_t investType,void * ack)
{
	tx_ack *ack_t=(tx_ack*)ack;
	TxHelper::vrfAgentType type;

	DBReader db_reader;
    uint64_t height = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(height))
    {
        return "-1 db get top failed!!"; 
    }

	height+=1;
	// Check parameters
	std::vector<std::string> vecfromAddr;
	vecfromAddr.push_back(fromAddr);
	int ret = Check(vecfromAddr, height);
	if(ret != 0)
	{
		std::string strError = "-2 Check parameters failed! The error code is " + std::to_string(ret-100);
		return strError;
	}

	// Neither fromaddr nor toaddr can be a virtual account
	if (CheckBase58Addr(fromAddr, Base58Ver::kBase58Ver_MultiSign) == true)
	{
		return "-3 FromAddr is not normal base58 addr.";
	}

	if (CheckBase58Addr(toAddr, Base58Ver::kBase58Ver_MultiSign) == true)
	{
		return "-4 To address is not base58 address!";
	}

	if(invest_amount < global::ca::kMinInvestAmt){
		std::string strError = "-5 Invest less = " + std::to_string(global::ca::kMinInvestAmt);
		return "-72014";
	}

	ret = CheckInvestQualification(fromAddr, toAddr, invest_amount);
	if(ret != 0)
	{
		std::string strError = "-6 FromAddr is not qualified to invest! The error code is " + std::to_string(ret-200);
		if(ret==-9){
            return "-72017";
        }
		return "-72016";
	}	
	std::string strinvestType;
	TxHelper::InvestType investType_ = (TxHelper::InvestType)investType;
	if (investType_ ==  TxHelper::InvestType::kInvestType_NetLicence)
	{
		strinvestType = global::ca::kInvestTypeNormal;
	}
	else
	{
		return "-7 Unknown invest type!";
	}
	
	// Find utxo
	uint64_t total = 0;
	uint64_t expend = invest_amount;

	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize, total, setOutUtxos);
	if (ret != 0)
	{
		std::string strError = "-8 FindUtxo failed! The error code is " + std::to_string(ret-300);
		return strError;
	}
	if (setOutUtxos.empty())
	{
		return "-9 Utxo is empty!";
	}

	CTransaction outTx;
	outTx.Clear();
	CTxUtxo * txUtxo = outTx.mutable_utxo();
	
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		return "-10 Tx owner is empty!";
	}

	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 0;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		// std::string serVinHash = getsha256hash(vin->SerializeAsString());
		// std::string signature;
		// std::string pub;
		// if(!jsonrpc_get_sigvalue(owner, serVinHash, signature, pub))
		// {
		// 	return "-11 sign fail";
		// }

		// CSign * vinSign = vin->mutable_vinsign();
		// vinSign->set_sign(signature);
		// vinSign->set_pub(pub);
	}

	nlohmann::json txInfo;
	txInfo["InvestType"] = strinvestType;
	txInfo["BonusAddr"] = toAddr;
	txInfo["InvestAmount"] = invest_amount;

	nlohmann::json data;
	data["TxInfo"] = txInfo;
	outTx.set_data(data.dump());
	outTx.set_type(global::ca::kTxSign);

	uint64_t gas = 0;	
	// Calculate total expenditure
	std::map<std::string, int64_t> toAddrs;
	toAddrs.insert(std::make_pair(global::ca::kVirtualStakeAddr, invest_amount));
	toAddrs.insert(std::make_pair(fromAddr, total - expend));
	toAddrs.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas));
	
	
	if(GenerateGas(outTx, toAddrs.size(), gas) != 0)
	{
		std::cout << "GenerateGas gas = " << gas << std::endl;
		return "-12 gas = 0 !";
	}

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	GetTxStartIdentity(vecfromAddr,height,current_time,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
	//This indicates that the current node has not met the pledge within 30 seconds beyond the height of 50 and the investment node can initiate the investment operation at this time
		type = TxHelper::vrfAgentType_defalut;
	}


	expend += gas;
	ack_t->gas = std::to_string(gas);
	ack_t->time = std::to_string(current_time);

	if(total < expend)
	{
		std::string strError = "-13 The total cost = " + std::to_string(total) + " is less than the cost = {}" + std::to_string(expend);
		return "-72013"; 
	}

	CTxOutput * vout = txUtxo->add_vout(); //vout[0]
	vout->set_addr(global::ca::kVirtualInvestAddr);
	vout->set_value(invest_amount);

	CTxOutput * voutFromAddr = txUtxo->add_vout();//vout[1]
	voutFromAddr->set_addr(fromAddr);
	voutFromAddr->set_value(total - expend);

	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);

	// std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	// for (auto & owner : setTxowners)
	// {	
	// 	if (AddMutilSign_rpc(owner, outTx) != 0)
	// 	{
	// 		return "-14 AddMutilSign_rpc(owner, outTx) != 0";
	// 	}
	// }
	
	outTx.set_version(0);
	outTx.set_time(current_time);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeInvest);

	//Determine whether dropshipping is default or local dropshipping
	Vrf info;
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(TxHelper::GetEligibleNodes());
	}
	else{
		//Select dropshippers
		std::string allUtxos;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;
		
    	int ret= GetBlockPackager(id,allUtxos,info);
    	if(ret!=0){
			std::string strError = "-15 GetBlockPackager error , error code is " + std::to_string(ret);
			return strError;
    	}
		outTx.set_identity(id);
	}

	// std::string txHash = getsha256hash(outTx.SerializeAsString());
	// outTx.set_hash(txHash);


	// TxMsgReq txMsg;
	// txMsg.set_version(global::kVersion);
	// TxMsgInfo* txMsgInfo = txMsg.mutable_txmsginfo();
	// txMsgInfo->set_type(0);
	// txMsgInfo->set_tx(outTx.SerializeAsString());
	// txMsgInfo->set_height(height-1);

	// if (type == TxHelper::vrfAgentType::vrfAgentType_vrf) {
	// 	Vrf* new_info = txMsg.mutable_vrfinfo();
	// 	new_info->CopyFrom(info);
		
	// }
	//  auto msg = make_shared<TxMsgReq>(txMsg);
	// std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    // if (type == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    // {

    //     ret = DropshippingTx(msg, outTx);
    // }
    // else
    // {
    //     ret = DoHandleTx(msg, outTx);
    // }

	// return "0";


	std::string txJsonString;
	std::string vrfJsonString;
	google::protobuf::util::Status status =google::protobuf::util::MessageToJsonString(outTx,&txJsonString);
	status=google::protobuf::util::MessageToJsonString(info,&vrfJsonString);

	ack_t->txJson=txJsonString;
	ack_t->vrfJson=vrfJsonString;
	ack_t->ErrorCode="0";
	ack_t->height=std::to_string(height-1);
	ack_t->txType=std::to_string((int)type);
	return "0";
}


std::string TxHelper::ReplaceCreateDisinvestTransaction_test(const std::string& fromAddr,
                                    const std::string& toAddr, const std::string& utxo_hash,void * ack)
{
	tx_ack *ack_t=(tx_ack *) ack;
	TxHelper::vrfAgentType type;
	CTransaction outTx;
    Vrf info_;

	DBReader db_reader;
    uint64_t height = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(height))
    {
        return "-1 db get top failed!!"; 
    }

	height += 1;
	// Check parameters
	std::vector<std::string> vecfromAddr;
	vecfromAddr.push_back(fromAddr);
	int ret = Check(vecfromAddr, height);
	if(ret != 0)
	{
		std::string strError = "-2 Check parameters failed! The error code is " + std::to_string(ret-100);
		return strError;
	}

	if (CheckBase58Addr(fromAddr, Base58Ver::kBase58Ver_MultiSign) == true)
	{
		return "-3 FromAddr is not normal base58 addr.";
	}

	if (CheckBase58Addr(toAddr, Base58Ver::kBase58Ver_MultiSign) == true)
	{
		return "-4 To address is not base58 address!";
	}

	uint64_t invested_amount = 0;
	if(IsQualifiedToDisinvest(fromAddr, toAddr, utxo_hash, invested_amount) != 0)
	{
		return "-72015";
	}
	// Find utxo
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	// The utxo quantity sought here needs to be reduced by 1
	ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize - 1, total, setOutUtxos); 
	if (ret != 0)
	{
		std::string strError = "-6 FindUtxo failed! The error code is " + std::to_string(ret-300);
		return strError;
	}
	if (setOutUtxos.empty())
	{
		ERRORLOG(RED "Utxo is empty!" RESET);
		return "-7 Utxo is empty!";
	}

	outTx.Clear();
	CTxUtxo * txUtxo = outTx.mutable_utxo();
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		return "-8 Tx owner is empty!";
	}

	{
		// Fill vin
		txUtxo->add_owner(fromAddr);
		CTxInput* txin = txUtxo->add_vin();
		txin->set_sequence(0);
		CTxPrevOutput* prevout = txin->add_prevout();
		prevout->set_hash(utxo_hash);
		prevout->set_n(1);

		// std::string serVinHash = getsha256hash(txin->SerializeAsString());
		// std::string signature;
		// std::string pub;
		// if(!jsonrpc_get_sigvalue(fromAddr, serVinHash, signature, pub))
		// {
		// 	return "-9 sign fail";
		// }

		// CSign * vinSign = txin->mutable_vinsign();
		// vinSign->set_sign(signature);
		// vinSign->set_pub(pub);
	}

	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 1;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		// std::string serVinHash = getsha256hash(vin->SerializeAsString());
		// std::string signature;
		// std::string pub;
		// if(!jsonrpc_get_sigvalue(owner, serVinHash, signature, pub))
		// {
		// 	return "-10 sign fail";
		// }
		
		// CSign * vinSign = vin->mutable_vinsign();
		// vinSign->set_sign(signature);
		// vinSign->set_pub(pub);
	}

	nlohmann::json txInfo;
	txInfo["BonusAddr"] = toAddr;
	txInfo["DisinvestUtxo"] = utxo_hash;

	nlohmann::json data;
	data["TxInfo"] = txInfo;
	outTx.set_data(data.dump());
	outTx.set_type(global::ca::kTxSign);	

	uint64_t gas = 0;
	// Calculate total expenditure
	std::map<std::string, int64_t> targetAddrs;
	targetAddrs.insert(std::make_pair(global::ca::kVirtualStakeAddr, invested_amount));
	targetAddrs.insert(std::make_pair(fromAddr, total ));
	targetAddrs.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas ));
	
	
	if(GenerateGas(outTx, targetAddrs.size(), gas) != 0)
	{
		return "-11 gas = 0 !";
	}

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	GetTxStartIdentity(vecfromAddr,height,current_time,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
		type = TxHelper::vrfAgentType_defalut;
	}

	uint64_t expend = gas;
	
	if(total < expend)
	{
		std::string strError = "-12 The total cost = " + std::to_string(total) + " is less than the cost = {}" + std::to_string(expend);
		return "-72013"; 
	}	

	//Fill vout
	CTxOutput* txoutToAddr = txUtxo->add_vout();
	txoutToAddr->set_addr(fromAddr);      // Give my account the money I withdraw
	txoutToAddr->set_value(invested_amount);

	txoutToAddr = txUtxo->add_vout();
	txoutToAddr->set_addr(fromAddr);  	  // Give myself the rest
	txoutToAddr->set_value(total - expend);

	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);

	// std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	// for (auto & owner : setTxowners)
	// {	
	// 	if (AddMutilSign_rpc(owner, outTx) != 0)
	// 	{
	// 		return "-13 TxHelper::AddMutilSign(owner, outTx) != 0";
	// 	}
	// }

	outTx.set_time(current_time);
	outTx.set_version(0);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeDisinvest);

	//Determine whether dropshipping is default or local dropshipping
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(TxHelper::GetEligibleNodes());
	}
	else{
		//Select dropshippers
		std::string allUtxos = utxo_hash;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;
    	int ret= GetBlockPackager(id,allUtxos,info_);
    	if(ret!=0){
			std::string strError = "-14 GetBlockPackager error , error code is " + std::to_string(ret);
			return strError;
    	}
		outTx.set_identity(id);
	}

	// std::string txHash = getsha256hash(outTx.SerializeAsString());
	// outTx.set_hash(txHash);


	// TxMsgReq txMsg;
	// txMsg.set_version(global::kVersion);
	// TxMsgInfo* txMsgInfo = txMsg.mutable_txmsginfo();
	// txMsgInfo->set_type(0);
	// txMsgInfo->set_tx(outTx.SerializeAsString());
	// txMsgInfo->set_height(height-1);

	// if (type == TxHelper::vrfAgentType::vrfAgentType_vrf) {
	// 	Vrf* new_info = txMsg.mutable_vrfinfo();
	// 	new_info->CopyFrom(info_);
		
	// }
	// auto msg = make_shared<TxMsgReq>(txMsg);
	// std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    // if (type == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    // {

    //     ret = DropshippingTx(msg, outTx);
    // }
    // else
    // {
    //     ret = DoHandleTx(msg, outTx);
    // }

	std::string txJsonString;
	std::string vrfJsonString;
	google::protobuf::util::Status status =google::protobuf::util::MessageToJsonString(outTx,&txJsonString);
	status=google::protobuf::util::MessageToJsonString(info_,&vrfJsonString);

	ack_t->txJson=txJsonString;
	ack_t->vrfJson=vrfJsonString;
	ack_t->ErrorCode="0";
	ack_t->height=std::to_string(height-1);
	ack_t->txType=std::to_string((int)type);

	return "0";
}

std::string TxHelper::ReplaceCreateDeclareTransaction_test(const std::string & fromaddr,
                                    const std::string & toAddr,
                                    uint64_t amount, 
                                    const std::string & multiSignPub,
                                    const std::vector<std::string> & signAddrList,
                                    uint64_t signThreshold,void * ack)
{
	tx_ack * ack_t=(tx_ack*)ack;
	TxHelper::vrfAgentType type;
	CTransaction outTx;
	Vrf info_;

	DBReader db_reader;
    uint64_t height = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(height))
    {
        return "-1 db get top failed!!"; 
    }

	height += 1;
	// Check parameters	
	std::vector<std::string> VecfromAddr;
	VecfromAddr.emplace_back(fromaddr);
	int ret = Check(VecfromAddr, height);
	if (ret != 0)
	{
		std::string strError = "-2 Check parameters failed! The error code is " + std::to_string(ret-100);
		return strError;
	}

	if (fromaddr.empty())
	{
		return "-3 fromaddr is empty";
	}
	if (!CheckBase58Addr(fromaddr, Base58Ver::kBase58Ver_Normal))
	{
		return "-4 fromaddr CheckBase58Addr error";
	}

	if (toAddr.empty())
	{
		return "-5 toAddr is empty";
	}

	if (! CheckBase58Addr(toAddr, Base58Ver::kBase58Ver_MultiSign))
	{
		return "-6 toAddr CheckBase58Addr error";
	}

	if (amount <= 0)
	{
		return "-7 amount <= 0";
	}

	if (multiSignPub.empty())
	{
		return "-8 multiSignPub is empty";
	}

	if (toAddr != GetBase58Addr(multiSignPub, Base58Ver::kBase58Ver_MultiSign))
	{
		return "-9 toAddr CheckBase58Addr error";
	}

	if (signAddrList.size() < 2 || signAddrList.size() > 100)
	{
		return "-10 signAddrList.size() < 2 || signAddrList.size() > 100";
	}

	if (signThreshold > signAddrList.size())
	{
		return "-11 signThreshold > signAddrList.size()";
	}

	for (auto & addr : signAddrList)
	{
		if (! CheckBase58Addr(addr, Base58Ver::kBase58Ver_Normal))
		{
			return "-12 signAddrList CheckBase58Addr error";
		}
	}

	//CBlockDataApi data_reader;
	std::vector<std::string> multiSignAddrs;
	auto db_status = db_reader.GetMutliSignAddress(multiSignAddrs);
	if (DBStatus::DB_SUCCESS != db_status)
	{
		if (DBStatus::DB_NOT_FOUND != db_status)
		{
			return "-13 DBStatus::DB_NOT_FOUND != db_status";
		}
	}

	if (std::find(multiSignAddrs.begin(), multiSignAddrs.end(), toAddr) != multiSignAddrs.end())
	{
		return "-14 not find toAddr";
	}
	
	uint64_t expend = amount;

	// Find utxo
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	ret = FindUtxo(VecfromAddr, TxHelper::kMaxVinSize, total, setOutUtxos);//
	if (ret != 0)
	{
		std::string strError = "-15 FindUtxo failed! The error code is " + std::to_string(ret-200);
		return strError;
	}
	if (setOutUtxos.empty())
	{
		return "-16 Utxo is empty!";
	}

	outTx.Clear();

	CTxUtxo * txUtxo = outTx.mutable_utxo();
	
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		return "-17 Tx owner is empty!";
	}

	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 0;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		// std::string serVinHash = getsha256hash(vin->SerializeAsString());
		// std::string signature;
		// std::string pub;
		// if(!jsonrpc_get_sigvalue(owner, serVinHash, signature, pub))
		// {
		// 	return "-18 sign fail";
		// }
		
		// CSign * vinSign = vin->mutable_vinsign();
		// vinSign->set_sign(signature);
		// vinSign->set_pub(pub);
	}

	nlohmann::json txInfo;
	txInfo["SignThreshold"] = signThreshold; // SignThreshold
	txInfo["MultiSignPub"] = Base64Encode(multiSignPub); // MultiSignPub MultiSignAddr
	txInfo["SignAddrList"] = signAddrList; // SignAddr

	nlohmann::json data;
	data["TxInfo"] = txInfo;
	outTx.set_data(data.dump());
	outTx.set_type(global::ca::kTxSign);

	uint64_t gas = 0;
	std::map<std::string, int64_t> targetAddrs ;
	targetAddrs.insert(make_pair(toAddr, amount));
	targetAddrs.insert(make_pair(*VecfromAddr.rbegin(), total - expend));
	targetAddrs.insert(make_pair(global::ca::kVirtualBurnGasAddr, gas));
	if(GenerateGas(outTx, targetAddrs.size(), gas) != 0)
	{
		return "-19 gas = 0 !";
	}

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();

    GetTxStartIdentity(VecfromAddr, height, current_time, type);
	if(type == TxHelper::vrfAgentType_unknow)
	{
		return "-20 +++++++vrfAgentType_unknow +++++";
	}

	expend += gas;
	ack_t->gas = std::to_string(gas);
	ack_t->time = std::to_string(current_time);

	if(total < expend)
	{
		std::string strError = "-21 The total cost = " + std::to_string(total) + " is less than the cost = {}" + std::to_string(expend);
		return "-72013"; 
	}

	{
		CTxOutput * vout = txUtxo->add_vout();
		vout->set_addr(toAddr);
		vout->set_value(amount);
	}
	CTxOutput * voutFromAddr = txUtxo->add_vout();
	voutFromAddr->set_addr(*VecfromAddr.rbegin());
	voutFromAddr->set_value(total - expend);

	CTxOutput * vout_burn = txUtxo->add_vout();
	vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
	vout_burn->set_value(gas);


	// std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	// for (auto & owner : setTxowners)
	// {
	// 	if (AddMutilSign_rpc(owner, outTx) != 0)
	// 	{
	// 		return "-22 AddMutilSign_rpc(owner, outTx) != 0";
	// 	}
	// }

	outTx.set_time(current_time);

	//Determine whether dropshipping is default or local dropshipping
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(TxHelper::GetEligibleNodes());
	}
	else{
		
		//Select dropshippers
		std::string allUtxos;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;
    	int ret= GetBlockPackager(id,allUtxos,info_);
    	if(ret!=0){
        	std::string strError = "-23 GetBlockPackager error , error code is " + std::to_string(ret);
			return strError;
    	}
		outTx.set_identity(id);
	}

	outTx.set_version(0);
	outTx.set_consensus(global::ca::kConsensus);
	outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeDeclaration);




	// std::string txHash = getsha256hash(outTx.SerializeAsString());
	// outTx.set_hash(txHash);


	// TxMsgReq txMsg;
	// txMsg.set_version(global::kVersion);
	// TxMsgInfo* txMsgInfo = txMsg.mutable_txmsginfo();
	// txMsgInfo->set_type(0);
	// txMsgInfo->set_tx(outTx.SerializeAsString());
	// txMsgInfo->set_height(height-1);

	// if (type == TxHelper::vrfAgentType::vrfAgentType_vrf) {
	// 	Vrf* new_info = txMsg.mutable_vrfinfo();
	// 	new_info->CopyFrom(info_);
		
	// }
	// auto msg = make_shared<TxMsgReq>(txMsg);
	// std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    // if (type == TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    // {

    //     ret = DropshippingTx(msg, outTx);
    // }
    // else
    // {
    //     ret = DoHandleTx(msg, outTx);
    // }


	std::string txJsonString;
	std::string vrfJsonString;
	google::protobuf::util::Status status =google::protobuf::util::MessageToJsonString(outTx,&txJsonString);
	status=google::protobuf::util::MessageToJsonString(info_,&vrfJsonString);

	ack_t->txJson=txJsonString;
	ack_t->vrfJson=vrfJsonString;
	ack_t->ErrorCode="0";
	ack_t->height=std::to_string(height-1);
	ack_t->txType=std::to_string((int)type);


	return "0";
}



 std::string TxHelper::GetEligibleNodes(){
	std::vector<Node> nodelist = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
    std::vector<std::string> result_node;

    if(nodelist.size() <= 0){
        return "";
    }
    for (const auto &node : nodelist)
    {
        int ret = VerifyBonusAddr(node.base58address);

        int64_t stake_time = ca_algorithm::GetPledgeTimeByAddr(node.base58address, global::ca::StakeType::kStakeType_Node);
        if (stake_time > 0 && ret == 0)
        {
            result_node.push_back(node.base58address);
        }
    }
	auto getNextNumber=[&](int limit) ->int {
	  	std::random_device seed;
	 	std::ranlux48 engine(seed());
	 	std::uniform_int_distribution<int> u(0, limit-1);
	 	return u(engine);
	};

	int rumdom=getNextNumber(result_node.size());

	return result_node[rumdom];
	//return result_node;

 }


