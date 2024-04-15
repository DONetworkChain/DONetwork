#include "ca/ca_algorithm.h"

#include <sys/time.h>
#include <boost/math/constants/constants.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include "proto/transaction.pb.h"

#include "db/db_api.h"
#include "utils/MagicSingleton.h"
#include "utils/time_util.h"
#include "ca/ca_transaction.h"
#include "ca/ca_blockcache.h"
#include "ca/ca_global.h"
#include "ca/ca.h"
#include "ca/ca_sync_block.h"
#include "ca/ca_test.h"

#include "ca_block_http_callback.h"
#include "utils/console.h"
#include "include/ScopeGuard.h"
#include "ca_blockhelper.h"
#include "utils/AccountManager.h"

#include "ca_DonHost.hpp"
#include "ca_contract.h"
#include "utils/ContractUtils.h"
#include "utils/DONbenchmark.h"
#include <future>
#include <memory>
#include "common/task_pool.h"

typedef boost::multiprecision::cpp_bin_float_50 cpp_bin_float;

static uint64_t GetLocalTimestampUsec()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}
  
int ca_algorithm::GetAbnormalSignAddrListByPeriod(uint64_t &cur_time, std::vector<std::string> &abnormal_addr_list, std::unordered_map<std::string, uint64_t> & addr_sign_cnt)
{
    DBReader db_reader;
    std::vector<std::string> SignAddrs;
    uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(cur_time);
    if (DBStatus::DB_SUCCESS != db_reader.GetSignAddrByPeriod(Period - 1, SignAddrs))
    {
        ERRORLOG("GetSignAddrByPeriod error Period:{}", Period - 1);
        return -1;
    }
    uint64_t SignNumber = 0;

    for(auto addr : SignAddrs)
    {
        auto ret = db_reader.GetSignNumberByPeriod(Period - 1, addr, SignNumber);
        if (DBStatus::DB_SUCCESS != ret)
        {
            ERRORLOG("ret is {},SignNumber is {}",ret,SignNumber);
            ERRORLOG("GetSignNumberByPeriod error Period:{},addr:{}", Period - 1, addr);
            return -2;
        }
        addr_sign_cnt[addr] = SignNumber;
    }

    uint64_t quarter_num = addr_sign_cnt.size() * 0.25;
    uint64_t three_quarter_num = addr_sign_cnt.size() * 0.75;
    if (quarter_num == three_quarter_num)
    {
        return 0;
    }

    std::vector<uint64_t> sign_cnt;     // Number of signatures stored
    for (auto &item : addr_sign_cnt)
    {
        sign_cnt.push_back(item.second);
    }
    std::sort(sign_cnt.begin(), sign_cnt.end());

    uint64_t sign_cnt_quarter_num_value = sign_cnt.at(quarter_num);
    uint64_t sign_cnt_three_quarter_num_value = sign_cnt.at(three_quarter_num);
    int64_t sign_cnt_lower_limit_value = sign_cnt_quarter_num_value -
                                          ((sign_cnt_three_quarter_num_value - sign_cnt_quarter_num_value) * 1.5);

    DEBUGLOG("quarter_num:{},three_quarter:{},abnormal lower_limit_value :{}",sign_cnt_quarter_num_value, sign_cnt_three_quarter_num_value, sign_cnt_lower_limit_value);
    if(sign_cnt_lower_limit_value >= 0)
    {
        for (auto &item : addr_sign_cnt)
        {
            if (item.second < sign_cnt_lower_limit_value)
            {
                abnormal_addr_list.push_back(item.first);
            }
        }
    }
    return 0;  
}
int64_t ca_algorithm::GetPledgeTimeByAddr(const std::string &addr, global::ca::StakeType stakeType, DBReader *db_reader_ptr)
{
    if (stakeType != global::ca::StakeType::kStakeType_Node)
    {
        ERRORLOG("unknow pledge type");
        return -1;
    }
    DBReader db_reader;
    if (nullptr == db_reader_ptr)
    {
        db_reader_ptr = &db_reader;
    }
    std::vector<std::string> pledge_utxos;
    auto ret = db_reader.GetStakeAddressUtxo(addr, pledge_utxos);
    if (DBStatus::DB_NOT_FOUND == ret)
    {
        TRACELOG("DB_NOT_FOUND");
        return 0;
    }
    else if (DBStatus::DB_SUCCESS != ret)
    {
        ERRORLOG("fail to query addr pledge");
        return -2;
    }

    std::vector<CTransaction> txs;
    CTransaction tx;
    std::string tx_raw;
    std::string tmp_pledge_type;
    for (auto &pledge_utxo : pledge_utxos)
    {
        if (DBStatus::DB_SUCCESS != db_reader.GetTransactionByHash(pledge_utxo, tx_raw))
        {
            ERRORLOG("faile to query trasaction");
            return -3;
        }
        tx.Clear();
        if (!tx.ParseFromString(tx_raw))
        {
            ERRORLOG("trasaction parse fail");
            return -4;
        }

        if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
        {
            try
            {
                nlohmann::json data_json = nlohmann::json::parse(tx.data());
                global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();

                if (global::ca::TxType::kTxTypeStake != tx_type)
                {
                    continue;
                }

                nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
                tmp_pledge_type.clear();
                tx_info["StakeType"].get_to(tmp_pledge_type);

                if (tmp_pledge_type != global::ca::kStakeTypeNet)
                {
                    continue;
                }
                txs.push_back(tx);
            }
            catch (...)
            {
                ERRORLOG("get pledge trasaction fail");
                return -5;
            }
        }
    }
    std::sort(txs.begin(), txs.end(),
              [](const CTransaction &tx1, const CTransaction &tx2)
              {
                  return tx1.time() < tx2.time();
              });

    uint64_t total_stake_amount = 0;
    uint64_t last_time = 0;

    for (auto &tx : txs)
    {
        for (auto &vout : tx.utxo().vout())
        {
            if (vout.addr() == global::ca::kVirtualStakeAddr)
            {
                total_stake_amount += vout.value();
                last_time = tx.time();
                break;
            }
        }
        if (total_stake_amount >= global::ca::kMinStakeAmt)
        {
            break;
        }
    }

    if (total_stake_amount < global::ca::kMinStakeAmt)
    {
        TRACELOG("node type pledge amount is {}", total_stake_amount);
        return 0;
    }

    
    return last_time;
}

std::string ca_algorithm::CalcTransactionHash(CTransaction tx)
{
    tx.clear_hash();
    tx.clear_verifysign();
    return getsha256hash(tx.SerializeAsString());
}

std::string ca_algorithm::CalcBlockHash(CBlock block)
{
    block.clear_hash();
    block.clear_sign();
    return getsha256hash(block.SerializeAsString());
}

std::string ca_algorithm::CalcBlockMerkle(CBlock cblock)
{
	std::string merkle;
	if (cblock.txs_size() == 0)
	{
		return merkle;
	}

	std::vector<std::string> vTxHashs;
	for (int i = 0; i != cblock.txs_size(); ++i)
	{
		CTransaction tx = cblock.txs(i);
		vTxHashs.push_back(tx.hash());
	}

	unsigned int j = 0, nSize;
    for (nSize = cblock.txs_size(); nSize > 1; nSize = (nSize + 1) / 2)
	{
        for (unsigned int i = 0; i < nSize; i += 2)
		{
            unsigned int i2 = MIN(i+1, nSize-1);

			std::string data1 = vTxHashs[j + i];
			std::string data2 = vTxHashs[j + i2];
			data1 = getsha256hash(data1);
			data2 = getsha256hash(data2);

			vTxHashs.push_back(getsha256hash(data1 + data2));
        }

        j += nSize;
    }

	merkle = vTxHashs[vTxHashs.size() - 1];

	return merkle;
}

// int ca_algorithm::MemVerifyContractTransactionTx(const CTransaction & tx)
// {
//     uint64_t startTime=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
// 	// Transaction version number must be 0
//     if (tx.version() != global::ca::kInitTransactionVersion && tx.version() != global::ca::kCurrentTransactionVersion)
//     {
//         return -1;
//     }

//     // Is the transaction type a normal transaction
//     if ((TransactionType)GetTransactionType(tx) != kTransactionType_Tx)
//     {
//         return -2;
//     }

// 	if (tx.time() <= global::ca::kGenesisTime)
// 	{
// 		return -3;
// 	}

// 	// Is the transaction hash length 64
//     if (tx.hash().size() != 64)
//     {
//         return -4;
//     }

//     // Verify whether the transaction hash is consistent
//     if (tx.hash() != ca_algorithm::CalcTransactionHash(tx))
//     {
//         return -5;
//     }

// 	if (tx.identity().size() == 0)
// 	{
// 		return -6;
// 	}
    
// 	if ( !CheckBase58Addr(tx.identity()) )
// 	{
// 		return -7;
// 	}

//     if (tx.utxo().owner_size() == 0)
//     {
//         return -8;
//     }
    
//     // The number of vins must be less than or equal to 100 (it will be adjusted later)
//     if (tx.utxo().vin_size() > 100 || tx.utxo().vin_size() <= 0)
//     {
//         ERRORLOG("The number of vins must be less than or equal to 100!");
//         return -9;
//     }

//     if (tx.utxo().vout_size() < 3)
//     {
//         return -10;
//     }

//     if (tx.utxo().multisign_size() == 0)
//     {
//         return -11;
//     }

//     global::ca::TxType txType = (global::ca::TxType)tx.txtype();
// 	int needConsensus = tx.consensus();
//     nlohmann::json txInfo;
	
//     if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
//     {
//         try
//         {
//             nlohmann::json dataJson = nlohmann::json::parse(tx.data());
//             txInfo = dataJson["TxInfo"].get<nlohmann::json>();
//         }
//         catch (...)
//         {
//             return -12;
//         }

//         if (needConsensus != global::ca::kConsensus)
//         {
//             return -13;
//         }
//     }

//     // The transaction type can only be one of six, the output quantity  can only be 2
// 	bool isTx = false;
//     bool isStake = false;
//     bool isUnstake = false;
//     bool isInvest = false;
//     bool isDisinvest = false;
//     bool isBonus = false;
// 	bool isDeclare = false;
//     bool isDeployContract = false;
//     bool isCallContract = false;
//     uint64_t stakeAmount = 0;
//     uint64_t investAmount = 0; 

// 	try
// 	{
// 		if (global::ca::TxType::kTxTypeStake == txType)
// 		{
// 			isStake = true;
// 			stakeAmount = txInfo["StakeAmount"].get<uint64_t>();
// 			std::string pledgeType = txInfo["StakeType"].get<std::string>();

// 			if (global::ca::kStakeTypeNet != pledgeType)
// 			{
// 				ERRORLOG("Stake type can only be online stake and public network stake!");            
// 				return -14;
// 			}
// 		}
// 		else if (global::ca::TxType::kTxTypeUnstake == txType)
// 		{
// 			isUnstake = true;
// 			std::string redeemUtxoHash = txInfo["UnstakeUtxo"].get<std::string>();
// 			if(redeemUtxoHash.size() != 64)
// 			{
// 				return -15;
// 			}
// 		}
// 		else if (global::ca::TxType::kTxTypeInvest == txType)
// 		{
// 			isInvest = true;
// 			investAmount = txInfo["InvestAmount"].get<uint64_t>();
// 			std::string investNode = txInfo["BonusAddr"].get<std::string>();
// 			if (!CheckBase58Addr(investNode))
// 			{
// 				return -16;
// 			}
// 			std::string investType = txInfo["InvestType"].get<std::string>();
// 			if (global::ca::kInvestTypeNormal != investType )
// 			{
// 				ERRORLOG("the invest type can only be invest licence and reserve invest licence!");
// 				return -17;
// 			}
// 		}
// 		else if (global::ca::TxType::kTxTypeDisinvest == txType)
// 		{
// 			isDisinvest = true;
// 			std::string divestUtxoHash = txInfo["DisinvestUtxo"].get<std::string>();
// 			if (divestUtxoHash.size() != 64)
// 			{
// 				return -18;
// 			}
// 		}
// 		else if (global::ca::TxType::kTxTypeBonus == txType)
// 		{
// 			isBonus = true;
// 			uint64_t bonusAddrList;
// 			bonusAddrList = txInfo["BonusAddrList"].get<uint64_t>();

// 			if (bonusAddrList != tx.utxo().vout_size())
// 			{
// 				return -19;
// 			}
// 		}
//         else if (global::ca::TxType::kTxTypeDeclaration == txType)
//         {
//             isDeclare = true;
// 			std::string multiSignPub = txInfo["MultiSignPub"].get<std::string>();
// 			nlohmann::json signAddrList = txInfo["SignAddrList"].get<nlohmann::json>();
//             multiSignPub = Base64Decode(multiSignPub);
// 			uint64_t threshold = txInfo["SignThreshold"].get<uint64_t>();
            
// 			std::string multiSignAddr = GetBase58Addr(multiSignPub, Base58Ver::kBase58Ver_MultiSign);
// 			if (tx.utxo().vout_size() != 3 && tx.utxo().vout(1).addr() != multiSignAddr)
// 			{
// 				return -20;
// 			}

// 			if(signAddrList.size() < 2 || signAddrList.size() > 100)
// 			{
// 				return -21;
// 			}

//             std::set<std::string> setSignAddr;
// 			for (auto & signAddr : signAddrList)
// 			{
// 				if (!CheckBase58Addr(signAddr, Base58Ver::kBase58Ver_Normal))
// 				{
// 					return -22;
// 				}
//                 setSignAddr.insert(std::string(signAddr));
// 			}

//             if (setSignAddr.size() != signAddrList.size())
//             {
//                 return -23;
//             }

// 			if (threshold > signAddrList.size())
// 			{
// 				return -24;
// 			}
//         }
//         else if (global::ca::TxType::kTxTypeDeployContract == txType)
//         {
//             isDeployContract = true;
//         }
//         else if (global::ca::TxType::kTxTypeCallContract == txType)
//         {
//             isCallContract = true;
//         }
// 		else if (global::ca::TxType::kTxTypeTx == txType)
// 		{
// 			isTx = true;
// 		}               
// 		else
// 		{
// 			ERRORLOG("Unknown tx type!");  
// 			return -25;
// 		}
// 	}
// 	catch(const std::exception& e)
// 	{
// 		std::cerr << e.what() << '\n';
// 		return -26;
// 	}


//     if((isStake || isUnstake || isInvest || isDisinvest || isDeclare) && tx.utxo().vout_size() != 3)
//     {
//         ERRORLOG("The number of vouts must be equal to 3!" );
//         return -27;
//     }

//     std::set<std::string> ownerAddrs;
//     {
//         std::vector<std::string> tmpAddrs(tx.utxo().owner().begin(), tx.utxo().owner().end());
//         std::set<std::string>(tmpAddrs.cbegin(), tmpAddrs.cend()).swap(ownerAddrs);

// 		if (ownerAddrs.size() == 0)
// 		{
// 			return -28;
// 		}

// 		for (auto & addr : ownerAddrs)
// 		{
// 			if (!isTx)
// 			{
// 				if (CheckBase58Addr(addr, Base58Ver::kBase58Ver_MultiSign) == true)
// 				{
// 					return -29;
// 				}
// 			}
// 			else
// 			{
// 				if (!CheckBase58Addr(addr, Base58Ver::kBase58Ver_All))
// 				{
// 					return -30;
// 				}
// 			}
// 		}

//         // The owner size of the following five types of transactions must be 1
//         if (isStake || isUnstake || isInvest || isDisinvest || isBonus || isDeclare)
//         {
//             if (1 != ownerAddrs.size())
//             {
//                 ERRORLOG( "The owner size of the following five types of transactions must be 1!" );
//                 return -31;
//             }
//         }
//         else
//         {
//             // Txowner does not allow duplicate
//             if (tmpAddrs.size() != ownerAddrs.size())
//             {
//                 ERRORLOG( "Txowner does not allow duplicate!" );
//                 return -32;
//             }
//         }
//     }

//     {
//         uint64_t multiSignOwners = 0;
//         if (ownerAddrs.size() > 1)
//         {
//             for (auto & addr : ownerAddrs)
//             {
//                 if (CheckBase58Addr(addr, Base58Ver::kBase58Ver_MultiSign))
//                 {
//                     multiSignOwners++;
//                 }
//             }

//             if (multiSignOwners > 1)
//             {
//                 return -33;
//             }
//         }
//     }
    
//     bool isMultiSign = IsMultiSign(tx);
   
//     std::set<std::string> vinAddrs;
//     std::set<std::string> vinUtxos;
// 	uint64_t totalVinSize = 0;
//     for (auto &vin : tx.utxo().vin())
//     {
//         std::string ownerAddr;
//         if(vin.contractaddr().empty())
//         {
//             if (vin.vinsign().pub().size() == 0)
//             {
//                 return -34;
//             }
//             Base58Ver ver = isMultiSign ? Base58Ver::kBase58Ver_MultiSign : Base58Ver::kBase58Ver_Normal;
//             ownerAddr = GetBase58Addr(vin.vinsign().pub(), ver);
//         }
//         else if(isDeployContract || isCallContract)
//         {
//             if (vin.vinsign().pub().size() != 0)
//             {
//                 return -36;
//             }
//             ownerAddr = vin.contractaddr();
//         }

//         if (!CheckBase58Addr(ownerAddr))
//         {
//             ERRORLOG( "Check Base58Addr failed!" );
//             return -35;
//         }
		
//         vinAddrs.insert(ownerAddr);
// 		if (vin.prevout_size() == 0)
// 		{
// 			return -36;
// 		}

// 		for(auto & prevout : vin.prevout())
// 		{
// 			if (prevout.hash().size() != 64)
// 			{
// 				return -37;
// 			}
// 			totalVinSize++;
// 			vinUtxos.insert(prevout.hash() + "_" + std::to_string(prevout.n()));
// 		}
//     }
	
//     // Verify whether txowner and VIN signers are consistent
//     if (!std::equal(ownerAddrs.cbegin(), ownerAddrs.cend(), vinAddrs.cbegin(), vinAddrs.cend()))
//     {
//         ERRORLOG("Txowner and VIN signers are not consistent!");
//         return -38;
//     }

// 	// Verify the sequence of VIN
//     for (int i = 0; i < tx.utxo().vin_size(); i++)
//     {
//         if (i != tx.utxo().vin(i).sequence())
//         {
//             ERRORLOG(RED "The sequence of VIN is not consistent!" RESET);
//             return -39;
//         }        
//     }
    
// 	if (isUnstake || isDisinvest)
//     {
//         if (vinUtxos.size() != totalVinSize && (vinUtxos.size() != (totalVinSize - 1)))
//         {
//             ERRORLOG("Vin cannot be repeated except for the redeem or divest transaction!");
//             return -40;
//         }
//     }
//     else if(!(isDeployContract || isCallContract))
//     {
//         if (vinUtxos.size() != totalVinSize)
//         {
//             ERRORLOG( "Vin cannot be repeated except for the redeem or divest transaction!" );
//             return -41;
//         }
//     }

// 	if (tx.utxo().vout_size() == 0 || tx.utxo().vout_size() > 1000)
// 	{
// 		return -42;
// 	}

//     std::set<std::string> voutAddrs;
//     for (int i = 0; i < tx.utxo().vout_size(); i++)
//     {
//         auto &vout = tx.utxo().vout(i);

//         if(i == tx.utxo().vout_size() - 1)
//         {

//             if(tx.utxo().vout(i).addr() != global::ca::kVirtualBurnGasAddr)
//             {
//                 ERRORLOG("Destroy address is not a virtual address !");
//                 return -43;
//             }


//             uint64_t gas = 0;
//             if(CalculateGas(tx,gas) != 0)
//             {
//                 ERRORLOG("CalculateGas error gas = {}", gas);
//                 return -44;
//             }

//             if(tx.utxo().vout(i).value() != gas)
//             {
//                 ERRORLOG("Destroy amount error !");
//                 return -45;
//             }
//         }   
//         else
//         {
//             if (isStake)
//             {
//                 if (i == 0 && (vout.addr() != global::ca::kVirtualStakeAddr || vout.value() != stakeAmount))
//                 {
//                     // The pledge amount should be consistent with the output
//                     ERRORLOG(RED "The pledge amount should be consistent with the output!" RESET);
//                     return -46;
//                 }

//                 if(i == 0 && vout.value() < 100000000000)
//                 {
//                     ERRORLOG(RED "The pledge amount should be consistent with the output!" RESET);
//                     return -47;
//                 }
                
//                 if (i == 1 && (! CheckBase58Addr(vout.addr(), Base58Ver::kBase58Ver_Normal)))
//                 {
//                     return -48;
//                 }
                
//                 if (i >= 3)
//                 {
//                     return -49;
//                 }
//             }
//             else if(isInvest)
//             {
//                 if (i == 0 && (vout.addr() != global::ca::kVirtualInvestAddr || vout.value() != investAmount))
//                 {
//                     // The invest amount should be consistent with the output
//                     ERRORLOG(RED "The invest amount should be consistent with the output!" RESET);
//                     return -50;
//                 }
                
//                 if (i == 1 && (! CheckBase58Addr(vout.addr(), Base58Ver::kBase58Ver_Normal)))
//                 {
//                     return -51;
//                 }
                
//                 if(i >= 3)
//                 {
//                     return -52;
//                 }
//             }
//             else if (isDeclare)
//             {
//                 if (i == 0 && (!CheckBase58Addr(vout.addr(), Base58Ver::kBase58Ver_MultiSign) || vout.value() < 0) )
//                 {
//                     return -53;
//                 }
                
//                 if (i == 1 && (!CheckBase58Addr(vout.addr(), Base58Ver::kBase58Ver_Normal) || (*ownerAddrs.begin() != vout.addr() ) ) )
//                 {
//                     return -54;
//                 }
//                 if (i >= 2)
//                 {
//                     return -55;
//                 }
//             }
//             else if(isDeployContract)
//             {
//                 if (i == 0 && vout.addr() != global::ca::kVirtualDeployContractAddr)
//                 {
//                     // The DeployContract amount should be consistent with the output
//                     ERRORLOG(RED "The DeployContract amount should be consistent with the output!" RESET);
//                     return -56;
//                 }
//             }
//             else if(isCallContract && i == 0 && (vout.addr() == global::ca::kVirtualDeployContractAddr))
//             {
//                 DEBUGLOG("i {},isCall Contract{},Addr",i,isCallContract,vout.addr());
//                 continue; 
//             }
//             else
//             {
//                 if (!CheckBase58Addr(vout.addr()))
//                 {
//                     DEBUGLOG("vout.addr() {}",vout.addr());
//                     ERRORLOG( "Check Base58Addr failed!" );
//                     return -58;
//                 }
                
//                 // The amount in the output must be Greater than 0
//                 if (vout.value() < 0)
//                 {
//                     ERRORLOG( "The amount in the output must be Greater than 0!" );
//                     return -59;
//                 }
//             }
//         }
       
//         voutAddrs.insert(vout.addr());
//     }

//     if (vinAddrs.size() > 1 && !isDeployContract && !isCallContract)
//     {
//         std::vector<std::string> vDiff;
//         std::set_difference(voutAddrs.begin(), voutAddrs.end(),
//                             vinAddrs.begin(),vinAddrs.end(),
//                             std::back_inserter(vDiff));
//         if(vDiff.size() > 2)
//         {
//             ERRORLOG(RED "Multi-to-Multi transaction is not allowed!" RESET);
//             return -60;       
//         }
//     }

//     auto VerifySignLambda = [](const CSign & sign, const std::string & serHash)->int {
        
//         if (sign.sign().size() == 0 || sign.pub().size() == 0)
// 		{
// 			return -61;
// 		}
//         if (serHash.size() == 0)
//         {
//             return -62;
//         }

//         //TODO
//     EVP_PKEY* eckey = nullptr;
//     if(GetEDPubKeyByBytes(sign.pub(), eckey) == false)
//     {
//         EVP_PKEY_free(eckey);
//         ERRORLOG(RED "Get public key from bytes failed!" RESET);
//         return -3;
//     }

//     if(ED25519VerifyMessage(serHash, eckey, sign.sign()) == false)
//     {
//         EVP_PKEY_free(eckey);
//         ERRORLOG(RED "Public key verify sign failed!" RESET);
//         return -4;
//     }
//     EVP_PKEY_free(eckey);
//         // EVP_PKEY* eckey = nullptr;
//         // if(GetEDPubKeyByBytes(sign.pub(), eckey) == false)
//         // {
//         //     EVP_PKEY_free(eckey);
//         //     ERRORLOG(RED "Get public key from bytes failed!" RESET);
//         //     return -63;
//         // }

//         // if(ED25519VerifyMessage(serHash, eckey, sign.sign()) == false)
//         // {
//         //     EVP_PKEY_free(eckey);
//         //     ERRORLOG(RED "Public key verify sign failed!" RESET);
//         //     return -64;
//         // }
//         // EVP_PKEY_free(eckey);
//         return 0;
//     };

//     if( !(tx.utxo().vin_size() == tx.utxo().multisign_size() == tx.utxo().owner_size() == 1 && tx.utxo().vout_size() == 3 && tx.utxo().vout(1).addr() == tx.utxo().owner(0)) )
//     {
//         if( !(isStake || isUnstake || isInvest || isDisinvest || isBonus || isDeclare) )
//         {
//             // check vin sign 
//             for (auto & v : tx.utxo().vin())
//             {
//                 if(!v.contractaddr().empty() && (isDeployContract || isCallContract))
//                 {
//                     if(v.vinsign().pub().empty())
//                     {
//                         continue;
//                     }
//                     return -99;
//                 }
//                 CTxInput vin = v;
//                 CSign sign = vin.vinsign();
//                 vin.clear_vinsign();
//                 std::string serVinHash = getsha256hash(vin.SerializeAsString());

//                 int verifySignRet = VerifySign(sign, serVinHash);
//                 if (verifySignRet != 0)
//                 {
//                     return -65;
//                 }
//             }
//         }
//     }

// 	// check multiSign 
// 	if (tx.utxo().multisign_size() == 0)
// 	{
// 		return -66;
// 	}

// 	std::set<std::string> multiSignAddr;
// 	CTxUtxo utxo = tx.utxo();
// 	utxo.clear_multisign();
// 	std::string serUtxoHash = getsha256hash(utxo.SerializeAsString());
// 	for(auto & multiSign : tx.utxo().multisign())
// 	{
// 		multiSignAddr.insert(GetBase58Addr(multiSign.pub()));

//         int verifySignRet = VerifySign(multiSign, serUtxoHash);
//         if (verifySignRet != 0)
//         {
//             return -67;
//         }
// 	}

// 	if (isMultiSign)
// 	{
// 		if (GetBase58Addr(tx.utxo().multisign(0).pub(), Base58Ver::kBase58Ver_MultiSign) != *ownerAddrs.begin())
// 		{
// 			return -68;
// 		}
// 	}
// 	else if(!(isDeployContract || isCallContract))
// 	{
// 		if (!std::equal(ownerAddrs.cbegin(), ownerAddrs.cend(), multiSignAddr.cbegin(), multiSignAddr.cend()))
// 		{
// 			ERRORLOG("Txowner and multi sign signers are not consistent!");
// 			return -69;
// 		}
// 	}

// 	// check tx sign
//     if (tx.verifysign_size() < 0 || tx.verifysign_size() > global::ca::KRandomNodeGroup)
//     {
//         return -70;
//     }

//     if(global::ca::TxType::kTxTypeCallContract != txType && global::ca::TxType::kTxTypeDeployContract != txType)
//     {
//         if (tx.verifysign_size() > 0 && GetBase58Addr(tx.verifysign(0).pub()) != tx.identity())
//         {
//             ERRORLOG("tx verify sign size = {} " , tx.verifysign_size());
//             ERRORLOG("addr = {} , tx identity = {} ", GetBase58Addr(tx.verifysign(0).pub()), tx.identity());
//             return -71;
//         }
//     }

    
// 	CTransaction copyTx = tx;
// 	copyTx.clear_hash();
// 	copyTx.clear_verifysign();
// 	std::string serTxHash = getsha256hash(copyTx.SerializeAsString());

//     if(tx.verifysign_size() != 0)
//     {
//         if (!CheckBase58Addr(GetBase58Addr(tx.verifysign(0).pub()), Base58Ver::kBase58Ver_Normal))
//         {
//             return -72;
//         }

//         int verifySignRet = VerifySign(tx.verifysign(0), serTxHash);
//         if (verifySignRet != 0)
//         {
//             return -73;
//         }
//     }


//     for(int i = 1; i < tx.verifysign_size(); i++)
//     {
//         if (!CheckBase58Addr(GetBase58Addr(tx.verifysign(i).pub()), Base58Ver::kBase58Ver_Normal))
//         {
//             return -74;
//         }
// 	}
    
//     if (tx.info().size() != 0)
//     {
//         return -75;
//     }

//     if (tx.reserve0().size() != 0 || tx.reserve1().size() != 0)
//     {
//         return -76;
//     }

//     uint64_t endTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
//     if(global::ca::TxType::kTxTypeTx == txType)
//     {
//         MagicSingleton<DONbenchmark>::GetInstance()->AddtransactionMemVerifyMap(tx.hash(), endTime - startTime);
//     }

// 	return 0;

// }
int ca_algorithm::MemVerifyTransactionTx(const CTransaction & tx)
{
    uint64_t start_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	// Transaction version number must be 0
    if (tx.version() != 0)
    {
        return -1;
    }

    // Is the transaction type a normal transaction
    if (GetTransactionType(tx) != kTransactionType_Tx)
    {
        return -2;
    }

	if (tx.time() <= global::ca::kGenesisTime)
	{
		return -3;
	}

	// Is the transaction hash length 64
    if (tx.hash().size() != 64)
    {
        return -4;
    }

    // Verify whether the transaction hash is consistent
    if (tx.hash() != ca_algorithm::CalcTransactionHash(tx))
    {
        ERRORLOG("tx.hash() = {} , CalcTransactionHash = {}",tx.hash(), ca_algorithm::CalcTransactionHash(tx));
        return -5;
    }

	if (tx.identity().size() == 0)
	{
		return -6;
	}
    
	if ( !CheckBase58Addr(tx.identity()) )
	{
		return -7;
	}

    if (tx.utxo().owner_size() == 0)
    {
        return -8;
    }
    
    // The number of vins must be less than or equal to 100 (it will be adjusted later)
    if (tx.utxo().vin_size() > 100 || tx.utxo().vin_size() <= 0)
    {
        ERRORLOG("The number of vins must be less than or equal to 100!");
        return -9;
    }

    if (tx.utxo().vout_size() < 3)
    {
        return -10;
    }

    if (tx.utxo().multisign_size() == 0)
    {
        return -11;
    }
    
    global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();
	int needConsensus = tx.consensus();
    nlohmann::json tx_info;
	
    if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
    {
        try
        {
            nlohmann::json data_json = nlohmann::json::parse(tx.data());
            tx_info = data_json["TxInfo"].get<nlohmann::json>();
        }
        catch (...)
        {
            return -12;
        }

        if (needConsensus != global::ca::kConsensus)
        {
            return -13;
        }
    }

    // The transaction type can only be one of six, the output quantity  can only be 2
	bool is_tx = false;
    bool is_stake = false;
    bool is_unstake = false;
    bool is_invest = false;
    bool is_disinvest = false;
    bool is_bonus = false;
	bool is_declare = false;
    bool is_deployContract = false;
    bool is_callContract = false;
    uint64_t stake_amount = 0;
    uint64_t invest_amount = 0; 

	try
	{
		if (global::ca::TxType::kTxTypeStake == tx_type)
		{
			is_stake = true;
			stake_amount = tx_info["StakeAmount"].get<uint64_t>();
			std::string pledge_type = tx_info["StakeType"].get<std::string>();

			if (global::ca::kStakeTypeNet != pledge_type)
			{
				ERRORLOG("Stake type can only be online stake and public network stake!");            
				return -14;
			}
		}
		else if (global::ca::TxType::kTxTypeUnstake == tx_type)
		{
			is_unstake = true;
			std::string redeem_utxo_hash = tx_info["UnstakeUtxo"].get<std::string>();
			if(redeem_utxo_hash.size() != 64)
			{
				return -15;
			}
		}
		else if (global::ca::TxType::kTxTypeInvest == tx_type)
		{
			is_invest = true;
			invest_amount = tx_info["InvestAmount"].get<uint64_t>();
			std::string invest_node = tx_info["BonusAddr"].get<std::string>();
			if (!CheckBase58Addr(invest_node))
			{
				return -16;
			}
			std::string invest_type = tx_info["InvestType"].get<std::string>();
			if (global::ca::kInvestTypeNormal != invest_type )
			{
				ERRORLOG("the invest type can only be invest licence and reserve invest licence!");
				return -17;
			}
		}
		else if (global::ca::TxType::kTxTypeDisinvest == tx_type)
		{
			is_disinvest = true;
			std::string divest_utxo_hash = tx_info["DisinvestUtxo"].get<std::string>();
			if (divest_utxo_hash.size() != 64)
			{
				return -18;
			}
		}
		else if (global::ca::TxType::kTxTypeBonus == tx_type)
		{
			is_bonus = true;
			uint64_t bonusAddrList;
			bonusAddrList = tx_info["BonusAddrList"].get<uint64_t>();

			if (bonusAddrList != tx.utxo().vout_size())
			{
				return -19;
			}
		}
        else if (global::ca::TxType::kTxTypeDeclaration == tx_type)
        {
            is_declare = true;
			std::string multiSignPub = tx_info["MultiSignPub"].get<std::string>();
            multiSignPub = Base64Decode(multiSignPub);
			nlohmann::json signAddrList = tx_info["SignAddrList"].get<nlohmann::json>();
			uint64_t threshold = tx_info["SignThreshold"].get<uint64_t>();
            
			std::string multiSignAddr = GetBase58Addr(multiSignPub, Base58Ver::kBase58Ver_MultiSign);
			if (tx.utxo().vout_size() != 3 && tx.utxo().vout(1).addr() != multiSignAddr)
			{
				return -20;
			}

			if(signAddrList.size() < 2 || signAddrList.size() > 100)
			{
				return -21;
			}

            std::set<std::string> setSignAddr;
			for (auto & signAddr : signAddrList)
			{
				if (!CheckBase58Addr(signAddr, Base58Ver::kBase58Ver_Normal))
				{
					return -22;
				}
                setSignAddr.insert(std::string(signAddr));
			}

            if (setSignAddr.size() != signAddrList.size())
            {
                return -23;
            }

			if (threshold > signAddrList.size())
			{
				return -24;
			}
        }
        else if (global::ca::TxType::kTxTypeDeployContract == tx_type)
        {
            is_deployContract = true;
        }
        else if (global::ca::TxType::kTxTypeCallContract == tx_type)
        {
            is_callContract = true;
        }
		else if (global::ca::TxType::kTxTypeTx == tx_type)
		{
			is_tx = true;
		}               
		else
		{
			ERRORLOG("Unknown tx type!");  
			return -25;
		}
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		return -26;
	}


    if((is_stake || is_unstake || is_invest || is_disinvest || is_declare) && tx.utxo().vout_size() != 3)
    {
        ERRORLOG("The number of vouts must be equal to 3!" );
        return -27;
    }

    std::set<std::string> owner_addrs;
    {
        std::vector<std::string> tmp_addrs(tx.utxo().owner().begin(), tx.utxo().owner().end());
        std::set<std::string>(tmp_addrs.cbegin(), tmp_addrs.cend()).swap(owner_addrs);

		if (owner_addrs.size() == 0)
		{
			return -28;
		}

		for (auto & addr : owner_addrs)
		{
			if (!is_tx)
			{
				if (CheckBase58Addr(addr, Base58Ver::kBase58Ver_MultiSign) == true)
				{
					return -29;
				}
			}
			else
			{
				if (!CheckBase58Addr(addr, Base58Ver::kBase58Ver_All))
				{
					return -30;
				}
			}
		}

        // The owner size of the following five types of transactions must be 1
        if (is_stake || is_unstake || is_invest || is_disinvest || is_bonus || is_declare)
        {
            if (1 != owner_addrs.size())
            {
                ERRORLOG( "The owner size of the following five types of transactions must be 1!" );
                return -31;
            }
        }
        else
        {
            // Txowner does not allow duplicate
            if (tmp_addrs.size() != owner_addrs.size())
            {
                ERRORLOG( "Txowner does not allow duplicate!" );
                return -32;
            }
        }
    }

    {
        uint64_t multiSignOwners = 0;
        if (owner_addrs.size() > 1)
        {
            for (auto & addr : owner_addrs)
            {
                if (CheckBase58Addr(addr, Base58Ver::kBase58Ver_MultiSign))
                {
                    multiSignOwners++;
                }
            }

            if (multiSignOwners > 1)
            {
                return -33;
            }
        }
    }
    
    bool isMultiSign = IsMultiSign(tx);
   
    std::set<std::string> vin_addrs;
    std::set<std::string> vin_utxos;
	uint64_t total_vin_size = 0;
    std::string addr;
    for (auto &vin : tx.utxo().vin())
    {
        if(vin.contractaddr().empty())
        {
		if (vin.vinsign().pub().size() == 0)
		{
			return -34;
		}

        Base58Ver ver = isMultiSign ? Base58Ver::kBase58Ver_MultiSign : Base58Ver::kBase58Ver_Normal;
        addr = GetBase58Addr(vin.vinsign().pub(), ver);
        }
        else if(is_deployContract|| is_callContract)
        {
            if(vin.vinsign().pub().size() != 0)
            {
                return -35;
            }
            addr = vin.contractaddr();
        }
        if (!CheckBase58Addr(addr))
        {
            ERRORLOG( "Check Base58Addr failed!" );
            return -35;
        }
        vin_addrs.insert(addr);
		if (vin.prevout_size() == 0)
		{
			return -36;
		}

		for(auto & prevout : vin.prevout())
		{
			if (prevout.hash().size() != 64)
			{
				return -37;
			}
			total_vin_size++;
			vin_utxos.insert(prevout.hash() + "_" + std::to_string(prevout.n()));
		}
    }
	
    // Verify whether txowner and VIN signers are consistent
    if (!std::equal(owner_addrs.cbegin(), owner_addrs.cend(), vin_addrs.cbegin(), vin_addrs.cend()))
    {
        ERRORLOG("Txowner and VIN signers are not consistent!");
        return -38;
    }

	// Verify the sequence of VIN
    for (int i = 0; i < tx.utxo().vin_size(); i++)
    {
        if (i != tx.utxo().vin(i).sequence())
        {
            ERRORLOG(RED "The sequence of VIN is not consistent!" RESET);
            return -39;
        }

        
    }
    
    // Vin cannot be repeated except for the redeem or divest transaction
	if (is_unstake || is_disinvest)
    {
        if (vin_utxos.size() != total_vin_size && (vin_utxos.size() != (total_vin_size - 1)))
        {
            ERRORLOG("Vin cannot be repeated except for the redeem or divest transaction!");
            return -40;
        }
    }
    else if(!(is_deployContract || is_callContract))
    {
        if (vin_utxos.size() != total_vin_size)
        {
            ERRORLOG( "Vin cannot be repeated except for the redeem or divest transaction!" );
            return -41;
        }
    }

	if (tx.utxo().vout_size() == 0 || tx.utxo().vout_size() > 1000)
	{
		return -42;
	}

    std::set<std::string> vout_addrs;
    for (int i = 0; i < tx.utxo().vout_size(); i++)
    {
        auto &vout = tx.utxo().vout(i);
        //The last vout is that destruction requires special judgment
        if(i == tx.utxo().vout_size() - 1)
        {
            //Determine whether the destroyed address is a virtual address
            if(tx.utxo().vout(i).addr() != global::ca::kVirtualBurnGasAddr)
            {
                ERRORLOG("Destroy address is not a virtual address !");
                return -43;
            }

            //Judge whether the destroyed amount is correct
            uint64_t gas = 0;
            if(CalculateGas(tx,gas) != 0)
            {
                ERRORLOG("CalculateGas error gas = {}", gas);
                return -44;
            }
            
            if(tx.utxo().vout(i).value() != gas)
            {
                ERRORLOG("gas is {}",gas);
                ERRORLOG("tx.utxo().vout(i).value()",tx.utxo().vout(i).value());
                ERRORLOG("Destroy amount error !");
                return -45;
            }
        }   
        else
        {
            if (is_stake)
            {
                if (i == 0 && (vout.addr() != global::ca::kVirtualStakeAddr || vout.value() != stake_amount))
                {
                    // The pledge amount should be consistent with the output
                    ERRORLOG(RED "The pledge amount should be consistent with the output!" RESET);
                    return -46;
                }

                if(i == 0 && vout.value() < global::ca::kMinStakeAmt)
                {
                    ERRORLOG(RED "The pledge amount should be consistent with the output! {}",vout.value(), RESET);
                    return -47;
                }
                
                if (i == 1 && (! CheckBase58Addr(vout.addr(), Base58Ver::kBase58Ver_Normal)))
                {
                    return -48;
                }
                
                if (i >= 3)
                {
                    return -49;
                }
            }
            else if(is_invest)
            {
                if (i == 0 && (vout.addr() != global::ca::kVirtualInvestAddr || vout.value() != invest_amount))
                {
                    // The invest amount should be consistent with the output
                    ERRORLOG(RED "The invest amount should be consistent with the output!" RESET);
                    return -50;
                }
                
                if (i == 1 && (! CheckBase58Addr(vout.addr(), Base58Ver::kBase58Ver_Normal)))
                {
                    return -51;
                }
                
                if(i >= 3)
                {
                    return -52;
                }
            }
            else if (is_declare)
            {
                if (i == 0 && (!CheckBase58Addr(vout.addr(), Base58Ver::kBase58Ver_MultiSign) || vout.value() < 0) )
                {
                    return -53;
                }
                
                if (i == 1 && (!CheckBase58Addr(vout.addr(), Base58Ver::kBase58Ver_Normal) || (*owner_addrs.begin() != vout.addr() ) ) )
                {
                    return -54;
                }
                if (i >= 2)
                {
                    return -55;
                }
            }
            else if(is_deployContract)
            {
                if (i == 0 && vout.addr() != global::ca::kVirtualDeployContractAddr)
                {
                    // The DeployContract amount should be consistent with the output
                    ERRORLOG(RED "The DeployContract amount should be consistent with the output!" RESET);
                    return -56;
                }
                
                if (i == 1 && (! CheckBase58Addr(vout.addr(), Base58Ver::kBase58Ver_Normal)))
                {
                    return -57;
                }
            }
            else if(is_callContract && i == 0 && (vout.addr() == global::ca::kVirtualCallContractAddr))
            {
                continue;
            }
            else
            {
                if (!CheckBase58Addr(vout.addr()))
                {
                    ERRORLOG( "Check Base58Addr failed!" );
                    return -58;
                }
                
                // The amount in the output must be Greater than 0
                if (vout.value() < 0)
                {
                    ERRORLOG( "The amount in the output must be Greater than 0!" );
                    return -59;
                }
            }
        }
       
        vout_addrs.insert(vout.addr());
    }

    // Multi-to-Multi transaction is not allowed
    if (vin_addrs.size() > 1 &&!is_deployContract && !is_callContract)
    {
        std::vector<std::string> v_diff;
        std::set_difference(vout_addrs.begin(), vout_addrs.end(),
                            vin_addrs.begin(),vin_addrs.end(),
                            std::back_inserter(v_diff));
        if(v_diff.size() > 2)
        {
            ERRORLOG(RED "Multi-to-Multi transaction is not allowed!" RESET);
            return -60;       
        }
    }

    auto VerifySignLambda = [](const CSign & sign, const std::string & serHash)->int {
        
        if (sign.sign().size() == 0 || sign.pub().size() == 0)
		{
			return -61;
		}
        if (serHash.size() == 0)
        {
            return -62;
        }

        EVP_PKEY* eckey = nullptr;
        if(GetEDPubKeyByBytes(sign.pub(), eckey) == false)
        {
            EVP_PKEY_free(eckey);
            ERRORLOG(RED "Get public key from bytes failed!" RESET);
            return -63;
        }

        if(ED25519VerifyMessage(serHash, eckey, sign.sign()) == false)
        {
            EVP_PKEY_free(eckey);
            ERRORLOG(RED "Public key verify sign failed!" RESET);
            return -64;
        }
        EVP_PKEY_free(eckey);
        return 0;
    };

    if( !(tx.utxo().vin_size() == tx.utxo().multisign_size() == tx.utxo().owner_size() == 1 && tx.utxo().vout_size() == 3 && tx.utxo().vout(1).addr() == tx.utxo().owner(0)) )
    {
        if( !(is_stake || is_unstake || is_invest || is_disinvest || is_bonus || is_declare) )
        {
            // check vin sign 

            for (auto & v : tx.utxo().vin())
            {
                if(!v.contractaddr().empty() && (is_deployContract || is_callContract))
                {
                    if(v.vinsign().pub().empty())
                    {
                        continue;
                    }
                    return -99;
                }
                CTxInput vin = v;
                CSign sign = vin.vinsign();
                vin.clear_vinsign();
                std::string serVinHash = getsha256hash(vin.SerializeAsString());

                int verifySignRet = VerifySignLambda(sign, serVinHash);
                if (verifySignRet != 0)
                {
                    return -65;
                }
            }
        }
    }


	// check multiSign 
	if (tx.utxo().multisign_size() == 0)
	{
		return -66;
	}

	std::set<std::string> multiSignAddr;
	CTxUtxo utxo = tx.utxo();
	utxo.clear_multisign();
	std::string serUtxoHash = getsha256hash(utxo.SerializeAsString());
	for(auto & multiSign : tx.utxo().multisign())
	{
		multiSignAddr.insert(GetBase58Addr(multiSign.pub()));

        int verifySignRet = VerifySignLambda(multiSign, serUtxoHash);
        if (verifySignRet != 0)
        {
            return -67;
        }
	}

	if (isMultiSign)
	{
		if (GetBase58Addr(tx.utxo().multisign(0).pub(), Base58Ver::kBase58Ver_MultiSign) != *owner_addrs.begin())
		{
			return -68;
		}
	}
	else if(!(is_deployContract || is_callContract))
	{
		if (!std::equal(owner_addrs.cbegin(), owner_addrs.cend(), multiSignAddr.cbegin(), multiSignAddr.cend()))
		{
			ERRORLOG("Txowner and multi sign signers are not consistent!");
			return -69;
		}
	}

	// check tx sign
    if (tx.verifysign_size() < 0 || tx.verifysign_size() > global::ca::kConsensus)
    {
        return -70;
    }

    if(global::ca::TxType::kTxTypeCallContract != tx_type && global::ca::TxType::kTxTypeDeployContract != tx_type)
    {
    if (tx.verifysign_size() > 0 && GetBase58Addr(tx.verifysign(0).pub()) != tx.identity())
    {
        ERRORLOG("tx verify sign size = {} " , tx.verifysign_size());
        ERRORLOG("addr = {} , tx identity = {} ", GetBase58Addr(tx.verifysign(0).pub()), tx.identity());
        return -71;
    }
    }
	CTransaction copyTx = tx;
	copyTx.clear_hash();
	copyTx.clear_verifysign();
	std::string serTxHash = getsha256hash(copyTx.SerializeAsString());

	// for (auto & verifySign : tx.verifysign())
	// {
	// 	if (!CheckBase58Addr(GetBase58Addr(verifySign.pub()), Base58Ver::kBase58Ver_Normal))
	// 	{
	// 		return -72;
	// 	}

    //     int verifySignRet = VerifySignLambda(verifySign, serTxHash);
    //     if (verifySignRet != 0)
    //     {
    //         return -73;
    //     }
        
	// }
        if(tx.verifysign_size() != 0)
    {
        if (!CheckBase58Addr(GetBase58Addr(tx.verifysign(0).pub()), Base58Ver::kBase58Ver_Normal))
        {
            return -73;
        }

        int verifySignRet = VerifySignLambda(tx.verifysign(0), serTxHash);
        if (verifySignRet != 0)
        {
            return -74;
        }
    }


    for(int i = 1; i < tx.verifysign_size(); i++)
    {
        if (!CheckBase58Addr(GetBase58Addr(tx.verifysign(i).pub()), Base58Ver::kBase58Ver_Normal))
        {
            return -75;
        }
	}
    
    if (tx.info().size() != 0)
    {
        return -74;
    }

    if (tx.reserve0().size() != 0 || tx.reserve1().size() != 0)
    {
        return -75;
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
				return -76;
			}
            sign_addr = GetBase58Addr(tx_sign_pre_hash.pub());
            if (!CheckBase58Addr(sign_addr))
            {
                ERRORLOG(RED "Check Base58Addr failed!" RESET);
                return -77;
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
            return -78;
        }
    }

    uint64_t end_time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    if(global::ca::TxType::kTxTypeTx == tx_type)
    {
        MagicSingleton<DONbenchmark>::GetInstance()->AddtransactionMemVerifyMap(tx.hash(), end_time - start_time);
    }

	return 0;
}

int ca_algorithm::VerifyTransactionTx(const CTransaction &tx, uint64_t tx_height, bool turn_on_missing_block_protocol, bool verify_abnormal)
{
    uint64_t start_time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    
    DBReader db_reader;

    // Parse parameters
    bool is_redeem = false;
    std::string redeem_utxo_hash;
    bool is_invest = false;
    std::string invest_node;
    uint64_t invest_amount = 0;
    bool is_divest = false;
    std::string invested_node;
    std::string divest_utxo_hash; 
	bool is_declare = false;
	std::string multiSignPub;
    bool is_deploy_contract = false;
    bool is_call_contract = false;
    std::string deployer_addr;
    std::string deploy_hash;
    std::string OwnerEvmAddr;
    std::string code;
    std::string input;
    std::string output;
    nlohmann::json storage;
    global::ca::VmType vm_type;

    global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();

    bool is_claim = false;
    uint64_t claim_amount = 0;

    bool is_tx = false;

    if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
    {
        try
        {
            nlohmann::json data_json = nlohmann::json::parse(tx.data());
            nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();

            if (global::ca::TxType::kTxTypeUnstake == tx_type)
            {   
                is_redeem = true;            
                redeem_utxo_hash = tx_info["UnstakeUtxo"].get<std::string>();
            }
            else if (global::ca::TxType::kTxTypeInvest == tx_type)
            {
                is_invest = true;
                invest_node = tx_info["BonusAddr"].get<std::string>();
                invest_amount = tx_info["InvestAmount"].get<uint64_t>();
            }  
            else if (global::ca::TxType::kTxTypeDisinvest == tx_type)
            {
                is_divest = true;
                divest_utxo_hash = tx_info["DisinvestUtxo"].get<std::string>();
                invested_node = tx_info["BonusAddr"].get<std::string>();        
            }
            else if(global::ca::TxType::kTxTypeBonus == tx_type)
            {
                is_claim = true;
                claim_amount = tx_info["BonusAmount"].get<uint64_t>();  
            }
            else if (global::ca::TxType::kTxTypeDeclaration == tx_type)
            {
                is_declare = true;
                multiSignPub = tx_info["MultiSignPub"].get<std::string>();
                multiSignPub = Base64Decode(multiSignPub);
            }
            else if (global::ca::TxType::kTxTypeDeployContract == tx_type)
            {
                is_deploy_contract = true;
                if(tx_info.find("OwnerEvmAddr") != tx_info.end())
                {
                    OwnerEvmAddr = tx_info["OwnerEvmAddr"].get<std::string>();
                }
                code = tx_info["Code"].get<std::string>();
                output = tx_info["Output"].get<std::string>();
                storage = tx_info["Storage"];
                vm_type = tx_info["VmType"].get<global::ca::VmType>();
            }
            else if (global::ca::TxType::kTxTypeCallContract == tx_type)
            {
                is_call_contract = true;
                if(tx_info.find("OwnerEvmAddr") != tx_info.end())
                {
                    OwnerEvmAddr = tx_info["OwnerEvmAddr"].get<std::string>();
                }
                deployer_addr = tx_info["DeployerAddr"].get<std::string>();
                deploy_hash = tx_info["DeployHash"].get<std::string>();
                input = tx_info["Input"].get<std::string>();
                output = tx_info["Output"].get<std::string>();
                storage = tx_info["Storage"];
                vm_type = tx_info["VmType"].get<global::ca::VmType>();
            }
            else if (global::ca::TxType::kTxTypeTx == tx_type)
            {
                is_tx = true;
            }

        }
        catch(...)
        {
            ERRORLOG(RED "JSON failed to parse data field!" RESET);
            return -1;
        }
    }

    auto passCode = DoubleSpendCheck(tx, turn_on_missing_block_protocol);
    if (passCode != 0)
    {
        return passCode - 100;
    }

    bool isMultiSign = IsMultiSign(tx);

    uint64_t vin_amount = 0;
    int count = 0;
    for (auto &vin : tx.utxo().vin())
    {
        global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();

        Base58Ver ver = isMultiSign ? Base58Ver::kBase58Ver_MultiSign : Base58Ver::kBase58Ver_Normal;
        std::string addr = GetBase58Addr(vin.vinsign().pub(), ver);
        
        for (auto & prevout : vin.prevout())
        {
            std::string utxo = prevout.hash();


            std::string balance ;
            if(tx_type ==  global::ca::TxType::kTxTypeUnstake && ++count == 1)
            {
                addr = global::ca::kVirtualStakeAddr;
            }
            else if(tx_type == global::ca::TxType::kTxTypeDisinvest && ++count == 1)
            {
                addr = global::ca::kVirtualInvestAddr;
            }

			if (DBStatus::DB_SUCCESS != db_reader.GetUtxoValueByUtxoHashs(utxo, addr, balance))
			{
                MagicSingleton<BlockHelper>::GetInstance()->PushMissUTXO(utxo);
				ERRORLOG("GetTransactionByHash failed!");
				continue;
			}

            //If I get the pledged utxo, I will use it together
            uint64_t stakeValue = 0;
            std::string underline = "_";
            std::vector<std::string> utxo_values;

            if(balance.find(underline) != string::npos)
            {
                StringUtil::SplitString(balance, "_", utxo_values);
                
                for(int i = 0; i < utxo_values.size(); ++i)
                {
                    stakeValue += std::stol(utxo_values[i]);
                }

                vin_amount += stakeValue;
            }
            else
            {
                vin_amount +=  std::stol(balance);
            }
        
        }
    }
    
    //vin Accumulated claim balance
    std::map<std::string, uint64_t> CompanyDividend;
    uint64_t costo=0;
	uint64_t NodeDividend=0;
    uint64_t VinAmountCopia=vin_amount;
    uint64_t TotalClaim=0;
    if(is_claim)
    {
        std::string Addr;
        Addr = GetBase58Addr(tx.utxo().vin(0).vinsign().pub());
        uint64_t tx_time = tx.time();
        auto ret = ca_algorithm::CalcBonusValue(tx_time, Addr, CompanyDividend);
        if(ret < 0)
        {
            ERRORLOG(RED "Failed to obtain the amount claimed by the investor ret:({})" RESET, ret);
            return -2;
        } 
        for(auto & Company : CompanyDividend)
        {
            costo = Company.second * global::ca::kDividendsRate + 0.5;
            NodeDividend += costo;
            vin_amount += (Company.second-costo);
            TotalClaim += (Company.second-costo);
        }
        vin_amount += NodeDividend;
        TotalClaim += NodeDividend;

        if(TotalClaim != claim_amount) 
        {
            return -3;
        }
    }

    uint64_t vout_amount = 0;
    for (auto &vout : tx.utxo().vout())
    {
        vout_amount += vout.value();
    }
    if (vout_amount != vin_amount)
    {
        ERRORLOG("Input is not equal to output ,vout_amount = {}, vin_amount = {}", vout_amount, vin_amount);
        return -4;
    }

    {
    //Calculate whether the pre-transaction includes the account number used
        std::set<std::string> txVinVec;
        for(auto & vin : tx.utxo().vin())
        {
            Base58Ver ver = isMultiSign ? Base58Ver::kBase58Ver_MultiSign : Base58Ver::kBase58Ver_Normal;
            std::string vinAddr = GetBase58Addr(vin.vinsign().pub(), ver);
            for (auto & prevHash : vin.prevout())
            {
                std::string prevUtxo = prevHash.hash();
                std::string strTxRaw;
                if (DBStatus::DB_SUCCESS !=  db_reader.GetTransactionByHash(prevUtxo, strTxRaw))
                {
                    ERRORLOG("get tx failed");
                    return -5;
                }

                CTransaction prevTx;
                prevTx.ParseFromString(strTxRaw);
                if (prevTx.hash().size() == 0)
                {
                    return -6;
                }

                std::vector<std::string> prevTxOutAddr;
                for (auto & txOut : prevTx.utxo().vout())
                {
                    prevTxOutAddr.push_back(txOut.addr());
                }

                if (std::find(prevTxOutAddr.begin(), prevTxOutAddr.end(), vinAddr) == prevTxOutAddr.end())
                {
                    return -7;
                }
            }
        }
    }

    std::string redeem_utxo_raw;
    CTransaction redeem_utxo;
    std::string divest_utxo_raw;
    CTransaction divest_utxo;

    if(global::ca::TxType::kTxTypeStake == tx_type)
    {
        std::vector<std::string> stake_utxos;
        auto dbret = db_reader.GetStakeAddressUtxo(tx.utxo().owner(0),stake_utxos);
        if(dbret == DBStatus::DB_SUCCESS)
        {
            ERRORLOG("There has been a pledge transaction before !");
            return -8;
        }
    }
    else if (global::ca::TxType::kTxTypeUnstake == tx_type)
    {
        std::set<std::string> setOwner(tx.utxo().owner().begin(), tx.utxo().owner().end());
        if (setOwner.size() != 1)
        {
            return -9;
        }
        uint64_t staked_amount = 0;
        std::string owner = tx.utxo().owner().at(0);
        int ret = IsQualifiedToUnstake(owner, redeem_utxo_hash, staked_amount);
        if(ret != 0)
        {
            ERRORLOG(RED "Not allowed to invest!" RESET);
            return ret - 200;
        }
        if (tx.utxo().vout(0).addr() != owner)
        {
            ERRORLOG(RED "The address of the withdrawal utxo is incorrect!" RESET);
            return -10;
        }
        if (tx.utxo().vout(0).value() != staked_amount)
        {
            ERRORLOG(RED "The value of the withdrawal utxo is incorrect!" RESET);
            return -11;
        }
        

        for(int i = 0; i < tx.utxo().vin_size() ; ++i)
        {
            if(i == 0)
            {
                if(tx.utxo().vin(0).prevout(0).hash() != redeem_utxo_hash || tx.utxo().vin(0).prevout(0).n() != 1)
                {
                    ERRORLOG("un stake vin(0).n != 1");
                    return -12;
                }
            }
            else
            {
                for(auto & prevout : tx.utxo().vin(i).prevout())
                {
                    if(prevout.n() != 0)
                    {
                        ERRORLOG("un stake vin(1).n != 0");
                        return -13;
                    }
                }
            }
        }
             
    }
    else if(global::ca::TxType::kTxTypeInvest == tx_type)
    {
        if (tx.utxo().owner().size() != 1)
        {
            return -14;
        }
        std::string owner = tx.utxo().owner().at(0);
        int ret = CheckInvestQualification(owner, invest_node, invest_amount);
        if(ret != 0)
        {
            ERRORLOG(RED "Not allowed to invest!" RESET);
            return ret - 300;
        }
    }
    else if (global::ca::TxType::kTxTypeDisinvest == tx_type)
    {
        std::set<std::string> setOwner(tx.utxo().owner().begin(), tx.utxo().owner().end());
        if (setOwner.size() != 1)
        {
            return -15;
        }

        uint64_t invested_amount = 0;
        std::string owner = tx.utxo().owner().at(0);
        int ret = IsQualifiedToDisinvest(owner, invested_node, divest_utxo_hash, invested_amount);
        if(ret != 0)
        {
            ERRORLOG(RED "Not allowed to Dinvest!" RESET);
            return ret - 400;
        }
        if (tx.utxo().vout(0).addr() != owner)
        {
            ERRORLOG(RED "The address of the withdrawal utxo is incorrect!" RESET);
            return -16;
        }
        if (tx.utxo().vout(0).value() != invested_amount)
        {
            ERRORLOG(RED "The value of the withdrawal utxo is incorrect!" RESET);
            return -17;
        }

        for(int i = 0; i < tx.utxo().vin_size() ; ++i)
        {
            if(i == 0)
            {
                if(tx.utxo().vin(0).prevout(0).hash() != divest_utxo_hash || tx.utxo().vin(0).prevout(0).n() != 1)
                {
                    ERRORLOG("un invest vin(0).n != 1");
                    return -18;
                }
            }
            else
            {
                for(auto & prevout : tx.utxo().vin(i).prevout())
                {
                    if(prevout.n() != 0)
                    {
                        ERRORLOG("un invest vin(0).n != 1");
                        return -19;
                    }
                }
            }
        }
    }
	else if (global::ca::TxType::kTxTypeDeclaration == tx_type)
	{
		std::string multiSignAddr = GetBase58Addr(multiSignPub, Base58Ver::kBase58Ver_MultiSign);
        
        DBReader db_reader;
        std::vector<std::string> multiSignAddrs;
        auto db_status = db_reader.GetMutliSignAddress(multiSignAddrs);
        if (DBStatus::DB_SUCCESS != db_status)
        {
            if (DBStatus::DB_NOT_FOUND != db_status)
            {
                return -20;
            }
        }

        if (std::find(multiSignAddrs.begin(), multiSignAddrs.end(), multiSignAddr) != multiSignAddrs.end())
        {
            return -21;
        }
	}
    else if(global::ca::TxType::kTxTypeBonus == tx_type)
    {
        if (tx.utxo().owner().size() != 1)
        {
            return -22;
        }
        std::string owner = tx.utxo().owner().at(0);
        int ret = CheckBonusQualification(owner, tx.time(), verify_abnormal);
        if(ret != 0)
        {
            ERRORLOG(RED "Not allowed to Bonus!" RESET);
            return ret - 400;
        }

        int i=0;
        costo=0;
        NodeDividend=0;
        uint64_t burn_free = tx.utxo().vout(tx.utxo().vout().size()-1).value();
        for(auto &vout : tx.utxo().vout())
        {
            if(tx.utxo().vout().size()-2 != i && tx.utxo().vout().size()-1 != i)
            {
                if(CompanyDividend.end() != CompanyDividend.find(vout.addr()))
                {
                    costo=CompanyDividend[vout.addr()] * global::ca::kDividendsRate + 0.5;
                    NodeDividend+=costo;
                    if(CompanyDividend[vout.addr()] - costo != vout.value())
                    {
                        return -23;
                    }
                }
                else
                {
                    return -24;
                }
                ++i;
            }
        }
        uint64_t LastVoutAmount = VinAmountCopia - burn_free + NodeDividend;
        if(owner == tx.utxo().vout(i).addr())
        {
            if(LastVoutAmount != tx.utxo().vout(i).value())
            {
                return -25;
            }
        }
    }
    // else if (global::ca::TxType::kTxTypeDeployContract == tx_type)
    // {
    //     std::string expected_output;
    //     nlohmann::json expected_storage;
    //     DonHost host;
    //     int ret;
    //     int64_t gasCost = 0;
    //     if(vm_type == global::ca::VmType::EVM)
    //     {
    //         ret = Evmone::DeployContract(tx.utxo().owner().at(0), OwnerEvmAddr, code, expected_output,
    //                                      host, gasCost);
    //         Evmone::getStorage(host, expected_storage);
    //     }
    //     else
    //     {
    //         return -26;
    //     }

    //     if (ret != 0)
    //     {
    //         ERRORLOG("VM failed to deploy contract!");
    //         ret -= 600;
    //         return ret;
    //     }

    //     bool has_gas_cost = false;
    //     for(const auto& vout : tx.utxo().vout())
    //     {
    //         if (vout.addr() == global::ca::kVirtualDeployContractAddr)
    //         {
    //             has_gas_cost = true;
    //             auto calculate_gas = vout.value();
    //             if (calculate_gas == gasCost)
    //             {
    //                 break;
    //             }
    //             else
    //             {
    //                 ERRORLOG("verify contract gas cast fail, tx gas: {}, calculate gas: {}", calculate_gas, gasCost);
    //                 return -27;
    //             }
    //         }
    //     }
    //     if (!has_gas_cost)
    //     {
    //         ERRORLOG("fail to found gasCost");
    //         return -28;
    //     }


    //     if(output != expected_output || storage != expected_storage)
    //     {
    //         return -29;
    //     }

    // }
    // else if (global::ca::TxType::kTxTypeCallContract == tx_type)
    // {
    //     std::string expected_output;
    //     nlohmann::json expected_storage;
    //     DonHost host;
    //     int ret;
    //     int64_t gasCost = 0;
    //     if(vm_type == global::ca::VmType::EVM)
    //     {
    //         ret = Evmone::CallContract(tx.utxo().owner().at(0), OwnerEvmAddr, deployer_addr, deploy_hash, input, expected_output, host,
    //                                    gasCost);
    //         Evmone::getStorage(host, expected_storage);
    //     }
    //     else
    //     {
    //         return -30;
    //     }

    //     if (ret != 0)
    //     {
    //         ERRORLOG("VM failed to call contract!");
    //         ret -= 300;
    //         return ret;
    //     }

    //     bool has_gas_cost = false;
    //     for(const auto& vout : tx.utxo().vout())
    //     {
    //         if (vout.addr() == global::ca::kVirtualDeployContractAddr)
    //         {
    //             has_gas_cost = true;
    //             auto calculate_gas = vout.value();
    //             if (calculate_gas == gasCost)
    //             {
    //                 break;
    //             }
    //             else
    //             {
    //                 ERRORLOG("verify contract gas cast fail, tx gas: {}, calculate gas: {}", calculate_gas, gasCost);
    //                 return -31;
    //             }
    //         }
    //     }
    //     if (!has_gas_cost)
    //     {
    //         ERRORLOG("fail to found gasCost");
    //         return -32;
    //     }

    //     if(output != expected_output || storage != expected_storage)
    //     {
    //         return -33;
    //     }

    // }

    std::string award_addr;
    std::vector<std::string> pledge_addrs;
    auto status = db_reader.GetStakeAddress(pledge_addrs);
    if (DBStatus::DB_SUCCESS != status && DBStatus::DB_NOT_FOUND != status)
    {
        return -34;
    }

    if (global::ca::TxType::kTxTypeTx != tx_type)
    {
        std::set<std::string> setOwner(tx.utxo().owner().begin(), tx.utxo().owner().end());
        if (setOwner.size() != 1)
        {
            return -35;
        }
    }

    if (tx_height <= global::ca::kMinUnstakeHeight && (tx.utxo().owner().at(0) == global::ca::kInitAccountBase58Addr || global::ca::TxType::kTxTypeStake == tx_type || global::ca::TxType::kTxTypeInvest == tx_type))
    {
        int i = 0;
        for (auto &tx_sign_pre_hash : tx.verifysign())
        {
            award_addr = GetBase58Addr(tx_sign_pre_hash.pub());
            if (!CheckBase58Addr(award_addr, Base58Ver::kBase58Ver_Normal))
            {
                return -36;
            }
            ++i;
        }
    }
    else
    {
        //Modern development time judges whether the first circulation node is fully pledged and invested
        bool isNeedAgent = TxHelper::IsNeedAgent(tx);

        for (int i = (isNeedAgent ? 0 : 1); i < tx.verifysign_size(); ++i)
        {
            std::string sign_addr = GetBase58Addr(tx.verifysign(i).pub(), Base58Ver::kBase58Ver_Normal);
            if(CheckVerifyNodeQualification(sign_addr) != 0)
            {
                ERRORLOG("isNeedAgent Check Verify Node Qualification fail");
                return -37;
            }
        }
    }
    uint64_t end_time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    if(global::ca::TxType::kTxTypeTx == tx_type)
    {
        MagicSingleton<DONbenchmark>::GetInstance()->AddtransactionDBVerifyMap(tx.hash(), end_time - start_time);  
    }
	
    return 0;
}



int ca_algorithm::GetTxSignAddr(const CTransaction &tx, std::vector<std::string> &tx_sign_addr)
{
    if(tx.verifysign().empty())
    {
        return -1;
    }

    for (auto &tx_sign_pre_hash : tx.verifysign())
    {
        std::string addr = GetBase58Addr(tx_sign_pre_hash.pub());
        if (!CheckBase58Addr(addr))
        {
            return -2;
        }
        tx_sign_addr.push_back(addr);
    }

    return 0;
}

int ca_algorithm::DoubleSpendCheck(const CTransaction &tx, bool turn_on_missing_block_protocol, std::string* missing_utxo)
{
    std::string redeem_utxo_hash;
    std::string divest_utxo_hash;
    std::string invested_node;
    global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();

    if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
    {
        try
        {
            nlohmann::json data_json = nlohmann::json::parse(tx.data());
            nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
            if (global::ca::TxType::kTxTypeUnstake == tx_type)
            {             
                redeem_utxo_hash = tx_info["UnstakeUtxo"].get<std::string>();
            }
            else if (global::ca::TxType::kTxTypeDisinvest == tx_type)
            {
                divest_utxo_hash = tx_info["DisinvestUtxo"].get<std::string>();
                invested_node = tx_info["BonusAddr"].get<std::string>();        
            }

        }
        catch(...)
        {
            ERRORLOG(RED "JSON failed to parse data field!" RESET);
            return -1;
        }
    }

    bool isMultiSign = IsMultiSign(tx);
    DBReader db_reader;
    for (auto &vin : tx.utxo().vin())
    {
        Base58Ver ver = isMultiSign ? Base58Ver::kBase58Ver_MultiSign : Base58Ver::kBase58Ver_Normal;
        std::string addr = GetBase58Addr(vin.vinsign().pub(), ver);

        // Verify whether the utxo used exists and is used
        std::vector<std::string> utxo_hashs;
        if (DBStatus::DB_SUCCESS != db_reader.GetUtxoHashsByAddress(addr, utxo_hashs))
        {
            ERRORLOG(RED "GetUtxoHashsByAddress failed!" RESET);
            return -2;
        }
        
        for (auto & prevout : vin.prevout())
        {
            std::string utxo = prevout.hash();
            uint32_t index = prevout.n();
            

            if(global::ca::TxType::kTxTypeStake == tx_type)
            {
                std::vector<std::string> stake_utxos;
                auto ret = db_reader.GetStakeAddressUtxo(addr,stake_utxos);
                if(ret != DBStatus::DB_NOT_FOUND)
                {
                    ERRORLOG("There has been a pledge transaction before!");
                    return -3;
                }

            }
            else if ((global::ca::TxType::kTxTypeUnstake == tx_type) && redeem_utxo_hash == utxo && 1 == index)
            {
                if (DBStatus::DB_SUCCESS != db_reader.GetStakeAddressUtxo(addr, utxo_hashs))
                {
                    ERRORLOG(RED "GetStakeAddressUtxo failed!" RESET);
                    return -4;
                } 
                if (utxo_hashs.cend() == std::find(utxo_hashs.cbegin(), utxo_hashs.cend(), utxo))
                {
                    if(missing_utxo != nullptr)
                    {
                        *missing_utxo = utxo;
                    }
                    return -5;
                }
            }
            else if((global::ca::TxType::kTxTypeDisinvest == tx_type) && divest_utxo_hash == utxo && 1 == index)
            {
                if (DBStatus::DB_SUCCESS != db_reader.GetBonusAddrInvestUtxosByBonusAddr(invested_node, addr, utxo_hashs))
                {
                    ERRORLOG(RED "GetBonusAddrInvestUtxosByBonusAddr failed!" RESET);
                    return -6;
                }
                if (utxo_hashs.cend() == std::find(utxo_hashs.cbegin(), utxo_hashs.cend(), utxo))
                {
                    if(missing_utxo != nullptr)
                    {
                        *missing_utxo = utxo;
                    }
                    return -7;
                }                
            }
            else
            {
                if (utxo_hashs.cend() == std::find(utxo_hashs.cbegin(), utxo_hashs.cend(), utxo))
                {
                    if(missing_utxo != nullptr)
                    {
                        *missing_utxo = utxo;
                    }
                    //The previous block exists, but the block corresponding to utxo does not exist
                    if(turn_on_missing_block_protocol)
                    {
                        DEBUGLOG("turn_on_missing_block_protocol");
                        MagicSingleton<BlockHelper>::GetInstance()->PushMissUTXO(utxo);                        
                    }
                    return -8;
                }
            }
        }
    }
    return 0;
}

int ca_algorithm::VerifyCacheTranscation(const CTransaction &tx)
{
    // 1. Transaction  number must be 0
    if (tx.version() != 0)
    {
        return -1;
    }

    // 2. The number of signatures must be equal to 8\
    the same as the extended field   
    std::vector<std::string> tx_sign_addr;
    int res = GetTxSignAddr(tx,tx_sign_addr);
    if(res != 0)
    {
        return res;
    }
    if (tx_sign_addr.size() != global::ca::kConsensus)
    {
        return -2;
    }

    std::vector<std::string> award_addrs;
    for (int i = 2; i < tx.verifysign_size(); ++i)
    {
        auto &pub = tx.verifysign(i).pub();
        award_addrs.push_back(GetBase58Addr(tx.verifysign(i).pub()));
    }
    {
        std::set<std::string> addrs(award_addrs.cbegin(), award_addrs.cend());
        if (addrs.size() != (global::ca::kConsensus - 2) || addrs.size() != award_addrs.size())
        {
            return -3;
        }
    }
    
    return 0;
}
int ca_algorithm::MemVerifyContractBlock(const CBlock& block, bool isVerify, BlockStatus* blockStatus)
{
    // Block version number must be 0
    if (block.version() != global::ca::kInitBlockVersion && block.version() != global::ca::kCurrentBlockVersion)
    {
        return -1;
    }
    
    // The size of the serialized block must be less than 1000000
    if (block.SerializeAsString().length() > 1024 * 1024 * 4)
    {
        return -2;
    }
    
    // Verify whether the block hash is the same
    if (block.hash() != CalcBlockHash(block))
    {
        return -3;
    }

    // Verify that merklelot is the same
    if (block.merkleroot() != CalcBlockMerkle(block))
    {
        return -4;
    }
    
    // The number of transactions in the block must be greater than 0 \
    and a multiple of 2 (normal transaction, signature transaction)
    if(block.txs_size() % 1 != 0)
    {
       return -5;
    } 

    // Transactions in the block must be in groups of 2 \
    Key is the calculated hash and value is the transaction
    std::map<std::string ,vector<CTransaction>>  txGroup; 
    for(auto tx : block.txs())
    {
        std::string hash;
        if (GetTransactionType(tx) == kTransactionType_Tx) 
        {
            hash = tx.hash();
        }
        else
        {
            return -6;
        }

        auto iter = txGroup.find(hash);
        if(iter == txGroup.end())
        {
            txGroup[hash] = std::vector<CTransaction>{};
        }
        txGroup[hash].push_back(tx);
    }

    // Whether there are two transactions in the same group and whether they are of two types. \
    Re insert the type sorting into the new array
    std::vector<CTransaction> txSort;
    auto iter = txGroup.begin();

    CBlock tmpBlock = block;
    tmpBlock.clear_txs();
    std::map<std::string, future<int>> taskResults;
    //std::vector<future<int>> taskResults;
    while(iter != txGroup.end())
    {
        if(iter->second.size() != 1)
        {
            DEBUGLOG("Number of transaction types:{}",iter->second.size());
            return -7;
        }

        CTransaction tx;
        for(auto itemTx : iter->second)
        {
            TransactionType txType = GetTransactionType(itemTx);
            if(txType == kTransactionType_Tx)
            {
                tx = itemTx;
            }
        }

		if (tx.hash().empty() )
		{
			return -8;
		}


        if(isVerify)
        {
            auto task = std::make_shared<std::packaged_task<int()>>([tx] { return ca_algorithm::MemVerifyTransactionTx(tx); });
            try
            {
                taskResults[tx.hash()] = task->get_future();
                //taskResults.push_back(task->get_future());
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }
            MagicSingleton<taskPool>::GetInstance()->commit_work_task([task](){(*task)();});
        }

        ++iter;
    }

    bool verifyFlag = false;
    for (auto& res : taskResults)
    {
        int ret = res.second.get();
        if (ret != 0)
        {
            verifyFlag = true;
            if(blockStatus != NULL)
            {
                auto txStatus = blockStatus->add_txstatus();
                txStatus->set_txhash(res.first);
                txStatus->set_status(ret);
            }
            ERRORLOG("AAAC MemVerifyTransactionTx Error:{}, txHash:{}",ret, res.first);
        }
    }
    if(verifyFlag)
    {
        return -10;
    }
    return 0;
}
int ca_algorithm::MemVerifyBlock(const CBlock& block, bool isVerify)
{
    // Block version number must be 0
    if (block.version() != 0)
    {
        return -1;
    }

    // The size of the serialized block must be less than 1000000
    if (block.SerializeAsString().length() > 1000000)
    {
        return -2;
    }

    // Verify whether the block hash is the same
    if (block.hash() != CalcBlockHash(block))
    {
        return -3;
    }

    // Verify that merklelot is the same
    if (block.merkleroot() != CalcBlockMerkle(block))
    {
        return -4;
    }

    // The number of transactions in the block must be greater than 0 \
    and a multiple of 2 (normal transaction, signature transaction)
    if(block.txs_size() % 1 != 0)
    {
       return -5;
    }
    
    // std::set<std::string> block_sign;
    // for(auto & Sign : block.sign())
    // {
    //     block_sign.insert(GetBase58Addr(Sign.pub()));
    // }

    // if(block_sign.size() != global::ca::kConsensus)
    // {
    //     ERRORLOG("block sign size is >:{} less than >:{}",block_sign.size(), global::ca::kConsensus);
    //     return -6;
    // } 

    // Transactions in the block must be in groups of 2 \
    Key is the calculated hash and value is the transaction
    std::map<std::string ,vector<CTransaction>>  tx_group; 
    for(auto tx : block.txs())
    {
        std::string hash;
        if (GetTransactionType(tx) == kTransactionType_Tx) 
        {
            hash = tx.hash();
        }
        else
        {
            return -7;
        }

        auto iter = tx_group.find(hash);
        if(iter == tx_group.end())
        {
            tx_group[hash] = std::vector<CTransaction>{};
        }
        tx_group[hash].push_back(tx);
    }

    // Whether there are two transactions in the same group and whether they are of two types. \
    Re insert the type sorting into the new array
    std::vector<CTransaction> tx_sort;
    auto iter = tx_group.begin();

    CBlock tmp_block = block;
    tmp_block.clear_txs();
    std::vector<future<int>> task_results;
    while(iter != tx_group.end())
    {
        if(iter->second.size() != 1)
        {
            DEBUGLOG("Number of transaction types:{}",iter->second.size());
            return -8;
        }

        CTransaction tx;
        for(auto itemTx : iter->second)
        {
            TransactionType tx_type = GetTransactionType(itemTx);
            if(tx_type == kTransactionType_Tx)
            {
                tx = itemTx;
            }
        }

		if (tx.hash().empty() )
		{
			return -9;
		}

        if(isVerify)
        {
            auto task = std::make_shared<std::packaged_task<int()>>([tx] { return ca_algorithm::MemVerifyTransactionTx(tx); });
            try
            {
                task_results.push_back(task->get_future());
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }
            MagicSingleton<taskPool>::GetInstance()->commit_work_task([task](){(*task)();});
        }

        ++iter;
    }

    for (auto& res : task_results)
    {
        int ret = res.get();
        if (ret != 0)
        {
            ERRORLOG("MemVerifyTransactionTx Error:{},Hash:{}",ret, block.hash());
            return -10;
        }
    }
    return 0;
}


int ca_algorithm::VerifyContractStorage(const nlohmann::json& txInfo, const nlohmann::json& expectedTxInfo)
{
    nlohmann::json storage = txInfo["Storage"];
    nlohmann::json prevHash = txInfo["PrevHash"];
    nlohmann::json log;
    auto logFound = txInfo.find("log");
    if (logFound != txInfo.end())
    {
        log = logFound.value();
    }

    nlohmann::json selfdestructed = txInfo["selfdestructs"];

    nlohmann::json expectedStorage = expectedTxInfo["Storage"];
    nlohmann::json expectedPrevHash = expectedTxInfo["PrevHash"];
    nlohmann::json expectedLog;
    logFound = expectedTxInfo.find("log");
    if (logFound != expectedTxInfo.end())
    {
        expectedLog = logFound.value();
    }
    nlohmann::json expectedSelfdestructed = expectedTxInfo["selfdestructs"];


    if (prevHash != expectedPrevHash)
    {
        ERRORLOG("prevHash doesn't match\ntx: {} \n expect: {}", prevHash.dump(4), expectedPrevHash.dump(4));
        return -1;
    }
    if (storage != expectedStorage)
    {
        ERRORLOG("storage doesn't match\ntx: {} \n expect: {}", storage.dump(4), expectedStorage.dump(4));
        return -2;
    }
    if (log != expectedLog)
    {
        ERRORLOG("log doesn't match\ntx: {} \n expect: {}", log.dump(4), expectedLog.dump(4));
        return -3;
    }
    if (selfdestructed != expectedSelfdestructed)
    {
        ERRORLOG("selfdestructed doesn't match\ntx: {} \n expect: {}", selfdestructed.dump(4), expectedSelfdestructed.dump(4));
        return -4;
    }
    return 0;
}



int ca_algorithm::ContractVerifyBlock(const CBlock &block, bool turnOnMissingBlockProtocol, bool verifyAbnormal, bool isVerify, BlockStatus* blockStatus)
{
    uint64_t startTimeForBenchmark = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();

    DBReader dbReader;
    // Verify whether the block exists locally
    std::string blockRaw;
    auto status = dbReader.GetBlockByBlockHash(block.hash(), blockRaw);
    if (DBStatus::DB_SUCCESS == status)
    {
        return 0;
    }

    if (DBStatus::DB_NOT_FOUND != status)
    {
        return -1;
    }

    // Verify whether the front block exists
    blockRaw.clear();
    if (DBStatus::DB_SUCCESS != dbReader.GetBlockByBlockHash(block.prevhash(), blockRaw))
    {
        MagicSingleton<BlockHelper>::GetInstance()->SetMissingPrehash();
        return -2;
    }

    CBlock preBlock;
    if (!preBlock.ParseFromString(blockRaw))
    {
        MagicSingleton<BlockHelper>::GetInstance()->SetMissingPrehash();
        return -3;
    }

    // The block height must be the height of the preceding block plus one
    if (block.height() - preBlock.height() != 1)
    {
        ERRORLOG("++++block.height:{}, preBlock.height:{}, block.prevhash:{}, block.txs_size:{}", block.height(), preBlock.height(), block.prevhash(),block.txs_size());
        return -4;
    }

    auto startMemVerify = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    auto ret = MemVerifyContractBlock(block, isVerify, blockStatus);
    if (0 != ret)
    {
        ERRORLOG(RED "MemVerifyBlock failed! The error code is {}." RESET, ret);
        ret -= 10000;
        return ret;
    }

    auto endMemVerify = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    // Verify whether the block time is greater than the maximum block time before 10 heights
    uint64_t startTime = 0;
    uint64_t endTime = GetLocalTimestampUsec() + 10 * 60 * 1000 * 1000;

    {
        uint64_t blockHeight = 0;
        if (block.height() > 10)
        {
            blockHeight = block.height() - 10;
        }
        std::vector<std::string> blockHashs;

        if (DBStatus::DB_SUCCESS != dbReader.GetBlockHashsByBlockHeight(blockHeight, blockHashs))
        {
            return -5;
        }
        std::vector<std::string> blocks;

        if (DBStatus::DB_SUCCESS != dbReader.GetBlocksByBlockHash(blockHashs, blocks))
        {
            return -6;
        }
        CBlock block;
        for (auto &blockRaw : blocks)
        {
            if (!block.ParseFromString(blockRaw))
            {
                return -7;
            }
            if (startTime < block.time())
            {
                startTime = block.time();
            }
        }
    }

    // Verify whether the transaction time is greater than the maximum block time before 10 heights
    uint64_t tenSec = 10000000;
    if (block.time() > endTime || block.time() < startTime - tenSec)
    {
        return -8;
    }
    
    auto startTxVerify = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    if(isVerify)
    {

         MagicSingleton<ContractDataCache>::GetInstance()->lock();
        MagicSingleton<ContractDataCache>::GetInstance()->clear();

        ON_SCOPE_EXIT{
            MagicSingleton<ContractDataCache>::GetInstance()->clear();
            MagicSingleton<ContractDataCache>::GetInstance()->unlock();
        };
        //std::map<std::string, nlohmann::json> txHashAndJson;
        std::map<std::string, future<int>> taskResults;
        for (auto& tx : block.txs())
        {

            if (GetTransactionType(tx) != kTransactionType_Tx)
            {
                continue;
            }
            if(tx.verifysign_size() != global::ca::KRandomNodeGroup)
            {
                return -9;
            }

            auto blockHeight = block.height();
            auto task = std::make_shared<std::packaged_task<int()>>([tx, blockHeight, turnOnMissingBlockProtocol, verifyAbnormal] { return VerifyTransactionTx(tx, blockHeight, turnOnMissingBlockProtocol, verifyAbnormal); });
            if(task)
            {
                taskResults[tx.hash()] = task->get_future();
            }
            else
            {
                return -10;
            }

            MagicSingleton<taskPool>::GetInstance()->commit_work_task([task](){(*task)();});
        }
        
        DEBUGLOG("VerifyContractBlock, blockHash:{}", block.hash());

        ret = VerifyContractBlock(block);
        if (ret != 0)
        {
            ERRORLOG("VerifyContractBlock fail ret : {}", ret);
            return -11;
        }
        bool verifyFlag = false;

        for (auto& res : taskResults)
        {
            ret = res.second.get();
            if (ret != 0)
            {
                verifyFlag = true;
                if(blockStatus != NULL)
                {
                    auto txStatus = blockStatus->add_txstatus();
                    txStatus->set_txhash(res.first);
                    txStatus->set_status(ret);
                }
                ERRORLOG(RED "AAAC VerifyTransactionTx failed! The error code is {}. txHash:{}" RESET, ret, res.first);
            }
        }

        if(verifyFlag)
        {
            return -12;
        }
    }
    auto endTxVerify = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    if(isVerify)
    {
        uint64_t memVerify = endMemVerify - startMemVerify;
        uint64_t txVerify = endTxVerify - startTxVerify;
        MagicSingleton<DONbenchmark>::GetInstance()->SetByBlockHash(block.hash(), &memVerify, 5, &txVerify);
    }

    uint64_t endTimeForBenchmark = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    MagicSingleton<DONbenchmark>::GetInstance()->AddBlockVerifyMap(block.hash(), endTimeForBenchmark - startTimeForBenchmark);
    return 0;
}

int ca_algorithm::VerifyPreSaveBlock(const CBlock &block)
{
    std::set<std::string> addrs;
    for(auto &sig : block.sign())
    {
        addrs.insert(GetBase58Addr(sig.pub()));
    }

    if(addrs.size() != global::ca::kConsensus)
    {
        ERRORLOG("size is >:{}, less than >:{}",addrs.size(), global::ca::kConsensus);
        return -1;
    }
    
    return 0;
}

bool ca_algorithm::CalculateHeightSumHash(uint64_t start_height, uint64_t end_height, DBReadWriter &db_writer, std::string& sum_hash)
{
    std::map<uint64_t, std::vector<std::string>> sum_hash_data;
    for(uint64_t height = start_height; height < end_height; ++height)
    {
        std::vector<std::string> blockhashes;
        auto ret = db_writer.GetBlockHashsByBlockHeight(height, blockhashes);
        if(ret != DBStatus::DB_SUCCESS)
        {
            ERRORLOG("calculate sum hash fail");
            return false;
        }
        sum_hash_data[height] = blockhashes;
    }
    SyncBlock::SumHeightsHash(sum_hash_data, sum_hash);
    return true;
}


int ca_algorithm::SaveBlock(DBReadWriter &db_writer, const CBlock &block, global::ca::SaveType saveType, global::ca::BlockObtainMean obtainMean)
{
    // Determine whether there is a local block
    DEBUGLOG("save block contract");
    std::string block_raw;
    auto ret = db_writer.GetBlockByBlockHash(block.hash(), block_raw);
    if (DBStatus::DB_SUCCESS == ret)
    {
        INFOLOG("block {} already in cache , skip",block.hash().substr(0, 6));
        return 0;
    }
    else if (DBStatus::DB_NOT_FOUND != ret)
    {
        ERRORLOG("DB error!  {}",ret);
        return -1;
    }

    std::string pre_block_raw;
    auto dbstatus = db_writer.GetBlockByBlockHash(block.prevhash(), pre_block_raw);
    if (dbstatus != DBStatus::DB_SUCCESS)
    {
        if(dbstatus == DBStatus::DB_NOT_FOUND)
        {
        MagicSingleton<BlockHelper>::GetInstance()->SetMissingBlock(block);
        MagicSingleton<BlockHelper>::GetInstance()->SetMissingPrehash();
        DEBUGLOG("DB not found prev block");
        }
        else{
            DEBUGLOG("DB error");
        }
        
        return -2;
    }

    // Update node height
    uint64_t node_height = 0;
    if (DBStatus::DB_SUCCESS != db_writer.GetBlockTop(node_height))
    {
         ERRORLOG("GetBlockTop error!");
        return -3;
    }

    if (block.height() > node_height)
    {
        if (DBStatus::DB_SUCCESS != db_writer.SetBlockTop(block.height()))
        {
            ERRORLOG("GetBlockTop");
            return -4;
        }
    }

    // Add the height corresponding to the block hash
    if (DBStatus::DB_SUCCESS != db_writer.SetBlockHeightByBlockHash(block.hash(), block.height()))
    {
        ERRORLOG("SetBlockHeightByBlockHash error! hash:{}",block.hash());
        return -5;
    }

    // Update block hash on height
    if (DBStatus::DB_SUCCESS != db_writer.SetBlockHashByBlockHeight(block.height(), block.hash(), false))
    {
        ERRORLOG("SetBlockHeightByBlockHash error! hash:{}",block.hash());
        return -6;
    }
    
    // Add block data corresponding to block hash
    if (DBStatus::DB_SUCCESS != db_writer.SetBlockByBlockHash(block.hash(), block.SerializeAsString()))
    {
        ERRORLOG("SetBlockByBlockHash error! hash:{}",block.hash());
        return -7;
    }

    // {
    //     uint64_t period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(block.time());
    //     std::vector<std::string> signAddrs;
    //     auto ret = db_writer.GetSignAddrByPeriod(period,signAddrs);
    //     if(DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
    //     {
    //         ERRORLOG("GetSignAddrByPeriod error! ret:{}",ret);
    //         return -8;
    //     }
    //     for (auto &sign : block.sign())
    //     {
            
    //         std::string voutAddr = GetBase58Addr(sign.pub());
    //         if (!CheckBase58Addr(voutAddr, Base58Ver::kBase58Ver_Normal))
    //         {
    //             return -9;
    //         }

    //         auto found = std::find(signAddrs.begin(), signAddrs.end(), voutAddr);
    //         if(found == signAddrs.end())
    //         {
    //             if(DBStatus::DB_SUCCESS != db_writer.SetSignAddrByPeriod(period, voutAddr))
    //             {
    //                 ERRORLOG("SetSignAddrByPeriod error! period:{},vout.addr{}",period,voutAddr);
    //                 return -10;
    //             }
    //         }
    //         uint64_t signNumber = 0;
    //         auto ret = db_writer.GetSignNumberByPeriod(period, voutAddr, signNumber);
    //         if(DBStatus::DB_SUCCESS != ret)
    //         {
    //             if(DBStatus::DB_NOT_FOUND == ret)
    //             {
    //                 signNumber = 0;
    //             }
    //             else
    //             {
    //                 ERRORLOG("GetSignNumberByPeriod error! ret:{}",ret);
    //                 return -11;
    //             }
    //         }
    //         signNumber += 1;
    //         if(DBStatus::DB_SUCCESS != db_writer.SetSignNumberByPeriod(period, voutAddr, signNumber))
    //         {
    //             ERRORLOG("SetSignNumberByPeriod error! period:{},vout.addr:{},signNumber:{}",period,voutAddr,signNumber);
    //             return -12;
    //         }
    //     }
    //     {
    //         uint64_t blockNumber = 0;
    //         auto ret = db_writer.GetBlockNumberByPeriod(period,blockNumber);
    //         if(DBStatus::DB_SUCCESS != ret)
    //         {
    //             if(DBStatus::DB_NOT_FOUND == ret)
    //             {
    //                 blockNumber = 0;
    //             }
    //             else
    //             {
    //                ERRORLOG("Get BLock Num Failed!");
    //                return -13;
    //             }
    //         }
    //         blockNumber += 1;

    //         if(DBStatus::DB_SUCCESS != db_writer.SetBlockNumberByPeriod(period, blockNumber))
    //         {
    //             ERRORLOG("SetBlockNumberByPeriod error! period:{},signNumber:{}",period,blockNumber);
    //             return -14;
    //         }
    //     }
    // }
    std::set<std::string> block_addr;
    std::set<std::string> all_addr;
    for (auto &tx : block.txs())
    {
        auto transaction_type = GetTransactionType(tx);
        block_addr.insert(all_addr.cbegin(), all_addr.cend());
        all_addr.clear();
        if (kTransactionType_Tx == transaction_type)
        {
            std::string redeem_utxo_hash;
            std::string divest_utxo_hash;
            if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
            {
                try
                {
                    nlohmann::json data_json = nlohmann::json::parse(tx.data());
                    global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();
                    // The pledge transaction updates the pledge address and the utxo of the pledge address
                    if (tx_type == global::ca::TxType::kTxTypeStake)
                    {
                        for (auto &vin : tx.utxo().vin())
                        {
                            std::string addr = GetBase58Addr(vin.vinsign().pub());
                            if (!CheckBase58Addr(addr))
                            {
                                ERRORLOG("CheckBase58Addr error!",addr);
                                return -8;
                            }
                            if (DBStatus::DB_SUCCESS != db_writer.SetStakeAddressUtxo(addr, tx.hash()))
                            {
                                ERRORLOG("SetStakeAddressUtxo error! addr:{} hash:{}",addr,tx.hash());
                                return -9;
                            }
                            std::vector<std::string> pledge_addrs;
                            ret = db_writer.GetStakeAddress(pledge_addrs);
                            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                            {
                                ERRORLOG("GetStakeAddress error! ret:{}",ret);
                                return -10;
                            }
                            if (pledge_addrs.cend() == std::find(pledge_addrs.cbegin(), pledge_addrs.cend(), addr))
                            {
                                if (DBStatus::DB_SUCCESS != db_writer.SetStakeAddresses(addr))
                                {
                                    ERRORLOG("SetStakeAddresses addr:{}",addr);
                                    return -11;
                                }
                            }
                            break;
                        }
                    }
                    // The reddem transaction, update the pledge address and the utxo of the pledge address
                    else if (tx_type == global::ca::TxType::kTxTypeUnstake)
                    {
                        bool flag = false;
                        
                        nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
                        redeem_utxo_hash = tx_info["UnstakeUtxo"].get<std::string>();
                        for (auto &vin : tx.utxo().vin())
                        {
                            for (auto & prevout : vin.prevout())
                            {
                                if (redeem_utxo_hash != prevout.hash() && prevout.n() != 1)
                                {
                                    DEBUGLOG("continue not unstake_hash");
                                    continue;
                                }
                                flag = true;
                                std::string addr = GetBase58Addr(vin.vinsign().pub());
                                if (!CheckBase58Addr(addr))
                                {
                                    ERRORLOG("CheckBase58Addr error! addr:{}",addr);
                                    return -12;
                                }
                                if (DBStatus::DB_SUCCESS != db_writer.RemoveStakeAddressUtxo(addr, redeem_utxo_hash))
                                {
                                    ERRORLOG("RemoveStakeAddressUtxo error");
                                    return -13;
                                }
                                std::vector<std::string> pledge_utxo_hashs;
                                ret = db_writer.GetStakeAddressUtxo(addr, pledge_utxo_hashs);
                                if (DBStatus::DB_NOT_FOUND == ret || pledge_utxo_hashs.empty())
                                {
                                    if (DBStatus::DB_SUCCESS != db_writer.RemoveStakeAddresses(addr))
                                    {
                                        ERRORLOG("RemoveStakeAddresses addr:{}",addr);
                                        return -14;
                                    }
                                }
                                else if (DBStatus::DB_SUCCESS != ret)
                                {
                                    ERRORLOG("GetStakeAddressUtxo ret:{}",ret);
                                    return -15;
                                }
                                break;

                            }
                        }
                        if (!flag)
                        {
                            ERRORLOG(" TxType unknow");
                            return -16;
                        }
                    }
                    else if ( global::ca::TxType::kTxTypeDeclaration == tx_type )
                    {
                        std::string addr;
                        for (auto & vout : tx.utxo().vout())
                        {
                            if (CheckBase58Addr(vout.addr(), Base58Ver::kBase58Ver_MultiSign))
                            {
                                addr = vout.addr();
                                break;
                            }
                        }
                        if(addr.size() == 0)
                        {
                            ERRORLOG("addr.size() == 0");
                            return -17;
                        }
                        std::vector<std::string> mutliaddrs;
                        auto db_status = db_writer.GetMutliSignAddress(mutliaddrs);
                        if (DBStatus::DB_SUCCESS != db_status)
                        {
                            if (DBStatus::DB_NOT_FOUND != db_status)
                            {
                                ERRORLOG("DB error! db_status:{}",db_status);
                                return -18;
                            }
                        }
                        if(std::find(mutliaddrs.begin(), mutliaddrs.end(), addr) != mutliaddrs.end())
                        {
                            ERRORLOG("can't find addr from mutliaddrs! addr:{} ",addr);
                            return -19;
                        }

                        if (DBStatus::DB_SUCCESS != db_writer.SetMutliSignAddresses(addr) )
                        {
                            ERRORLOG(" SetMutliSignAddresses error! addr:{}", addr);
                            return -20;
                        }
                        if (DBStatus::DB_SUCCESS != db_writer.SetMutliSignAddressUtxo(addr,tx.hash()))
                        {
                            ERRORLOG("SetMutliSignAddressUtxo addr:{}",addr);
                            return -21;
                        }
                    }
                    // The invest transaction updates the investment address and the utxo of the investment address
                    else if (tx_type == global::ca::TxType::kTxTypeInvest)
                    {
                        nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
                        std::string invest_node = tx_info["BonusAddr"].get<std::string>();
                        uint64_t invest_amount = tx_info["InvestAmount"].get<uint64_t>();
                        std::vector<std::string> invest_nodes;
                        ret = db_writer.GetBonusaddr(invest_nodes);
                        if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                        {
                            ERRORLOG("GetBonusaddr error ret:{}",ret);
                            return -22;
                        }
                        if (invest_nodes.cend() == std::find(invest_nodes.cbegin(), invest_nodes.cend(), invest_node))
                        {
                            if (DBStatus::DB_SUCCESS != db_writer.SetBonusAddr(invest_node))
                            {
                                ERRORLOG("can't find invest_node from invest_nodes");
                                return -23;
                            }
                        }

                        uint64_t Totalinvest = 0;
                        for (auto &vin : tx.utxo().vin())
                        {
                            std::string addr = GetBase58Addr(vin.vinsign().pub());
                            if (!CheckBase58Addr(addr))
                            {
                                ERRORLOG("CheckBase58Addr addr:{}",addr);
                                return -24;
                            }                      

                            if (DBStatus::DB_SUCCESS != db_writer.SetBonusAddrInvestAddrUtxoByBonusAddr(invest_node, addr, tx.hash()))
                            {
                                ERRORLOG("SetBonusAddrInvestAddrUtxoByBonusAddr addr:{} invest_node:{}",addr,invest_node);
                                return -25;
                            }
                            std::vector<std::string> invest_addrs;
                            ret = db_writer.GetInvestAddrsByBonusAddr(invest_node, invest_addrs);
                            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                            {
                                ERRORLOG("GetInvestAddrsByBonusAddr ret:{}",ret);
                                return -26;
                            }
                            if (invest_addrs.cend() == std::find(invest_addrs.cbegin(), invest_addrs.cend(), addr))
                            {
                                if (DBStatus::DB_SUCCESS != db_writer.SetInvestAddrByBonusAddr(invest_node, addr))
                                {
                                    ERRORLOG("can't find addr from invest_addrs addr:{}",addr);
                                    return -27;
                                }
                            }

                            std::vector<std::string> invest_nodes;
                            ret = db_writer.GetBonusAddrByInvestAddr(addr, invest_nodes);
                            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                            {
                                ERRORLOG("GetBonusAddrByInvestAddr addr:{}",addr);
                                return -28;
                            }
                            if (invest_nodes.cend() == std::find(invest_nodes.cbegin(), invest_nodes.cend(), invest_node))
                            {
                                if (DBStatus::DB_SUCCESS != db_writer.SetBonusAddrByInvestAddr(addr,invest_node))
                                {
                                    ERRORLOG("can't find invest_node from invest_nodes addr:{} ,invest_node{}", addr,invest_node);
                                    return -29;
                                }
                            }
                            break;
                        }
                        {
                            std::lock_guard<std::mutex> lock(global::ca::kInvestMutex);
                            ret = db_writer.GetTotalInvestAmount(Totalinvest);
                            if(DBStatus::DB_SUCCESS != ret)
                            {
                                if(DBStatus::DB_NOT_FOUND == ret)
                                {
                                    Totalinvest=0;
                                }
                                else
                                {
                                    return -30;
                                }
                            }
                            
                            Totalinvest += invest_amount;
                            if (DBStatus::DB_SUCCESS != db_writer.SetTotalInvestAmount(Totalinvest))
                            {
                                ERRORLOG("SetTotalInvestAmount error! {}",Totalinvest);
                                return -31;
                            }
                            uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(tx.time());
                            if(DBStatus::DB_SUCCESS != db_writer.SetInvestUtxoByPeriod(Period, tx.hash()))
                            {
                                ERRORLOG("SetInvestUtxoByPeriod Period:{},hash:{}",Period,tx.hash());
                                return -32;
                            }
                        }
                    }
                    // The divest transaction updates the investment address and the utxo of the investment address
                    else if (tx_type == global::ca::TxType::kTxTypeDisinvest)
                    {
                        bool flag = false;
                        

                        nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
                        divest_utxo_hash = tx_info["DisinvestUtxo"].get<std::string>();
                        std::string invested_node = tx_info["BonusAddr"].get<std::string>();

                        for (auto &vin : tx.utxo().vin())
                        {
                            for (auto & prevout : vin.prevout())
                            {
                                if (divest_utxo_hash != prevout.hash() && prevout.n() != 1)
                                {
                                    DEBUGLOG("continue not divest_hash");
                                    continue;
                                }
                                flag = true;
                                std::string addr = GetBase58Addr(vin.vinsign().pub());
                                if (!CheckBase58Addr(addr))
                                {
                                    ERRORLOG("CheckBase58Addr error addr:{}",addr);
                                    return -33;
                                }
                                if (DBStatus::DB_SUCCESS != db_writer.RemoveBonusAddrInvestAddrUtxoByBonusAddr(invested_node, addr, divest_utxo_hash))
                                {
                                    ERRORLOG("RemoveBonusAddrInvestAddrUtxoByBonusAddr error invested_node:{},addr:{},divest_utxo_hash:{}",invested_node, addr, divest_utxo_hash);
                                    return -34;
                                }
                                std::vector<string> utxos;
                                ret = db_writer.GetBonusAddrInvestUtxosByBonusAddr(invested_node, addr, utxos);
                                if (ret == DBStatus::DB_NOT_FOUND || utxos.empty())
                                {
                                    if (DBStatus::DB_SUCCESS != db_writer.RemoveInvestAddrByBonusAddr(invested_node, addr))
                                    {
                                        ERRORLOG("RemoveInvestAddrByBonusAddr invested_node:{},addr:{}",invested_node, addr);
                                        return -35;
                                    }
                                    std::vector<string> invest_addrs;
                                    if (db_writer.GetInvestAddrsByBonusAddr(invested_node, invest_addrs) == DBStatus::DB_NOT_FOUND || invest_addrs.empty())
                                    {
                                        if (DBStatus::DB_SUCCESS != db_writer.RemoveBonusAddr(invested_node))
                                        {
                                            ERRORLOG("RemoveBonusAddr error invested_node:{}",invested_node);
                                            return -36;
                                        }                                
                                    }
                                    
                                    if (DBStatus::DB_SUCCESS != db_writer.RemoveBonusAddrByInvestAddr(addr,invested_node))
                                    {
                                        ERRORLOG("RemoveBonusAddrByInvestAddr error! addr:{},invested_node:{}",addr,invested_node);
                                        return -37;
                                    }
                                }
                                else if (DBStatus::DB_SUCCESS != ret)
                                {
                                    ERRORLOG("GetBonusAddrInvestUtxosByBonusAddr error! ret:{}",ret);
                                    return -38;
                                }
                                break;
                            }
                            
                        }
                        if (!flag)
                        {
                            ERRORLOG("unknow type");
                            return -39;
                        }
            
                        uint64_t invest_amount = 0;
                        std::string strTx;
                        if (db_writer.GetTransactionByHash(divest_utxo_hash, strTx) != DBStatus::DB_SUCCESS)
                        {
                            MagicSingleton<BlockHelper>::GetInstance()->PushMissUTXO(divest_utxo_hash);
                            ERRORLOG("GetTransactionByHash error! divest_utxo_hash:{},strTx:{}",divest_utxo_hash, strTx);
                            return -40;
                        }
                        CTransaction InvestTx;
                        if(!InvestTx.ParseFromString(strTx))
                        {
                            ERRORLOG("InvestTx.ParseFromString(strTx) = {} ",strTx);
                            return -41;
                        }

                        for (int i = 0; i < InvestTx.utxo().vout_size(); i++)
                        {
                            if (InvestTx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr)
                            {
                                invest_amount += InvestTx.utxo().vout(i).value();
                                break;
                            }
                        }
                        uint64_t Totalinvest = 0;
                        std::vector<std::string> utxos;
                        {
                            std::lock_guard<std::mutex> lock(global::ca::kInvestMutex);
                            uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(InvestTx.time());
                            auto ret = db_writer.GetInvestUtxoByPeriod(Period, utxos);
                            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                            {
                                ERRORLOG("DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret {}",ret);
                                return -42;
                            }
                            if (utxos.cend() != std::find(utxos.cbegin(), utxos.cend(), divest_utxo_hash))
                            {
                                if(DBStatus::DB_SUCCESS != db_writer.GetTotalInvestAmount(Totalinvest))
                                {
                                    ERRORLOG("GetTotalInvestAmount error! Totalinvest:{}",Totalinvest);
                                    return -43;
                                }
                                Totalinvest-=invest_amount;
                                if(DBStatus::DB_SUCCESS != db_writer.SetTotalInvestAmount(Totalinvest))
                                {
                                    ERRORLOG("SetTotalInvestAmount error! Totalinvest:{}",Totalinvest);
                                    return -44;
                                }
                                uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(InvestTx.time());
                                if(DBStatus::DB_SUCCESS != db_writer.RemoveInvestUtxoByPeriod(Period, divest_utxo_hash))
                                {
                                    ERRORLOG("RemoveInvestUtxoByPeriod error! Period:{},divest_utxo_hash:{}",Period, divest_utxo_hash);
                                    return -45;
                                }
                            }
                        }
                    }
                    // Renewal of claim transaction......
                    else if(tx_type == global::ca::TxType::kTxTypeBonus)
                    {
                        uint64_t claim_amount = 0;
                        uint64_t claim_Vout_amount = 0;
                        uint64_t TotalCirculation = 0;
                        uint64_t MiningBalance=0;
                        int i=0;
                        
                        nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
                        tx_info["BonusAmount"].get_to(claim_amount);
                        
                        {
                            std::lock_guard<std::mutex> lock(global::ca::kBonusMutex);
                            if(DBStatus::DB_SUCCESS != db_writer.GetM2(TotalCirculation))
                            {
                                ERRORLOG("GetM2 error! TotalCirculation:{}",TotalCirculation);
                                return -46;
                            }
                            if (DBStatus::DB_SUCCESS != db_writer.GetTotalAwardAmount(MiningBalance))
                            {
                                ERRORLOG("GetTotalAwardAmount MiningBalance:{}",MiningBalance);
                                return -47;
                            }
                            TotalCirculation += claim_amount;
                            MiningBalance-=claim_amount;
                            if(MiningBalance - claim_amount < 0)
                            {
                                ERRORLOG("MiningBalance - claim_amount < 0 {},{}",MiningBalance,claim_amount);
                                return -48;
                            }
                            uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(tx.time());
                            if(DBStatus::DB_SUCCESS != db_writer.SetBonusUtxoByPeriod(Period,tx.hash()))
                            {
                                ERRORLOG("SetBonusUtxoByPeriod error! Period:{},hash:{}",Period,tx.hash());
                                return -49;
                            }
                            if (DBStatus::DB_SUCCESS != db_writer.SetTotalAwardAmount(MiningBalance))
                            {
                                ERRORLOG("SetTotalAwardAmount error! MiningBalance:{}",MiningBalance);
                                return -50;
                            }
                            if (DBStatus::DB_SUCCESS != db_writer.SetTotalCirculation(TotalCirculation))
                            {
                                ERRORLOG("SetTotalCirculation TotalCirculation:{}",TotalCirculation);
                                return -51;
                            }
                        } 
                    }
                    else if(tx_type == global::ca::TxType::kTxTypeDeployContract)
                    {
                        for (auto &vin : tx.utxo().vin())
                        {
                            const std::string deployer_address = GetBase58Addr(vin.vinsign().pub());
                            const std::string deploy_hash = tx.hash();
                            std::string ContractAddress = evm_utils::generateEvmAddr(deployer_address + deploy_hash);//Evmone::GenContractAddress(deployer_address, deploy_hash);
                            std::cout << "ContractAddress: " << ContractAddress << std::endl;
                            nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
                            std::string code = tx_info["Output"].get<std::string>();
                            if (DBStatus::DB_SUCCESS != db_writer.SetContractDeployUtxoByContractAddr(ContractAddress, deploy_hash))
                            {
                                return -52;
                            }
                            for(auto &it : tx_info["PrevHash"].items())
                            {
                                if(it.key() == "") continue;
                                std::string currentPreHash;
                                if (DBStatus::DB_SUCCESS != db_writer.GetLatestUtxoByContractAddr(it.key(), currentPreHash))
                                {
                                    
                                    return -53;
                                }

                                if(currentPreHash != it.value())
                                {
                                    return -54;
                                }

                                if (DBStatus::DB_SUCCESS != db_writer.SetLatestUtxoByContractAddr(it.key(), deploy_hash))
                                {
                                    
                                    return -55;
                                }
                            }
                            if (DBStatus::DB_SUCCESS != db_writer.SetLatestUtxoByContractAddr(ContractAddress, deploy_hash))
                            {
                                
                                return -56;
                            }

                            if (DBStatus::DB_SUCCESS != db_writer.SetDeployUtxoByDeployerAddr(deployer_address, deploy_hash))
                            {
                                return -57;
                            }
                            std::vector<std::string> vecDeployerAddrs;
                            auto ret = db_writer.GetAllDeployerAddr(vecDeployerAddrs);
                            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                            {
                                return -58;
                            }
                            auto iter = std::find(vecDeployerAddrs.begin(), vecDeployerAddrs.end(), deployer_address);
                            if(iter == vecDeployerAddrs.end())
                            {
                                if (DBStatus::DB_SUCCESS != db_writer.SetDeployerAddr(deployer_address))
                                {
                                    return -59;
                                }
                            }
                            nlohmann::json storage = tx_info["Storage"];
                            if(!storage.is_null())
                            {
                                // nlohmann::json storage = nlohmann::json::parse(Storage_json);
                                for (auto it = storage.begin(); it != storage.end(); ++it)
                                {
                                    std::string strKey = it.key();
                                    if (strKey.substr(strKey.length() - 8 , strKey.length()) == "rootHash" || strKey.empty())
                                    {
                                        continue;
                                    }
                                    size_t pos = strKey.find('_');
                                    if(pos != std::string::npos)
                                    {
                                        strKey = ContractAddress + strKey.substr(pos);
                                    }
                                    if (db_writer.SetMptValueByMptKey(strKey, it.value()) != DBStatus::DB_SUCCESS)
                                    {
                                        return -60;
                                    }
                                }
                            }
                            break;
                        
                        }
                    }
                    else if(tx_type == global::ca::TxType::kTxTypeCallContract)
                    {
                        nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
                        for(auto &it : tx_info["PrevHash"].items())
                        {
                            std::string currentPreHash;
                            if (DBStatus::DB_SUCCESS != db_writer.GetLatestUtxoByContractAddr(it.key(), currentPreHash))
                            {
                                
                                return -61;
                            }

                            if(currentPreHash != it.value())
                            {
                                return -62;
                            }
                            if (DBStatus::DB_SUCCESS != db_writer.SetLatestUtxoByContractAddr(it.key(), tx.hash()))
                            {
                                
                                return -63;
                            }
                        }
                        nlohmann::json storage = tx_info["Storage"];
                        if(!storage.is_null())
                        {
                            for (auto it = storage.begin(); it != storage.end(); ++it)
                            {
                                std::string strKey = it.key();
                                if (strKey.substr(strKey.length() - 8 , strKey.length()) == "rootHash" || strKey.empty())
                                {
                                    continue;
                                }
                                if (db_writer.SetMptValueByMptKey(strKey, it.value()) != DBStatus::DB_SUCCESS)
                                {
                                    return -64;
                                }
                            }
                        }

                    }
                }
                catch (...)
                {
                    return -65;
                }
                    
                

            }

            bool isMultiSign = IsMultiSign(tx);
            // All transaction updates delete the utxo used, and subtract the balance of utxo used by the transaction address
            std::vector<std::string> vin_hashs;
            for (auto &vin : tx.utxo().vin())
            {
                global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();
                
                
                std::string addr;
                if(vin.contractaddr().empty())
                {
                    if (vin.vinsign().pub().size() == 0)
                    {
                        return -34;
                    }
                    Base58Ver ver = isMultiSign ? Base58Ver::kBase58Ver_MultiSign : Base58Ver::kBase58Ver_Normal;
                    addr = GetBase58Addr(vin.vinsign().pub(), ver);
                }
                else if(global::ca::TxType::kTxTypeDeployContract == tx_type || global::ca::TxType::kTxTypeCallContract == tx_type)
                {
                    if (vin.vinsign().pub().size() != 0)
                    {
                        return -36;
                    }
                    addr = vin.contractaddr();
                }
                all_addr.insert(addr);

                for (auto & prevout : vin.prevout())
                {
                    std::string utxo_hash = prevout.hash();
                    std::string utxo_n = utxo_hash + "_" + std::to_string(prevout.n());
                    if (tx_type == global::ca::TxType::kTxTypeUnstake && 
                        redeem_utxo_hash == utxo_hash && 
                        1 == prevout.n())
                    {
                        continue;
                    }
                    else if (tx_type == global::ca::TxType::kTxTypeDisinvest && 
                            divest_utxo_hash == utxo_hash && 
                            1 == prevout.n())
                    {
                        continue;
                    }                

                    if (vin_hashs.cend() != std::find(vin_hashs.cbegin(), vin_hashs.cend(), utxo_n))
                    {
                        continue;
                    }
                    vin_hashs.push_back(utxo_n);

                    if (DBStatus::DB_SUCCESS != db_writer.RemoveUtxoHashsByAddress(addr, utxo_hash))
                    {
                        ERRORLOG("RemoveUtxoHashsByAddress addr:{},utxo_hash:{}",addr,utxo_hash);
                        return -66;
                    }

                    
                    uint64_t amount = 0;
                    std::string balance_utxo ;
                    if (DBStatus::DB_SUCCESS != db_writer.GetUtxoValueByUtxoHashs(utxo_hash, addr, balance_utxo))
                    {
                        MagicSingleton<BlockHelper>::GetInstance()->PushMissUTXO(utxo_hash);
                        ERRORLOG("GetTransactionByHash failed!");
                        return - 67;
                    }

                    if (DBStatus::DB_SUCCESS != db_writer.RemoveUtxoValueByUtxoHashs(utxo_hash, addr, balance_utxo))
                    {
                        ERRORLOG("GetTransactionByHash failed!");
                        return - 68;
                    }
                    
                    //If I get the pledged utxo, I will use it together
                    uint64_t stakeValue = 0;
                    std::string underline = "_";
                    std::vector<std::string> utxo_values;

                    if(balance_utxo.find(underline) != string::npos)
                    {
                        StringUtil::SplitString(balance_utxo, "_", utxo_values);
                        
                        for(int i = 0; i < utxo_values.size(); ++i)
                        {
                            stakeValue += std::stol(utxo_values[i]);
                        }
                        amount = stakeValue;
                    }
                    else
                    {
                        amount = std::stol(balance_utxo);
                    }

                    int64_t balance = 0;
                    ret = db_writer.GetBalanceByAddress(addr, balance);
                    if (DBStatus::DB_SUCCESS != ret)
                    {
                        if (DBStatus::DB_NOT_FOUND != ret)
                        {
                            ERRORLOG("GetBalanceByAddress error! ret:{}",ret);
                            return -69;
                        }
                        else
                        {
                            balance = 0;
                        }
                    }
                    balance -= amount;
                    if (balance < 0)
                    {
                        ERRORLOG("SaveBlock vin height:{} hash:{} addr:{} balance:{}", block.height(), block.hash(), addr, balance);
                        return -70;
                    }
                    if (0 == balance)
                    {
                        if (DBStatus::DB_SUCCESS != db_writer.DeleteBalanceByAddress(addr))
                        {
                            ERRORLOG("DeleteBalanceByAddress error! addr:{}",addr);
                            return -71;
                        }
                    }
                    else
                    {
                        if (DBStatus::DB_SUCCESS != db_writer.SetBalanceByAddress(addr, balance))
                        {
                            ERRORLOG("SetBalanceByAddress error! addr:{},balance:{}",addr,balance);
                            return -72;
                        }
                    }
                }
            }

        }
        {
            uint64_t SignNumber = 0;
            uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(tx.time());
            std::vector<std::string> SignAddrs;
            auto ret = db_writer.GetSignAddrByPeriod(Period, SignAddrs);
            if(DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
            {
                ERRORLOG("GetSignAddrByPeriod error! ret:{}",ret);
                return -73;
            }
            for (auto &sign : tx.verifysign())
            {
                
                std::string vout_addr = GetBase58Addr(sign.pub());
                if (!CheckBase58Addr(vout_addr, Base58Ver::kBase58Ver_Normal))
                {
                    return -74;
                }

                auto found = std::find(SignAddrs.begin(), SignAddrs.end(), vout_addr);
                if(found == SignAddrs.end())
                {
                    if(DBStatus::DB_SUCCESS != db_writer.SetSignAddrByPeriod(Period, vout_addr))
                    {
                        ERRORLOG("SetSignAddrByPeriod error! Period:{},vout.addr{}",Period,vout_addr);
                        return -75;
                    }
                }
                auto ret = db_writer.GetSignNumberByPeriod(Period, vout_addr, SignNumber);
                if(DBStatus::DB_SUCCESS != ret)
                {
                    if(DBStatus::DB_NOT_FOUND == ret)
                    {
                        SignNumber = 0;
                    }
                    else
                    {
                        ERRORLOG("GetSignNumberByPeriod error! ret:{}",ret);
                        return -76;
                    }
                }
                SignNumber += 1;
                if(DBStatus::DB_SUCCESS != db_writer.SetSignNumberByPeriod(Period, vout_addr, SignNumber))
                {
                    ERRORLOG("SetSignNumberByPeriod error! Period:{},vout.addr:{},SignNumber:{}",Period,vout_addr,SignNumber);
                    return -77;
                }
            }
        }

        // Add new utxo to all transactions and increase the balance of utxo used by the transaction address
        std::multimap<std::string,std::string> utxo_value;
        std::multimap<std::string,std::string> bouns_utxo_value;
        std::map<std::string,std::multimap<std::string,std::string>> ContractUtxoValue;
        for (auto &vout : tx.utxo().vout())
        {
            if(vout.addr() == global::ca::kVirtualBurnGasAddr)
            {
                uint64_t Totalburn = 0;
                uint64_t burnAmount = 0;
                uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(tx.time());
                std::lock_guard<std::mutex> lock(global::ca::kBurnMutex);
                auto ret = db_writer.GetDM(Totalburn);
                DEBUGLOG("Totalburn {}",Totalburn);
                if(ret != DBStatus::DB_SUCCESS && ret != DBStatus::DB_NOT_FOUND)
                {
                    ERRORLOG("GetDM error! Totalburn:{}",Totalburn);
                    return -78;
                }

                ret = db_writer.GetburnAmountByPeriod(Period, burnAmount);
                DEBUGLOG("burnAmount {}",burnAmount);
                if(DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                {
                    ERRORLOG("GetburnAmountByPeriod error! ret:{}",ret);
                    return -79;
                }
                DEBUGLOG("vout.value() {}",vout.value());
                DEBUGLOG("Totalburn {}",Totalburn);
                DEBUGLOG("burnAmount {}",burnAmount);
                burnAmount += vout.value();
                Totalburn += vout.value();
                if(DBStatus::DB_SUCCESS != db_writer.SetburnAmountByPeriod(Period, burnAmount))
                {
                    ERRORLOG("SetburnAmountByPeriod error! Period:{}, burnAmount:{}", Period, burnAmount);
                    return -80;
                }
                if (DBStatus::DB_SUCCESS != db_writer.SetDM(Totalburn))
                {
                    ERRORLOG("SetDM error! Totalburn:{}", Totalburn);
                    return -81;
                }
                
                continue;
            }

            if(vout.addr() == global::ca::kVirtualDeployContractAddr ||vout.addr() == global::ca::kVirtualCallContractAddr)
            {
                continue;
            }

            global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();
            if (vout.addr() != global::ca::kVirtualStakeAddr && vout.addr() != global::ca::kVirtualInvestAddr)
            {
                all_addr.insert(vout.addr());
            }

            std::vector<std::string> utxoHashs;
            db_writer.GetUtxoHashsByAddress(vout.addr(), utxoHashs);
            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
            {
                ERRORLOG("SetUtxoHashsByAddress error! ret:{}",ret);
                return -82;
            }
            
            if(utxoHashs.cend() == std::find(utxoHashs.cbegin(), utxoHashs.cend(), tx.hash()))
            {
                ret = db_writer.SetUtxoHashsByAddress(vout.addr(), tx.hash());
                if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                {
                    ERRORLOG("SetUtxoHashsByAddress error! ret:{}",ret);
                    return -83;
                }
            }

            if(tx_type == global::ca::TxType::kTxTypeUnstake || tx_type == global::ca::TxType::kTxTypeDisinvest)
            {
                utxo_value.insert(std::make_pair(tx.hash() + "_" + vout.addr(),std::to_string(vout.value())));
            }
            else if(tx_type == global::ca::TxType::kTxTypeBonus)
            {
                //If hash is the same, use it together
                if(vout.addr() == tx.utxo().owner(0))
                {
                    bouns_utxo_value.insert(std::make_pair(tx.hash() + "_" + vout.addr(),std::to_string(vout.value())));
                }
                else
                {
                    ret = db_writer.SetUtxoValueByUtxoHashs(tx.hash(), vout.addr(), std::to_string(vout.value()));
                    if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                    {
                        ERRORLOG("SetUtxoHashsByAddress error! ret:{}",ret);
                        return -84;
                    }
                }
            }
            else if(tx_type == global::ca::TxType::kTxTypeDeployContract || tx_type == global::ca::TxType::kTxTypeCallContract)
            {
                ContractUtxoValue[vout.addr()].insert(std::make_pair(tx.hash() + "_" + vout.addr(),std::to_string(vout.value())));
            }
            else
            {
                ret = db_writer.SetUtxoValueByUtxoHashs(tx.hash(), vout.addr(), std::to_string(vout.value()));
                if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                {
                    ERRORLOG("SetUtxoHashsByAddress error! ret:{}",ret);
                    return -85;
                }
            }

            int64_t balance = 0;
            ret = db_writer.GetBalanceByAddress(vout.addr(), balance);
            if (DBStatus::DB_SUCCESS != ret)
            {
                if (DBStatus::DB_NOT_FOUND != ret)
                {
                    ERRORLOG("DBStatus::DB_SUCCESS != ret");
                    return -86;
                }
                else
                {
                    balance = 0;
                }
            }
            DEBUGLOG("save balace current is {}",balance);
            balance += vout.value();
            DEBUGLOG("save balace current is after{}",balance);
            if (balance < 0)
            {
                ERRORLOG("SaveBlock vout height:{} hash:{} addr:{} balance:{}", block.height(), block.hash(), vout.addr(), balance);
                return -87;
            }
            DEBUGLOG("vout.addr() {}",vout.addr());
            if (DBStatus::DB_SUCCESS != db_writer.SetBalanceByAddress(vout.addr(), balance))
            {
                ERRORLOG("SetBalanceByAddress error! vout.addr{},balance:{}",vout.addr(),balance);
                return -88;
            }
        }


        std::vector<std::string> utxo_values;
        if(utxo_value.size() == 2)
        {
            std::string utxo_hash_balance;
            auto iter = utxo_value.begin();
            for(;iter != utxo_value.end(); iter ++)
            {
                utxo_hash_balance += iter->second + "_";
                utxo_values.clear();
                StringUtil::SplitString(iter->first, "_", utxo_values);      
            }

            if(utxo_hash_balance[utxo_hash_balance.length()-1] == '_')
            {
                utxo_hash_balance = utxo_hash_balance.substr(0,utxo_hash_balance.length()-1);
            }

            ret = db_writer.SetUtxoValueByUtxoHashs(utxo_values[0], utxo_values[1], utxo_hash_balance);
            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
            {
                ERRORLOG("SetUtxoValueByUtxoHashs error! ret:{}",ret);
                return -89;
            }

        }

        std::vector<std::string> bouns_utxo_values;
        if(!bouns_utxo_value.empty())
        {
            std::string utxo_hash_balance;
            auto iter = bouns_utxo_value.begin();
            for(;iter != bouns_utxo_value.end(); iter ++)
            {
                utxo_hash_balance += iter->second + "_";   
                bouns_utxo_values.clear();
                StringUtil::SplitString(iter->first, "_", bouns_utxo_values);   
            }
            if(utxo_hash_balance[utxo_hash_balance.length()-1] == '_')
            {
                utxo_hash_balance = utxo_hash_balance.substr(0,utxo_hash_balance.length()-1);
            }

            ret = db_writer.SetUtxoValueByUtxoHashs(bouns_utxo_values[0], bouns_utxo_values[1], utxo_hash_balance);
            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
            {
                ERRORLOG("SetUtxoValueByUtxoHashs error! ret:{}",ret);
                return -90;
            }

        }
        if(!ContractUtxoValue.empty())
        {
            for(const auto& UtxoValue : ContractUtxoValue)
            {
                std::vector<std::string> ContractUtxoValues;
                std::string utxoHashBalance;
                auto iter = UtxoValue.second.begin();
                for(;iter != UtxoValue.second.end(); iter ++)
                {
                    utxoHashBalance += iter->second+"_";
                    ContractUtxoValues.clear();
                    StringUtil::SplitString(iter->first, "_", ContractUtxoValues);   
                }
                if(utxoHashBalance[utxoHashBalance.length()-1] == '_')
                {
                    utxoHashBalance = utxoHashBalance.substr(0,utxoHashBalance.length()-1);
                }

                ret = db_writer.SetUtxoValueByUtxoHashs(ContractUtxoValues[0], ContractUtxoValues[1], utxoHashBalance);
                if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                {
                    ERRORLOG("SetUtxoValueByUtxoHashs error! ret:{}",ret);
                    return -79;
                }
            }   
        }
        // Add transaction body data corresponding to transaction hash
        if (DBStatus::DB_SUCCESS != db_writer.SetTransactionByHash(tx.hash(), tx.SerializeAsString()))
        {
            ERRORLOG("SetTransactionByHash error! tx.hash:{},tx:{}",tx.SerializeAsString());
            return -91;
        }

        // Add block hash corresponding to transaction hash
        if (DBStatus::DB_SUCCESS != db_writer.SetBlockHashByTransactionHash(tx.hash(), block.hash()))
        {
            ERRORLOG("SetBlockHashByTransactionHash error! tx.hash:{},block.hash:{}",tx.hash(),block.hash());
            return -92;
        } 
    }
    
    if (block.version() == global::ca::kCurrentBlockVersion && IsContractBlock(block))
    {
        nlohmann::json blockData;
        try
        {
            blockData = nlohmann::json::parse(block.data());
        }
        catch (...)
        {
            ERRORLOG("parse blockData fail");
            return -82;
        }
        for (const auto& tx : block.txs())
        {
            global::ca::VmType vmType;
            try
            {
                nlohmann::json dataJson = nlohmann::json::parse(tx.data());
                nlohmann::json _txInfo = dataJson["TxInfo"].get<nlohmann::json>();
                vmType = _txInfo["VmType"].get<global::ca::VmType>();
            }
            catch(...)
            {
                ERRORLOG("parse TxInfo fail");
                return -83;
            }
            if (global::ca::TxType::kTxTypeDeployContract == (global::ca::TxType)tx.txtype())
            {
                for (auto &vin : tx.utxo().vin())
                {
                    const std::string deployerAddress = GetBase58Addr(vin.vinsign().pub());
                    const std::string deployHash = tx.hash();
                    std::string contractAddress = evm_utils::GenerateContractAddr(
                            deployerAddress + deployHash);
                    std::cout << "contractAddress: " << contractAddress << std::endl;
                    if(vmType ==  global::ca::VmType::EVM)
                    {
                        std::cout << "EvmAddress: "
                            << evm_utils::generateEvmAddr(evm_utils::generateEvmAddr(deployerAddress + deployHash))
                            << std::endl;
                    }

                    nlohmann::json txInfo;
                    for (const auto&[key, value] : blockData.items())
                    {
                        if (key == deployHash)
                        {
                            txInfo = value;
                            break;
                        }
                    }

                    if (DBStatus::DB_SUCCESS != db_writer.SetContractDeployUtxoByContractAddr(contractAddress, deployHash))
                    {
                        return -84;
                    }
                    for(auto &it : txInfo["PrevHash"].items())
                    {
                        if(it.key() == "") continue;
                        std::string currentPreHash;
                        if (DBStatus::DB_SUCCESS != db_writer.GetLatestUtxoByContractAddr(it.key(), currentPreHash))
                        {
                            
                            return -85;
                        }

                        if(currentPreHash != it.value())
                        {
                            MagicSingleton<BlockHelper>::GetInstance()->PushMissUTXO(it.value());
                            return -86;
                        }

                        if (DBStatus::DB_SUCCESS != db_writer.SetLatestUtxoByContractAddr(it.key(), deployHash))
                        {
                           
                            return -87;
                        }
                    }

                    for(const auto& it : txInfo["selfdestructs"].items())
                    {
                        if(it.key() == "") continue;
                        DEBUGLOG("RemoveContractDeployUtxoByContractAddr,addr:{}", it.key());
                        if (DBStatus::DB_SUCCESS != db_writer.RemoveContractDeployUtxoByContractAddr(it.key()))
                        {
                            return -88;
                        }
                    }

                    nlohmann::json storage = txInfo["Storage"];
                    if(!storage.is_null())
                    {
                        for (auto it = storage.begin(); it != storage.end(); ++it)
                        {
                            std::string strKey = it.key();
                            if (strKey.substr(strKey.length() - 8 , strKey.length()) == "rootHash" || strKey.empty())
                            {
                                continue;
                            }
                            size_t pos = strKey.find('_');
                            if(pos != std::string::npos)
                            {
                                strKey = contractAddress + strKey.substr(pos);
                            }
                            if (db_writer.SetMptValueByMptKey(strKey, it.value()) != DBStatus::DB_SUCCESS)
                            {
                                return -89;
                            }
                        }
                    }
                    if (DBStatus::DB_SUCCESS != db_writer.SetLatestUtxoByContractAddr(contractAddress, deployHash))
                    {
                        
                        return -90;
                    }

                    if (DBStatus::DB_SUCCESS != db_writer.SetDeployUtxoByDeployerAddr(deployerAddress, deployHash))
                    {
                        return -91;
                    }
                    std::vector<std::string> vecDeployerAddrs;
                    DBStatus ret;
                    if(vmType == global::ca::VmType::EVM)
                    {
                        ret = db_writer.GetAllEvmDeployerAddr(vecDeployerAddrs);
                    }
                    else if(vmType == global::ca::VmType::WASM)
                    {
                        ret = db_writer.GetAllWasmDeployerAddr(vecDeployerAddrs);
                    }
                    
                    if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                    {
                        return -92;
                    }
                    auto iter = std::find(vecDeployerAddrs.begin(), vecDeployerAddrs.end(), deployerAddress);
                    if(iter == vecDeployerAddrs.end())
                    {
                        if(vmType == global::ca::VmType::EVM)
                        {
                            if (DBStatus::DB_SUCCESS != db_writer.SetEvmDeployerAddr(deployerAddress))
                            {
                                return -93;
                            }
                        }
                        else if(vmType == global::ca::VmType::WASM)
                        {
                            if(DBStatus::DB_SUCCESS != db_writer.SetWasmDeployerAddr(deployerAddress))
                            {
                                return -94;
                            }
                        }
                    }

                    break;
                }
            }
            else if (global::ca::TxType::kTxTypeCallContract == (global::ca::TxType)tx.txtype())
            {
                nlohmann::json txInfo;
                for (const auto&[key, value] : blockData.items())
                {
                    if (key == tx.hash())
                    {
                        txInfo = value;
                        break;
                    }

                }
                DEBUGLOG("blockHash:{}, txHash:{} \n txInfo:{}", block.hash().substr(0,6), tx.hash().substr(0,6), txInfo["PrevHash"].dump(4));
                for(auto &it : txInfo["PrevHash"].items())
                {
                    std::string currentPreHash;
                    if (DBStatus::DB_SUCCESS != db_writer.GetLatestUtxoByContractAddr(it.key(), currentPreHash))
                    {
                        
                        return -95;
                    }
                    DEBUGLOG("it.key:{}, it.value:{}, currentPreHash:{}", it.key(), it.value(), currentPreHash);
                    if(currentPreHash != it.value())
                    {
                        MagicSingleton<BlockHelper>::GetInstance()->PushMissUTXO(it.value());
                        return -96;
                    }
                    if (DBStatus::DB_SUCCESS != db_writer.SetLatestUtxoByContractAddr(it.key(), tx.hash()))
                    {
                       
                        return -97;
                    }
                }

                for(const auto& it : txInfo["selfdestructs"].items())
                {
                    if(it.key() == "") continue;
                    DEBUGLOG("RemoveContractDeployUtxoByContractAddr,addr:{}", it.key());
                    if (DBStatus::DB_SUCCESS != db_writer.RemoveContractDeployUtxoByContractAddr(it.key()))
                    {
                        return -98;
                    }
                }

                nlohmann::json storage = txInfo["Storage"];
                if(!storage.is_null())
                {
                    for (auto it = storage.begin(); it != storage.end(); ++it)
                    {
                        std::string strKey = it.key();
                        if (strKey.substr(strKey.length() - 8 , strKey.length()) == "rootHash" || strKey.empty())
                        {
                            continue;
                        }
                        if (db_writer.SetMptValueByMptKey(strKey, it.value()) != DBStatus::DB_SUCCESS)
                        {
                            return -99;
                        }
                    }
                }
            }
        }
    }

    int result = CalcHeightsSumHash(block.height(), db_writer);
    if(result != 0)
    {
        return result - 10000;
    }
    
    return 0;
}

int ca_algorithm::DeleteBlock(DBReadWriter &db_writer, const std::string &block_hash)
{
    CBlock block;
    std::string block_raw;
    auto ret = db_writer.GetBlockByBlockHash(block_hash, block_raw);

    if (DBStatus::DB_NOT_FOUND == ret)
    {
        return 0;
    }
    else if (DBStatus::DB_SUCCESS != ret)
    {
        ERRORLOG("GetBlockByBlockHash block_hash:{},block_raw:{}",block_hash,block_raw);
        return -1;
    }
    if (!block.ParseFromString(block_raw))
    {
        ERRORLOG("ParseFromString error!");
        return -2;
    }

    // Judge the height of the block and whether to update the node height
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_writer.GetBlockTop(top))
    {
        ERRORLOG("GetBlockTop error! top:{}",top);
        return -3;
    }
    if (block.height() == top)
    {
        std::vector<std::string> tmp_block_hashs;
        if (DBStatus::DB_SUCCESS != db_writer.GetBlockHashsByBlockHeight(block.height(), tmp_block_hashs)) //Get the hash of all blocks with the height of this block
        {
            ERRORLOG("GetBlockHashsByBlockHeight  block.height:{}",block.height());
            return -4;
        }
        if (1 == tmp_block_hashs.size())
        {
            if (DBStatus::DB_SUCCESS != db_writer.SetBlockTop(block.height() - 1))
            {
                return -5;
            }
        }
	}

    // Delete the height corresponding to the block hash
    if (DBStatus::DB_SUCCESS != db_writer.DeleteBlockHeightByBlockHash(block.hash()))
    {
        ERRORLOG("DeleteBlockHeightByBlockHash block.hash:{}",block.hash());
        return -6;
    }

    // Delete block hash corresponding to height
    if (DBStatus::DB_SUCCESS != db_writer.RemoveBlockHashByBlockHeight(block.height(), block.hash()))
    {
        ERRORLOG("RemoveBlockHashByBlockHeight block.height:{},block.hash:{}",block.height(),block.hash());
        return -7;
    }

    // Delete the block data corresponding to the block hash
    if (DBStatus::DB_SUCCESS != db_writer.DeleteBlockByBlockHash(block.hash()))
    {
        ERRORLOG("DeleteBlockByBlockHash failed block.hash:{}",block.hash());
        return -8;
    }

    std::set<std::string> block_addr; //Currently, all transactions in the start processing block are removed
    std::set<std::string> all_addr;
    for (auto &tx : block.txs())
    {
        auto transaction_type = GetTransactionType(tx);
        block_addr.insert(all_addr.cbegin(), all_addr.cend());
        all_addr.clear();
        if (kTransactionType_Tx == transaction_type)
        {
            bool is_redeem = false;
            std::string redeem_utxo_hash;
            bool is_divest = false;
            std::string divest_utxo_hash;
            if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
            {
                try
                {
                    nlohmann::json data_json = nlohmann::json::parse(tx.data());
                    global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();

                    // The stake transaction updates the pledge address and the utxo of the pledge address
                    if (global::ca::TxType::kTxTypeStake == tx_type)
                    {
                        for (auto &vin : tx.utxo().vin())
                        {
                            std::string addr = GetBase58Addr(vin.vinsign().pub());
                            if (!CheckBase58Addr(addr))
                            {
                                ERRORLOG("CheckBase58Addr error! addr:{}",addr);
                                return -9;
                            }
                            if (DBStatus::DB_SUCCESS != db_writer.RemoveStakeAddressUtxo(addr, tx.hash()))
                            {
                                ERRORLOG("RemoveStakeAddressUtxo error! addr:{},tx.hash:{}",addr,tx.hash());
                                return -10;
                            }
                            std::vector<std::string> pledge_utxo_hashs;
                            auto ret = db_writer.GetStakeAddressUtxo(addr, pledge_utxo_hashs);
                            if (DBStatus::DB_NOT_FOUND == ret || pledge_utxo_hashs.empty())
                            {
                                if (DBStatus::DB_SUCCESS != db_writer.RemoveStakeAddresses(addr))
                                {
                                    ERRORLOG("RemoveStakeAddressUtxo error! ret:{}",ret);
                                    return -11;
                                }
                            }
                            break;
                        }
                    }
                    // The redeem transaction, update the pledge address and the utxo of the pledge address
                    else if (global::ca::TxType::kTxTypeUnstake == tx_type)
                    {
                        nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
                        is_redeem = true;
                        redeem_utxo_hash = tx_info["UnstakeUtxo"].get<std::string>();
                        for (auto &vin : tx.utxo().vin())
                        {
                            std::string addr = GetBase58Addr(vin.vinsign().pub());
                            if (!CheckBase58Addr(addr))
                            {
                                ERRORLOG("CheckBase58Addr error! addr:{}",addr);
                                return -12;
                            }
                            if (DBStatus::DB_SUCCESS != db_writer.SetStakeAddressUtxo(addr, redeem_utxo_hash))
                            {
                                ERRORLOG("SetStakeAddressUtxo addr:{},utxo_hash:{}",addr,redeem_utxo_hash);
                                return -13;
                            }
                            std::vector<std::string> pledge_addrs;
                            auto ret = db_writer.GetStakeAddress(pledge_addrs);
                            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                            {
                                ERRORLOG("GetStakeAddress error! ret:{}",ret);
                                return -14;
                            }
                            if (pledge_addrs.cend() == std::find(pledge_addrs.cbegin(), pledge_addrs.cend(), addr))
                            {
                                if (DBStatus::DB_SUCCESS != db_writer.SetStakeAddresses(addr))
                                {
                                    ERRORLOG("SetStakeAddresses error! can't find addr from pledge_addrs addr:{}",addr);
                                    return -15;
                                }
                            }
                            break;
                        }
                    }
                    // The investment transaction updates the investment address and the utxo of the investment address
                    else if (global::ca::TxType::kTxTypeInvest == tx_type)
                    {
                        uint64_t invest_amount = 0; 
                        nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
                        std::string invest_node = tx_info["BonusAddr"].get<std::string>();
                        tx_info["InvestAmount"].get_to(invest_amount);
                        for (auto &vin : tx.utxo().vin())
                        {
                            std::string addr = GetBase58Addr(vin.vinsign().pub());

                            if (DBStatus::DB_SUCCESS != db_writer.RemoveBonusAddrInvestAddrUtxoByBonusAddr(invest_node, addr, tx.hash()))
                            {
                                ERRORLOG("RemoveBonusAddrInvestAddrUtxoByBonusAddr error invest_node:{},addr:{},tx.hash:{}",invest_node, addr, tx.hash());
                                return -16;
                            }
                            std::vector<string> utxos;
                            if (db_writer.GetBonusAddrInvestUtxosByBonusAddr(invest_node, addr, utxos) == DBStatus::DB_NOT_FOUND || utxos.empty())
                            {
                                if (DBStatus::DB_SUCCESS != db_writer.RemoveInvestAddrByBonusAddr(invest_node, addr))
                                {
                                    ERRORLOG("RemoveInvestAddrByBonusAddr error! invest_node:{},addr:{}",invest_node,addr);
                                    return -17;
                                }
                                std::vector<string> invest_addrs;
                                if (db_writer.GetInvestAddrsByBonusAddr(invest_node, invest_addrs) == DBStatus::DB_NOT_FOUND || invest_addrs.empty())
                                {
                                    if (DBStatus::DB_SUCCESS != db_writer.RemoveBonusAddr(invest_node))
                                    {
                                        ERRORLOG("RemoveBonusAddr invest_node:{}",invest_node);
                                        return -18;
                                    }                                
                                }

                                if (DBStatus::DB_SUCCESS != db_writer.RemoveBonusAddrByInvestAddr(addr,invest_node))
                                {
                                    ERRORLOG("RemoveBonusAddrByInvestAddr addr:{},invest_node:{}",addr,invest_node);
                                    return -19;
                                }
                            }
                            break;
                        }
                        uint64_t Totalinvest = 0;
                        std::vector<std::string> utxos;
                        {
                            std::lock_guard<std::mutex> lock(global::ca::kInvestMutex);
                            uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(tx.time());
                            auto ret = db_writer.GetInvestUtxoByPeriod(Period, utxos);
                            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                            {
                                return -20;
                            }
                            if (utxos.cend() != std::find(utxos.cbegin(), utxos.cend(), tx.hash()))
                            {
                                if(DBStatus::DB_SUCCESS != db_writer.GetTotalInvestAmount(Totalinvest))
                                {
                                    ERRORLOG("GetTotalInvestAmount Totalinves:{}",Totalinvest);
                                    return -21;
                                }
                                Totalinvest-=invest_amount;
                                if(DBStatus::DB_SUCCESS != db_writer.SetTotalInvestAmount(Totalinvest))
                                {
                                    ERRORLOG("SetTotalInvestAmount error! Totalinvest:{}",Totalinvest);
                                    return -22;
                                }
                                uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(tx.time());
                                if(DBStatus::DB_SUCCESS != db_writer.RemoveInvestUtxoByPeriod(Period, tx.hash()))
                                {
                                    ERRORLOG("RemoveInvestUtxoByPeriod error! Period:{},tx.hash:{}",Period,tx.hash());
                                    return -23;
                                }
                            }
                        }
                    }
                    // The divestment transaction updates the investment address and the utxo of the investment address
                    else if(global::ca::TxType::kTxTypeDisinvest == tx_type)
                    {
                        is_divest = true;
                        nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
                        divest_utxo_hash = tx_info["DisinvestUtxo"].get<std::string>();
                        std::string invested_node = tx_info["BonusAddr"].get<std::string>();
                        std::vector<std::string> invest_nodes;
                        ret = db_writer.GetBonusaddr(invest_nodes);
                        if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                        {
                            return -24;
                        }
                        if (invest_nodes.cend() == std::find(invest_nodes.cbegin(), invest_nodes.cend(), invested_node))
                        {
                            if (DBStatus::DB_SUCCESS != db_writer.SetBonusAddr(invested_node))
                            {
                                return -25;
                            }
                        }

                        for (auto &vin : tx.utxo().vin())
                        {
                            std::string addr = GetBase58Addr(vin.vinsign().pub());
                            if (!CheckBase58Addr(addr))
                            {
                                return -26;
                            }
                            if (DBStatus::DB_SUCCESS != db_writer.SetBonusAddrInvestAddrUtxoByBonusAddr(invested_node, addr, divest_utxo_hash))
                            {
                                return -27;
                            }
                            std::vector<std::string> invest_addrs;
                            auto ret = db_writer.GetInvestAddrsByBonusAddr(invested_node, invest_addrs);
                            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                            {
                                return -28;
                            }
                            if (invest_addrs.cend() == std::find(invest_addrs.cbegin(), invest_addrs.cend(), addr))
                            {
                                if (DBStatus::DB_SUCCESS != db_writer.SetInvestAddrByBonusAddr(invested_node, addr))
                                {
                                    return -29;
                                }
                            }

                            std::vector<std::string> invest_nodes;
                            ret = db_writer.GetBonusAddrByInvestAddr(addr, invest_nodes);
                            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                            {
                                return -30;
                            }
                            if (invest_nodes.cend() == std::find(invest_nodes.cbegin(), invest_nodes.cend(), invested_node))
                            {
                                if (DBStatus::DB_SUCCESS != db_writer.SetBonusAddrByInvestAddr(addr, invested_node))
                                {
                                    return -31;
                                }
                            }
                            break;
                        }

                        uint64_t invest_amount = 0;
                        std::string strTx;
                        if (db_writer.GetTransactionByHash(divest_utxo_hash, strTx) != DBStatus::DB_SUCCESS)
                        {
                            return -32;
                        }
                        CTransaction InvestTx;
                        if(!InvestTx.ParseFromString(strTx))
                        {
                            return -33;
                        }

                        for (int i = 0; i < InvestTx.utxo().vout_size(); i++)
                        {
                            if (InvestTx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr)
                            {
                                invest_amount += InvestTx.utxo().vout(i).value();
                                break;
                            }
                        }
                        uint64_t Totalinvest = 0;
                        std::vector<std::string> utxos;
                        {
                            std::lock_guard<std::mutex> lock(global::ca::kInvestMutex);
                            uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(InvestTx.time());
                            auto ret = db_writer.GetInvestUtxoByPeriod(Period, utxos);
                            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                            {
                                return -34;
                            }
                            if (utxos.cend() == std::find(utxos.cbegin(), utxos.cend(), divest_utxo_hash))
                            {
                                if(DBStatus::DB_SUCCESS != db_writer.GetTotalInvestAmount(Totalinvest))
                                {
                                    return -35;
                                }
                                Totalinvest+=invest_amount;
                                if(DBStatus::DB_SUCCESS != db_writer.SetTotalInvestAmount(Totalinvest))
                                {
                                    return -36;
                                }
                                uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(InvestTx.time());
                                if(DBStatus::DB_SUCCESS != db_writer.SetInvestUtxoByPeriod(Period, divest_utxo_hash))
                                {
                                    return -37;
                                }
                            }
                        }
                    }
                    else if(global::ca::TxType::kTxTypeBonus == tx_type)
                    {
                        uint64_t TotalCirculation = 0;
                        uint64_t claim_amount=0;
                        uint64_t MiningBalance=0;
                        int i = 0;
                        std::vector<std::string> utxos;
                        
                        nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
                        tx_info["BonusAmount"].get_to(claim_amount);

                        {
                            std::lock_guard<std::mutex> lock(global::ca::kBonusMutex);
                            uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(tx.time());
                            auto ret = db_writer.GetBonusUtxoByPeriod(Period, utxos);
                            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                            {
                                return -38;
                            }
                            if (utxos.cend() != std::find(utxos.cbegin(), utxos.cend(), tx.hash()))
                            {
                                if(DBStatus::DB_SUCCESS != db_writer.GetM2(TotalCirculation))
                                {
                                    return -39;
                                }
                                TotalCirculation-=claim_amount;
                                if(DBStatus::DB_SUCCESS != db_writer.SetTotalCirculation(TotalCirculation))
                                {
                                    return -40;
                                }
                                uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(tx.time());
                                if(DBStatus::DB_SUCCESS != db_writer.RemoveBonusUtxoByPeriod(Period, tx.hash()))
                                {
                                    return -41;
                                }
                                if (DBStatus::DB_SUCCESS != db_writer.GetTotalAwardAmount(MiningBalance))
                                {
                                    return -42;
                                }
                                MiningBalance += claim_amount;
                                if (DBStatus::DB_SUCCESS != db_writer.SetTotalAwardAmount(MiningBalance))
                                {
                                    return -43;
                                }
                            }
                        }
                        
                    }
                    else if(global::ca::TxType::kTxTypeDeclaration == tx_type)
                    {

                        for(auto &vout : tx.utxo().vout())
                        {
                            if(!CheckBase58Addr(vout.addr(),Base58Ver::kBase58Ver_MultiSign))
                            {
                                return -44;
                            }
                            if(DBStatus::DB_SUCCESS != db_writer.RemoveMutliSignAddressUtxo(vout.addr(),tx.hash()))
                            {
                                return -45;
                            }

                            std::vector<std::string> utxos;
                            auto ret =  db_writer.GetMutliSignAddressUtxo(vout.addr(),utxos);
                            if(DBStatus::DB_NOT_FOUND == ret || utxos.empty())
                            {
                                if(DBStatus::DB_SUCCESS != db_writer.RemoveMutliSignAddresses(vout.addr()))
                                {
                                    return -46;
                                }
                            }
                            break;
                        }

                    }
                else if(tx_type == global::ca::TxType::kTxTypeDeployContract && tx.version() == global::ca::kInitTransactionVersion)
                    {
                        for (auto &vin : tx.utxo().vin())
                        {
                            const std::string deployerAddress = GetBase58Addr(vin.vinsign().pub());
                            const std::string deployHash = tx.hash();
                            std::string contractAddress = evm_utils::GenerateContractAddr(deployerAddress + deployHash);//Evmone::GenContractAddress(deployerAddress, deployHash);
                            std::cout << "contractAddress: " << contractAddress << std::endl;
                            //std::cout << "EvmAddress: " << evm_utils::generateEvmAddr(evm_utils::GenerateEvmAddr(deployerAddress + deployHash)) << std::endl;
                            nlohmann::json txInfo = data_json["TxInfo"].get<nlohmann::json>();
                            std::string code = txInfo["Output"].get<std::string>();
                            if (DBStatus::DB_SUCCESS != db_writer.RemoveContractDeployUtxoByContractAddr(contractAddress))
                            {
                                return -54;
                            }
                            for(auto &it : txInfo["PrevHash"].items())
                            {
                                if(it.key() == "") continue;
                                std::cout<<"delete_addr: "<< it.key() <<std::endl;
                                std::string strPrevTxHash = it.value().get<std::string>();
                                std::cout<<"strPrevTxHash: "<< strPrevTxHash <<std::endl;
                                std::string currentPreHash;
                                if (DBStatus::DB_SUCCESS != db_writer.SetLatestUtxoByContractAddr(it.key(), currentPreHash))
                                {
                                   
                                    return -55;
                                }
                            }
                            for(const auto& it : txInfo["selfdestructs"].items())
                            {
                                if(it.key() == "") continue;
                                DEBUGLOG("SetContractDeployUtxoByContractAddr,addr:{},value:{}", it.key(), it.value());
                                if (DBStatus::DB_SUCCESS != db_writer.SetContractDeployUtxoByContractAddr(it.key(), it.value()));
                                {
                                    return -50;
                                }
                            }

                            if (DBStatus::DB_SUCCESS != db_writer.RemoveLatestUtxoByContractAddr(contractAddress))
                            {
                                return -52;
                            }

                            if (DBStatus::DB_SUCCESS != db_writer.RemoveDeployUtxoByDeployerAddr(deployerAddress, deployHash))
                            {
                                return -53;
                            }
                            std::vector<std::string> vecDeployUtxos;
                            auto ret = db_writer.GetDeployUtxoByDeployerAddr(deployerAddress, vecDeployUtxos);
                            if (DBStatus::DB_NOT_FOUND == ret || vecDeployUtxos.empty())
                            {
                                if (DBStatus::DB_SUCCESS != db_writer.RemoveDeployerAddr(deployerAddress))
                                {
                                    return -54;
                                }
                            }
                            nlohmann::json storage = txInfo["Storage"];
                            if(!storage.is_null())
                            {
                                for (auto it = storage.begin(); it != storage.end(); ++it)
                                {
                                    std::string strKey = it.key();
                                    if (strKey.substr(strKey.length() - 8 , strKey.length()) == "rootHash" || strKey.empty())
                                    {
                                        continue;
                                    }
                                    size_t pos = strKey.find('_');
                                    if(pos != std::string::npos)
                                    {
                                        strKey = contractAddress + strKey.substr(pos);
                                    }
                                    if (db_writer.RemoveMptValueByMptKey(strKey) != DBStatus::DB_SUCCESS)
                                    {
                                        return -55;
                                    }
                                }                            
                            }
                            break;
                        }
                    }
                    else if(global::ca::TxType::kTxTypeCallContract == tx_type && tx.version() == global::ca::kInitTransactionVersion)
                    {
                        nlohmann::json txInfo = data_json["TxInfo"].get<nlohmann::json>();
                        for(auto &it : txInfo["PrevHash"].items())
                        {
                            if(it.key() == "") continue;
                            std::cout<<"delete_addr: "<< it.key() <<std::endl;
                            std::string strPrevTxHash = it.value().get<std::string>();
                            std::cout<<"strPrevTxHash: "<< strPrevTxHash <<std::endl;
                            if (DBStatus::DB_SUCCESS != db_writer.SetLatestUtxoByContractAddr(it.key(), strPrevTxHash))
                            {
                                
                                return -56;
                            }
                        }

                        for(const auto& it : txInfo["selfdestructs"].items())
                        {
                            if(it.key() == "") continue;
                            DEBUGLOG("SetContractDeployUtxoByContractAddr,addr:{},value:{}", it.key(), it.value());
                            if (DBStatus::DB_SUCCESS != db_writer.SetContractDeployUtxoByContractAddr(it.key(), it.value()));
                            {
                                return -50;
                            }
                        }

                        nlohmann::json storage = txInfo["Storage"];
                        if(!storage.is_null())
                        {
                            for (auto it = storage.begin(); it != storage.end(); ++it)
                            {
                                std::string strKey = it.key();
                                if (strKey.substr(strKey.length() - 8 , strKey.length()) == "rootHash" || strKey.empty())
                                {
                                    continue;
                                }
                                if (db_writer.RemoveMptValueByMptKey(strKey) != DBStatus::DB_SUCCESS)
                                {
                                    return -57;
                                }
                            }                        
                        }

                    }
                }
                catch (...)
                {
                    return -55;
                }
            }

            uint64_t SignNumber = 0;
            uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(tx.time());

            for (auto & sign : tx.verifysign())
            {
                std::string vout_addr = GetBase58Addr(sign.pub());
                if (!CheckBase58Addr(vout_addr, Base58Ver::kBase58Ver_Normal))
                {
                    return -56;
                }

                if(DBStatus::DB_SUCCESS != db_writer.GetSignNumberByPeriod(Period, vout_addr, SignNumber))
                {
                    ERRORLOG("GetSignNumberByPeriod Period:{},vout.addr:{},SignNumber:{}",Period, vout_addr, SignNumber);
                    return -57;
                }

                if(SignNumber > 1)
                {
                    --SignNumber;
                    if(DBStatus::DB_SUCCESS != db_writer.SetSignNumberByPeriod(Period, vout_addr, SignNumber))
                    {
                        ERRORLOG("SetSignNumberByPeriod error! Period:{},vout.addr:{},SignNumber:{}",Period, vout_addr, SignNumber);
                        return -58;
                    }
                }
                else
                {
                    if(DBStatus::DB_SUCCESS != db_writer.RemoveSignAddrberByPeriod(Period, vout_addr))
                    {
                        ERRORLOG("RemoveSignAddrberByPeriod error! Period:{},vout.addr:{}",Period,vout_addr);
                        return -59;
                    }
                    if(DBStatus::DB_SUCCESS != db_writer.RemoveSignNumberByPeriod(Period, vout_addr))
                    {
                        ERRORLOG("RemoveSignNumberByPeriod error! Period:{},vout.addr:{}",Period,vout_addr);
                        return -60;
                    }
                }
            }
            std::string addr;
            std::string utxo_hash;
            CTransaction utxo_tx;
            std::string utxo_tx_raw;
            std::vector<std::string> vin_hashs;
            std::string utxo_n;

            bool isMultiSign = IsMultiSign(tx);
            for (auto &vin : tx.utxo().vin())
            {
                global::ca::TxType txType = (global::ca::TxType)tx.txtype();
                
                if(vin.contractaddr().empty())
                {
                    if (vin.vinsign().pub().size() == 0)
                    {
                        DEBUGLOG("vin pub size {}",vin.vinsign().pub().size());
                        return -61;
                    }
                    Base58Ver ver = isMultiSign ? Base58Ver::kBase58Ver_MultiSign : Base58Ver::kBase58Ver_Normal;
                    addr = GetBase58Addr(vin.vinsign().pub(), ver);
                }
                else if(global::ca::TxType::kTxTypeDeployContract == txType || global::ca::TxType::kTxTypeCallContract == txType)
                {
                    if (vin.vinsign().pub().size() != 0)
                    {
                        DEBUGLOG("vin pub size {}",vin.vinsign().pub().size());
                        return -62;
                    }
                    addr = vin.contractaddr();
                }

                all_addr.insert(addr); //Transaction vin address is placed in set

                for (auto & prevout : vin.prevout())
                {
                    utxo_hash = prevout.hash(); 
                    utxo_n = utxo_hash + "_" + std::to_string(prevout.n());
                    if (is_redeem && redeem_utxo_hash == utxo_hash && 1 == prevout.n())
                    {
                        continue;
                    }
                    else if (is_divest && divest_utxo_hash == utxo_hash && 1 == prevout.n())
                    {
                        continue;
                    }  

                    if (vin_hashs.cend() != std::find(vin_hashs.cbegin(), vin_hashs.cend(), utxo_n)) //
                    {
                        continue;
                    }
                    vin_hashs.push_back(utxo_n); //
                    // All transactions update the utxo used and the balance of utxo used by the transaction address
                    if (DBStatus::DB_SUCCESS != db_writer.SetUtxoHashsByAddress(addr, utxo_hash))
                    {
                        return -63;
                    }
                    
                    if (DBStatus::DB_SUCCESS != db_writer.GetTransactionByHash(utxo_hash, utxo_tx_raw))
                    {
                        return -64;
                    }
                    if (!utxo_tx.ParseFromString(utxo_tx_raw))
                    {
                        return -65;
                    }

                    uint64_t amount = 0;
                    for (int j = 0; j < utxo_tx.utxo().vout_size(); j++)
                    {
                        const CTxOutput & txout = utxo_tx.utxo().vout(j);
                        if (txout.addr() == addr)
                        {
                            amount += txout.value();
                        }
                        
                    }

                    ret = db_writer.SetUtxoValueByUtxoHashs(utxo_hash, addr, std::to_string(amount));
                    if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                    {
                        ERRORLOG("SetUtxoHashsByAddress error! ret:{}",ret);
                        return -66;
                    }
                      
                    int64_t balance = 0;
                    ret = db_writer.GetBalanceByAddress(addr, balance);
                    if (DBStatus::DB_SUCCESS != ret)
                    {
                        if (DBStatus::DB_NOT_FOUND != ret)
                        {
                            return -67;
                        }
                        else
                        {
                            balance = 0;
                        }
                    }
                    DEBUGLOG("balance is before{}",balance);
                    balance += amount;
                    DEBUGLOG("balance is after{}",balance);
                    if (balance < 0)
                    {
                        ERRORLOG("DeleteBlock vin height:{} hash:{} addr:{} balance:{}", block.height(), block.hash(), addr, balance);
                        return -68;
                    }
                    DEBUGLOG("vout.addr {}",addr);
                    if (DBStatus::DB_SUCCESS != db_writer.SetBalanceByAddress(addr, balance))
                    {
                        return -69;
                    }
                }
            }
        }

        // All transactions delete utxo and the balance of utxo used by the transaction address
        std::multimap<std::string,std::string> utxo_value;
        std::multimap<std::string,std::string> bouns_utxo_value;
        std::map<std::string,std::multimap<std::string,std::string>> ContractUtxoValue;
        for (auto &vout : tx.utxo().vout())
        {
            if(vout.addr() == global::ca::kVirtualBurnGasAddr)
            {
                uint64_t Totalburn = 0;
                uint64_t burnAmount = 0;
                uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(tx.time());
                std::lock_guard<std::mutex> lock(global::ca::kBurnMutex);
                auto ret = db_writer.GetDM(Totalburn);
                if(ret != DBStatus::DB_SUCCESS && ret != DBStatus::DB_NOT_FOUND)
                {
                    ERRORLOG("GetDM error! Totalburn:{}",Totalburn);
                    return -70;
                }

                ret = db_writer.GetburnAmountByPeriod(Period, burnAmount);
                if(DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                {
                    ERRORLOG("GetburnAmountByPeriod error! ret:{}",ret);
                    return -71;
                }
                burnAmount -= vout.value();
                Totalburn -= vout.value();
                if(DBStatus::DB_SUCCESS != db_writer.SetburnAmountByPeriod(Period, burnAmount))
                {
                    ERRORLOG("SetburnAmountByPeriod error! Period:{}, burnAmount:{}", Period, burnAmount);
                    return -72;
                }
                if (DBStatus::DB_SUCCESS != db_writer.SetDM(Totalburn))
                {
                    ERRORLOG("SetDM error! Totalburn:{}", Totalburn);
                    return -73;
                }
                continue;
            }
            DEBUGLOG("vout.addr {}",vout.addr());
            std::cout << vout.addr();
            if(vout.addr() == global::ca::kVirtualDeployContractAddr ||vout.addr() ==global::ca::kVirtualCallContractAddr)
            {
                continue;
            }
            global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();
            all_addr.insert(vout.addr());
            ret = db_writer.RemoveUtxoHashsByAddress(vout.addr(), tx.hash());
            if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
            {
                return -74;
            }


            std::string balance_utxo ;
            if(tx_type == global::ca::TxType::kTxTypeUnstake || tx_type == global::ca::TxType::kTxTypeDisinvest)
            {
                utxo_value.insert(std::make_pair(tx.hash() + "_" + vout.addr(),std::to_string(vout.value())));
            }
            else if(tx_type == global::ca::TxType::kTxTypeBonus)
            {
                //If hash is the same, use it together
                if(vout.addr() == tx.utxo().owner(0))
                {
                    bouns_utxo_value.insert(std::make_pair(tx.hash() + "_" + vout.addr(),std::to_string(vout.value())));
                }
                else
                {
                    if (DBStatus::DB_SUCCESS != db_writer.RemoveUtxoValueByUtxoHashs(tx.hash(), vout.addr(), balance_utxo))
                    {
                        ERRORLOG("GetTransactionByHash failed!");
                        return - 75;
                    }
                }
            }
            //to be 
            
            else if(tx_type == global::ca::TxType::kTxTypeDeployContract || tx_type == global::ca::TxType::kTxTypeCallContract)
            {
                ContractUtxoValue[vout.addr()].insert(std::make_pair(tx.hash() + "_" + vout.addr(),std::to_string(vout.value())));
            }
            else
            {
                if (DBStatus::DB_SUCCESS != db_writer.RemoveUtxoValueByUtxoHashs(tx.hash(), vout.addr(), balance_utxo))
                {
                    ERRORLOG("GetTransactionByHash failed!");
                    return - 76;
                }
            }

            int64_t balance = 0;
            ret = db_writer.GetBalanceByAddress(vout.addr(), balance);
            if (DBStatus::DB_SUCCESS != ret)
            {
                if (DBStatus::DB_NOT_FOUND != ret)
                {
                    ERRORLOG("GetBalanceByAddress error! ret:{}",ret);
                    return -77;
                }
                else
                {
                    balance = 0;
                }
            }
            DEBUGLOG("vout.addr()",vout.addr());
            DEBUGLOG("balance is {}",balance);
            DEBUGLOG("vout value {}",vout.value());
            std::cout << "balance"<<balance;
            std::cout <<"vout" <<vout.value();
            balance -= vout.value();
            if (balance < 0)
            {
                ERRORLOG("DeleteBlock vout height:{} hash:{} addr:{} balance:{}", block.height(), block.hash(), vout.addr(), balance);
                return -78;
            }
            if (0 == balance)
            {
                if (DBStatus::DB_SUCCESS != db_writer.DeleteBalanceByAddress(vout.addr()))
                {
                    ERRORLOG("DeleteBalanceByAddress vout.addr:{}",vout.addr());
                    return -79;
                }
            }
            else
            {
                if (DBStatus::DB_SUCCESS != db_writer.SetBalanceByAddress(vout.addr(), balance))
                {
                    ERRORLOG("SetBalanceByAddress vout.addr:{},balance:{}",vout.addr(),balance);
                    return -80;
                }
            }
        }

        std::vector<std::string> utxo_values;
        if(utxo_value.size() == 2)
        {
            std::string utxo_hash_balance;
            auto iter = utxo_value.begin();
            for(;iter != utxo_value.end(); iter ++)
            {
                utxo_hash_balance += iter->second + "_";
                utxo_values.clear();
                StringUtil::SplitString(iter->first, "_", utxo_values);      
            }

            if(utxo_hash_balance[utxo_hash_balance.length()-1] == '_')
            {
                utxo_hash_balance = utxo_hash_balance.substr(0,utxo_hash_balance.length()-1);
            }

            if (DBStatus::DB_SUCCESS != db_writer.RemoveUtxoValueByUtxoHashs(utxo_values[0], utxo_values[1], utxo_hash_balance))
            {
                ERRORLOG("GetTransactionByHash failed!");
                return -81;
            }

        }

        std::vector<std::string> bouns_utxo_values;
        if(!bouns_utxo_value.empty())
        {
            std::string utxo_hash_balance;
            auto iter = bouns_utxo_value.begin();
            for(;iter != bouns_utxo_value.end(); iter ++)
            {
                utxo_hash_balance += iter->second + "_";
                bouns_utxo_values.clear();
                StringUtil::SplitString(iter->first, "_", bouns_utxo_values);      
            }

            if(utxo_hash_balance[utxo_hash_balance.length()-1] == '_')
            {
                utxo_hash_balance = utxo_hash_balance.substr(0,utxo_hash_balance.length()-1);
            }

            if (DBStatus::DB_SUCCESS != db_writer.RemoveUtxoValueByUtxoHashs(bouns_utxo_values[0], bouns_utxo_values[1], utxo_hash_balance))
            {
                ERRORLOG("GetTransactionByHash failed!");
                return - 82;
            }

        }


        if(!ContractUtxoValue.empty())
        {
            for(const auto& UtxoValue : ContractUtxoValue)
            {
                std::vector<std::string> ContractUtxoValues;
                std::string utxoHashBalance;
                auto iter = UtxoValue.second.begin();
                for(;iter != UtxoValue.second.end(); iter ++)
                {
                    utxoHashBalance += iter->second + "_";   
                    ContractUtxoValues.clear();
                    StringUtil::SplitString(iter->first, "_", ContractUtxoValues);   
                }
                if(utxoHashBalance[utxoHashBalance.length()-1] == '_')
                {
                    utxoHashBalance = utxoHashBalance.substr(0,utxoHashBalance.length()-1);
                }

                ret = db_writer.RemoveUtxoValueByUtxoHashs(ContractUtxoValues[0], ContractUtxoValues[1], utxoHashBalance);
                if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
                {
                    ERRORLOG("SetUtxoValueByUtxoHashs error! ret:{}",ret);
                    return -83;
                }
                
            }
        }
        
        // Delete transaction body data corresponding to transaction hash
        if (DBStatus::DB_SUCCESS != db_writer.DeleteTransactionByHash(tx.hash()))
        {
            ERRORLOG("DeleteTransactionByHash hash:{}",tx.hash());
            return -84;
        }

        // Delete the block hash corresponding to the transaction hash
        if (DBStatus::DB_SUCCESS != db_writer.DeleteBlockHashByTransactionHash(tx.hash()))
        {
            ERRORLOG("DeleteBlockHashByTransactionHash error! hash:{}",tx.hash());
            return -85;
        }

        auto block_height = block.height();
        auto sum_hash_height = GetSumHashCeilingHeight(block_height);
        std::string sum_hash;
        uint64_t new_top = 0;
        if (DBStatus::DB_SUCCESS != db_writer.GetBlockTop(new_top))
        {
            ERRORLOG("GetBlockTop error! top:{}",top);
            return -86;
        }
        
        if (DBStatus::DB_SUCCESS == db_writer.GetSumHashByHeight(sum_hash_height, sum_hash))
        {

            if (block_height % global::ca::sum_hash_range == 1)
            {
                uint64_t new_top = 0;
                if (DBStatus::DB_SUCCESS != db_writer.GetBlockTop(new_top))
                {
                    ERRORLOG("GetBlockTop error! top:{}",top);
                    return -87;
                }
                INFOLOG("rollback block height: {}, top: {}", block_height, new_top);
                if (block_height > new_top)
                {
                    if (DBStatus::DB_SUCCESS != db_writer.RemoveSumHashByHeight(sum_hash_height))
                    {
                        return -88;
                    }
                    INFOLOG("delete height sum hash at height {}", sum_hash_height);
                    // return 0;
                    continue;
                }
            }
            else
            {
                auto start_height = GetSumHashFloorHeight(block_height) + 1;
                auto end_height = std::min(new_top, GetSumHashCeilingHeight(block_height) + 1);
                if(!CalculateHeightSumHash(start_height, end_height, db_writer, sum_hash))
                {
                    return -89;
                }
                if (DBStatus::DB_SUCCESS != db_writer.SetSumHashByHeight(sum_hash_height, sum_hash))
                {
                    return -90;
                }
                INFOLOG("rollback set height sum hash at height {} hash: {}", sum_hash_height, sum_hash);
            }
        }

    }
        if (block.version() == global::ca::kCurrentBlockVersion && IsContractBlock(block))
    {
        nlohmann::json blockData = nlohmann::json::parse(block.data());
        global::ca::VmType vmType;
        const auto& txs = block.txs();
        for (auto iter = txs.rbegin(); iter != txs.rend() ; ++iter)
        {
            const auto& tx = *iter;
            try
            {
                nlohmann::json data_json = nlohmann::json::parse(tx.data());
                nlohmann::json _txInfo = data_json["TxInfo"].get<nlohmann::json>();
                vmType = _txInfo["VmType"].get<global::ca::VmType>();
            }
            catch(...)
            {
                ERRORLOG("parse TxInfo fail");
                return -91;
            }
            
            if(global::ca::TxType::kTxTypeDeployContract == (global::ca::TxType)tx.txtype())
            {
                for (auto &vin : tx.utxo().vin())
                {
                    const std::string deployerAddress = GetBase58Addr(vin.vinsign().pub());
                    const std::string deployHash = tx.hash();
                    std::string contractAddress = evm_utils::GenerateContractAddr(deployerAddress + deployHash);

                    nlohmann::json txInfo;
                    for (const auto&[key, value] : blockData.items())
                    {
                        if (key == tx.hash())
                        {
                            txInfo = value;
                            break;
                        }
                    }

                    if (DBStatus::DB_SUCCESS != db_writer.RemoveContractDeployUtxoByContractAddr(contractAddress))
                    {
                        return -92;
                    }
                    for(auto &it : txInfo["PrevHash"].items())
                    {
                        if(it.key() == "") continue;
                        ERRORLOG("=========================delete_addr: {}", it.key());
                        std::string strPrevTxHash = it.value().get<std::string>();
                        ERRORLOG("=========================strPrevTxHash: {}", strPrevTxHash);
                        if (DBStatus::DB_SUCCESS != db_writer.SetLatestUtxoByContractAddr(it.key(), strPrevTxHash))
                        {
                           
                            return -93;
                        }
                    }

                    for(const auto& it : txInfo["selfdestructs"].items())
                    {
                        if(it.key() == "") continue;
                        DEBUGLOG("SetContractDeployUtxoByContractAddr,addr:{},value:{}", it.key(), it.value());
                        if (DBStatus::DB_SUCCESS != db_writer.SetContractDeployUtxoByContractAddr(it.key(), it.value()));
                        {
                            return -94;
                        }
                    }

                    if (DBStatus::DB_SUCCESS != db_writer.RemoveLatestUtxoByContractAddr(contractAddress))
                    {
                        return -95;
                    }

                    if (DBStatus::DB_SUCCESS != db_writer.RemoveDeployUtxoByDeployerAddr(deployerAddress, deployHash))
                    {
                        return -96;
                    }
                    std::vector<std::string> vecDeployUtxos;
                    auto ret = db_writer.GetDeployUtxoByDeployerAddr(deployerAddress, vecDeployUtxos);
                    if (DBStatus::DB_NOT_FOUND == ret || vecDeployUtxos.empty())
                    {
                        if(vmType == global::ca::VmType::EVM)
                        {
                            if (DBStatus::DB_SUCCESS != db_writer.RemoveEvmDeployerAddr(deployerAddress))
                            {
                                return -97;
                            }
                        }
                        // else if(vmType == global::ca::VmType::WASM)
                        // {
                        //     if(DBStatus::DB_SUCCESS != db_writer.RemoveWasmDeployerAddr(deployerAddress))
                        //     {
                        //         return -98;
                        //     }
                        // }
                    }
                    nlohmann::json storage = txInfo["Storage"];
                    if(!storage.is_null())
                    {
                        for (auto it = storage.begin(); it != storage.end(); ++it)
                        {
                            std::string strKey = it.key();
                            if (strKey.substr(strKey.length() - 8 , strKey.length()) == "rootHash" || strKey.empty())
                            {
                                continue;
                            }
                            size_t pos = strKey.find('_');
                            if(pos != std::string::npos)
                            {
                                strKey = contractAddress + strKey.substr(pos);
                            }
                            if (db_writer.RemoveMptValueByMptKey(strKey) != DBStatus::DB_SUCCESS)
                            {
                                return -99;
                            }
                        }
                    }

                    break;
                }
            }
            else if(global::ca::TxType::kTxTypeCallContract == (global::ca::TxType)tx.txtype())
            {
                nlohmann::json txInfo;
                for (const auto&[key, value] : blockData.items())
                {
                    if (key == tx.hash())
                    {
                        txInfo = value;
                        break;
                    }

                }
                for(auto &it : txInfo["PrevHash"].items())
                {
                    if(it.key() == "") continue;
                    ERRORLOG("=========================delete_addr: {}", it.key());
                    std::string strPrevTxHash = it.value().get<std::string>();
                    ERRORLOG("=========================strPrevTxHash: {}", strPrevTxHash);
                    if (DBStatus::DB_SUCCESS != db_writer.SetLatestUtxoByContractAddr(it.key(), strPrevTxHash))
                    {
                       
                        return -100;
                    }
                }

                for(const auto& it : txInfo["selfdestructs"].items())
                {
                    if(it.key() == "") continue;
                    DEBUGLOG("SetContractDeployUtxoByContractAddr,addr:{},value:{}", it.key(), it.value());
                    if (DBStatus::DB_SUCCESS != db_writer.SetContractDeployUtxoByContractAddr(it.key(), it.value()));
                    {
                        return -101;
                    }
                }

                nlohmann::json storage = txInfo["Storage"];
                if(!storage.is_null())
                {
                    for (auto it = storage.begin(); it != storage.end(); ++it)
                    {
                        std::string strKey = it.key();
                        if (strKey.substr(strKey.length() - 8 , strKey.length()) == "rootHash" || strKey.empty())
                        {
                            continue;
                        }
                        if (db_writer.RemoveMptValueByMptKey(strKey) != DBStatus::DB_SUCCESS)
                        {
                            return -102;
                        }
                    }
                }

            }
        }
    }
    return 0;
}

static int RollBackBlock(const std::multimap<uint64_t, std::string> &hashs)
{
    int i = 0;
    DBReadWriter db_writer;

    for (auto it = hashs.rbegin(); hashs.rend() != it; ++it)
    {
        ++i;
        std::string delete_hash = it->second;
        TRACELOG("begin delete block {}", delete_hash);
        auto ret = ca_algorithm::DeleteBlock(db_writer, delete_hash);
        if (0 != ret)
        {
            ERRORLOG("faill to delete block {}, ret {}", delete_hash, ret);
            return ret - 100;
        }
        else
        {
            DEBUGLOG("RollBackBlock delete block: {}",delete_hash);
            // if(MagicSingleton<CBlockCache>::GetInstance()->Remove(it->first, delete_hash) != 0)
            // {
            //     ERRORLOG("RollBackBlock delete block fail!  block hash :{}", delete_hash);
            //     return -1;
            // }
        }
        TRACELOG("successfully delete block {}", delete_hash);
        {
            CBlock block;
            DBReadWriter db_reader;
            std::ostringstream filestream;
            std::string block_raw;
            
            auto ret = db_reader.GetBlockByBlockHash(delete_hash, block_raw); //hash Deleted block hash

            if (DBStatus::DB_NOT_FOUND == ret)
            {
                return 0;
            }
            else if (DBStatus::DB_SUCCESS != ret)
            {
                ERRORLOG("GetBlockByBlockHash delete_block_hash:{},block_raw:{}",delete_hash,block_raw);
                return -2;
            }
            if (!block.ParseFromString(block_raw))
            {
                ERRORLOG("ParseFromString error!");
                return -3;
            }
            printBlock(block,true,filestream);

            std::string test_str = filestream.str();
            DEBUGLOG("rollback block --> {}", test_str);
        }
        
        if(10 == i)
        {
            i = 0;
            if (DBStatus::DB_SUCCESS != db_writer.TransactionCommit())
            {
                return -4;
            }
            if (DBStatus::DB_SUCCESS != db_writer.ReTransactionInit())
            {
                return -5;
            }
        }
    }
    if(i > 0)
    {
        if (DBStatus::DB_SUCCESS != db_writer.TransactionCommit())
        {
            return -6;
        }
    }
        MagicSingleton<BlockStroage>::GetInstance()->ClearPreHashMap();
    return 0;
}
int ca_algorithm::RollBackToHeight(uint64_t height)
{
    DBReadWriter db_writer;
    uint64_t node_height = 0;
    if (DBStatus::DB_SUCCESS != db_writer.GetBlockTop(node_height))
    {
        return -1;
    }
    std::multimap<uint64_t, std::string> hashs;
    std::vector<CBlock>backupblocks;
    std::vector<std::string> block_hashs;
    for (uint32_t i = node_height; i > height; --i)
    {
        block_hashs.clear();
        int res = db_writer.GetBlockHashsByBlockHeight(i, block_hashs);
        if (DBStatus::DB_SUCCESS != res)
        {
            DEBUGLOG("query block height {} fail, ret: {}", i, res);
            return -2;
        }
        for (auto &hash : block_hashs)
        {
            hashs.insert(std::make_pair(i, hash)); //All hash keys in a height can have multiple
        }
    }

    for(auto it = hashs.begin(); hashs.end() != it; ++it)
    {
        std::string blockStr;
        if (DBStatus::DB_SUCCESS != db_writer.GetBlockByBlockHash(it->second,blockStr))
        {
            return -3;
        }
        CBlock block;
        if (!block.ParseFromString(blockStr))
        {
            return -4;
        }
        backupblocks.push_back(block);
    }

    auto ret = RollBackBlock(hashs);
    if (0 != ret)
    {
        return ret - 1000;
    }
    if(ret == 0)
    {
        for (auto &block:backupblocks)
        {
            if (MagicSingleton<CBlockHttpCallback>::GetInstance()->IsRunning())
            {
                MagicSingleton<CBlockHttpCallback>::GetInstance()->RollbackBlock(block);
            }
        }
    }
    
    return 0;
}

int ca_algorithm::RollBackByHash(const std::string &block_hash)
{
    DBReadWriter db_writer;
    std::multimap<uint64_t, std::string> hashs;
    std::vector<CBlock> backupblocks;
    uint64_t height = 0;
    bool rollback_by_height = false;
    {
        std::set<std::string> rollback_block_hashs;
        std::set<std::string> rollback_trans_hashs;
        CBlock block;
        {
            std::string block_raw;
            auto ret = db_writer.GetBlockByBlockHash(block_hash, block_raw);
            if (DBStatus::DB_NOT_FOUND == ret)
            {
                return 0;
            }
            else if (DBStatus::DB_SUCCESS != ret)
            {
                return -1;
            }
            if (!block.ParseFromString(block_raw))
            {
                return -2;
            }
            hashs.insert(std::make_pair(block.height(), block.hash()));
            rollback_block_hashs.insert(block.hash());
            for (auto &tx : block.txs())
            {
                rollback_trans_hashs.insert(tx.hash());
            }
        }
        uint64_t node_height = 0;
        if (DBStatus::DB_SUCCESS != db_writer.GetBlockTop(node_height))
        {
            return -3;
        }
        std::vector<std::string> block_raws;
        std::vector<std::string> block_hashs;
        for (height = block.height(); height < node_height + 1; ++height)
        {
            block_hashs.clear();
            block_raws.clear();
            if (DBStatus::DB_SUCCESS != db_writer.GetBlockHashsByBlockHeight(height, block_hashs))
            {
                return -4;
            }
            if (DBStatus::DB_SUCCESS != db_writer.GetBlocksByBlockHash(block_hashs, block_raws))
            {
                return -5;
            }
            bool flag = false;
            for (auto &block_raw : block_raws)
            {
                block.Clear();
                if (!block.ParseFromString(block_raw))
                {
                    return -6;
                }
                if (rollback_block_hashs.end() == std::find(rollback_block_hashs.cbegin(), rollback_block_hashs.cend(), block.prevhash()))
                {
                    for (auto &tx : block.txs())
                    {
                        if (GetTransactionType(tx) != kTransactionType_Tx)
                        {
                            continue;
                        }
                        for (auto &vin : tx.utxo().vin())
                        {
                            for (auto & prevout : vin.prevout())
                            {
                                auto utxo_hash = prevout.hash();
                                if (rollback_trans_hashs.end() != std::find(rollback_trans_hashs.cbegin(), rollback_trans_hashs.cend(), utxo_hash))
                                {
                                    flag = true;
                                    break;
                                }
                            }
                        }
                        if (flag)
                        {
                            break;
                        }
                    }
                }
                else
                {
                    flag = true;
                }
                if (flag)
                {
                    hashs.insert(std::make_pair(block.height(), block.hash()));
                    rollback_block_hashs.insert(block.hash());
                    for (auto &tx : block.txs())
                    {
                        rollback_trans_hashs.insert(tx.hash());
                    }
                }
            }
            if (flag && block_hashs.size() <= 1)
            {
                height = block.height();
                rollback_by_height = true;
                break;
            }
        }
    }
    if (rollback_by_height)
    {
        uint64_t node_height = 0;
        if (DBStatus::DB_SUCCESS != db_writer.GetBlockTop(node_height))
        {
            return -7;
        }
        std::vector<std::string> block_hashs;

        for (uint32_t i = node_height; i > height; --i)
        {
            block_hashs.clear();
            if (DBStatus::DB_SUCCESS != db_writer.GetBlockHashsByBlockHeight(i, block_hashs))
            {
                return -8;
            }
            for (auto &hash : block_hashs)
            {
                hashs.insert(std::make_pair(i, hash));

            }
        }
    }

    for(auto it = hashs.begin(); hashs.end() != it; ++it)
    {
        std::string blockStr;
        if (DBStatus::DB_SUCCESS != db_writer.GetBlockByBlockHash(it->second,blockStr))
        {
            return -9;
        }
        CBlock block;
        if (!block.ParseFromString(blockStr))
        {
            return -10;
        }
        backupblocks.push_back(block);
    }

    auto ret = RollBackBlock(hashs);
    if (0 != ret)
    {
        return ret - 1000;
    }
    if(ret == 0)
    {
        for (auto &block :backupblocks)
        {
            if (MagicSingleton<CBlockHttpCallback>::GetInstance()->IsRunning())
            {
                MagicSingleton<CBlockHttpCallback>::GetInstance()->RollbackBlock(block);
            }
        }
    }
    return 0;
}

void ca_algorithm::PrintTx(const CTransaction &tx)
{
    using namespace std;
    cout << "========================================================================================================================" << endl;
    cout << "\ttx.version:" << tx.version() << endl;
    cout << "\ttx.time:" << tx.time() << endl;

    std::string hex;
    for (auto &sign_pre_hash : tx.verifysign())
    {
        cout << "\t\tsign_pre_hash.addr:" << GetBase58Addr(sign_pre_hash.pub()) << endl;
    }

    for (auto &vin : tx.utxo().vin())
    {
        cout << "\t\tvin.sequence:" << vin.sequence() << endl;
        for (auto & prevout : vin.prevout())
        {
            cout << "\t\t\tprevout.hash:" << prevout.hash() << endl;
            cout << "\t\t\tprevout.n:" << prevout.n() << endl;
        }
        auto &scriptSig = vin.vinsign();
        cout << "\t\t\tscriptSig.addr:" << GetBase58Addr(scriptSig.pub()) << endl;
    }
    for (auto &vout : tx.utxo().vout())
    {
        cout << "\t\tvout.scriptpubkey:" << vout.addr() << endl;
        cout << "\t\tvout.value:" << vout.value() << endl;
    }

    cout << "\ttx.owner:";
    for (auto & owner : tx.utxo().owner())
    {
        cout << owner << ", ";
    }
    cout << endl;
    cout << "\ttx.n:" << tx.n() << endl;
    cout << "\ttx.identity:" << tx.identity() << endl;
    cout << "\ttx.hash:" << tx.hash() << endl;
    cout << "\ttx.data:" << tx.data() << endl;
    cout << "\ttx.info:" << tx.info() << endl;
}

void ca_algorithm::PrintBlock(const CBlock &block)
{
    using namespace std;
    cout << "version:" << block.version() << endl;
    cout << "hash:" << block.hash() << endl;
    cout << "prevhash:" << block.prevhash() << endl;
    cout << "height:" << block.height() << endl;
    cout << "merkleroot:" << block.merkleroot() << endl;

    for (auto &tx : block.txs())
    {
        PrintTx(tx);
    }

    cout << "data:" << block.data() << endl;
    cout << "info:" << block.info() << endl;
    cout << "time:" << block.time() << endl;
    cout << "========================================================================================================================" << endl;
}

int ca_algorithm::GetInflationRate(const uint64_t &cur_time, const uint64_t &&StakeRate, double &InflationRate)
{
    if(StakeRate < 0 || StakeRate >= 90)
    {
        return -1;
    }

    std::vector<std::vector<double>> RateArray = {  
            {0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.085,0.083725,0.08245,0.081175,0.0799,0.078625,0.07735,0.076075,0.0748,0.073525,0.07225,0.070975,0.0697,0.068425,0.06715,0.065875,0.0646,0.063325,0.06205,0.060775,0.0595,0.058225,0.05695,0.055675,0.0544,0.053125,0.05185,0.050575,0.0493,0.048025,0.04675,0.045475,0.0442,0.042925,0.04165,0.040375,0.0391,0.037825,0.03655,0.035275,0.034,0.032725,0.03145,0.030175,0.0289,0.027625,0.02635,0.025075,0.0238,0.022525,0.02125,0.019975,0.0187,0.017425,0.01615,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.0765,0.075225,0.07395,0.072675,0.0714,0.070125,0.06885,0.067575,0.0663,0.065025,0.06375,0.062475,0.0612,0.059925,0.05865,0.057375,0.0561,0.054825,0.05355,0.052275,0.051,0.049725,0.04845,0.047175,0.0459,0.044625,0.04335,0.042075,0.0408,0.039525,0.03825,0.036975,0.0357,0.034425,0.03315,0.031875,0.0306,0.029325,0.02805,0.026775,0.0255,0.024225,0.02295,0.021675,0.0204,0.019125,0.01785,0.016575,0.0153,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.068,0.066725,0.06545,0.064175,0.0629,0.061625,0.06035,0.059075,0.0578,0.056525,0.05525,0.053975,0.0527,0.051425,0.05015,0.048875,0.0476,0.046325,0.04505,0.043775,0.0425,0.041225,0.03995,0.038675,0.0374,0.036125,0.03485,0.033575,0.0323,0.031025,0.02975,0.028475,0.0272,0.025925,0.02465,0.023375,0.0221,0.020825,0.01955,0.018275,0.017,0.015725,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.0595,0.058225,0.05695,0.055675,0.0544,0.053125,0.05185,0.050575,0.0493,0.048025,0.04675,0.045475,0.0442,0.042925,0.04165,0.040375,0.0391,0.037825,0.03655,0.035275,0.034,0.032725,0.03145,0.030175,0.0289,0.027625,0.02635,0.025075,0.0238,0.022525,0.02125,0.019975,0.0187,0.017425,0.01615,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.051,0.049725,0.04845,0.047175,0.0459,0.044625,0.04335,0.042075,0.0408,0.039525,0.03825,0.036975,0.0357,0.034425,0.03315,0.031875,0.0306,0.029325,0.02805,0.026775,0.0255,0.024225,0.02295,0.021675,0.0204,0.019125,0.01785,0.016575,0.0153,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.0425,0.041225,0.03995,0.038675,0.0374,0.036125,0.03485,0.033575,0.0323,0.031025,0.02975,0.028475,0.0272,0.025925,0.02465,0.023375,0.0221,0.020825,0.01955,0.018275,0.017,0.015725,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.034,0.032725,0.03145,0.030175,0.0289,0.027625,0.02635,0.025075,0.0238,0.022525,0.02125,0.019975,0.0187,0.017425,0.01615,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.0255,0.024225,0.02295,0.021675,0.0204,0.019125,0.01785,0.016575,0.0153,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.017,0.015725,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
            {0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015,0.015},
    };
    
    time_t now = (time_t)(cur_time / 1000000);
	tm* curr_tm = gmtime(&now); 
	unsigned int CurrentYear = curr_tm -> tm_year + 1900;
    unsigned int Year = CurrentYear - 2023;
	InflationRate = RateArray.at(Year).at(StakeRate);
	return 0;
}

int ca_algorithm::CalcBonusValue(uint64_t &cur_time, const std::string &bonusAddr, std::map<std::string, uint64_t> & values)
{
    std::vector<std::string> abnormal_addr_list;
    std::unordered_map<std::string, uint64_t> addr_sign_cnt;
    auto ret = ca_algorithm::GetAbnormalSignAddrListByPeriod(cur_time, abnormal_addr_list, addr_sign_cnt);
    if(ret < 0) return ret - 100;
    
    if(addr_sign_cnt.find(bonusAddr) == addr_sign_cnt.end() || std::find(abnormal_addr_list.begin(),abnormal_addr_list.end(), bonusAddr) != abnormal_addr_list.end())
    {
        std::cout << RED <<"AbnormalAddr:"<<bonusAddr<< RESET << std::endl;
        return -1;
    }
    
	std::string strTx;
	CTransaction tx;
    uint64_t total_award;
    uint64_t TotalCirculationYesterday;
    uint64_t TotalinvestYesterday;
	uint64_t zero_time = MagicSingleton<TimeUtil>::GetInstance()->getMorningTime(cur_time) * 1000000;
    std::map<std::string, std::pair<uint64_t,uint64_t>> mpInvestAddr2Amount;

    ret = GetInvestmentAmountAndDuration(bonusAddr, cur_time, zero_time, mpInvestAddr2Amount);
    if(ret < 0) return ret-=200;

    ret = GetTotalCirculationYesterday(cur_time, TotalCirculationYesterday);
    if(ret < 0) return ret-=300;

    ret = GetTotalInvestmentYesterday(cur_time, TotalinvestYesterday);
    if(ret < 0) return ret-=400;

    uint64_t TotalBrunYesterday = 0;
    ret = GetTotalBurnYesterday(cur_time, TotalBrunYesterday);
    if(ret < 0) return ret-=500;

	if(TotalinvestYesterday == 0) return -2;
    
    if(TotalBrunYesterday > TotalCirculationYesterday)  return -3;
    TotalCirculationYesterday = TotalCirculationYesterday - TotalBrunYesterday;

	uint64_t StakeRate = ((double)TotalinvestYesterday / TotalCirculationYesterday + 0.005) * 100;
	double InflationRate;
    if(StakeRate <= 25) StakeRate = 25;
    else if(StakeRate >= 90) StakeRate = 90;
	ret = ca_algorithm::GetInflationRate(cur_time, StakeRate - 1, InflationRate);
	if(ret < 0) return ret-=600;

    std::stringstream ss;
    ss << std::setprecision(8) << InflationRate;
    std::string InflationRateStr = ss.str();
    ss.str(std::string());
    ss.clear();
    ss << std::setprecision(2) << (StakeRate/100.0);

    std::string StakeRateStr = ss.str();
    cpp_bin_float EarningRate0 = static_cast<cpp_bin_float>(std::to_string(global::ca::kDecimalNum)) * (static_cast<cpp_bin_float>(InflationRateStr) / static_cast<cpp_bin_float>(StakeRateStr));
    ss.str(std::string());
    ss.clear();
    ss << std::setprecision(8) << EarningRate0;
    
    uint64_t EarningRate1 = std::stoi(ss.str());

    double EarningRate2 = (double)EarningRate1 / global::ca::kDecimalNum;
    // 0.085 / 0.25 = 0.34
    //Maximum inflation rate/minimum pledge rate=maximum yield rate
    if(EarningRate2 > 0.34) return -4;

    for(auto &it : mpInvestAddr2Amount)
    {
        values[it.first] = EarningRate2 * it.second.first / 365;
    }
    return 0;
}

int ca_algorithm::CalcBonusValue()
{
    const std::string bonusAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    std::map<std::string, uint64_t> values;
    std::vector<std::string> abnormal_addr_list;
    std::unordered_map<std::string, uint64_t> addr_sign_cnt;
    uint64_t cur_time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    auto ret = ca_algorithm::GetAbnormalSignAddrListByPeriod(cur_time, abnormal_addr_list, addr_sign_cnt);
    if(ret < 0) return ret - 100;

    std::cout << "SignInfo:" << std::endl;
    for(auto it : addr_sign_cnt)
    {
        std::cout << it.first << " " << it.second << std::endl;
    }
    std::cout << "AbnormalAddr: " << std::endl;
    for(auto it : abnormal_addr_list)
    {
        std::cout << it << std::endl;
    }

    if(addr_sign_cnt.find(bonusAddr) == addr_sign_cnt.end() || std::find(abnormal_addr_list.begin(),abnormal_addr_list.end(), bonusAddr) != abnormal_addr_list.end())
    {
        std::cout << RED <<"AbnormalAddr:"<<bonusAddr<< RESET << std::endl;
        return -1;
    }
    
	std::string strTx;
	CTransaction tx;
    uint64_t total_award;
    uint64_t TotalCirculationYesterday;
    uint64_t TotalinvestYesterday;
	uint64_t zero_time = MagicSingleton<TimeUtil>::GetInstance()->getMorningTime(cur_time) * 1000000;
    std::map<std::string, std::pair<uint64_t,uint64_t>> mpInvestAddr2Amount;

    ret = GetInvestmentAmountAndDuration(bonusAddr, cur_time, zero_time, mpInvestAddr2Amount);
    if(ret < 0) return ret-=200;

    std::cout << "bonusAddr: " << bonusAddr << std::endl;
    for(auto &it : mpInvestAddr2Amount)
    {
        std::cout << "investor: " << it.first << " amount: " << it.second.first << " duration: " << it.second.second << std::endl;
    }
    std::cout<<std::endl;

    ret = GetTotalCirculationYesterday(cur_time, TotalCirculationYesterday);
    if(ret < 0) return ret-=300;

    ret = GetTotalInvestmentYesterday(cur_time, TotalinvestYesterday);
    if(ret < 0) return ret-=400;

    uint64_t TotalBrunYesterday = 0;
    ret = GetTotalBurnYesterday(cur_time, TotalBrunYesterday);
    if(ret < 0) return ret-=500;

	if(TotalinvestYesterday == 0) return -2;

    if(TotalBrunYesterday > TotalCirculationYesterday)  return -3;
    std::cout << "OldTotalCirculationYesterday: " << TotalCirculationYesterday << std::endl;

    TotalCirculationYesterday = TotalCirculationYesterday - TotalBrunYesterday;

    std::cout << "TotalBrunYesterday: " << TotalBrunYesterday << std::endl;
    std::cout << "NewTotalCirculationYesterday: " << TotalCirculationYesterday << std::endl;
    std::cout << "TotalinvestYesterday: " << TotalinvestYesterday << std::endl;

	uint64_t StakeRate = ((double)TotalinvestYesterday / TotalCirculationYesterday + 0.005) * 100;
	double InflationRate;
    if(StakeRate <= 25) StakeRate = 25;
    else if(StakeRate >= 90) StakeRate = 90;
	ret = ca_algorithm::GetInflationRate(cur_time, StakeRate - 1, InflationRate);
	if(ret < 0) return ret-=600;

    std::cout << "interest rate: " << InflationRate << std::endl;

    std::cout << "Investment rate:" << StakeRate << "%" << std::endl;

    std::stringstream ss;
    ss << std::setprecision(8) << InflationRate;
    std::string InflationRateStr = ss.str();
    ss.str(std::string());
    ss.clear();
    ss << std::setprecision(2) << (StakeRate/100.0);
    std::string StakeRateStr = ss.str();
    cpp_bin_float EarningRate0 = static_cast<cpp_bin_float>(std::to_string(global::ca::kDecimalNum)) * (static_cast<cpp_bin_float>(InflationRateStr) / static_cast<cpp_bin_float>(StakeRateStr));
    ss.str(std::string());
    ss.clear();
    ss << std::setprecision(8) << EarningRate0;
    
    uint64_t EarningRate1 = std::stoi(ss.str());

    double EarningRate2 = (double)EarningRate1 / global::ca::kDecimalNum;

    std::cout << "EarningRate2 : " << EarningRate2 << std::endl;

    // 0.085 / 0.25 = 0.34
    //Maximum inflation rate/minimum pledge rate=maximum yield rate
    if(EarningRate2 > 0.34) return -4;
    for(auto &it : mpInvestAddr2Amount)
    {
        values[it.first] = EarningRate2 * it.second.first / 365;

        std::cout << "InvestAddr: " <<it.first << std::endl;
        std::cout << "InvestAmount: " << it.second.first << std::endl; 
        std::cout << "reward: " << values[it.first] << std::endl;
    }
    return 0;
}

uint64_t ca_algorithm::GetSumHashCeilingHeight(uint64_t height)
{
    if(height == 0)
    {
        return global::ca::sum_hash_range;
    }
    auto quotient = height / global::ca::sum_hash_range;
    auto remainder = height % global::ca::sum_hash_range;
    if(remainder == 0)
    {
        return height;
    }
    else
    {
        return (quotient + 1) * global::ca::sum_hash_range;
    }
}

uint64_t ca_algorithm::GetSumHashFloorHeight(uint64_t height)
{
    auto quotient = height / global::ca::sum_hash_range;
    auto remainder = height % global::ca::sum_hash_range;
    if(remainder == 0)
    {
        return (quotient - 1) * global::ca::sum_hash_range;
    }
    else
    {
        return quotient * global::ca::sum_hash_range;
    }
}

int ca_algorithm::CalcHeightsSumHash(uint64_t block_height, DBReadWriter &db_writer)
{
    if (block_height == 0)
    {
        return 0;
    }
    uint64_t sum_hash_key = GetSumHashCeilingHeight(block_height);
    if(block_height % global::ca::sum_hash_range != 0)
    {
        uint64_t node_height = 0;
        if (DBStatus::DB_SUCCESS != db_writer.GetBlockTop(node_height))
        {
            ERRORLOG("GetBlockTop error!");
            return -1;
        }

        if (sum_hash_key > node_height)
        {
            return 0;
        }
    }

    std::string sumHash;
    auto start_height = GetSumHashFloorHeight(block_height) + 1;
    auto end_height = GetSumHashCeilingHeight(block_height) + 1;
    if(!CalculateHeightSumHash(start_height, end_height, db_writer, sumHash))
    {
        return -2;
    }
    if (DBStatus::DB_SUCCESS != db_writer.SetSumHashByHeight(sum_hash_key, sumHash))
    {
        return -3;
    }
    INFOLOG("set height sum hash at height {} hash: {}, key: {}", block_height, sumHash, sum_hash_key);

    return 0;
}

int ca_algorithm::Calc1000HeightsSumHash(uint64_t blockHeight, DBReadWriter &dbWriter, std::string& back_hask)
{

    if(blockHeight < global::ca::thousand_sum_hash_range)
    {
        return 0;
    }

    int  quotient  = blockHeight / global::ca::thousand_sum_hash_range;
    auto remainder = blockHeight % global::ca::thousand_sum_hash_range;

    //We need to determine whether one is the first thousand-height store
    std::vector<std::string> hundredHash;
    if(quotient != 1)
    {
        //Take out the previous 1000 height joint hash and the current required 1000 height joint hash together to calculate a hash
        std::string Comhash;
        if(DBStatus::DB_SUCCESS != dbWriter.GetCheckBlockHashsByBlockHeight((quotient - 1) * global::ca::thousand_sum_hash_range ,Comhash))
        {
            return -1;
        }
        hundredHash.push_back(Comhash);
    }

    //The combined hashes within the height of the current requirement of 1000 are counted together as a hash
    auto sumHashHeight =  (quotient - 1) * global::ca::thousand_sum_hash_range;
    for(int i = 1 ; i <= 10; ++i )
    {   
        sumHashHeight += global::ca::sum_hash_range;
        std::string sumHash;
        if (DBStatus::DB_SUCCESS != dbWriter.GetSumHashByHeight(sumHashHeight, sumHash))
        {    
            return -2;
        }

        hundredHash.push_back(sumHash);
    }


    //The joint hash within one thousand and the joint hash of the first thousand heights calculated before are calculated as a joint hash of the new height
    std::string endComhash;
    std::sort(hundredHash.begin(), hundredHash.end());
    endComhash = getsha256hash(StringUtil::concat(hundredHash, ""));

    back_hask = endComhash;

    return 0;
}

int ca_algorithm::CalcHeightsSumHash(uint64_t block_height, global::ca::SaveType saveType, global::ca::BlockObtainMean obtainMean, DBReadWriter &db_writer)
{
    if(block_height <= global::ca::sum_hash_range)
    {
        return 0;
    }
    //If the synchronization is from zero and normal
    if(global::ca::SaveType::SyncFromZero == saveType && global::ca::BlockObtainMean::Normal == obtainMean)
    {
        //If block height% 100==1 and there is no sum hash of block height - 1 in the database
        std::string sumHash;
        auto ret = db_writer.GetSumHashByHeight(block_height - 1, sumHash);
        if(block_height % global::ca::sum_hash_range == 1 && DBStatus::DB_SUCCESS != ret)
        {
            //Calculate and hash and save to the database
            auto start_height = block_height - global::ca::sum_hash_range;
            auto end_height = block_height;
            if(!CalculateHeightSumHash(start_height, end_height, db_writer, sumHash))
            {
                return -1;
            }
            if (DBStatus::DB_SUCCESS != db_writer.SetSumHashByHeight(block_height - 1, sumHash))
            {
                return -2;
            }
            INFOLOG("set height sum hash at height {} hash: {}", block_height - 1, sumHash);
        }
    }
    //If the synchronization is from zero and the pre-hash is missing
    else if(global::ca::SaveType::SyncFromZero == saveType && global::ca::BlockObtainMean::ByPreHash == obtainMean)
    {
        //If block height% 100==0
        if(block_height % global::ca::sum_hash_range == 0)
        {
            std::string sumHash;
            auto start_height = block_height + 1 - global::ca::sum_hash_range;
            auto end_height = block_height + 1;
            if(!CalculateHeightSumHash(start_height, end_height, db_writer, sumHash))
            {
                return -3;
            }
            if (DBStatus::DB_SUCCESS != db_writer.SetSumHashByHeight(block_height, sumHash))
            {
                return -4;
            }
            INFOLOG("set height sum hash at height {} hash: {}", block_height, sumHash);
        }
    }
    //If the synchronization is from zero and there is no uxto
    else if(global::ca::SaveType::SyncFromZero == saveType && global::ca::BlockObtainMean::ByUtxo == obtainMean)
    {
        //If there is this and hash in the database
        std::string sumHash;
        if(db_writer.GetSumHashByHeight(GetSumHashCeilingHeight(block_height), sumHash) == DBStatus::DB_SUCCESS)
        {
            auto start_height = GetSumHashFloorHeight(block_height) + 1;
            auto end_height = GetSumHashCeilingHeight(block_height) + 1;
            if(!CalculateHeightSumHash(start_height, end_height, db_writer, sumHash))
            {
                return -5;
            }
            if (DBStatus::DB_SUCCESS != db_writer.SetSumHashByHeight(block_height, sumHash))
            {
                return -6;
            }
            INFOLOG("set height sum hash at height {} hash: {}", block_height, sumHash);
        }
    }
    //If it is synchronous and normal, or if it is synchronous and short of cash hash       
    else if((global::ca::SaveType::SyncNormal == saveType && global::ca::BlockObtainMean::Normal == obtainMean)
            || (global::ca::SaveType::SyncNormal == saveType && global::ca::BlockObtainMean::ByPreHash == obtainMean))
    {
        //If the block height is greater than or equal to the current node height
        uint64_t node_height = 0;
        if (DBStatus::DB_SUCCESS != db_writer.GetBlockTop(node_height))
        {
            ERRORLOG("GetBlockTop error!");
            return -7;
        }
        if(block_height >= node_height)
        {
            //If block height% 100==1 and there is no sum hash of block height - 1-100 in the database
            std::string sumHash;
            if(block_height % global::ca::sum_hash_range == 1 && DBStatus::DB_SUCCESS != db_writer.GetSumHashByHeight(block_height - 1 - global::ca::sum_hash_range, sumHash))
            {
                //Calculate the block height - 1-100 and hash and store it in the database
                auto start_height = block_height - 2 * global::ca::sum_hash_range;
                auto end_height = block_height - 1 - global::ca::sum_hash_range + 1;
                if(!CalculateHeightSumHash(start_height, end_height, db_writer, sumHash))
                {
                    return -8;
                }
                if (DBStatus::DB_SUCCESS != db_writer.SetSumHashByHeight(end_height - 1, sumHash))
                {
                    return -9;
                }
                INFOLOG("set height sum hash at height {} hash: {}", end_height - 1, sumHash);
            }
        }
        else
        {
            //If there is any hash in the area, calculate the hash sum in the area where the block is located and update it
            std::string sumHash;
            if(db_writer.GetSumHashByHeight(GetSumHashCeilingHeight(block_height), sumHash) == DBStatus::DB_SUCCESS)
            {
                auto start_height = GetSumHashFloorHeight(block_height) + 1;
                auto end_height = GetSumHashCeilingHeight(block_height) + 1;
                if(!CalculateHeightSumHash(start_height, end_height, db_writer, sumHash))
                {
                    return -10;
                }
                if (DBStatus::DB_SUCCESS != db_writer.SetSumHashByHeight(block_height, sumHash))
                {
                    return -11;
                }
                INFOLOG("set height sum hash at height {} hash: {}", block_height, sumHash);
            } 
        }
    }
    //In case of synchronization and lack of utxo
    else if(global::ca::SaveType::SyncNormal == saveType && global::ca::BlockObtainMean::ByUtxo == obtainMean)
    {
        //If there is a sum hash in the region, if the current height is rounded down - 100 is greater than or equal to the block height, calculate the hash sum in the region where the block is located and update it
        std::string sumHash;
        if(db_writer.GetSumHashByHeight(GetSumHashCeilingHeight(block_height), sumHash) == DBStatus::DB_SUCCESS)
        {
            auto start_height = GetSumHashFloorHeight(block_height) + 1;
            auto end_height = GetSumHashCeilingHeight(block_height) + 1;
            if(!CalculateHeightSumHash(start_height, end_height, db_writer, sumHash))
            {
                return -12;
            }
            if (DBStatus::DB_SUCCESS != db_writer.SetSumHashByHeight(block_height, sumHash))
            {
                return -13;
            }
            INFOLOG("set height sum hash at height {} hash: {}", block_height, sumHash);
        } 
    }
    //If it is a broadcast building block  
    else if(global::ca::SaveType::Broadcast == saveType)
    {
        //If block height% 100==1 and there is no sum hash of block height - 1-100 in the database
        std::string sumHash;
        if(block_height % 100 == 1 && DBStatus::DB_SUCCESS != db_writer.GetSumHashByHeight(block_height - 1 - global::ca::sum_hash_range, sumHash))
        {
            //Calculate the block height - 1-100 and hash and store it in the database
            auto start_height = block_height - 2 * global::ca::sum_hash_range;
            auto end_height = block_height - 1 - global::ca::sum_hash_range + 1;
            if(!CalculateHeightSumHash(start_height, end_height, db_writer, sumHash))
            {
                return -14;
            }
            if (DBStatus::DB_SUCCESS != db_writer.SetSumHashByHeight(end_height - 1, sumHash))
            {
                return -15;
            }
            INFOLOG("set height sum hash at height {} hash: {}", end_height - 1, sumHash);
        }
    }

    return 0;
}

int ca_algorithm::GetCallContractFromAddr(const CTransaction& transaction, bool isMultiSign, std::string& fromAddr)
{
    for (auto &vin : transaction.utxo().vin())
    {
        if(vin.contractaddr().empty())
        {
            Base58Ver ver = isMultiSign ? Base58Ver::kBase58Ver_MultiSign : Base58Ver::kBase58Ver_Normal;
            if(vin.vinsign().pub().empty())
            {
                ERRORLOG("vin.vinsign().pub() is empty");
                return -1;
            }
            CTxInput CopyVin = vin;
            CopyVin.clear_vinsign();
            int verifySignRet = VerifySign(vin.vinsign(), getsha256hash(CopyVin.SerializeAsString()));
            if (verifySignRet != 0)
            {
                ERRORLOG("VerifySign fail ret : {}", verifySignRet);
                return -2;
            }
            fromAddr = GetBase58Addr(vin.vinsign().pub(), ver);
            break;
        }
    }
    if (fromAddr.empty())
    {
        ERRORLOG("fail to parse fromaddr");
        return -3;
    }
    return 0;
}

int ca_algorithm::VerifySign(const CSign & sign, const std::string & serHash)
{       
    if (sign.sign().size() == 0 || sign.pub().size() == 0)
    {
        std::cout << "sign size is 0";
        return -1;
    }
    if (serHash.size() == 0)
    {
        std::cout << "serHash size is 0" <<std::endl;
        return -2;
    }

    EVP_PKEY* eckey = nullptr;
    if(GetEDPubKeyByBytes(sign.pub(), eckey) == false)
    {
        EVP_PKEY_free(eckey);
        ERRORLOG(RED "Get public key from bytes failed!" RESET);
        return -3;
    }

    if(ED25519VerifyMessage(serHash, eckey, sign.sign()) == false)
    {
        EVP_PKEY_free(eckey);
        ERRORLOG(RED "Public key verify sign failed!" RESET);
        return -4;
    }
    EVP_PKEY_free(eckey);
    return 0;
}

int ca_algorithm::GetCommissionPercentage(const std::string& addr, double& retCommissionRate)
{
    DBReader bonusDbReader;
    std::vector<std::string> bonusutxos; 
    auto ret = bonusDbReader.GetStakeAddressUtxo(addr, bonusutxos);
    if(ret != DBStatus::DB_SUCCESS)
    {
        ERRORLOG("GetCommissionPercentage GetStakeAddressUtxo error:{}", -1);
        return -1;
    }
    std::reverse(bonusutxos.begin(), bonusutxos.end());
	CTransaction tx;

    bool flag = false;
    for (auto &utxo : bonusutxos) 
	{
        std::string txRaw;
        if(DBStatus::DB_SUCCESS != bonusDbReader.GetTransactionByHash(utxo, txRaw))
        {
            ERRORLOG("GetCommissionPercentage GetTransactionByHash error{} ", -2);
            return -2;
        }

        tx.ParseFromString(txRaw);
        for (auto &vout : tx.utxo().vout()) 
		{
            if (vout.addr() == global::ca::kVirtualStakeAddr)
			{
                flag = true;
                break;
            }
        }
    }

    if(!flag)
    {
        ERRORLOG("GetCommissionPercentage Get Stake tx error{} ", -3);
        return -3;
    }

    nlohmann::json txInfo;
    try
    {
        nlohmann::json commissionJson = nlohmann::json::parse(tx.data());
        txInfo = commissionJson["TxInfo"].get<nlohmann::json>();
    }
    catch (const std::exception&)
    {
        ERRORLOG("GetCommissionPercentage Get TxInfo error{} ", -4);
        return -4;
    }


    return 0;
}

int ca_algorithm::VerifyContractTransactionTx(const CTransaction &tx, uint64_t txHeight, bool turnOnMissingBlockProtocol, bool verifyAbnormal)
{
    uint64_t startTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    
    DBReader dbReader;

    bool isStake = false;
    double donusPumping = 0.0;
    bool isRedeem = false;
    std::string redeemUtxoHash;
    bool isInvest = false;
    std::string investNode;
    uint64_t investAmount = 0;
    bool isDivest = false;
    std::string investedNode;
    std::string divestUtxoHash; 
	bool isDeclare = false;
	std::string multiSignPub;
    bool isDeployContract = false;
    bool isCallContract = false;
    std::string deployerAddr;
    std::string deployHash;
    std::string OwnerEvmAddr;
    std::string code;
    std::string input;
    std::string output;
//    nlohmann::json jStorage;
//    nlohmann::json jPrevHash;
//    nlohmann::json jLog;
//    nlohmann::json jSelfdestructed;
    global::ca::VmType vmType;

    uint64_t contractTransfer = 0;
    uint64_t contractTip = 0;

    auto txType = (global::ca::TxType)tx.txtype();

    bool isClaim = false;
    uint64_t claimAmount = 0;

    bool isTx = false;
    nlohmann::json txInfo;
    if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
    {
        try
        {
            nlohmann::json dataJson = nlohmann::json::parse(tx.data());
            txInfo = dataJson["TxInfo"].get<nlohmann::json>();

            // if(global::ca::TxType::kTxTypeStake == txType)
            // {
            //     isStake = true;
            //     try
            //     {
            //         donusPumping = txInfo["BonusPumping"].get<double>();
            //     }
            //     catch (...)
            //     {
            //         donusPumping = global::ca::KMaxBonusPumping;
            //     }
                
            // }
            // if (global::ca::TxType::kTxTypeUnstake == txType)
            // {   
            //     isRedeem = true;            
            //     redeemUtxoHash = txInfo["UnstakeUtxo"].get<std::string>();
            // }
            // else if (global::ca::TxType::kTxTypeInvest == txType)
            // {
            //     isInvest = true;
            //     investNode = txInfo["BonusAddr"].get<std::string>();
            //     investAmount = txInfo["InvestAmount"].get<uint64_t>();
            // }  
            // else if (global::ca::TxType::kTxTypeDisinvest == txType)
            // {
            //     isDivest = true;
            //     divestUtxoHash = txInfo["DisinvestUtxo"].get<std::string>();
            //     investedNode = txInfo["BonusAddr"].get<std::string>();        
            // }
            // else if(global::ca::TxType::kTxTypeBonus == txType)
            // {
            //     isClaim = true;
            //     claimAmount = txInfo["BonusAmount"].get<uint64_t>();  
            // }
            // else if (global::ca::TxType::kTxTypeDeclaration == txType)
            // {
            //     isDeclare = true;
            //     multiSignPub = txInfo["MultiSignPub"].get<std::string>();
            //     multiSignPub = Base64Decode(multiSignPub);
            // }
            if (global::ca::TxType::kTxTypeDeployContract == txType)
            {
                isDeployContract = true;
                if(txInfo.find("OwnerEvmAddr") != txInfo.end())
                {
                    OwnerEvmAddr = txInfo["OwnerEvmAddr"].get<std::string>();
                }
                code = txInfo["Code"].get<std::string>();
                output = txInfo["Output"].get<std::string>();
//                jStorage = txInfo["Storage"];
//                jPrevHash = txInfo["PrevHash"];
//                jLog = txInfo["log"];
                vmType = txInfo["VmType"].get<global::ca::VmType>();
//                jSelfdestructed = txInfo["selfdestructed"];

            }
            else if (global::ca::TxType::kTxTypeCallContract == txType)
            {
                isCallContract = true;
                if(txInfo.find("OwnerEvmAddr") != txInfo.end())
                {
                    OwnerEvmAddr = txInfo["OwnerEvmAddr"].get<std::string>();
                }
                deployerAddr = txInfo["DeployerAddr"].get<std::string>();
                deployHash = txInfo["DeployHash"].get<std::string>();
                input = txInfo["Input"].get<std::string>();
                output = txInfo["Output"].get<std::string>();
                vmType = txInfo["VmType"].get<global::ca::VmType>();
                contractTip = txInfo["contractTip"].get<uint64_t>();
                contractTransfer = txInfo["contractTransfer"].get<uint64_t>();

//                if (tx.version() == 0)
//                {
//                    jStorage = txInfo["Storage"];
//                    jPrevHash = txInfo["PrevHash"];
//                    jLog = txInfo["log"];
//                    jSelfdestructed = txInfo["selfdestructed"];
//                }


            }
            else if (global::ca::TxType::kTxTypeTx == txType)
            {
                isTx = true;
            }

        }
        catch(...)
        {
            ERRORLOG(RED "JSON failed to parse data field!" RESET);
            return -1;
        }
    }

    std::string missingUtxo = "";
    auto passCode = DoubleSpendCheck(tx, turnOnMissingBlockProtocol, &missingUtxo);
    if (passCode != 0)
    {
        DEBUGLOG("DoubleSpendCheck missingUtxo:{}, ret:{}", missingUtxo, passCode);
        if(passCode == -5 || passCode == -7 || passCode == -8 && !missingUtxo.empty())
        {
            std::string blockHash;
            if(dbReader.GetBlockHashByTransactionHash(missingUtxo, blockHash) == DBStatus::DB_SUCCESS)
            {
                //doubleSpend
                return passCode - 20000;
            }
            else
            {
                //block not found
                return passCode - 30000;
            }
        }
    }

    bool isMultiSign = IsMultiSign(tx);

    uint64_t vinAmount = 0;
    int count = 0;
    for (auto &vin : tx.utxo().vin())
    {
        global::ca::TxType txType = (global::ca::TxType)tx.txtype();
        std::string addr;
        if(vin.contractaddr().empty())
        {
            Base58Ver ver = isMultiSign ? Base58Ver::kBase58Ver_MultiSign : Base58Ver::kBase58Ver_Normal;
            addr = GetBase58Addr(vin.vinsign().pub(), ver);
        }
        else if(isDeployContract || isCallContract)
        {
            addr = vin.contractaddr();
        }
        for (auto & prevout : vin.prevout())
        {
            std::string utxo = prevout.hash();


            std::string balance ;
            if(txType ==  global::ca::TxType::kTxTypeUnstake && ++count == 1)
            {
                addr = global::ca::kVirtualStakeAddr;
            }
            else if(txType == global::ca::TxType::kTxTypeDisinvest && ++count == 1)
            {
                addr = global::ca::kVirtualInvestAddr;
            }

			if (DBStatus::DB_SUCCESS != dbReader.GetUtxoValueByUtxoHashs(utxo, addr, balance))
			{
                MagicSingleton<BlockHelper>::GetInstance()->PushMissUTXO(utxo);
				ERRORLOG("GetTransactionByHash failed!");
				continue;
			}


            uint64_t stakeValue = 0;
            std::string underline = "_";
            std::vector<std::string> utxoValues;

            if(balance.find(underline) != string::npos)
            {
                StringUtil::SplitString(balance, "_", utxoValues);
                
                for(int i = 0; i < utxoValues.size(); ++i)
                {
                    stakeValue += std::stol(utxoValues[i]);
                }

                vinAmount += stakeValue;
            }
            else
            {
                vinAmount +=  std::stol(balance);
            }
        
        }
    }
    
    //vin Accumulated claim balance
    std::map<std::string, uint64_t> companyDividend;
    uint64_t costo=0;
	uint64_t nodeDividend=0;
    uint64_t vinAmountCopia=vinAmount;
    uint64_t TotalClaim=0;
    double   claimBonusPumping;
    if(isClaim)
    {
        std::string owner = tx.utxo().owner().at(0);
        int rt = ca_algorithm::GetCommissionPercentage(owner, claimBonusPumping);
        if(rt != 0)
        {
            ERRORLOG(RED "GetCommissionPercentage ret: " RESET, rt);
            return 801;
        }
        // if(claimBonusPumping > global::ca::KMaxBonusPumping || claimBonusPumping < global::ca::KMinBonusPumping)
        // {
        //     ERRORLOG("Stake tx BonusPumping enter error!");
        //     return -802;
        // }

        uint64_t tx_time = tx.time();
        auto ret = ca_algorithm::CalcBonusValue(tx_time, owner, companyDividend);
        if(ret < 0)
        {
            ERRORLOG(RED "Failed to obtain the amount claimed by the investor ret:({})" RESET, ret);
            return -2;
        } 
        for(auto & Company : companyDividend)
        {
            costo = Company.second * claimBonusPumping + 0.5;
            nodeDividend += costo;
            vinAmount += (Company.second-costo);
            TotalClaim += (Company.second-costo);
        }
        vinAmount += nodeDividend;
        TotalClaim += nodeDividend;

        if(TotalClaim != claimAmount) 
        {
            return -3;
        }
    }

    // 3. The transaction amount must be consistent 
    uint64_t voutAmount = 0;
    for (auto &vout : tx.utxo().vout())
    {
        voutAmount += vout.value();
    }
    if (voutAmount != vinAmount)
    {
        ERRORLOG("Input is not equal to output ,voutAmount = {}, vinAmount = {}", voutAmount, vinAmount);
        return -4;
    }

    {
    //Calculate whether the pre-transaction includes the account number used
        std::set<std::string> txVinVec;
        for(auto & vin : tx.utxo().vin())
        {
            std::string vinAddr;
            if(vin.contractaddr().empty())
            {
                Base58Ver ver = isMultiSign ? Base58Ver::kBase58Ver_MultiSign : Base58Ver::kBase58Ver_Normal;
                vinAddr = GetBase58Addr(vin.vinsign().pub(), ver);
            }
            else if(isDeployContract || isCallContract)
            {
                vinAddr = vin.contractaddr();
            }

            for (auto & prevHash : vin.prevout())
            {
                std::string prevUtxo = prevHash.hash();
                std::string strTxRaw;
                if (DBStatus::DB_SUCCESS !=  dbReader.GetTransactionByHash(prevUtxo, strTxRaw))
                {
                    ERRORLOG("get tx failed");
                    return -5;
                }

                CTransaction prevTx;
                prevTx.ParseFromString(strTxRaw);
                if (prevTx.hash().size() == 0)
                {
                    return -6;
                }

                std::vector<std::string> prevTxOutAddr;
                for (auto & txOut : prevTx.utxo().vout())
                {
                    prevTxOutAddr.push_back(txOut.addr());
                }

                if (std::find(prevTxOutAddr.begin(), prevTxOutAddr.end(), vinAddr) == prevTxOutAddr.end())
                {
                    return -7;
                }
            }
        }
    }

    std::string redeemUtxoRaw;
    CTransaction redeemUtxo;
    std::string divestUtxoRaw;
    CTransaction divestUtxo;
    if(global::ca::TxType::kTxTypeStake == txType)
    {
        // if(donusPumping > global::ca::KMaxBonusPumping || donusPumping < global::ca::KMinBonusPumping)
        // {
        //     ERRORLOG("Stake tx BonusPumping enter error!");
        //     return -800;
        // }

        std::vector<std::string> stakeUtxos;
        auto dbret = dbReader.GetStakeAddressUtxo(tx.utxo().owner(0),stakeUtxos);
        if(dbret == DBStatus::DB_SUCCESS)
        {
            ERRORLOG("There has been a pledge transaction before !");
            return -8;
        }
    }
    else if (global::ca::TxType::kTxTypeUnstake == txType)
    {
        std::set<std::string> setOwner(tx.utxo().owner().begin(), tx.utxo().owner().end());
        if (setOwner.size() != 1)
        {
            return -9;
        }
        uint64_t stakedAmount = 0;
        std::string owner = tx.utxo().owner().at(0);
        int ret = IsQualifiedToUnstake(owner, redeemUtxoHash, stakedAmount);
        if(ret != 0)
        {
            ERRORLOG(RED "Not allowed to invest!" RESET);
            return ret - 200;
        }
        if (tx.utxo().vout(0).addr() != owner)
        {
            ERRORLOG(RED "The address of the withdrawal utxo is incorrect!" RESET);
            return -10;
        }
        if (tx.utxo().vout(0).value() != stakedAmount)
        {
            ERRORLOG(RED "The value of the withdrawal utxo is incorrect!" RESET);
            return -11;
        }

        for(int i = 0; i < tx.utxo().vin_size() ; ++i)
        {
            if(i == 0)
            {
                if(tx.utxo().vin(0).prevout(0).hash() != redeemUtxoHash || tx.utxo().vin(0).prevout(0).n() != 1)
                {
                    return -12;
                }
            }
            else
            {
                for(auto & prevout : tx.utxo().vin(i).prevout())
                {
                    if(prevout.n() != 0)
                    {
                        return -13;
                    }
                }
            }
        }
    }
    else if(global::ca::TxType::kTxTypeInvest == txType)
    {
        if (tx.utxo().owner().size() != 1)
        {
            return -14;
        }
        std::string owner = tx.utxo().owner().at(0);
        int ret = CheckInvestQualification(owner, investNode, investAmount);
        if(ret != 0)
        {
            ERRORLOG(RED "Not allowed to invest!" RESET);
            return ret - 300;
        }
    }
    else if (global::ca::TxType::kTxTypeDisinvest == txType)
    {
        std::set<std::string> setOwner(tx.utxo().owner().begin(), tx.utxo().owner().end());
        if (setOwner.size() != 1)
        {
            return -15;
        }

        uint64_t investedAmount = 0;
        std::string owner = tx.utxo().owner().at(0);
        int ret = IsQualifiedToDisinvest(owner, investedNode, divestUtxoHash, investedAmount);
        if(ret != 0)
        {
            ERRORLOG(RED "Not allowed to Dinvest!" RESET);
            return ret - 400;
        }
        if (tx.utxo().vout(0).addr() != owner)
        {
            ERRORLOG(RED "The address of the withdrawal utxo is incorrect!" RESET);
            return -16;
        }
        if (tx.utxo().vout(0).value() != investedAmount)
        {
            ERRORLOG(RED "The value of the withdrawal utxo is incorrect!" RESET);
            return -17;
        }

        for(int i = 0; i < tx.utxo().vin_size() ; ++i)
        {
            if(i == 0)
            {
                if(tx.utxo().vin(0).prevout(0).hash() != divestUtxoHash || tx.utxo().vin(0).prevout(0).n() != 1)
                {
                    return -18;
                }
            }
            else
            {
                for(auto & prevout : tx.utxo().vin(i).prevout())
                {
                    if(prevout.n() != 0)
                    {
                        return -19;
                    }
                }
            }
        }
    }
	else if (global::ca::TxType::kTxTypeDeclaration == txType)
	{
		std::string multiSignAddr = GetBase58Addr(multiSignPub, Base58Ver::kBase58Ver_MultiSign);
        
        DBReader dbReader;
        std::vector<std::string> multiSignAddrs;
        auto db_status = dbReader.GetMutliSignAddress(multiSignAddrs);
        if (DBStatus::DB_SUCCESS != db_status)
        {
            if (DBStatus::DB_NOT_FOUND != db_status)
            {
                return -20;
            }
        }

        if (std::find(multiSignAddrs.begin(), multiSignAddrs.end(), multiSignAddr) != multiSignAddrs.end())
        {
            return -21;
        }
	}
    else if(global::ca::TxType::kTxTypeBonus == txType)
    {
        if (tx.utxo().owner().size() != 1)
        {
            return -22;
        }
        std::string owner = tx.utxo().owner().at(0);
        int ret = CheckBonusQualification(owner, tx.time(), verifyAbnormal);
        if(ret != 0)
        {
            ERRORLOG(RED "Not allowed to Bonus!" RESET);
            return ret - 400;
        }
        
        int i=0;
        costo=0;
        nodeDividend=0;
        uint64_t burnFree = tx.utxo().vout(tx.utxo().vout().size()-1).value();
        for(auto &vout : tx.utxo().vout())
        {
            if(tx.utxo().vout().size()-2 != i && tx.utxo().vout().size()-1 != i)
            {
                if(companyDividend.end() != companyDividend.find(vout.addr()))
                {
                    costo=companyDividend[vout.addr()] * claimBonusPumping + 0.5;
                    nodeDividend+=costo;
                    if(companyDividend[vout.addr()] - costo != vout.value())
                    {
                        return -23;
                    }
                }
                else
                {
                    return -24;
                }
                ++i;
            }
        }
        uint64_t LastVoutAmount = vinAmountCopia - burnFree + nodeDividend;
        if(owner == tx.utxo().vout(i).addr())
        {
            if(LastVoutAmount != tx.utxo().vout(i).value())
            {
                return -25;
            }
        }
    }
    else if (global::ca::TxType::kTxTypeDeployContract == txType || global::ca::TxType::kTxTypeCallContract == txType)
    {

    }
    std::string award_addr;
    std::vector<std::string> pledgeAddrs;
    auto status = dbReader.GetStakeAddress(pledgeAddrs);
    if (DBStatus::DB_SUCCESS != status && DBStatus::DB_NOT_FOUND != status)
    {
        return -34;
    }

    if (global::ca::TxType::kTxTypeTx != txType && global::ca::TxType::kTxTypeDeployContract != txType && global::ca::TxType::kTxTypeCallContract != txType)
    {
        std::set<std::string> setOwner(tx.utxo().owner().begin(), tx.utxo().owner().end());
        if (setOwner.size() != 1)
        {
            return -35;
        }
    }

    // Within the height of 50, the pledge transaction or the transaction of the initial account can be initiated arbitrarily
    if (txHeight <= global::ca::kMinUnstakeHeight && (tx.utxo().owner().at(0) == global::ca::kInitAccountBase58Addr || global::ca::TxType::kTxTypeStake == txType || global::ca::TxType::kTxTypeInvest == txType))
    {
        for (auto &signNode : tx.verifysign())
        {
            if (!CheckBase58Addr(GetBase58Addr(signNode.pub()), Base58Ver::kBase58Ver_Normal))
            {
                return -36;
            }
        }
    }
    else
    {
        //Modern development time judges whether the first circulation node is fully pledged and invested
        bool isNeedAgent = TxHelper::IsNeedAgent(tx);

        for (int i = (isNeedAgent ? 0 : 1); i < tx.verifysign_size(); ++i)
        {
            std::string signAddr;
            signAddr = GetBase58Addr(tx.verifysign(i).pub(), Base58Ver::kBase58Ver_Normal);
            auto ret = VerifyBonusAddr(signAddr);
            if(ret < 0)
            {
                ERRORLOG("VerifyBonusAddr error ret:{} signAddr:({})", ret, signAddr);
                return -37;
            }
            
            int64_t stakeTime = ca_algorithm::GetPledgeTimeByAddr(signAddr, global::ca::StakeType::kStakeType_Node);
            if (stakeTime <= 0)
            {
                return -38;
            }
        }
    }
    uint64_t endTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    if(global::ca::TxType::kTxTypeTx == txType)
    {
        MagicSingleton<DONbenchmark>::GetInstance()->AddtransactionDBVerifyMap(tx.hash(), endTime - startTime);  
    }
	
    return 0;
}


int ca_algorithm::VerifyBlock(const CBlock &block, bool turn_on_missing_block_protocol, bool verify_abnormal, bool isVerify)
{
    uint64_t start_time_for_benchmark = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();

    DBReader db_reader;

    // Verify whether the block exists locally
    std::string block_raw;
    auto status = db_reader.GetBlockByBlockHash(block.hash(), block_raw);
    if (DBStatus::DB_SUCCESS == status)
    {
        return 0;
    }
    if (DBStatus::DB_NOT_FOUND != status)
    {
        return -1;
    }

    // Verify whether the front block exists
    block_raw.clear();
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockByBlockHash(block.prevhash(), block_raw))
    {
        MagicSingleton<BlockHelper>::GetInstance()->SetMissingPrehash();
        return -2;
    }
    CBlock pre_block;
    if (!pre_block.ParseFromString(block_raw))
    {
        MagicSingleton<BlockHelper>::GetInstance()->SetMissingPrehash();
        return -3;
    }

    // The block height must be the height of the preceding block plus one
    if (block.height() - pre_block.height() != 1)
    {
        return -4;
    }

    auto ret = MemVerifyBlock(block, isVerify);
    if (0 != ret)
    {
        ret -= 10000;
        ERRORLOG(RED "MemVerifyBlock failed! The error code is {}." RESET, ret);
        return ret;
    }

    // Verify whether the block time is greater than the maximum block time before 10 heights
    uint64_t start_time = 0;
    uint64_t end_time = GetLocalTimestampUsec() + 10 * 60 * 1000 * 1000;
    {
        uint64_t block_height = 0;
        if (block.height() > 10)
        {
            block_height = block.height() - 10;
        }
        std::vector<std::string> block_hashs;
        if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(block_height, block_hashs))
        {
            return -5;
        }
        std::vector<std::string> blocks;
        if (DBStatus::DB_SUCCESS != db_reader.GetBlocksByBlockHash(block_hashs, blocks))
        {
            return -6;
        }
        CBlock block;
        for (auto &block_raw : blocks)
        {
            if (!block.ParseFromString(block_raw))
            {
                return -7;
            }
            if (start_time < block.time())
            {
                start_time = block.time();
            }
        }
    }

    // Verify whether the transaction time is greater than the maximum block time before 10 heights
    if (block.time() > end_time || block.time() < start_time)
    {
        return -8;
    }

    if(isVerify)
    {
        std::vector<future<int>> task_results;
        for (auto& tx : block.txs())
        {
            if (GetTransactionType(tx) != kTransactionType_Tx)
            {
                continue;
            }
            if(tx.verifysign_size() != global::ca::kConsensus)
            {
                return -9;
            }
            auto block_height = block.height();
            auto task = std::make_shared<std::packaged_task<int()>>([tx, block_height, turn_on_missing_block_protocol, verify_abnormal] { return VerifyTransactionTx(tx, block_height, turn_on_missing_block_protocol, verify_abnormal); });
            try
            {
                task_results.push_back(task->get_future());
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }
            MagicSingleton<taskPool>::GetInstance()->commit_work_task([task](){(*task)();});
        }

        for (auto& res : task_results)
        {
            ret = res.get();
            if (ret != 0)
            {
                return ret - 20000;
            }
        }
    }
    
    uint64_t end_time_for_benchmark = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    MagicSingleton<DONbenchmark>::GetInstance()->AddBlockVerifyMap(block.hash(), end_time_for_benchmark - start_time_for_benchmark);
    return 0;

}

int ca_algorithm::VerifyContractBlock(const CBlock &block)
{
    MagicSingleton<ContractDataCache>::GetInstance()->clear();
    ON_SCOPE_EXIT{
        MagicSingleton<ContractDataCache>::GetInstance()->clear();
    };
    
    bool isContractBlock = IsContractBlock(block);
    if (!isContractBlock)
    {
        return 0;
    }
    nlohmann::json blockData;
    try
    {
        blockData = nlohmann::json::parse(block.data());
    }
    catch (...)
    {
        ERRORLOG("fail to parse block data");
        return -1;
    }

    std::map<std::string, std::string> contractPrehashCache;
    for (const auto& tx : block.txs())
    {
        auto txType = (global::ca::TxType)tx.txtype();
        if (txType != global::ca::TxType::kTxTypeCallContract && txType != global::ca::TxType::kTxTypeDeployContract)
        {
            continue;
        }
        auto storageFound = blockData.find(tx.hash());
        if (storageFound == blockData.end())
        {
            ERRORLOG("can't find {} storage in block {}", tx.hash(), block.hash());
            return -2;
        }

        try
        {
            auto output = storageFound.value()["Output"].get<std::string>();
            nlohmann::json dataJson = nlohmann::json::parse(tx.data());
            nlohmann::json txInfo = dataJson["TxInfo"].get<nlohmann::json>();

            std::string OwnerEvmAddr;
            if(txInfo.find("OwnerEvmAddr") != txInfo.end())
            {
                OwnerEvmAddr = txInfo["OwnerEvmAddr"].get<std::string>();
            }
            auto vmType = txInfo["VmType"].get<global::ca::VmType>();

            std::string code;

            std::string deployerAddr;
            std::string deployHash;
            std::string input;
            uint64_t contractTip = 0;
            uint64_t contractTransfer = 0;
            std::string contractFunName;

            if (txType == global::ca::TxType::kTxTypeCallContract)
            {
                deployerAddr = txInfo["DeployerAddr"].get<std::string>();
                deployHash = txInfo["DeployHash"].get<std::string>();
                input = txInfo["Input"].get<std::string>();
                if(vmType == global::ca::VmType::WASM)
                {
                    contractFunName = txInfo["contractFunName"].get<std::string>();
                }
                else if(vmType == global::ca::VmType::EVM)
                {
                    contractTransfer = txInfo["contractTransfer"].get<uint64_t>();
                }
                contractTip = txInfo["contractTip"].get<uint64_t>();
            }
            else if (txType == global::ca::TxType::kTxTypeDeployContract)
            {
                code = txInfo["Code"].get<std::string>();
            }

            std::string expectedOutput;
            nlohmann::json expectedJTxInfo;
            DonHost host;
            int64_t gasCost = 0;
            std::string fromAddr = evm_utils::EvmAddrToBase58(OwnerEvmAddr);
            CTransaction callOutTx;
            callOutTx.set_type(global::ca::kTxSign);
            std::vector<std::string> utxoHashs;

            int ret = 0;
            if(vmType == global::ca::VmType::EVM)
            { 
                if(txType == global::ca::TxType::kTxTypeDeployContract)
                {
                    ret = Evmone::DeployContract(fromAddr, OwnerEvmAddr, code, expectedOutput,
                                                host, gasCost);
                    if(ret != 0)
                    {
                        ERRORLOG("VM failed to deploy contract!, ret {}", ret);
                        return ret - 100;
                    }
                }
                else if(txType == global::ca::TxType::kTxTypeCallContract)
                {
                    ret = Evmone::CallContract(fromAddr, OwnerEvmAddr, deployerAddr, deployHash, input, expectedOutput, host,
                                            gasCost, contractTransfer);
                    if(ret != 0)
                    {
                        ERRORLOG("VM failed to call contract!, ret {}", ret);
                        return ret - 200;
                    }
                }

                ret = Evmone::ContractInfoAdd(host, tx.hash(), txType, tx.version(), expectedJTxInfo, contractPrehashCache);
                if(ret != 0)
                {
                    ERRORLOG("ContractInfoAdd fail! ret {}", ret);
                    return -3;
                }
                
                callOutTx.set_data(tx.data());
                ret = Evmone::GenCallOutTx(fromAddr, deployerAddr, txType, host.coin_transferrings, gasCost, callOutTx, contractTip, utxoHashs, false);
                if(ret < 0)
                {
                    ERRORLOG("GenCallOutTx fail !!! ret:{}", ret);
                    return -4;
                }
                ret = Evmone::VerifyUtxo(tx, callOutTx);
                if(ret < 0)
                {
                    ERRORLOG("VerifyUtxo fail !!! ret:{}", ret);
                    return -5;
                }

      
            }
            // else if(vmType == global::ca::VmType::WASM)
            // {

            //     ret = GetCallContractFromAddr(tx, false, fromAddr);
            //     if (ret != 0)
            //     {
            //         ERRORLOG("GetCallContractFromAddr fail ret : {}", ret);
            //         return -6;
            //     }   
            //     if(txType == global::ca::TxType::kTxTypeDeployContract)
            //     {
            //         std::string hexCode = Hex2Str(code);
            //         ret = Wasmtime::DeployWasmContract(fromAddr, hexCode, expectedOutput, gasCost);
            //         if(ret != 0)
            //         {
            //             ERRORLOG("WASM failed to deploy contract!");
            //             return ret - 300;
            //         }
            //     }
            //     else if(txType == global::ca::TxType::kTxTypeCallContract)
            //     {
            //         ret = Wasmtime::CallWasmContract(fromAddr, deployerAddr, deployHash, input, contractFunName, expectedOutput, gasCost);
            //         if(ret != 0)
            //         {
            //             ERRORLOG("WASM failed to call contract!");
            //             return ret - 400;
            //         }
            //     }
            //     callOutTx.set_data(tx.data());
            //     ret = Wasmtime::GenCallWasmOutTx(fromAddr, deployerAddr, txType, gasCost, callOutTx, contractTip, utxoHashs, false);
            //     if(ret < 0)
            //     {
            //         ERRORLOG("WASM GenCallOutTx fail !!! ret:{}", ret);
            //         return -7;
            //     }

            //     ret = Wasmtime::ContractInfoAdd(tx.hash(), expectedJTxInfo, txType, tx.version(), contractPrehashCache);
            //     if(ret != 0)
            //     {
            //         ERRORLOG("Wasmtime ContractInfoAdd fail! ret {}", ret);
            //         return -8;
            //     }
            // }

            if (output != expectedOutput)
            {
                return -9;
            }
            ret = VerifyContractStorage(storageFound.value(), expectedJTxInfo);
            // if (ret != 0)
            // {
            //     ERRORLOG("VerifyContractStorage fail TX HASH {}\nblock: {} \n expect: {}", tx.hash(), blockData.dump(4), expectedJTxInfo.dump(4));
            //     ERRORLOG("tx order:");
            //     ERRORLOG("this may caused by data inconsistent");
            //     for (const auto& tx : block.txs())
            //     {
            //         ERRORLOG("{}", tx.hash());
            //     }
            //     return -10;
            // }
            if (ret != 0)
            {
                ERRORLOG("VerifyContractStorage fail TX HASH {}\nblock: {} \n expect: {}", tx.hash(), blockData.dump(4), expectedJTxInfo.dump(4));
                ERRORLOG("VerifyContractStorage fail TX HASH {}\n", block.hash());

                ERRORLOG("tx order:");
                for (const auto& tx : block.txs())
                {
                    ERRORLOG("{}", tx.hash());
                }
                DBReader dbReader;
                std::map<std::string, std::vector<std::pair<std::string, std::string>>> contractTxPreHashMap;
                nlohmann::json dataJson = nlohmann::json::parse(block.data());
                for (const auto&[key, value] : dataJson.items())
                {
                    for(auto &it : value["PrevHash"].items())
                    {
                        contractTxPreHashMap[key].push_back({it.key(), it.value()});
                    }
                }

                for(auto& iter : contractTxPreHashMap)
                {
                    for(auto& preHashPair : iter.second)
                    {
                        if(contractTxPreHashMap.find(preHashPair.second) != contractTxPreHashMap.end())
                        {
                            continue;
                        }
                        std::string DBContractPreHash;
                        if (DBStatus::DB_SUCCESS != dbReader.GetLatestUtxoByContractAddr(preHashPair.first, DBContractPreHash))
                        {
                            ERRORLOG("??????");
                        }
                        ERRORLOG("txHash:{}, DBContractPreHash:{}, MEMContractAddr:{}, MEMContractPreHash:{}", iter.first, DBContractPreHash, preHashPair.first, preHashPair.second);
                    }
                }
                return -10;
            }

            MagicSingleton<ContractDataCache>::GetInstance()->set(expectedJTxInfo["Storage"]);
        }
        catch (...)
        {
            ERRORLOG("parse tx data fail");
            return -11;
        }
    }
    return 0;
}