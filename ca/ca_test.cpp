#include <iostream>
#include <time.h>
#include <fstream>
#include <string>
#include "ca_test.h"
#include "utils/console.h"
#include "utils/hexcode.h"
#include "../include/logging.h"
#include "utils/base58.h"
#include "ca/ca_global.h"
#include "utils/json.hpp"
#include "utils/time_util.h"
#include "utils/MagicSingleton.h"
#include "db/db_api.h"
#include "utils/AccountManager.h"


int PrintFormatTime(uint64_t time, bool isConsoleOutput, std::ostream & stream)
{
    time_t s = (time_t)(time / 1000000);
    struct tm * gm_date;
    gm_date = localtime(&s);

	ca_console tmColor(kConsoleColor_White, kConsoleColor_Black, true);
    if(isConsoleOutput)
	{
        stream << tmColor.color() << gm_date->tm_year + 1900 << "-" << gm_date->tm_mon + 1 << "-" << gm_date->tm_mday << " "  << gm_date->tm_hour << ":" << gm_date->tm_min << ":" << gm_date->tm_sec << "(" << time << ")" << tmColor.reset() << std::endl;
	}
	else
	{
        stream << gm_date->tm_year + 1900 << "-" << gm_date->tm_mon + 1 << "-" << gm_date->tm_mday << " "  << gm_date->tm_hour << ":" << gm_date->tm_min << ":" << gm_date->tm_sec << "(" << time << ")" << std::endl;
    }

    return 0;
}

int printRocksdb(uint64_t start, uint64_t end, bool isConsoleOutput, std::ostream & stream)
{
    if(start > end)
    {
        ERRORLOG("start > end");
        return -1;
    }

    //CBlockDataApi data_reader;
	DBReader db_reader;
    ca_console bkColor(kConsoleColor_Blue, kConsoleColor_Black, true);
    uint64_t count = 0 ;
    uint64_t height = end;
    for (; height >= start; --height) 
    {
	    std::vector<std::string> vBlockHashs;
	    db_reader.GetBlockHashsByBlockHeight(height, vBlockHashs);
        std::vector<CBlock> blocks;
        for (auto hash : vBlockHashs)
        {
            std::string strHeader;
            db_reader.GetBlockByBlockHash(hash, strHeader);
            CBlock block;
            block.ParseFromString(strHeader);
            blocks.push_back(block);
        }
        std::sort(blocks.begin(), blocks.end(), [](CBlock & a, CBlock & b){
            return a.time() < b.time();
        });

        count ++;
        std::cout << "rate of progress------>" << count << "/" << end << std::endl;
        for (auto & block : blocks)
        {

            printBlock(block, isConsoleOutput, stream);
        }
        if(height == start)break;
    }
    
    return 0;
}

int printBlock(const CBlock & block, bool isConsoleOutput, std::ostream & stream)
{
    ca_console bkColor(kConsoleColor_Blue, kConsoleColor_Black, true);
    ca_console greenColor(kConsoleColor_Green, kConsoleColor_Black, true);
    stream << std::endl << "BlockInfo ---------------------- > height [" << block.height() << "]" << std::endl;
    stream << "HashMerkleRoot -> " << block.merkleroot() << std::endl;
    stream << "HashPrevBlock -> " << block.prevhash() << std::endl;
    if (isConsoleOutput)
    {
        stream << "BlockHash -> " << bkColor.color() << block.hash() << bkColor.reset() << std::endl;
    }
    else
    {
        stream << "BlockHash -> " << block.hash() << std::endl;
    }

    stream << "blockverifySign[" << block.sign_size() << "]" << std::endl;
    for (auto & verifySign : block.sign())
    {
        stream << "block Verify Sign " << Str2Hex(verifySign.sign()) << " : " << Str2Hex(verifySign.pub()) << "[" << greenColor.color() << GetBase58Addr(verifySign.pub()) << greenColor.reset() << "]" << std::endl;
    }
    
    for (auto & verifySign : block.sign())
    {
        stream << "block signer -> [" << greenColor.color() << GetBase58Addr(verifySign.pub()) << greenColor.reset() << "]" << std::endl;
    }
    
    stream << "Time-> ";
    PrintFormatTime(block.time(), isConsoleOutput, stream);
    
    for (int i = 0; i < block.txs_size(); i++) 
    {
        CTransaction tx = block.txs(i);
        stream << "TX_INFO -----------> index[" << i << "]" << std::endl;
        printTx(tx, isConsoleOutput, stream);
    }

    stream << "Block data ------->"<<  block.data() << std::endl;
    return 0;
}

std::string printBlocks(int num, bool pre_hash_flag)
{
    DBReader db_read;
    uint64_t top = 0;
    db_read.GetBlockTop(top);
    std::string str = "top:\n";
    str += "--------------\n";
    int j = 0;
    for(int i = top; i >= 0; i--){
        str += (std::to_string(i) + "\t");
        std::vector<std::string> vBlockHashs;
        db_read.GetBlockHashsByBlockHeight(i, vBlockHashs);
        std::sort(vBlockHashs.begin(), vBlockHashs.end());
        for (auto hash : vBlockHashs) {
            std::string strHeader;
            db_read.GetBlockByBlockHash(hash, strHeader);
            CBlock header;
            header.ParseFromString(strHeader);
            auto tempTransactions = header.txs();
            if(pre_hash_flag)
            {
                if((global::ca::TxType)tempTransactions[0].txtype()==global::ca::TxType::kTxTypeCallContract || (global::ca::TxType)tempTransactions[0].txtype()==global::ca::TxType::kTxTypeDeployContract)
                {
                    str = str + hash.substr(0,6) + "(" + header.prevhash().substr(0,6) + ")" + " ";
                }
                else
                {
                    str = str + hash.substr(0,6) +"(c)"+ "(" + header.prevhash().substr(0,6) + ")" + " ";
                }
            }
            else
            {
                 if((global::ca::TxType)tempTransactions[0].txtype()==global::ca::TxType::kTxTypeCallContract || (global::ca::TxType)tempTransactions[0].txtype()==global::ca::TxType::kTxTypeDeployContract)
                {
                    str = str + hash.substr(0,6) +"(c)"+ " " ;
                }
                else
                {
                    str = str + hash.substr(0,6) + " ";
                }
            }
        }
        str += "\n";
        j++;
        if(num > 0 && j >= num)
        {
            break;
        }
    }
    str += "--------------\n";
    return str;
}

std::string printBlocksHash(int num, bool pre_hash_flag)
{
    DBReader db_read;
    uint64_t top = 0;
    db_read.GetBlockTop(top);
    std::string str = "top:\n";
    str += "--------------\n";
    int j = 0;
    for(int i = top; i >= 0; i--){
        str += (std::to_string(i) + "\n");
        std::vector<std::string> vBlockHashs;
        db_read.GetBlockHashsByBlockHeight(i, vBlockHashs);
        std::sort(vBlockHashs.begin(), vBlockHashs.end());
        for (auto hash : vBlockHashs) {
            std::string strHeader;
            db_read.GetBlockByBlockHash(hash, strHeader);
            CBlock header;
            header.ParseFromString(strHeader);
            if(pre_hash_flag)
            {
                str = str + hash + "(" + header.prevhash().substr(0,6) + ")" + " \n";
            }else{
                str = str + hash + " \n";
            }
        }
        str += "\n";
        j++;
        if(num > 0 && j >= num)
        {
            break;
        }
    }
    str += "--------------\n";
    return str;
}

std::string printRangeBlocks(int startNum,int num, bool pre_hash_flag)
{
    DBReader db_read;
    uint64_t top = 0;
    db_read.GetBlockTop(top);
    std::string str = "top:\n";
    str += "--------------\n";

    if(startNum > top || startNum < 0)
    {
        std::string strTop = std::to_string(top);
        str += "height error,Current height ";
        str += strTop;
        return str;
    }
    if(num > startNum)
    {
        num = startNum;
    }

    int j = 0;
    for(int i = startNum; i >= 0; i--){
        str += (std::to_string(i) + "\t");
        std::vector<std::string> vBlockHashs;
        db_read.GetBlockHashsByBlockHeight(i, vBlockHashs);
        std::sort(vBlockHashs.begin(), vBlockHashs.end());
        for (auto hash : vBlockHashs) {
            std::string strHeader;
            db_read.GetBlockByBlockHash(hash, strHeader);
            CBlock header;
            header.ParseFromString(strHeader);
            auto tempTransactions = header.txs();
            if(pre_hash_flag)
            {
                if((global::ca::TxType)tempTransactions[0].txtype()==global::ca::TxType::kTxTypeCallContract || (global::ca::TxType)tempTransactions[0].txtype()==global::ca::TxType::kTxTypeDeployContract)
                {
                    str = str + hash.substr(0,6) +"(c)"+ "(" + header.prevhash().substr(0,6) + ")" + " ";
                }
                else
                {
                    str = str + hash.substr(0,6)  +"(" + header.prevhash().substr(0,6) + ")" + " ";
                }
            }
            else
            {
                 if((global::ca::TxType)tempTransactions[0].txtype()==global::ca::TxType::kTxTypeCallContract || (global::ca::TxType)tempTransactions[0].txtype()==global::ca::TxType::kTxTypeDeployContract)
                {
                    str = str + hash.substr(0,6) +"(c)"+ " " ;
                }
                else
                {
                    str = str + hash.substr(0,6) + " ";
                }
            }
        }
        str += "\n";
        j++;
        if(num > 0 && j >= num)
        {
            break;
        }
    }

    str += "--------------\n";
    return str;
}

int printTx(const CTransaction & tx, bool isConsoleOutput, std::ostream & stream)
{
    if (isConsoleOutput)
    {
        ca_console txColor(kConsoleColor_Red, kConsoleColor_Black, true);
        ca_console greenColor(kConsoleColor_Green, kConsoleColor_Black, true);
        stream << "TxHash -> " << txColor.color() << tx.hash() << txColor.reset() << std::endl;
        stream << "n -> " << tx.n() << std::endl;
        stream << "identity -> " << "[" << greenColor.color() << tx.identity() << greenColor.reset() << "] " << std::endl;
        stream << "type -> " << tx.type() << std::endl;

        stream << "verifySign[" << tx.verifysign_size() << "]" << std::endl;

        for (auto & verifySign : tx.verifysign())
        {
            stream << "Verify Sign " << Str2Hex(verifySign.sign()) << " : " << Str2Hex(verifySign.pub()) << "[" << greenColor.color() << GetBase58Addr(verifySign.pub()) << greenColor.reset() << "]" << std::endl;
        }
        
        for (auto & verifySign : tx.verifysign())
        {
            stream << "Transaction signer -> [" << greenColor.color() << GetBase58Addr(verifySign.pub()) << greenColor.reset() << "]" << std::endl;
        }

        stream << "Owner -> ";
        for (auto & addr : tx.utxo().owner())
        {
            stream << "[" << greenColor.color() << addr << greenColor.reset() << "]";
        }
        stream << std::endl;

        for (int j = 0; j < tx.utxo().vin_size(); j++)
        {
            const CTxInput & vin = tx.utxo().vin(j);
            stream << "vin[" << j << "] sequence -> " << vin.sequence() << std::endl;
            stream << "vin[" << j << "] sign -> " << Str2Hex(vin.vinsign().sign()) << " : " << Str2Hex(vin.vinsign().pub()) << "[" << greenColor.color() << GetBase58Addr(vin.vinsign().pub()) << greenColor.reset() << "]" << std::endl;

            for (auto & prevout : vin.prevout())
            {
                stream << "vin[" << j << "] Prev Output Hash -> " << prevout.n() << " : " << prevout.hash() << std::endl;
            }
        }

        for (int j = 0; j < tx.utxo().vout_size(); j++)
        {
            const CTxOutput & vout = tx.utxo().vout(j);
            ca_console amount(kConsoleColor_Yellow, kConsoleColor_Black, true);
            stream << "vout[" << j << "] public key -> [" << greenColor.color() <<  vout.addr() << greenColor.reset() << "]" << std::endl;
            stream << "vout[" << j << "] value -> [" << amount.color() <<  vout.value() << amount.reset() << "]" << std::endl;
        }

        for (int j = 0; j < tx.utxo().multisign_size(); j++)
        {
            const CSign & multiSign = tx.utxo().multisign(j);
            stream << "multiSign[" << j << "] -> " << Str2Hex(multiSign.sign()) << " : " << Str2Hex(multiSign.pub()) << "[" << greenColor.color() << GetBase58Addr(multiSign.pub()) << greenColor.reset() << "]" << std::endl;
        }
    }
    else
    {
        stream << "TxHash -> " << tx.hash() << std::endl;
        stream << "n -> " << tx.n() << std::endl;
        stream << "identity -> " << tx.identity() << std::endl;
        stream << "type -> " << tx.type() << std::endl;

        stream << "verifySign[" << tx.verifysign_size() << "]" << std::endl;

        for (auto & verifySign : tx.verifysign())
        {
            stream << "Verify Sign " << Str2Hex(verifySign.sign()) << " : " << Str2Hex(verifySign.pub()) << "[" << GetBase58Addr(verifySign.pub()) << "]" << std::endl;
        }
        
        for (auto & verifySign : tx.verifysign())
        {
            stream << "Transaction signer -> [" << GetBase58Addr(verifySign.pub()) << "]" << std::endl;
        }

        stream << "Owner -> ";
        for (auto & addr : tx.utxo().owner())
        {
            stream << "[" << addr << "]";
        }
        stream << std::endl;

        for (int j = 0; j < tx.utxo().vin_size(); j++)
        {
            const CTxInput & vin = tx.utxo().vin(j);
            stream << "vin[" << j << "] sequence -> " << vin.sequence() << std::endl;
            stream << "vin[" << j << "] sign -> " << Str2Hex(vin.vinsign().sign()) << " : " << Str2Hex(vin.vinsign().pub()) << "[" << GetBase58Addr(vin.vinsign().pub()) << "]" << std::endl;

            for (auto & prevout : vin.prevout())
            {
                stream << "vin[" << j << "] Prev Output Hash -> " << prevout.n() << " : " << prevout.hash() << std::endl;
            }
        }

        for (int j = 0; j < tx.utxo().vout_size(); j++)
        {
            const CTxOutput & vout = tx.utxo().vout(j);
            stream << "vout[" << j << "] public key -> [" << vout.addr() << "]" << std::endl;
            stream << "vout[" << j << "] value -> [" << vout.value() << "]" << std::endl;
        }

        for (int j = 0; j < tx.utxo().multisign_size(); j++)
        {
            const CSign & multiSign = tx.utxo().multisign(j);
            stream << "multiSign[" << j << "] -> " << Str2Hex(multiSign.sign()) << " : " << Str2Hex(multiSign.pub()) << GetBase58Addr(multiSign.pub()) << std::endl;
        }
    }

    stream << "Time -> " << MagicSingleton<TimeUtil>::GetInstance()->formatUTCTimestamp(tx.time()) << std::endl;
    stream << "(" << tx.time() <<")" << std::endl;

    std::vector<std::pair<std::string, std::string>> dataMap;
    std::string strData;
    if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
    {
        try
        {
            nlohmann::json data_json = nlohmann::json::parse(tx.data());
            global::ca::TxType txType = (global::ca::TxType)tx.txtype();
            dataMap.push_back(std::make_pair("TxType", std::to_string((int32_t)txType)));
            dataMap.push_back(std::make_pair("Consensus", std::to_string(tx.consensus())));
            if (txType == global::ca::TxType::kTxTypeTx)
            {
                // nothing to do
            }
            else if (txType == global::ca::TxType::kTxTypeStake)
            {
                dataMap.push_back(std::make_pair("StakeType", data_json["TxInfo"]["StakeType"].get<std::string>()));
                dataMap.push_back(std::make_pair("StakeAmount", std::to_string(data_json["TxInfo"]["StakeAmount"].get<uint64_t>())));
            }
            else if (txType == global::ca::TxType::kTxTypeUnstake)
            {
                dataMap.push_back(std::make_pair("UnstakeUtxo", data_json["TxInfo"]["UnstakeUtxo"].get<std::string>()));
            }
            
            for (auto & item : dataMap)
            {
                strData += "  " + item.first + " : " + item.second + "\n";
            }
        }
        catch (...)
        {
        }
    }

    stream << "data -> " << std::endl;
    stream << strData;
    stream << "version -> " << tx.version() << std::endl;

    stream << "----------------------------" << std::endl;
    stream << tx.data() << std::endl;
    return 0;
}

void BlockInvert(const std::string & strHeader, nlohmann::json &blocks)
{
    CBlock block;
    if(!block.ParseFromString(strHeader))
    {
        ERRORLOG("block_raw parse fail!");
        return ;
        
    }

    nlohmann::json allTx;
    nlohmann::json jsonBlock;
    jsonBlock["merkleroot"] = block.merkleroot();
    jsonBlock["prevhash"] = block.prevhash();
    jsonBlock["hash"] = block.hash();
    jsonBlock["height"] = block.height();
    jsonBlock["time"] = block.time();
    jsonBlock["bytes"] = block.ByteSizeLong();
    // try{
    // nlohmann::json blockdataJson = nlohmann::json::parse(block.data());
    // jsonBlock["data"] = blockdataJson;
    // }catch(const nlohmann::json::parse_error& e)
    // {
    //     jsonBlock["data"] = nullptr;
    //     ERRORLOG("BlockInvert block data is empty error is:",e.what());
    // }
    if(!block.data().empty())
    {
    nlohmann::json blockdataJson = nlohmann::json::parse(block.data());
    jsonBlock["data"] = blockdataJson;
    }
    else{
        jsonBlock["data"] = "";
    }
    for(auto & blocksign : block.sign())
    {
        nlohmann::json block_verifySign;
        block_verifySign["sign"] = Base64Encode(blocksign.sign());
        block_verifySign["pub"] = Base64Encode(blocksign.pub());
        std::string sign_addr = GetBase58Addr(blocksign.pub(), Base58Ver::kBase58Ver_Normal);
        block_verifySign["signaddr"] = sign_addr;

        jsonBlock["blocksign"].push_back(block_verifySign);
    }


    int k = 0;
    for(auto & tx : block.txs())
    {
        nlohmann::json Tx;
        if(tx.type() == global::ca::kTxSign)
        {   
            Tx["time"] = tx.time();
            Tx["txHash"] = tx.hash();
            Tx["identity"] = tx.identity();

            for(auto & owner: tx.utxo().owner())
            {
                Tx["utxo"]["owner"].push_back(owner);
            }

            for(auto & vin : tx.utxo().vin())
            {
                for(auto &prevout : vin.prevout())
                {
                    Tx["utxo"]["vin"]["prevout"]["hash"].push_back(prevout.hash());
                }

                nlohmann::json utxoVinsign;
                utxoVinsign["sign"] = Base64Encode(vin.vinsign().sign());
                utxoVinsign["pub"] = Base64Encode(vin.vinsign().pub());

                Tx["utxo"]["vin"]["vinsign"].push_back(utxoVinsign);
            }

            for(auto & vout : tx.utxo().vout())
            {
                nlohmann::json utxoVout;
                utxoVout["addr"] = vout.addr();
                utxoVout["value"] = vout.value();

                Tx["utxo"]["vout"].push_back(utxoVout); 
            }

            for(auto & multiSign : tx.utxo().multisign())
            {
                nlohmann::json utxoMultisign;
                utxoMultisign["sign"] = Base64Encode(multiSign.sign());
                utxoMultisign["pub"] = Base64Encode(multiSign.sign());

                Tx["utxo"]["multisign"].push_back(utxoMultisign);
            }

            Tx["Type"] = tx.type();
            Tx["Consensus"] = tx.consensus();
            Tx["Gas"] = 0;
            Tx["Cost"] = 0;
            Tx["txType"] = tx.txtype();

            if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
            {
                nlohmann::json dataJson = nlohmann::json::parse(tx.data());
                Tx["data"] = dataJson;
            }

            for(auto & verifySign : tx.verifysign())
            {
                nlohmann::json utxoVerifySign;
                utxoVerifySign["sign"] = Base64Encode(verifySign.sign());
                utxoVerifySign["pub"] = Base64Encode(verifySign.pub());
                std::string signAddr = GetBase58Addr(verifySign.pub(), Base58Ver::kBase58Ver_Normal);
                utxoVerifySign["signaddr"] = signAddr;

                Tx["verifySign"].push_back(utxoVerifySign);
            }
            
            allTx[k++] = Tx;
        }
        else if(tx.type() == global::ca::kGenesisSign)
        {
            Tx["time"] = tx.time();
            Tx["txHash"] = tx.hash();
            Tx["identity"] = tx.identity();

            for(auto & owner: tx.utxo().owner())
            {
                Tx["utxo"]["owner"].push_back(owner);
            }

            for(auto & vin : tx.utxo().vin())
            {
                for(auto &prevout : vin.prevout())
                {
                    Tx["utxo"]["vin"]["prevout"]["hash"].push_back(prevout.hash());
                }

                nlohmann::json utxoVinsign;
                utxoVinsign["sign"] = Base64Encode(vin.vinsign().sign());
                utxoVinsign["pub"] = Base64Encode(vin.vinsign().pub());

                Tx["utxo"]["vin"]["vinsign"].push_back(utxoVinsign);
            }

            for(auto & vout : tx.utxo().vout())
            {
                nlohmann::json utxoVout;
                utxoVout["addr"] = vout.addr();
                utxoVout["value"] = vout.value();

                Tx["utxo"]["vout"].push_back(utxoVout); 
            }
            Tx["Type"] = tx.type();
            allTx[k++] = Tx;
        }
    }

    blocks["block"] = jsonBlock;
    blocks["tx"] = allTx;

}
    


