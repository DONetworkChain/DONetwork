#include "ContractUtils.h"
#include "utils/base58.h"
#include <evmc/hex.hpp>
#include <evmone/evmone.h>
#include "utils/base64.h"
#include <iostream>
std::string evm_utils::toChecksumAddress(const std::string& hash, const std::string& address)
{
    std::string ret;
	for (int i = 0; i < address.length(); i++)
	{
        std::string str;
        str = str + hash[i];
		if (stoi(str, 0, 16) >= 8)
		{
			ret += std::toupper(address[i]);
		}
		else
		{
			ret += address[i];
		}
	}
	return ret;
}

evmc_address evm_utils::stringToEvmAddr(const std::string& addr)
{
    const char *s = addr.data();
    evmc_address evmAddr = evmc::from_hex<evmc::address>(s).value_or(evmc_address{});
    return evmAddr;
}

std::string evm_utils::EvmAddrToString(const evmc_address& addr)
{
    return hex({addr.bytes,sizeof(addr.bytes)});
}

std::string evm_utils::EvmAddrToBase58(const evmc_address& addr)
{
    using bytes = std::basic_string<uint8_t>;
    bytes str2=bytes(addr.bytes, sizeof(addr.bytes));
    char buf[2048] = {0};
    size_t bufLen = sizeof(buf);
    auto convertResult = evmc::from_hex(evmc::hex(str2).data());
    if (!convertResult.has_value())
    {
        return "";
    }
    
    b58check_enc(buf, &bufLen, 0x00, convertResult.value().data(), RIPEMD160_DIGEST_LENGTH);
    std::string bs58Addr;
    bs58Addr.append(buf, bufLen - 1 );
    return bs58Addr;
}

evmc_address evm_utils::pubStrToEvmAddr(const std::string& pub)
{
    std::string evmAddress = generateEvmAddr(pub);
    const char *s = evmAddress.data();
    evmc_address evmaddr = evmc::from_hex<evmc::address>(s).value_or(evmc_address{});;
    return evmaddr;
}


std::string evm_utils::generateEvmAddr(const std::string& pub)
{
    std::string md160 = GetMd160(pub);
    //std::cout << "md160:" << md160 << std::endl;
    return md160;
}

std::string evm_utils::EvmAddrToBase58(const std::string& addr)
{
    evmc_address evm_addr = stringToEvmAddr(addr);
    return EvmAddrToBase58(evm_addr);
}

std::string evm_utils::getEvmAddr(const std::string& pub)
{
    std::string md160 = generateEvmAddr(pub);
    std::string EvmAddress = EvmAddrToChecksum(md160);
    // const uint8_t* data = reinterpret_cast<const uint8_t*> (md160.c_str());
    // std::string hash = keccak256(data, md160.length());
    // if(hash.length() < 64)
    // {
    //    hash = "0" + hash;
    // }
    // std::string EvmAddress = toChecksumAddress(hash, md160);
    return "0x" + EvmAddress;
}

std::string evm_utils::EvmAddrToChecksum(const std::string& addr)
{
    const uint8_t* data = reinterpret_cast<const uint8_t*> (addr.c_str());
    std::string hash = keccak256(data, addr.length());
    if(hash.length() < 64)
    {
       hash = "0" + hash;
    }
    return toChecksumAddress(hash, addr);
}

std::string evm_utils::GenerateContractAddr(const std::string& input)
{
    return EvmAddrToBase58(generateEvmAddr(input));
}