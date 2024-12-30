#include "../utils/keccak_cryopp.hpp"
#include <cryptopp/keccak.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <stdio.h>
#include <sstream>
#include <iomanip>
std::string Keccak256Crypt(const std::string& input) 
{
    using namespace CryptoPP;
    std::string digest;
    Keccak_256 hash;
    StringSource ss(input, true, 
        new HashFilter(hash,
            new HexEncoder(
                new StringSink(digest)
            )
        )
    );

    return digest;
}

