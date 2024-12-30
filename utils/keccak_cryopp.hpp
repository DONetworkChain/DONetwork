
#ifndef __KECCAK256CRY_H__
#define __KECCAK256CRY_H__
#include <cryptopp/keccak.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <stdio.h>
#include <sstream>
#include <iomanip>
std::string Keccak256Crypt(const std::string& input);
#endif