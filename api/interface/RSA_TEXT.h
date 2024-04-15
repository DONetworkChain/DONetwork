#ifndef _RSA_TEXT_H_
#define _RSA_TEXT_H_
#include "utils/Envelop.h"
#include "tx.h"
#include "base64.h"
/// <summary>
/// 
/// </summary>
/// <param name="data">����</param>
/// <param name="enve">���ܹ��ߣ��Լ��Ĺ�Կ˽Կ��</param>
/// <param name="rsa_pubstr">�Է��Ĺ�Կ</param>
/// <param name="message">����</param>
/// <returns></returns>
bool RSAEnCode(const std::string& data, envelop* enve, const std::string& rsa_pubstr, std::string& message);

/// <summary>
/// 
/// </summary>
/// <param name="data">����</param>
/// <param name="enve">���ܹ��ߣ��Լ��Ĺ�Կ˽Կ��</param>
/// <param name="message">����</param>
/// <returns></returns>
bool RSADeCode(const std::string& data, envelop* enve, std::string& message);
#endif