#include <sys/time.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include "./util.h"
#include "common/version.h"
#include "common/global.h"
#include "logging.h"
#include "db/db_api.h"
double Util::Aror[25][100]={0};
bool Util::ArorFlag=true;
uint32_t Util::adler32(const unsigned char *data, size_t len) 
{
    const uint32_t MOD_ADLER = 65521;
    uint32_t a = 1, b = 0;
    size_t index;
    
    // Process each byte of the data in order
    for (index = 0; index < len; ++index)
    {
        a = (a + data[index]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    return (b << 16) | a;
}

int Util::IsLinuxVersionCompatible(const std::vector<std::string> & vRecvVersion)
{
	if (vRecvVersion.size() != 3)
	{
		ERRORLOG("(linux) version error-1");
		return -1;
	}

	if (g_testflag == 0)
	{
		if (vRecvVersion[2] != "p")
		{
			ERRORLOG("(linux) version error-2");
			return -2;
		}
	}
	else if (g_testflag == 1)
	{
		if (vRecvVersion[2] != "t")
		{
			ERRORLOG("(linux) version error-3");
			return -3;
		}
	}
	else
	{
		if (vRecvVersion[2] != "d")
		{
			ERRORLOG("(linux) version error-4");
			return -4;
		}
	}

	std::string ownerVersion = getVersion();
	std::vector<std::string> vOwnerVersion;
	StringUtil::SplitString(ownerVersion, vOwnerVersion, "_");

	if (vOwnerVersion.size() != 3)
	{
		ERRORLOG("(linux) version error-5");
		return -5;
	}

	std::vector<std::string> vOwnerVersionNum;
	StringUtil::SplitString(vOwnerVersion[1], vOwnerVersionNum, ".");
	if (vOwnerVersionNum.size() == 0)
	{
		ERRORLOG("(linux) version error-6");
		return -6;
	}

	std::vector<std::string> vRecvVersionNum;
	StringUtil::SplitString(vRecvVersion[1], vRecvVersionNum, ".");
	if (vRecvVersionNum.size() != vOwnerVersionNum.size() || vRecvVersionNum.size() != 3)
	{
		ERRORLOG("(linux) version error-7");
		return -7;
	}

	if (vRecvVersionNum[0] != vOwnerVersionNum[0])
	{
		ERRORLOG("(linux) version error-8");
		return -8;
	}

	if (vRecvVersionNum[1] != vOwnerVersionNum[1])
	{
		ERRORLOG("(linux) version error-9");
		return -9;
	}

	return 0;
}

int Util::IsOtherVersionCompatible(const std::string & vRecvVersion, bool bIsAndroid)
{
	if (vRecvVersion.size() == 0)
	{
		ERRORLOG("(other)  version error: -1");
		return -1;
	}

	std::vector<std::string> vRecvVersionNum;
	StringUtil::SplitString(vRecvVersion, vRecvVersionNum, ".");
	if (vRecvVersionNum.size() != 3)
	{
		ERRORLOG("(other)  version error: -2");
		return -2;
	}

	std::string ownerVersion;
	if (bIsAndroid)
	{
		ownerVersion = g_AndroidCompatible;
	}
	else
	{
		ownerVersion = g_IOSCompatible;
	}
	
	std::vector<std::string> vOwnerVersionNum;
	StringUtil::SplitString(ownerVersion, vOwnerVersionNum, ".");

	for (size_t i = 0; i < vOwnerVersionNum.size(); ++i)
	{
		if (vRecvVersionNum[i] < vOwnerVersionNum[i])
		{
			ERRORLOG("(other)  version error: -3");
			ERRORLOG("(other) receive version: {}", vRecvVersion); // receive version
			ERRORLOG("(other) local version: {}", ownerVersion); // local version
			return -3;
		}
		else if (vRecvVersionNum[i] > vOwnerVersionNum[i])
		{
			return 0;
		}
	}

	return 0;
}

int Util::IsVersionCompatible( std::string recvVersion )
{
	if (recvVersion.size() == 0)
	{
		ERRORLOG(" version error-1");
		return -1;
	}

	std::vector<std::string> vRecvVersion;
	StringUtil::SplitString(recvVersion, vRecvVersion, "_");
	if (vRecvVersion.size() < 1 || vRecvVersion.size() > 3 )
	{
		ERRORLOG(" version error-2");
		return -2;
	}

	if (vRecvVersion.size() == 1)
	{
		if (vRecvVersion[0] == g_NetVersion)
		{
			return 0;
		}
		else
		{
			ERRORLOG(" version error-3");
			return -3;
		}
	}

	int versionPrefix = std::stoi(vRecvVersion[0]);
	if (versionPrefix > 4 || versionPrefix < 1)
	{
		ERRORLOG(" version error-3");
		return -4;
	}
	
	switch(versionPrefix)
	{
		case 1:
		{
			if ( 0 != IsLinuxVersionCompatible(vRecvVersion) )
			{
				return -5;
			}
			break;
		}
		case 2:
		{
			return -6;
		}
		case 3:
		{
			if ( 0 != IsOtherVersionCompatible(vRecvVersion[1], false) )
			{
				return -7;
			}
			break;
		}
		case 4:
		{
			if ( 0 != IsOtherVersionCompatible(vRecvVersion[1], true) )
			{
				return -8;
			}
			break;
		}
		default:
		{
			return -9;
		}
	}
	return 0;
}

int Util::CalcAnnualizedReturn()
{
	for(int i=1;i<=30;i++)
	{
		Aror[1][i]=0.12;
	}
	for(int i=1;i<=20;i++)
	{
		for(int j=1;j<=90;j++)
		{
			if(i==1&&j<=30) continue;
			else if(i==1)
			{
				Aror[i][j]=Aror[i][j-1]-0.12*0.00825;
			}
			else
			{
				if(Aror[i-1][j]-0.12*0.05>=0.018)
				{
					Aror[i][j]=Aror[i-1][j]-0.12*0.05;
				}
				else 
				{
					Aror[i][j]=0.018;
				}
				
			}
		}
	}
	return 0;
}
int Util::CalcPledgeRate(double &AnnualizedReturn)
{
	DBReadWriter db_writer;
	uint64_t TotalPledge;
	uint64_t TotalCirculation;
	if (DBStatus::DB_SUCCESS != db_writer.GetTotalPledge(TotalPledge,23))
    {
		ERRORLOG("Failed to obtain the total pledge amount");
		return -1;
	}
	if (DBStatus::DB_SUCCESS != db_writer.GetTotalCirculation(TotalCirculation,23))
    {
		ERRORLOG("Failed to obtain the total Circulation amount");
		return -2;
	}
	uint64_t PledgeRate=((double)TotalPledge/TotalCirculation+0.005)*100;
	std::cout<<TotalPledge<<" "<<TotalCirculation<<" "<<PledgeRate<<std::endl;
	Util::GetAnnualizedReturn(PledgeRate,AnnualizedReturn);
	return 0;
}

int Util::GetAnnualizedReturn(uint64_t PledgeRate,double &AnnualizedReturn)
{
	if(Util::ArorFlag)
	{
		Util::CalcAnnualizedReturn();
		Util::ArorFlag=false;
	}
	time_t now = time(nullptr);  
	tm* curr_tm = gmtime(&now); 
	unsigned int CurrentYear=curr_tm->tm_year+1900;
	AnnualizedReturn=Util::Aror[CurrentYear-2021][PledgeRate];
	std::cout<<Util::Aror[CurrentYear-2021][PledgeRate]<<std::endl;
	return 0;
}
