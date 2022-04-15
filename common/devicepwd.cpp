#include <iostream>
#include <fstream>
#include "./devicepwd.h"
#include "../net/ip_port.h"
#include "../include/logging.h"
#include "../net/peer_node.h"
#include "../ca/ca_global.h"


std::string DevicePwd::GetAbsopath()
{
    int i;
    char buf[1024];
    int len = readlink("/proc/self/exe", buf, 1024 - 1);

    if (len < 0 || (len >= 1024 - 1))
    {
        return "";
    }

    buf[len] = '\0';
    for (i = len; i >= 0; i--)
    {
        if (buf[i] == '/')
        {
            buf[i + 1] = '\0';
            break;
        }
    }
    return std::string(buf);
}

bool DevicePwd::NewDevPWDFile(std::string strFile)
{
    
    ofstream file( strFile.c_str(), fstream::out );
    if( file.fail() )
    {
        DEBUGLOG(" file_path = {}", strFile.c_str());
		return false;
    }
	
    std::string jsonstr;
    {
        jsonstr = "{\"DevicePassword\":\"fc4cba5c7611ed00b03939592671864c2d55983c5e6936c0c962be35370bc2d4\"}";
    }
    auto json = nlohmann::json::parse(jsonstr);
    file << json.dump(4);
    file.close();
    return true;
}


void DevicePwd::WriteDevPwdFile(const std::string &name )
{
    std::ofstream fconf;
    std::string fileName ;

    fileName = this->GetAbsopath() + name;
    
    fconf.open( fileName.c_str() );
    fconf << this->m_Json.dump(4);
    fconf.close();
}

bool DevicePwd::InitPWDFile(const std::string &name)
{
    std::ifstream fconf;
    std::string conf;
    std::string tmp = this->GetAbsopath();
    tmp += name;
    
    if (access(tmp.c_str(), F_OK))
    {
        if (false == NewDevPWDFile(tmp) )
        {
            ERRORLOG("Invalid file...  Please check if the configuration file exists!");
            return false;
        }
    }
    fconf.open(tmp.c_str());
    fconf >> this->m_Json;
    fconf.close();
    return true;
}

std::string DevicePwd::GetDevPassword()
{
    string devpwd;
    try
    {
        devpwd = this->m_Json["DevicePassword"].get<std::string>();
    }
    catch(const std::exception& e)
    {
        ERRORLOG("exception DevicePassword");
        devpwd = "";
    }
    return devpwd;    
}

bool DevicePwd::SetDevPassword(const std::string & password)
{
    if (password.size() == 0)
    {
        return false;
    }
    this->m_Json["DevicePassword"] = password;
    WriteDevPwdFile();
    return true;
}

bool DevicePwd::UpdateDevPwdConfig(const std::string &name)
{
    // nop
    return true;
}