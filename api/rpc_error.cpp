#include "rpc_error.h"
#include "utils/tmp_log.h"
#include "../include/logging.h"

static thread_local std::pair<std::string, std::string> error={"0",""};
static thread_local bool isGet=true;

void SetRpcError(const std::string & errorCode,const std::string & errorMessage)
{
    if(isGet==false)
    {
        ERRORLOG(" {} , {}", error.first, error.second);
    }
    isGet=false;
    error={errorCode,errorMessage};
}

std::pair<std::string,std::string> GetRpcError()
{
    isGet=true;
    return error;
}

void RpcErrorClear()
{
    error={"0",""};
}