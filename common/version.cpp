#include "version.h"
#include <sstream>
#include "global.h"

std::string getDonVersion()
{
    static std::string version = g_LinuxCompatible;
    return version;
}

std::string  getVersion()
{
    std::string versionNum = getDonVersion();
    std::ostringstream ss;
    ss << getSystem();
    std::string version = ss.str() + "_" + versionNum ; 
    if(k_testflag == 0)
    {
        version = version + "_" + "p";
    }
    else if (k_testflag == 1)
    {
        version = version + "_" + "t";
    }
    else 
    {
        version = version + "_" + "d";
    }
    
    return version;
}

Version getSystem()
{
#if WINDOWS
    return kWINDOWS;
#else
    return kLINUX;
#endif 
}
