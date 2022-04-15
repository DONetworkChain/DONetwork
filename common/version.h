#ifndef _VERSION_H_
#define _VERSION_H_
#include <string>

const std::string g_NetVersion = "2";


const std::string g_LinuxCompatible = "2.0.4";
const std::string g_WindowsCompatible = "1.0";
const std::string g_IOSCompatible = "4.0.4";
const std::string g_AndroidCompatible = "3.1.0";


typedef enum CAVERSION
{
    kUnknown = 0,
    kLINUX   = 1,        
    kWINDOWS = 2,        
    kIOS     = 3,        
    kANDROID = 4,        
} Version;

std::string getVersion();
std::string getDonVersion();
Version getSystem();


#endif // !_VERSION_H_
