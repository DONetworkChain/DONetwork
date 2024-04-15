#include "tmp_log.h"

void write_tmplog(const std::string& content, OUTTYPE out, const std::string& log_name)
{
    if (out == file)
    {
        std::string fileName = log_name;
        std::ofstream file(fileName, std::ios::app);
        if (!file.is_open() )
        {
            ERRORLOG("Open file failed!");
            return;
        }
        file << content << std::endl;
        file.close();
    }
    else if (out == screen)
    {
        std::cout << content << std::endl;
    }

}

// void cast_log(const std::string& content,const std::string & log){
   
//     std::ofstream file(log, std::ios::app);
//     if (!file.is_open() )
//     {
//             ERRORLOG("Open file failed!");
//             return;
//     }
//     file << content << std::endl;
//     file.close();
// }
