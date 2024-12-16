/*
 * @Author: HaoXuDong 2848973813@qq.com
 * @Date: 2024-08-08 19:50:53
 * @LastEditors: HaoXuDong 2848973813@qq.com
 * @LastEditTime: 2024-09-04 09:20:43
 * @FilePath: /don/common/global.h
 * @Description: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#ifndef _GLOBAL_H
#define _GLOBAL_H
#include <string>
#include <atomic>
namespace global{

    enum class BuildType
    {
        kBuildType_Primary,
        kBuildType_Test,
        kBuildType_Dev
    };
    
    // data
    #ifdef PRIMARYCHAIN
        const BuildType kBuildType = BuildType::kBuildType_Primary;
    #elif TESTCHAIN
        const BuildType kBuildType = BuildType::kBuildType_Test;
    #else // DEVCHAIN
        static const BuildType kBuildType = BuildType::kBuildType_Dev;
    #endif

     
    /*
        @brief Version 
        @brief Network version number depends on the first version number
    */
    static const std::string kNetVersion = "2.4";
    static const std::string kLinuxCompatible = "2.4.0";
    static const std::string kWindowsCompatible = "2.4.0";
    static const std::string kIOSCompatible = "4.0.4";
    static const std::string kAndroidCompatible = "3.1.0";

    #if WINDOWS
        static const std::string kSystem = "2";
        static const std::string kCompatibleVersion = kWindowsCompatible;
    #else
        static const std::string kSystem = "1";
        static const std::string kCompatibleVersion = kLinuxCompatible;
    #endif 

    #ifdef PRIMARYCHAIN
        static const std::string kVersion = kSystem + "_" + kCompatibleVersion + "_p";
    #elif TESTCHAIN
        static const std::string kVersion = kSystem + "_" + kCompatibleVersion + "_t";
    #else // DEVCHAIN
        static const std::string kVersion = kSystem + "_" + kCompatibleVersion + "_d";
    #endif

    //thread pool 
    static const int kCaThreadNumber = 15;
    static const int kNetThreadNumber = 15;
    static const int kBroadcastThreadNumber = 10;
    static const int kTxThreadNumber = 50;
    static const int kSyncBlockThreadNumber = 25;
    static const int kSaveBlockThreadNumber = 50;

    static const int kBlockThreadNumber = 50;
    static const int kWorkThreadNumber = 50;
}

#endif // !_GLOBAL_H
