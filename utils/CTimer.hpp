/*
 * @Author: your name
 * @Date: 2020-11-17 14:14:11
 * @LastEditTime: 2020-11-17 14:14:12
 * @LastEditors: your name
 * @Description: In User Settings Edit
 * @FilePath: \ebpc\utils\CTimer.hpp
 */
//
//  CTimer.hpp
//
//  Created by lzj<lizhijian_21@163.com> on 2018/7/20.
//  Copyright © 2018 ZJ. All rights reserved.
//

#ifndef CTimer_hpp
#define CTimer_hpp

#include <stdio.h>
#include <functional>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <string>
#include <condition_variable>

class CTimer
{
public:
    CTimer(const std::string sTimerName = "");   //
    ~CTimer();
    
    /**
     

     @param msTime (ms)
     @param task 
     @param bLoop (1)
     @param async ()
     @return true:
     */
    bool Start(unsigned int msTime, std::function<void()> task, bool bLoop = false, bool async = true);
    
    /**
     ()
     */
    void Cancel();
    
    /**
     
     #

     @param msTime (ms)
     @param fun lambda
     @param args 
     @return true:
     */
    template<typename callable, typename... arguments>
    bool SyncOnce(int msTime, callable&& fun, arguments&&... args) {
        std::function<typename std::result_of<callable(arguments...)>::type()> task(std::bind(std::forward<callable>(fun), std::forward<arguments>(args)...)); //lambdafunction
        return Start(msTime, task, false, false);
    }
    
    /**
     
     
     @param msTime 
     @param fun lambda
     @param args 
     @return true:
     */
    template<typename callable, typename... arguments>
    bool AsyncOnce(int msTime, callable&& fun, arguments&&... args) {
        std::function<typename std::result_of<callable(arguments...)>::type()> task(std::bind(std::forward<callable>(fun), std::forward<arguments>(args)...));
        
        return Start(msTime, task, false);
    }
    
    /**
     (1)
     
     @param fun lambda
     @param args 
     @return true:
     */
    template<typename callable, typename... arguments>
    bool AsyncOnce(callable&& fun, arguments&&... args) {
        std::function<typename std::result_of<callable(arguments...)>::type()> task(std::bind(std::forward<callable>(fun), std::forward<arguments>(args)...));
        
        return Start(1, task, false);
    }
    
    
    /**
     

     @param msTime 
     @param fun lambda
     @param args 
     @return true:
     */
    template<typename callable, typename... arguments>
    bool AsyncLoop(int msTime, callable&& fun, arguments&&... args) {
        std::function<typename std::result_of<callable(arguments...)>::type()> task(std::bind(std::forward<callable>(fun), std::forward<arguments>(args)...));
        
        return Start(msTime, task, true);
    }
    
    
private:
    void DeleteThread();    //

public:
    int m_nCount = 0;   //
    
private:
    std::string m_sName;   //
    
    std::atomic_bool m_bExpired;       //
    std::atomic_bool m_bTryExpired;    //()
    std::atomic_bool m_bLoop;          //
    
    std::thread *m_Thread = nullptr;
    std::mutex m_ThreadLock;
    std::condition_variable_any m_ThreadCon;
};

#endif /* CTimer_hpp */

