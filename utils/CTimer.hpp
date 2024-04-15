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
    CTimer(const std::string sTimerName = "");   //Constructs the timer, with a name
    ~CTimer();
    
    /**
     Start running the timer

     @param msTime  Delayed operation (in ms)
     @param taskTask function interface
     @param bLoop Whether to loop (1 time by default)
     @param async Async (default async)
     */
    bool Start(unsigned int msTime, std::function<void()> task, bool bLoop = false, bool async = true);
    
    /**
     Cancel the timer, the synchronization timer cannot be canceled (cancellation is invalid if the task code has been executed)
     */
    void Cancel();
    
    /**
     @param msTimeDelay time (ms)
     @param fun Function interface or lambda code block
     @param argsparameter
     @return Ready for execution, otherwise it fails
     */
    template<typename callable, typename... arguments>
    bool SyncOnce(int msTime, callable&& fun, arguments&&... args) {
        std::function<typename std::result_of<callable(arguments...)>::type()> task(std::bind(std::forward<callable>(fun), std::forward<arguments>(args)...));
        return Start(msTime, task, false, false);
    }
    
    /**
    Executes a task asynchronously
     
     @param msTime Delay and interval
     @param fun Function interface or lambda code block
     @param args
     @return Ready for execution, otherwise it fails
     */
    template<typename callable, typename... arguments>
    bool AsyncOnce(int msTime, callable&& fun, arguments&&... args) {
        std::function<typename std::result_of<callable(arguments...)>::type()> task(std::bind(std::forward<callable>(fun), std::forward<arguments>(args)...));
        
        return Start(msTime, task, false);
    }
    
    /**
     * Execute a task asynchronously (execute after 1 millisecond delay by default)
     
     @param fun Function interface or lambda code block
     @param args
     @return Ready for execution, otherwise it fails
     */
    template<typename callable, typename... arguments>
    bool AsyncOnce(callable&& fun, arguments&&... args) {
        std::function<typename std::result_of<callable(arguments...)>::type()> task(std::bind(std::forward<callable>(fun), std::forward<arguments>(args)...));
        
        return Start(1, task, false);
    }
    
    
    /**
     Executes tasks in an asynchronous loop

     @param msTime Delay and interval
     @param fun Function interface or lambda code block
     @param args 
     @return Ready for execution, otherwise it fails
     */
    template<typename callable, typename... arguments>
    bool AsyncLoop(int msTime, callable&& fun, arguments&&... args) {
        std::function<typename std::result_of<callable(arguments...)>::type()> task(std::bind(std::forward<callable>(fun), std::forward<arguments>(args)...));
        
        return Start(msTime, task, true);
    }
    
    
private:
    void DeleteThread();    //Delete a task thread

public:
    int m_nCount = 0;   //Number of cycles
    
private:
    std::string m_sName;   //Timer name
    
    std::atomic_bool m_bExpired;       //Whether the loaded task has expired
    std::atomic_bool m_bTryExpired;    //Equipment expires loaded tasks (markers)
    std::atomic_bool m_bLoop;          //Whether to loop or not
    
    std::thread *m_Thread = nullptr;
    std::mutex m_ThreadLock;
    std::condition_variable_any m_ThreadCon;
};

#endif /* CTimer_hpp */

