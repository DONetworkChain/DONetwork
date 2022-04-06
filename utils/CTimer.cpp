/*
 * @Author: your name
 * @Date: 2020-11-17 14:14:33
 * @LastEditTime: 2020-11-17 14:14:33
 * @LastEditors: your name
 * @Description: In User Settings Edit
 * @FilePath: \ebpc\utils\CTimer.cpp
 */
#include "CTimer.hpp"
#include <future>

CTimer::CTimer(const std::string sTimerName):m_bExpired(true), m_bTryExpired(false), m_bLoop(false)
{
    m_sName = sTimerName;
}

CTimer::~CTimer()
{
    m_bTryExpired = true;   
    DeleteThread();
}

bool CTimer::Start(unsigned int msTime, std::function<void()> task, bool bLoop, bool async)
{
    if (!m_bExpired || m_bTryExpired) return false;  
    m_bExpired = false;
    m_bLoop = bLoop;
    m_nCount = 0;

    if (async) {
        DeleteThread();
        m_Thread = new std::thread([this, msTime, task]() {
            if (!m_sName.empty()) {
#if (defined(__ANDROID__) || defined(ANDROID))      
                pthread_setname_np(pthread_self(), m_sName.c_str());
#elif defined(__APPLE__)                            
                pthread_setname_np(m_sName.c_str());  
#endif
            }
            
            while (!m_bTryExpired) {
                m_ThreadCon.wait_for(m_ThreadLock, std::chrono::milliseconds(msTime));  
                if (!m_bTryExpired) {
                    task();     

                    m_nCount ++;
                    if (!m_bLoop) {
                        break;
                    }
                }
            }
            
            m_bExpired = true;      
            m_bTryExpired = false;  
        });
    } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(msTime));
        if (!m_bTryExpired) {
            task();
        }
        m_bExpired = true;
        m_bTryExpired = false;
    }
    
    return true;
}

void CTimer::Cancel()
{
    if (m_bExpired || m_bTryExpired || !m_Thread) {
        return;
    }
    
    m_bTryExpired = true;
}

void CTimer::DeleteThread()
{
    if (m_Thread) {
        m_ThreadCon.notify_all();   
        m_Thread->join();           
        delete m_Thread;
        m_Thread = nullptr;
    }
}

