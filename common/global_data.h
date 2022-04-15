#ifndef DON_COMMON_GLOBAL_DATA_H_
#define DON_COMMON_GLOBAL_DATA_H_

#include <condition_variable>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

struct GlobalData;
class GlobalDataManager
{
public:
    bool CreateWait(uint32_t time_out_sec, uint32_t ret_num,
                    std::string &out_msg_id);
    bool AddWaitData(const std::string &msg_id, const std::string &data);
    bool WaitData(const std::string &msg_id, std::vector<std::string> &ret_data);
    static GlobalDataManager &GetGlobalDataManager();

private:
    GlobalDataManager() = default;
    ~GlobalDataManager() = default;
    GlobalDataManager(GlobalDataManager &&) = delete;
    GlobalDataManager(const GlobalDataManager &) = delete;
    GlobalDataManager &operator=(GlobalDataManager &&) = delete;
    GlobalDataManager &operator=(const GlobalDataManager &) = delete;
    std::mutex global_data_mutex_;
    std::unordered_map<std::string, std::shared_ptr<GlobalData>> global_data_;
};

#define GLOBALDATAMGRPTR GlobalDataManager::GetGlobalDataManager()

#endif
