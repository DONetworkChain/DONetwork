// Setting wizard for configure, Create 20210705  Liu
#include <string>
using namespace std;

class Config;

class SettingWizard
{
public:
    SettingWizard() : config_(nullptr) { }
    SettingWizard(const SettingWizard&) = delete;
    SettingWizard(SettingWizard&&) = delete;

    SettingWizard& operator=(const SettingWizard&) = delete;
    SettingWizard& operator=(SettingWizard&&) = delete;

    ~SettingWizard()
    {
        config_ = nullptr;
    }

public:
    void Init(Config* config);
    void AskWizard();
    void Wizard();
    void SettingPublicNode();
    void SettingSyncDataCount();
    void SettingSyncDataIntervalTime();
    void SettingLocalIp();

    static void ToLower(string& text);
    static bool IsIp(const string& ip);
    static bool IsLocalIP(const string& ip);

private:
    bool AskForYesNo(const string& title);
    int InputNumber(const string& title, int min, int max, int defaultValue);
    string GetInputString(const string& title);
    string GetInputString();

private:
    Config* config_;
};