// Setting wizard for configure, Create 20210705  Liu
#include "setting_wizard.h"
#include "config.h"
#include <iostream>
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <limits>


void SettingWizard::Init(Config* config)
{
    this->config_ = config;
}

void SettingWizard::ToLower(string& text)
{
    transform(text.begin(), text.end(), text.begin(), ::tolower);
}

bool SettingWizard::AskForYesNo(const string& title)
{
    while (true)
    {
        string prompt(title + "(y/n/yes/no)?");
        cout << prompt;
        string answer = GetInputString();
        ToLower(answer);
        if (answer == "y" || answer == "yes")
        {
            return true;
        }
        else if (answer == "n" || answer == "no")
        {
            return false;
        }
        else
        {
            cout << "Input is wrong, please input(y/n/yes/no)." << endl;
        }
    }

    return false;
}

int SettingWizard::InputNumber(const string& title, int min, int max, int defaultValue)
{
    int number = 0;
    while (true)
    {
        cout << title << "(" << min << " - " << max << ")";
        string text = GetInputString();
        if (text.empty())
        {
            number = defaultValue;
            break ;
        }

        try
        {
            number = stoi(text);
        }
        catch (const std::exception& e)
        {
            cout << "Number is wrong, please input right number" << "(" << min << " - " << max << ")" << endl;
            continue ;
        }
        
        if (number < min || number > max)
        {
            cout << "Number is wrong, please input right number" << "(" << min << " - " << max << ")" << endl;
            continue;
        }

        break;
    }

    return number;
}

void SettingWizard::AskWizard()
{
    assert(config_ != nullptr);

    bool setting = AskForYesNo("Do you want to set config");
    if (setting)
    {
        Wizard();
    }
}

void SettingWizard::Wizard()
{
    assert(config_ != nullptr);

    SettingPublicNode();
    SettingSyncDataCount();
    SettingSyncDataIntervalTime();
}

void SettingWizard::SettingPublicNode()
{
    assert(config_ != nullptr);
    SettingLocalIp(); 
}

void SettingWizard::SettingSyncDataCount()
{
    assert(config_ != nullptr);

    int defaultCount = config_->GetSyncDataCount();
    int number = InputNumber("Please input number of synchronous", 1, 300, defaultCount);
    config_->SetSyncDataCount(number);
}

void SettingWizard::SettingSyncDataIntervalTime()
{
    assert(config_ != nullptr);

    int defaultInterval = config_->GetSyncDataPollTime();
    int number = InputNumber("please input interval time of synchronous", 30, 100, defaultInterval);
    config_->SetSyncDataPollTime(number);
}

void SettingWizard::SettingLocalIp()
{
    assert(config_ != nullptr);

    string ip;
    while (true)
    {
        cout << "input the local ip:";
        ip = GetInputString();
        if (ip.empty())
        {
            continue ;
        }
        if (!IsIp(ip))
        {
            cout << "ip format is wrong, please input right formate of ip" << endl;
            continue ;
        }
        if (IsLocalIP(ip))
        {
            cout << "ip is private, please input public ip" << endl;
            continue ;
        }

        break;
    }
    config_->SetLocalIP(ip);
}

bool SettingWizard::IsIp(const string& ip)
{
    int ipseg[4]{0};
    int count = sscanf(ip.c_str(), "%d.%d.%d.%d", &ipseg[0], &ipseg[1], &ipseg[2], &ipseg[3]);
    if (count != 4)
        return false;
    //std::cout << ipseg[0] << " " << ipseg[1] << " "  << ipseg[2] << " "  << ipseg[3] << endl;
    if ((ipseg[0] >= 0 && ipseg[0] <= 255) && (ipseg[1] >= 0 && ipseg[1] <= 255) && 
        (ipseg[2] >= 0 && ipseg[2] <= 255) && (ipseg[3] >= 0 && ipseg[3] <= 255))
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool SettingWizard::IsLocalIP(const string& ip)
{
    int ipseg[4]{0};
    int count = sscanf(ip.c_str(), "%d.%d.%d.%d", &ipseg[0], &ipseg[1], &ipseg[2], &ipseg[3]);
    if (count != 4)
        return false;
    if ((ipseg[0] == 10) || 
        (ipseg[0] == 172 && ipseg[1] >= 16 && ipseg[1] <= 31) || 
        (ipseg[0] == 192 && ipseg[1] == 168) || 
        (ipseg[0] == 0 && ipseg[1] == 0 && ipseg[2] == 0 && ipseg[3] == 0) ||
        (ipseg[0] == 255 && ipseg[1] == 255 && ipseg[2] == 255 && ipseg[3] == 255) ||
        (ipseg[0] == 127))
    {
        return true;
    }
    else
    {
        return false;
    }
}

template <typename CharT>
void ignore_line(std::basic_istream<CharT>& in)
{
    if (in.rdbuf()->sungetc() != std::char_traits<CharT>::eof() && in.get() != in.widen('\n'))
    {
        in.ignore(std::numeric_limits<std::streamsize>::max(), in.widen('\n'));
    }
}

// void ignore_line(istream& in)
// {
//     if (in.rdbuf()->sungetc() != EOF && in.get() != '\n')
//     {
//         in.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
//     }
// }

string SettingWizard::GetInputString(const string& title)
{
    cout << title;
    return GetInputString();
}

string SettingWizard::GetInputString()
{
    std::cin.clear();
    ignore_line(std::cin);

    string text;
    std::getline(std::cin, text);
    return text;
}