#include "time_report.h"
#include "../utils/time_util.h"
#include "../utils/singleton.h"
#include "../include/logging.h"
#include <sstream>
#include <assert.h>
#include <iostream>

TimeReport::TimeReport() : title_("Elapsed time:"), start_(0), end_(0)
{
    Init();
}

TimeReport::TimeReport(const string& title) : title_(title), start_(0), end_(0)
{
    Init();
}

TimeReport::~TimeReport()
{
    End();
    Report();
}

void TimeReport::Init()
{
    start_ = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();
}

void TimeReport::End()
{
    end_ = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();
}

void TimeReport::Report()
{
    Report(title_);
}

void TimeReport::Report(const string& title)
{
    assert(start_ <= end_);
    int64_t usedTime = end_ - start_;
    double dUsendTime = ((double)usedTime) / 1000000.0;

    std::cout << title << " " << usedTime << "ms" << std::endl;

    stringstream stream;
    stream << title << " {}ms";
    string log = stream.str();
    DEBUGLOG(log, usedTime);
}
