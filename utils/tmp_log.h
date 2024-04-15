


#ifndef __TMPLOG_HPP_
#define __TMPLOG_HPP_

#include <string>
#include <fstream>
#include <iostream>

#include "include/logging.h"

enum OUTTYPE
{
    file,screen
};

void write_tmplog(const std::string& content, OUTTYPE out = file, const std::string& log_name = "new_tmp.log");


// void cast_log(const std::string& content,const std::string & log="cast.log");


#define DSTR __FILE__+std::string(":")+std::to_string(__LINE__)+
#define ts_toString(value) std::to_string(value)

#define RED_t "\033[31m"
#define YELLOW_t "\033[33m"
#define GREEN_t "\033[32m"
#define WHITE_t "\033[37m"
#define BASECOLOER "\033[0m"


#define _S(n) std::to_string(n)

#include <sstream>
static std::string ArgToString(const char* value) {
    return  std::string(value);
}

static std::string ArgToString(char* value) {
    return  std::string(value);
}
template<int N>
std::string ArgToString(char(&s)[N]) {
    return  std::string(s);
}
template<int N>
std::string ArgToString(const char(&s)[N]) {
    return  std::string(s);
}

static std::string ArgToString(const std::string & str){
    return str;
}


template <typename T>
std::string ArgToString(T value) {
    return  std::to_string(value);
}

template <typename T>
void make_args_vect(std::vector<std::string>& vec, T t) {
    vec.push_back(ArgToString(t));
}
template<typename T, typename ...Ts>
void make_args_vect(std::vector<std::string>& vec, T t, Ts...  ts) {
    vec.push_back(ArgToString(t));
    make_args_vect(vec, ts...);
}

static void make_args_vect(std::vector<std::string>& vec){

}

std::string print_trace(void);


class Sutil {
public:
    template<typename T,typename... Ts>
    static std::string Format(const T &t, const Ts &... args) {
        std::vector<std::string> allArgs;
        make_args_vect(allArgs, args...);
        return BuildFormatTarget(ArgToString(t), allArgs);
    }


private:
    static std::string  BuildFormatTarget(const std::string& str, const std::vector<std::string>& allarg) {
        int arg_s = 0;
        int index = 0;
        std::stringstream svl;
        for (; index < str.size(); index++) {
            if (str[index] == '%' &&
                index != str.size() - 1 &&
                str[index + 1] == 's' &&
                arg_s < allarg.size()) {
                svl << allarg[arg_s];
                index += 1;
                arg_s++;
                continue;
            }
            svl << str[index];
        }
        return svl.str();
    }


};



#define errorL(msg) \
	std::cout << RED_t <<"Error:["<< __FILE__  << ":"<< __LINE__ << "]:"<< msg << std::endl;
#define debugL(msg) \
	std::cout << YELLOW_t <<"debug:["<< __FILE__ << ":"<< __LINE__ << "]:"<< msg << std::endl;
#define infoL(msg) \
	std::cout << GREEN_t <<"debug:["<< __FILE__ << ":" << __LINE__ << "]:"<< msg << std::endl;



class FileLog {
public:
	FileLog(const std::string& name) {
        file.open(name, std::ios::app);
        if (!file.is_open()) {
            errorL(name + "open fail!");
        }
	}
    ~FileLog() {
        file.close();
    }
    inline  void log(const std::string& msg) {
        file << msg << std::endl;
    }
    void ferror(const std::string& msg) {
        log(RED_t + msg);
    }

    void fdebug(const std::string& msg) {
        log(YELLOW_t + msg);
    }

    void finfo(const std::string& msg) {
        log(GREEN_t + msg);
    }
private:
    std::ofstream file;
};






#define LOG_NAME(name)\
    FileLog name(#name);




#endif
