#include "string.h"
#include "unistd.h"

#include <iostream>

#include <sys/wait.h>
#include "main/main.h"
#include "utils/time_util.h"
#include "utils/console.h"
#include "common/config.h"
#include "ca/ca.h"
#include "ca/global.h"
#include "ca/transaction.h"
#include "utils/single.hpp"
#include "utils/don_bench_mark.h"
#include "ca/test.h"

namespace IpFactor {
    bool kMOptionUsed = false;
    bool kMLocalhostUsed = false;
    bool kMPublicIpUsed = false;
    std::string kPublicIpAddress = "";
}

bool isDaemonMode = false;

void startDaemon(const char* programName, const char* programPath) {
    if (daemon(1, 0) == -1) {
        std::cerr << "Failed to daemonize process." << std::endl;
        exit(-1);
    }

    signal(SIGCHLD, SIG_IGN); 
    while (true) {
        pid_t pid = fork();  
        if (pid == 0) {
            chdir(programPath); 
            execlp(programName, programName, "-m", NULL);
            exit(0); 
        } else if (pid < 0) {
            perror("fork failed");
            exit(-1);
        }

        int status;
        waitpid(pid, &status, 0);  
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            std::cerr << "Child process crashed, restarting..." << std::endl;
        }
        sleep(10);  
    }
}

int main(int argc, char* argv[])
{
	if(-1 == InitPidFile()) {
		exit(-1);
	}

	/* Ctrl + C */
	if(signal(SIGINT, sigHandler) == SIG_ERR) {
		exit(-1);
	}

	/* kill pid / killall name */
	if(signal(SIGTERM, sigHandler) == SIG_ERR) {
		exit(-1);
	}

	//Modify process time UTC
	setenv("TZ","Universal",1);
    tzset();

	// Get the current number of CPU cores and physical memory size
	global::g_cpuNums = sysconf(_SC_NPROCESSORS_ONLN);
	uint64_t memory = (uint64_t)sysconf(_SC_PAGESIZE) * (uint64_t)sysconf(_SC_PHYS_PAGES) / 1024 / 1024;
	INFOLOG("Number of current CPU cores:{}", global::g_cpuNums);
	INFOLOG("Number of current memory size:{}", memory);
	if(global::g_cpuNums < 1 || memory < 0.5 * 1024)
	{
		std::cout << "Current machine configuration:\n"
				  << "The number of processors currently online (available): "<< global::g_cpuNums << "\n"
		          << "The memory size: " << memory << " MB" << std::endl;
		std::cout << RED << "Don basic configuration:\n"
						 << "The number of processors currently online (available): 8\n"
						 << "The memory size: 16,384 MB" << RESET << std::endl;
		return 1;
	}

	if (argc > 6)
	{
		ERRORLOG("Too many parameters!");
		std::cout << "Too many parameters!" << std::endl;
		return 2;
	}

	bool showMenu = false;
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-m") == 0)
		{
			showMenu = true;
			IpFactor::kMOptionUsed=true;
			if (i + 1 < argc)
			 {
                i++;
                if (strcmp(argv[i], "localhost") == 0) 
				{
                    IpFactor::kMLocalhostUsed = true;
                }
			 	else if (strcmp(argv[i], "publicip") == 0)
				{
                    IpFactor::kMPublicIpUsed = true;
                    if (i + 1 < argc) 
					{
                        i++;
                        IpFactor::kPublicIpAddress = argv[i];
                    }
				}
				else
				{
					ERRORLOG("Parameter parsing error!");
					std::cout << "Parameter parsing error!" << std::endl;
					return 4;
				}
	      	}		   
		}
		else if(strcmp(argv[i], "-d") == 0)
		{
            isDaemonMode = true;  
		}
		else if (strcmp(argv[i], "-c") == 0)
		{
		    std::ifstream configFile("config.json");
    		if (!configFile)
    		{
        	std::ofstream outFile("config.json");
        	nlohmann::json initjson = nlohmann::json::parse(global::ca::kConfigJson);
        	outFile << initjson.dump(4);
        	outFile.close();
    		}
			configFile.close();
		std::cout << "Init Config file" << std::endl;
		return 3;
		}
		else if (strcmp(argv[i], "--help") == 0)
		{
			ERRORLOG("The parameter is Help!");
			std::cout << argv[0] << ": --help version:" << global::kCompatibleVersion << " \n -m show Menu\n -s value, signature fee\n -p value, package fee" << std::endl;
			return 4;
		}
		else if (strcmp(argv[i], "-t") == 0)
		{
			showMenu = true;
			MagicSingleton<DONbenchmark>::GetInstance()->OpenBenchmark();
		}
		else if (strcmp(argv[i], "-p") == 0)
		{
			showMenu = true;
			MagicSingleton<DONbenchmark>::GetInstance()->OpenBenchmark2();
		}
		else
		{
			ERRORLOG("Parameter parsing error!");
			std::cout << "Parameter parsing error!" << std::endl;
			return 5;
		}
	}

	if (isDaemonMode) {
        const char* programName = argv[0];
        char resolved_path[1024];  
        getcwd(resolved_path, sizeof(resolved_path));
        const char* programPath = resolved_path;
        startDaemon(programName, programPath);
    }


	bool initFail = false;
	if (!Init())
	{
		initFail = true;
	}

	if (!Check())
	{
		initFail = true;
	}

	if(initFail)
	{
		CaCleanup();
		exit(0);
	}

	if (showMenu)
	{
		Menu();
	}

	while (true)
	{
		sleep(9999);
	}

	return 0;

}