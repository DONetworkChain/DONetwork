#include "./work_thread.h"
#include "../include/logging.h"
#include "./pack.h"
#include "./ip_port.h"
#include "peer_node.h"
#include "../include/net_interface.h"
#include "global.h"
#include "net.pb.h"
#include "dispatcher.h"
#include "./socket_buf.h"
#include "./epoll_mode.h"

static std::mutex g_mutex_for_vec_;
static deque<Node> g_deque_node; 

static std::mutex g_mutex_for_map_;
static std::mutex mutex_for_cpu_index;
static int cpu_index = 0;


int sys_get_tid()
{
	int tid = 0;
	tid = syscall(__NR_gettid);
	return tid;
}

void sys_thread_set_cpu(unsigned int cpu_index)
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpu_index, &mask);
	int tid = sys_get_tid();
	if (-1 == sched_setaffinity(tid, sizeof(mask), &mask))
	{
		printf("%s:%s:%d, WARNING: Could not set thread to CPU %d\n", __FUNCTION__, __FILE__, __LINE__, cpu_index);
	}
	else
	{
		printf("thread%d, bind cpu %u core.\n", tid, cpu_index);
	}
}

int get_cpu_index()
{
	std::lock_guard<std::mutex> lck(mutex_for_cpu_index);
	int res = cpu_index;
	if (cpu_index + 1 < global::cpu_nums)
	{
		cpu_index += 1;
	}
	else
	{
		cpu_index = 0;
	}

	return res;
}
void bind_cpu()
{
	if (global::cpu_nums >= 4)
	{
		int index = get_cpu_index();
		sys_thread_set_cpu(index);
	}
}

void WorkThreads::start()
{
	int k = 0;

	int WorkNum = Singleton<Config>::get_instance()->GetVarInt("work_thread_num");
	INFOLOG("will create {} threads", WorkNum);
	//if(0 == WorkNum)
	{
		WorkNum = global::cpu_nums * 2;
	}
    if(0 == WorkNum)
    {
        WorkNum = 8;
    }
	std::cout << "WorkNum:" << WorkNum << std::endl;
	for (auto i = 0; i < WorkNum; i++)
	{
		this->m_threads_read_list.push_back(std::thread(WorkThreads::work_read, i));
		this->m_threads_read_list[i].detach();
	}

	for (auto i = 0; i < WorkNum; i++)
	{
		this->m_threads_trans_list.push_back(std::thread(WorkThreads::work_write, i));
		this->m_threads_trans_list[i].detach();
	}

	for (auto i = 0; i < WorkNum; i++)
	{
		this->m_threads_work_list.push_back(std::thread(WorkThreads::work, i));
		this->m_threads_work_list[i].detach();
	}	
}

void WorkThreads::work_write(int id)
{

	bind_cpu();

	while (1)
	{
		MsgData data;
		if (false == global::queue_write.try_wait_pop(data))
			continue;

		switch (data.type)
		{
		case E_WRITE:
			// std::cout << "global::queue_write:" << global::queue_write.msg_queue_.size() << std::endl; 
			WorkThreads::handle_net_write(data);
			break;
		default:
			INFOLOG(YELLOW "work_write drop data: data.fd :{}" RESET, data.fd);
			break;
		}
	}
}
void WorkThreads::work_read(int id) 
{

	bind_cpu();

	while (1)
	{
		MsgData data;
		if (false == global::queue_read.try_wait_pop(data))
			continue;

		switch (data.type)
		{
		case E_READ:
			// std::cout << "global::queue_read:" << global::queue_read.msg_queue_.size() << std::endl; 
			WorkThreads::handle_net_read(data);
			break;
		default:
			INFOLOG(YELLOW "work_read drop data: data.fd {}" RESET, data.fd);
			break;
		}
	}
}

void WorkThreads::work(int id)
{

	bind_cpu();

	while (1)
	{
		MsgData data;
		if (false == global::queue_work.try_wait_pop(data))
			continue;

		switch (data.type)
		{
		case E_WORK:

			WorkThreads::handle_network_event(data);
			break;
		default:
			INFOLOG("drop data: data.fd :{}", data.fd);
			break;
		}
	}
}

int WorkThreads::handle_network_event(MsgData &data)
{
	Singleton<ProtobufDispatcher>::get_instance()->handle(data);
	return 0;
}


int WorkThreads::handle_net_read(const MsgData &data)
{
	int nread = 0;
	char buf[MAXLINE] = {0};
	do
	{
		nread = 0;
		memset(buf, 0, sizeof(buf));
		nread = read(data.fd, buf, MAXLINE); 
		if (nread > 0)
		{
			Singleton<BufferCrol>::get_instance()->add_read_buffer_queue(data.ip, data.port, buf, nread);
		}		
		if (nread == 0 && errno != EAGAIN)
		{
			Singleton<PeerNode>::get_instance()->delete_by_fd(data.fd);
			return -1;
		}
		if (nread < 0)
		{
			if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			{
				Singleton<EpollMode>::get_instance()->add_epoll_event(data.fd, EPOLLIN | EPOLLOUT | EPOLLET);
				return 0;
			}
			// ERRORLOG("errno:{} \n nread:{} \n ip:{} \n fd:{} \n", 
			// 		errno, nread, IpPort::ipsz(data.ip), data.fd);
			Singleton<PeerNode>::get_instance()->delete_by_fd(data.fd);

			return -1;
		}
	} while (nread >= MAXLINE);

	Singleton<EpollMode>::get_instance()->add_epoll_event(data.fd, EPOLLIN | EPOLLOUT | EPOLLET);
	return 0;
}

bool WorkThreads::handle_net_write(const MsgData &data)
{
	auto port_and_ip = net_com::pack_port_and_ip(data.port, data.ip);

	if (!Singleton<BufferCrol>::get_instance()->is_exists(port_and_ip))
	{
		DEBUGLOG("!Singleton<BufferCrol>::get_instance()->is_exists({})", port_and_ip);
		return false;
	}
	if(data.fd < 0)
	{
		ERRORLOG("handle_net_write fd < 0");
		return false;
	}
	std::mutex& buff_mutex = get_fd_mutex(data.fd);
	std::lock_guard<std::mutex> lck(buff_mutex);
	std::string buff = Singleton<BufferCrol>::get_instance()->get_write_buffer_queue(port_and_ip);
	
	if (0 == buff.size())
	{
		// DEBUGLOG("no data to send.");
		return true;
	}

	auto ret = net_tcp::Send(data.fd, buff.c_str(), buff.size(), 0);

	if (ret == -1)
	{
		ERRORLOG("net_tcp::Send error");
		return false;
	}
	if (ret > 0 && ret < (int)buff.size())
	{
		//DEBUGLOG("handle_net_write fd({}) u32_ip({} {}) u16_port({}) resend {}", data.fd, data.ip, IpPort::ipsz(data.ip), data.port, buff.size());
		Singleton<BufferCrol>::get_instance()->pop_n_write_buffer_queue(port_and_ip, ret);
		return true;
	}
	if (ret == (int)buff.size())
	{
		//DEBUGLOG("handle_net_write fd({}) u32_ip({} {}) u16_port({}) succ", data.fd, data.ip, IpPort::ipsz(data.ip), data.port);
		Singleton<BufferCrol>::get_instance()->pop_n_write_buffer_queue(port_and_ip, ret);
		global::mutex_for_phone_list.lock();
		for(auto it = global::phone_list.begin(); it != global::phone_list.end(); ++it)
		{
			if(data.fd == *it)
			{
				close(data.fd);
				Singleton<BufferCrol>::get_instance()->delete_buffer(data.ip, data.port);
				Singleton<EpollMode>::get_instance()->delete_epoll_event(data.fd);
				global::phone_list.erase(it);
				break;
			}
		}
		global::mutex_for_phone_list.unlock();
		return true;
	}

	//DEBUGLOG(RED "handle_net_write fd({}) u32_ip{} {}) u16_port({}) ret({}) data length({})fail" RESET, data.fd, data.ip, IpPort::ipsz(data.ip), data.port, ret, (int)buff.size());

	return false;
}

