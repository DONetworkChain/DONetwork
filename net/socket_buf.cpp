#include "socket_buf.h"
#include "global.h"
#include "../utils/util.h"
#include "../ca/ca_base64.h"

// #define BOOST_STACKTRACE_USE_ADDR2LINE
// #include <boost/stacktrace.hpp>


std::unordered_map<int, std::unique_ptr<std::mutex>> fds_mutex;
std::mutex mu;
std::mutex& get_fd_mutex(int fd)
{
	std::lock_guard<std::mutex> lck(mu);    
    auto search = fds_mutex.find(fd);
    if (search != fds_mutex.end()) {
        return *(search->second);
    } else {
        fds_mutex.insert(std::pair<int,std::unique_ptr<std::mutex>>(fd, std::unique_ptr<std::mutex>(new std::mutex)));
        return *(fds_mutex[fd]);
    }
}



std::string g_emptystr;

bool SocketBuf::is_sending_msg()
{
	return is_sending_;
}

void SocketBuf::set_sending_msg(bool is_sending)
{
	DEBUGLOG("set_sending_msg is_sending({})", is_sending ? "true" : "false");

	is_sending_ = is_sending;
}

void SocketBuf::verify_cache(size_t curr_msg_len)
{
    if (curr_msg_len > 100*1000*1000)
    {
        SocketBuf::correct_cache();
    }
}

void SocketBuf::correct_cache()
{  
    if(this->cache.size() < sizeof(uint32_t))
    {
        this->cache.clear();
        return;
    }
    const char * ptr = this->cache.data();
    bool find = false;
    size_t i;
    for(i = 0;i <= this->cache.size() - sizeof(uint32_t);i++)
    {
        int32_t tmp_flag = *((uint32_t*)(ptr + i));
        if(tmp_flag == END_FLAG)
        {
            find = true;
            break;
        }
    }
    if(find)
    {
        this->cache.erase(0, i+4);
    }
    else
    {
        this->cache.clear();
    }
}


bool SocketBuf::add_data_to_read_buf(char *data, size_t len)
{
	std::lock_guard<std::mutex> lck(mutex_for_read_);
    if (data == NULL || len == 0)
    {
        ERRORLOG("add_data_to_read_buf error: data == NULL or len == 0");
        return false;
    }

    std::string tmp(data, len);
    this->cache += tmp;
	size_t curr_msg_len = 0;
    if (this->cache.size() >= 4)
    {
        memcpy(&curr_msg_len, this->cache.data(), 4);  
        //DEBUGLOG("curr_msg_len:{} cache.size:{}" , (int)curr_msg_len, (int)cache.size() );
        
        SocketBuf::verify_cache(curr_msg_len);

        while (this->cache.size() >= (size_t)(4 + curr_msg_len))
        {
            this->cache.erase(0, 4);  //this leak! 
            std::string read_data(this->cache.begin(), this->cache.begin() + curr_msg_len);

            
            if (read_data.size() < sizeof(uint32_t) * 3)
            {
                SocketBuf::correct_cache();
                return false;
            }
            uint32_t checksum = Util::adler32((unsigned char *)read_data.data(), read_data.size() - sizeof(uint32_t) * 3);
            uint32_t pack_checksum = *((uint32_t *)(this->cache.data() + read_data.size() - sizeof(uint32_t) * 3));
            
            if(checksum != pack_checksum)
            {
                correct_cache();
                return false;    
            }
            this->cache.erase(0, curr_msg_len);

            // data + checksum + flag + end
            this->send_pk_to_mess_queue(read_data);

            if (this->cache.size() < 4)
                break;
            memcpy(&curr_msg_len, this->cache.data(), 4);
            SocketBuf::verify_cache(curr_msg_len);
        }
        
        //this->cache.reserve(this->cache.size());
        if(this->cache.capacity() > this->cache.size() * 20)
        {
            this->cache.shrink_to_fit();
        }
    }
    return true;
}

bool SocketBuf::send_pk_to_mess_queue(const std::string& data)
{
    MsgData send_data;
    
    std::pair<uint16_t, uint32_t> port_and_ip_i = net_data::apack_port_and_ip_to_int(this->port_and_ip);
    send_data.type = E_WORK;
    send_data.fd = this->fd;
    send_data.ip = port_and_ip_i.second;
    send_data.port = port_and_ip_i.first;
    send_data.data = data;
    Pack::apart_pack(send_data.pack, data.data(), data.size());
    return global::queue_work.push(send_data);
}

void SocketBuf::printf_cache()
{
	std::lock_guard<std::mutex> lck(mutex_for_read_);

    DEBUGLOG("fd: {}", this->fd);
    DEBUGLOG("port_and_ip: {}", this->port_and_ip);
    DEBUGLOG("cache: {}", this->cache.c_str());
    DEBUGLOG("send_cache: {}", this->send_cache.c_str());
}

std::string SocketBuf::get_send_msg()
{
    std::lock_guard<std::mutex> lck(mutex_for_send_);
    return this->send_cache;
}

bool SocketBuf::is_send_cache_empty()
{
    std::lock_guard<std::mutex> lck(mutex_for_send_);
    return this->send_cache.size() == 0;
}

void SocketBuf::push_send_msg(const std::string& data)
{
	std::lock_guard<std::mutex> lck(mutex_for_send_);
    this->send_cache += data;
}

void SocketBuf::pop_n_send_msg(int n)
{
	std::lock_guard<std::mutex> lck(mutex_for_send_);
    if((int)send_cache.size() >= n)
    {
        this->send_cache.erase(0 ,n);
    }
    else
    {
        this->send_cache.erase(0 ,send_cache.size());
    }
}




std::string BufferCrol::get_write_buffer_queue(uint64_t port_and_ip)
{
    auto itr = this->BufferMap.find(port_and_ip);
    if(itr == this->BufferMap.end())
    {
        return g_emptystr;
    }
    return itr->second->get_send_msg();
}

std::string BufferCrol::get_write_buffer_queue(std::string ip, uint16_t port)
{
    uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
    return this->get_write_buffer_queue(port_and_ip);
}

std::string BufferCrol::get_write_buffer_queue(uint32_t ip, uint16_t port)
{
    uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
    return this->get_write_buffer_queue(port_and_ip);
}

bool BufferCrol::add_write_buffer_queue(uint64_t port_and_ip, const std::string& data)
{
    if(data.size() == 0)
    {
        return false;
    }

    {
        std::lock_guard<std::mutex> lck(mutex_);

        auto itr = this->BufferMap.find(port_and_ip);
        if(itr == this->BufferMap.end())
        {
            return false;
        }
        itr->second->push_send_msg(data);
    }
	
    return true;
}

bool BufferCrol::add_write_buffer_queue(std::string ip, uint16_t port, const std::string& data)
{
    uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
    return this->add_write_buffer_queue(port_and_ip, data);
}

bool BufferCrol::add_write_buffer_queue(uint32_t ip, uint16_t port, const std::string& data)
{
    uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
    return this->add_write_buffer_queue(port_and_ip, data);
}

bool BufferCrol::add_read_buffer_queue(uint64_t port_and_ip, char *buf, socklen_t len)
{
    auto port_ip = net_data::apack_port_and_ip_to_str(port_and_ip);
    // std::cout << "read data==========================" << std::endl;
    // std::cout << "ip:" << port_ip.second << std::endl;
    // std::cout << "port:" << port_ip.first << std::endl;
    if (buf == NULL || len == 0)
    {
        ERRORLOG("add_read_buffer_queue error buf == NULL or len == 0");
        return false;
    }

    std::map<uint64_t,std::shared_ptr<SocketBuf>>::iterator itr;
    {
        std::lock_guard<std::mutex> lck(mutex_);

        itr = this->BufferMap.find(port_and_ip);
        if (itr == this->BufferMap.end())
        {
            DEBUGLOG("no key port_and_ip is {}", port_and_ip);
            return false;
        }
    }
	
    return itr->second->add_data_to_read_buf(buf, len);
}

bool BufferCrol::add_read_buffer_queue(std::string ip, uint16_t port, char *buf, socklen_t len)
{
    uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
    return this->add_read_buffer_queue(port_and_ip, buf, len);
}

bool BufferCrol::add_read_buffer_queue(uint32_t ip, uint16_t port, char *buf, socklen_t len)
{
    uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
    return this->add_read_buffer_queue(port_and_ip, buf, len);
}

bool BufferCrol::add_buffer(uint64_t port_and_ip, const int fd)
{

    if (port_and_ip == 0 || fd <= 0)
    {
        // ERRORLOG("add_buffer error port_and_ip == 0 or fd <= 0 port_and_ip: {}  fd: {}", port_and_ip, fd);
        // std::cout << boost::stacktrace::stacktrace() << std::endl;   
        return false;
    }

	std::lock_guard<std::mutex> lck(mutex_);

    auto itr = this->BufferMap.find(port_and_ip);
    if (itr != this->BufferMap.end())
    {
        //WARNLOG(" port_and_ip exist in map, port_and_ip: {}", port_and_ip);
        return false;
    }
    std::shared_ptr<SocketBuf> tmp(new SocketBuf());
    tmp->fd = fd;
    tmp->port_and_ip = port_and_ip;
    this->BufferMap[port_and_ip] = tmp;

    return true;
}

bool BufferCrol::add_buffer(std::string ip, uint16_t port, const int fd)
{
    uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
    return this->add_buffer(port_and_ip, fd);
}

bool BufferCrol::add_buffer(uint32_t ip, uint16_t port, const int fd)
{
    uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
    return this->add_buffer(port_and_ip, fd);
}

void BufferCrol::print_bufferes()
{
	std::lock_guard<std::mutex> lck(mutex_);
    DEBUGLOG("************************** print_bufferes b **************************");
    for(auto i : this->BufferMap)
    { 
        i.second->printf_cache();
    }
    DEBUGLOG("************************** print_bufferes e **************************");
}

bool BufferCrol::delete_buffer(std::string ip, uint16_t port)
{
    uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
    return this->delete_buffer(port_and_ip);
}
bool BufferCrol::delete_buffer(uint32_t ip, uint16_t port)
{
    uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
    return this->delete_buffer(port_and_ip);
}
bool BufferCrol::delete_buffer(uint64_t port_and_ip)
{
    if (port_and_ip == 0)
    {
        return false;
    }

	std::lock_guard<std::mutex> lck(mutex_);

    auto itr = this->BufferMap.find(port_and_ip);
    if(itr != this->BufferMap.end())
    {
      
        this->BufferMap.erase(port_and_ip);
        return true;
    }
    return false;
}

void BufferCrol::pop_n_write_buffer_queue(uint32_t ip, uint16_t port, int n)
{
    uint64_t port_and_ip = net_com::pack_port_and_ip(port, ip);
    return this->pop_n_write_buffer_queue(port_and_ip, n);
}

void BufferCrol::pop_n_write_buffer_queue(uint64_t port_and_ip, int n)
{
    if (port_and_ip == 0)
    {
        ERRORLOG("pop_n_write_buffer_queue error port_and_ip == 0 port_and_ip: {}", port_and_ip);
    }

	std::lock_guard<std::mutex> lck(mutex_);

    auto itr = this->BufferMap.find(port_and_ip);
    if(itr != this->BufferMap.end())
    {
        itr->second->pop_n_send_msg(n);
        return ;
    }
    DEBUGLOG(" port_and_ip is not exist in map, port_and_ip: {}", port_and_ip);    
}

void BufferCrol::pop_n_write_buffer_queue(std::string ip, uint16_t port, int n)
{
    uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
    DEBUGLOG("port_and_ip :{}, ip :{}, port :{}", port_and_ip, ip.c_str(), port);
    return this->pop_n_write_buffer_queue(port_and_ip, n);
}

bool BufferCrol::is_exists(uint64_t port_and_ip)
{
	std::lock_guard<std::mutex> lck(mutex_);

	auto itr = this->BufferMap.find(port_and_ip);
	if (itr == this->BufferMap.end())
	{
		DEBUGLOG(RED "no key port_and_ip is {}" RESET , port_and_ip);
		return false;
	}
	return true;
}


bool BufferCrol::is_exists(std::string ip, uint16_t port)
{
	uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
	return is_exists(port_and_ip);
}

bool BufferCrol::is_exists(uint32_t ip, uint16_t port)
{
	uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
	return is_exists(port_and_ip);
}

bool BufferCrol::add_write_pack(uint64_t port_and_ip, const std::string ios_msg)
{
	if (ios_msg.size() == 0)
	{
		ERRORLOG("add_write_buffer_queue error msg.size == 0");
		return false;
	}

	std::lock_guard<std::mutex> lck(mutex_);

	auto itr = this->BufferMap.find(port_and_ip);
	if (itr == this->BufferMap.end())
	{
		DEBUGLOG("no key port_and_ip is {}", port_and_ip);
		return false;
	}
	itr->second->push_send_msg(ios_msg);
	return true;
}

bool BufferCrol::add_write_pack(std::string ip, uint16_t port, const std::string ios_msg)
{
	uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
	add_write_pack(port_and_ip, ios_msg);
	return true;
}

bool BufferCrol::add_write_pack(uint32_t ip, uint16_t port, const std::string ios_msg)
{
	uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
	add_write_pack(port_and_ip, ios_msg);
	return true;
}


bool BufferCrol::is_cache_empty(uint32_t ip, uint16_t port)
{
    uint64_t port_and_ip = net_data::pack_port_and_ip(port, ip);
    auto itr = this->BufferMap.find(port_and_ip);
    if(itr == this->BufferMap.end())
    {
        return true;
    }
    return itr->second->is_send_cache_empty();
}

// void BufferCrol::print_cache_size()
// {
//     std::lock_guard<std::mutex> lck(mutex_);
//     for(auto i : this->BufferMap)
//     {
//         total_recv_capacity += i.second->cache.capacity();
//         total_send_capacity += i.second->send_cache.capacity();
//         total_recv_size += i.second->cache.size();
//         total_send_size += i.second->send_cache.size();
//     }
//     std::cout << "BufferMap size is " << this->BufferMap.size() << std::endl;
//     std::cout << "total_recv_capacity = " << total_recv_capacity / 1024 / 1024  << std::endl;
//     std::cout << "total_send_capacity = " << total_send_capacity / 1024 / 1024 << std::endl;
//     std::cout << "total_capacity = " << (total_recv_capacity + total_send_capacity) / 1024 / 1024 << std::endl;
//     std::cout << std::endl;
//     std::cout << "total_recv_size = " << total_recv_size / 1024 / 1024 << std::endl;
//     std::cout << "total_send_size = " << total_send_size / 1024 / 1024 << std::endl;
//     std::cout << "total_size = " << (total_recv_size + total_send_size) / 1024 / 1024 << std::endl;
//     total_recv_size = 0;
//     total_send_size = 0;
//     total_recv_capacity = 0;
//     total_send_capacity = 0;
// }