#ifndef _PEER_NODE_H_
#define _PEER_NODE_H_

#include <map>
#include <list>
#include <mutex>
#include <vector>
#include <string>
#include <thread>
#include <vector>
#include <bitset>
#include <iostream>
#include "./define.h"
#include "./ip_port.h"
#include <shared_mutex>

using namespace std;

enum NodeType
{
	NODE_ALL,
	NODE_PUBLIC
};

enum ConnKind
{
	NOTYET, 
	DRTI2I, 
	DRTI2O, 
	DRTO2I, 
	DRTO2O, 
	HOLING, 
	BYHOLE, 
	BYSERV, 
	PASSIV	
};

std::string parse_kind(int kind);

using id_type = std::string;

class Node
{
public:
	std::string     base58address     = "";
	std::string     pub               = "";
	std::string     sign              = "";
	std::string 	public_base58addr = "";
	u32      listen_ip                = 0;
	u32      listen_port              = 0;
	u32      public_ip                = 0;
	u32      public_port              = 0;
	bool     is_public_node           = false;
	u32      height                   = 0;
	u64      sign_fee                 = 0;
	u64      package_fee              = 0;
	ConnKind conn_kind                = NOTYET;
	int      fd                       = -1;
	int      heart_time               = HEART_TIME;
	int      heart_probes             = HEART_PROBES;

	Node()
	{
	}
	Node(std::string node_base58address)
	{
		base58address = node_base58address;
	}

	bool operator==(const Node &obj) const
	{
		return base58address == obj.base58address;
	}

	bool operator>(const Node &obj) 
	{
		return (*this).base58address > obj.base58address;
	}

	void ResetHeart()
	{
		heart_time = HEART_TIME;
		heart_probes = HEART_PROBES;
	}
	void print()
	{
		std::cout << info_str() << std::endl;
	}

	std::string info_str()
	{
		std::ostringstream oss;
		oss
			<< "  ip(" << string(IpPort::ipsz(public_ip)) << ")"
			<< "  port(" << public_port << ")"
			<< "  ip_l(" << string(IpPort::ipsz(listen_ip)) << ")"
			<< "  port_l(" << listen_port << ")"
			<< "  kind(" << parse_kind(conn_kind) << ")"
			<< "  fd(" << fd << ")"
			<< "  miner_fee(" << sign_fee << ")"
			<< "  package_fee(" << package_fee << ")"
			<< "  base58(" << base58address << ")"
			<< "  heart_probes(" << heart_probes << ")"
			<< "  is_public(" << is_public_node << ")"
			<< "  height( " << height << " )"
			<< "  public_node_id(" << public_base58addr << ")"

			<< std::endl;
		return oss.str();
	}
	bool is_connected() const
	{
		return fd > 0 || fd == -2;
	}
	void set_height(u32 height)
	{
		this->height = height;
	}
};
class Compare
{
public:
	Compare(bool f = true) : flag(f) {}
	bool operator()(const Node &s1, const Node &s2)
	{
		if (flag)
		{
			return s1.height > s2.height;
		}
		else
		{
			return s1.base58address > s2.base58address;
		}
	}

protected:
	bool flag;
};
class PeerNode
{
public:
	PeerNode() = default;
	~PeerNode() = default;

public:
	bool is_id_exists(id_type const& base58addr);
	bool find_node(id_type const& base58addr, Node& x);
	bool find_node_by_fd(int fd, Node& node_);
	bool find_public_node(id_type const& base58addr, Node& x);
	
	std::vector<Node> get_nodelist(NodeType type = NODE_ALL, bool mustAlive = false);
	std::vector<Node> get_public_node();
	std::vector<Node> get_sub_nodelist(std::string const &base58addr);

	void delete_node(std::string base58addr);
	void delete_by_fd(int fd);
	void delete_node_by_public_node_id(std::string public_node_base58addr);

	bool add(const Node &_node);
	bool add_public_node(const Node &_node);
	bool delete_public_node(const Node &_node);
	bool update(const Node &_node);
	bool update_public_node(const Node &_node);
	bool add_or_update(Node _node);
	void print(std::vector<Node> &nodelist);
	void print(const Node &node);
	std::string nodelist_info(std::vector<Node> &nodelist);
	std::string nodeid2str(std::bitset<K_ID_LEN> id);

	bool nodelist_refresh_thread_init();
	bool height_cache_thread_init();
	void nodelist_refresh_thread_fun();
	void height_cache_refresh_thread_fun();

	void conect_nodelist();

	const std::string get_self_id();
	const std::string get_self_pub();
	void set_self_id(const std::string &base58addr);
	void set_self_pub(const std::string &pub);
	void set_self_ip_p(const u32 public_ip);
	void set_self_ip_l(const u32 listen_ip);
	void set_self_port_p(const u16 port_p);
	void set_self_port_l(const u16 port_l);
	void set_self_public_node(bool bl);
	void set_self_fee(uint64_t fee);
	void set_self_package_fee(uint64_t package_fee);
	//void set_self_mac_md5(string mac_md5);
	void set_self_base58_address(string address);
	void set_self_public_node_id(string public_base58addr);
	void set_self_height(u32 height);
	void set_self_height();
	u32 get_self_chain_height_newest();
	const Node get_self_node();
	const std::string get_base58addr();
	bool update_fee_by_id(const string &base58addr, uint64_t fee);
	bool update_package_fee_by_id(const string &base58addr, uint64_t fee);
	void add_height_cache(const string &base58addr,const u32 height);

	bool make_rand_id();
	bool is_id_valid(const string &id);

private:
	//std::mutex mutex_for_nodes_;
	std::shared_mutex mutex_for_nodes_;
	std::map<std::string, Node> node_map_;
	std::map<std::string, uint32> height_cache_;

	//std::mutex mutex_for_public_nodes_;
	std::shared_mutex mutex_for_public_nodes_;
	std::map<std::string, Node> pub_node_map_;

	std::mutex mutex_for_height_cache_;
	Node curr_node_;
	std::mutex mutex_for_curr_;
	std::thread refresh_thread;

	std::thread height_cache_thread;

};

#endif