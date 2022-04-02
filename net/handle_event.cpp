#include <fstream>
#include "handle_event.h"
#include "../include/logging.h"
#include "./pack.h"
#include "./ip_port.h"
#include "peer_node.h"
#include "../include/net_interface.h"
#include "./global.h"
#include "net.pb.h"
#include "common.pb.h"
#include "dispatcher.h"
#include "../common/config.h"
#include "socket_buf.h"
#include <unordered_set>
#include <utility>
#include "node_cache.h"
#include "../common/global.h"
#include "global.h"
#include "../ca/MagicSingleton.h"
#include "../include/ScopeGuard.h"
#include "db/db_api.h"
#include "../ca/ca_global.h"
#include "../ca/Crypto_ECDSA.h"
#include "../ca/ca_hexcode.h"
#include "../ca/ca_base64.h"


static int PrintMsNum = 0;
int handlePrintMsgReq(const std::shared_ptr<PrintMsgReq> &printMsgReq, const MsgData &from)
{
	int type = printMsgReq->type();
	if (type == 0)
	{
		std::cout << ++PrintMsNum << " times data:" << printMsgReq->data() << std::endl;
	}
	else
	{
		ofstream file("bigdata.txt", fstream::out);
		file << printMsgReq->data();
		file.close();
		cout << "write bigdata.txt success!!!" << endl;
	}
	return 0;
}
static std::mutex node_mutex;
int handleRegisterNodeReq(const std::shared_ptr<RegisterNodeReq> &registerNode, const MsgData &from)
{
	//INFOLOG("handleRegisterNodeReq");
	//DEBUGLOG("handleRegisterNodeReq from.ip:{}", IpPort::ipsz(from.ip));
	//DEBUGLOG("handleRegisterNodeReq from.port:{}", from.port);

	std::lock_guard<std::mutex> lock(node_mutex);
	NodeInfo *nodeinfo = registerNode->mutable_mynode();

	std::string node_pub_key = nodeinfo->pub();
	if(node_pub_key.size() <= 0){
		ERRORLOG("public key is empty");
		return -1;
	}
	std::string node_base58addr = nodeinfo->base58addr();
	if (!CheckBase58Addr(node_base58addr))
	{
		ERRORLOG("base58address error !!");
		return -1;
	}
	if(nodeinfo->is_public_node() 
		&& nodeinfo->listen_ip() != from.ip)
	{
		ERRORLOG("Inconsistent ip, nodeinfo.listen_ip() {}",IpPort::ipsz(nodeinfo->listen_ip()));
		ERRORLOG("Inconsistent ip, from.ip {}",IpPort::ipsz(from.ip));
		return -1;
	}
	
	int pubLen = node_pub_key.size();
	char *rawPub = new char[pubLen * 2 + 2]{0};
	encode_hex(rawPub, node_pub_key.c_str(), pubLen);

	std::string sPubStr;
	sPubStr.append(rawPub, pubLen * 2);

	ECDSA<ECP, SHA1>::PublicKey publicKey;
	SetPublicKey(publicKey, sPubStr);

	std::string node_sign = nodeinfo->sign();
	if (node_sign.size() <= 0 || !VerifyMessage(publicKey, node_base58addr, node_sign))
	{
		ERRORLOG("VerifyMessage failed id: {}", node_pub_key);
		return -1;
	}

	if (!Singleton<Config>::get_instance()->GetIsPublicNode())
	{
		return 0;
	}
	std::string dest_pub = nodeinfo->pub();
	std::string dest_base58addr = nodeinfo->base58addr();
	auto public_self_id = Singleton<PeerNode>::get_instance()->get_self_id();
	Node node;
	node.fd = from.fd;
	node.base58address = dest_base58addr;
	node.pub = dest_pub;
	node.sign = nodeinfo->sign();
	node.listen_ip = nodeinfo->listen_ip();
	node.listen_port = nodeinfo->listen_port();
	node.public_ip = from.ip;
	node.public_port = from.port;
	node.is_public_node = nodeinfo->is_public_node();
	node.sign_fee = nodeinfo->sign_fee();
	node.package_fee = nodeinfo->package_fee();
	node.height = nodeinfo->height();
	node.public_base58addr = node.is_public_node ? "" : public_self_id;

	if (nodeinfo->is_public_node())
	{
		if (from.port == SERVERMAINPORT)
		{
			node.public_port = from.port;
		}
		else
		{
			node.public_port = SERVERMAINPORT;
		}
	}

	Node tem_node;
	auto find = Singleton<PeerNode>::get_instance()->find_node(node.base58address, tem_node);
	if ((find && tem_node.conn_kind == NOTYET) || !find)
	{
		node.conn_kind = PASSIV;
	}
	else
	{
		node.conn_kind = tem_node.conn_kind;
	}

	if (find)
	{
		if (tem_node.fd != from.fd)
		{
			DEBUGLOG("tem_node.fd != from.fd");

			close(tem_node.fd);
			Singleton<BufferCrol>::get_instance()->delete_buffer(tem_node.public_ip, tem_node.public_port);
			Singleton<BufferCrol>::get_instance()->add_buffer(from.ip, SERVERMAINPORT, from.fd);
		}
		Singleton<PeerNode>::get_instance()->update(node);
		if (node.is_public_node)
		{
			Singleton<PeerNode>::get_instance()->update_public_node(node);
		}
	}
	else
	{
		Singleton<PeerNode>::get_instance()->add(node);
		if (node.is_public_node)
		{
			Singleton<PeerNode>::get_instance()->add_public_node(node);
		}
	}

	Node selfNode = Singleton<PeerNode>::get_instance()->get_self_node();

	RegisterNodeAck registerNodeAck;
	std::vector<Node> nodelist;

	if (nodeinfo->is_public_node() && selfNode.is_public_node)
	{
		// std::vector<Node> tmp = Singleton<PeerNode>::get_instance()->get_nodelist();
		std::vector<Node> &&tmp = Singleton<PeerNode>::get_instance()->get_sub_nodelist(selfNode.base58address);
		nodelist.insert(nodelist.end(), tmp.begin(), tmp.end());
		std::vector<Node> publicNode = Singleton<PeerNode>::get_instance()->get_public_node();
		nodelist.insert(nodelist.end(), publicNode.begin(), publicNode.end());
	}
	else if (!nodeinfo->is_public_node() && selfNode.is_public_node)
	{
		nodelist = Singleton<PeerNode>::get_instance()->get_public_node();
	}

	nodelist.push_back(selfNode);
	nodelist.push_back(node);

	for (auto &node : nodelist)
	{

		if (node.is_public_node && node.fd < 0) //liuzg
		{
			if (node.base58address != selfNode.base58address)
			{
				continue;
			}
		}

		if (g_testflag == 0 && node.is_public_node) //liuzg
		{
			u32 &localIp = node.listen_ip;
			u32 &publicIp = node.public_ip;

			if (localIp != publicIp || IpPort::is_public_ip(localIp) == false)
			{
				continue;
			}
		}
		NodeInfo *nodeinfo = registerNodeAck.add_nodes();

		nodeinfo->set_base58addr(node.base58address);
		nodeinfo->set_listen_ip(node.listen_ip);
		nodeinfo->set_listen_port(node.listen_port);
		nodeinfo->set_public_ip(node.public_ip);
		nodeinfo->set_public_port(node.public_port);
		nodeinfo->set_is_public_node(node.is_public_node);
		nodeinfo->set_sign_fee(node.sign_fee);
		nodeinfo->set_package_fee(node.package_fee);
		nodeinfo->set_pub(node.pub);
		nodeinfo->set_height(node.height);
		nodeinfo->set_public_base58addr(node.public_base58addr);
	}

	net_com::send_message(dest_base58addr, registerNodeAck, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_2);
	return 0;
}

int handleRegisterNodeAck(const std::shared_ptr<RegisterNodeAck> &registerNodeAck, const MsgData &from)
{
	INFOLOG("handleRegisterNodeAck");

	auto self_node = Singleton<PeerNode>::get_instance()->get_self_node();

	DEBUGLOG("handleRegisterNodeAck from.ip: {}", IpPort::ipsz(from.ip));
	DEBUGLOG("handleRegisterNodeAck from.fd: {}", from.fd);
	DEBUGLOG("handleRegisterNodeAck self_node_id:", self_node.base58address);

	for (int i = 0; i < registerNodeAck->nodes_size(); i++)
	{
		const NodeInfo &nodeinfo = registerNodeAck->nodes(i);
		if(!CheckBase58Addr(nodeinfo.base58addr()))
		{
			continue;
		}
		if(nodeinfo.is_public_node() 
			&& nodeinfo.listen_ip() != nodeinfo.public_ip())
		{
			ERRORLOG("Inconsistent ip, nodeinfo.listen_ip() {}",IpPort::ipsz(nodeinfo.listen_ip()));
			ERRORLOG("Inconsistent ip ,nodeinfo.public_ip() {}",IpPort::ipsz(nodeinfo.public_ip()));
			continue;
		}
		
		Node node;
		node.base58address = nodeinfo.base58addr();
		node.pub = nodeinfo.pub();
		node.sign = nodeinfo.sign();
		node.listen_ip = nodeinfo.listen_ip();
		node.listen_port = nodeinfo.listen_port();
		node.public_ip = nodeinfo.public_ip();
		node.public_port = nodeinfo.public_port();
		node.is_public_node = nodeinfo.is_public_node();
		node.sign_fee = nodeinfo.sign_fee();
		node.package_fee = nodeinfo.package_fee();
		node.height = nodeinfo.height();
		node.public_base58addr = nodeinfo.public_base58addr();

		if (from.ip == node.public_ip && from.port == node.public_port)
		{
			node.fd = from.fd;
			net_com::parse_conn_kind(node);
		}

		DEBUGLOG("handleRegisterNodeAck node.id: {}", node.base58address);

		if (node.base58address != Singleton<PeerNode>::get_instance()->get_self_id())
		{
			Node temp_node;
			bool find_result = Singleton<PeerNode>::get_instance()->find_node(node.base58address, temp_node);
			if (find_result)
			{
			}
			else
			{
				DEBUGLOG("handleRegisterNodeAck add node: {}", IpPort::ipsz(node.public_ip));
				Singleton<PeerNode>::get_instance()->add(node);
				if (node.is_public_node)
				{
					Singleton<PeerNode>::get_instance()->add_public_node(node);
				}
			}
		}
		else if (node.base58address == Singleton<PeerNode>::get_instance()->get_self_id() && !Singleton<Config>::get_instance()->GetIsPublicNode())
		{
			Singleton<PeerNode>::get_instance()->set_self_ip_p(node.public_ip);
			Singleton<PeerNode>::get_instance()->set_self_port_p(node.public_port);
			Singleton<PeerNode>::get_instance()->set_self_public_node_id(node.public_base58addr);
		}

		if (node.is_public_node)
		{
			if (self_node.is_public_node && node.fd > 0)
			{
				Singleton<PeerNode>::get_instance()->update(node);
				Singleton<PeerNode>::get_instance()->update_public_node(node);
			}
		}
		else
		{
			Singleton<PeerNode>::get_instance()->update(node);
		}
	}
	Singleton<PeerNode>::get_instance()->conect_nodelist();
	return 0;
}

int handleConnectNodeReq(const std::shared_ptr<ConnectNodeReq> &connectNodeReq, const MsgData &from)
{
	std::lock_guard<std::mutex> lock(node_mutex);

	auto self_node = Singleton<PeerNode>::get_instance()->get_self_node();
	NodeInfo *nodeinfo = connectNodeReq->mutable_mynode();

	Node node;
	node.fd = from.fd;
	node.base58address = nodeinfo->base58addr();
	node.pub = nodeinfo->pub();
	node.sign = nodeinfo->sign();
	node.listen_ip = nodeinfo->listen_ip();
	node.listen_port = nodeinfo->listen_port();
	node.is_public_node = nodeinfo->is_public_node();
	node.sign_fee = nodeinfo->sign_fee();
	node.package_fee = nodeinfo->package_fee();
	node.height = nodeinfo->height();
	node.public_base58addr = nodeinfo->public_base58addr();

	//if (nodeinfo->conn_kind() != BYSERV)
	{
		node.conn_kind = PASSIV;
		node.public_ip = from.ip;
		node.public_port = from.port;
	}
//	else
//	{
//		node.conn_kind = BYSERV;
//		node.fd = -2;
		//node.public_ip      = nodeinfo->public_port();
		//node.public_port    =  nodeinfo->public_port();
//	}

	if (nodeinfo->is_public_node())
	{
		if (from.port == SERVERMAINPORT)
		{
			node.public_port = from.port;
		}
		else
		{
			node.public_port = SERVERMAINPORT;
		}
	}

	Node tem_node;
	auto find = Singleton<PeerNode>::get_instance()->find_node(node.base58address, tem_node);
	if (find)
	{
		if (tem_node.fd != from.fd && node.conn_kind != BYSERV)
		{
			close(tem_node.fd);
			Singleton<BufferCrol>::get_instance()->delete_buffer(tem_node.public_ip, tem_node.public_port);
			Singleton<BufferCrol>::get_instance()->add_buffer(from.ip, SERVERMAINPORT, from.fd);
		}
		else if (node.conn_kind == BYSERV && tem_node.fd > 0)
		{
			return 0;
		}
		if (self_node.base58address != node.base58address)
		{
			Singleton<PeerNode>::get_instance()->update(node);
			if (node.is_public_node)
			{
				Singleton<PeerNode>::get_instance()->update_public_node(node);
			}
		}
	}
	else
	{
		if (self_node.base58address != node.base58address)
		{
			Singleton<PeerNode>::get_instance()->add(node);
			if (node.is_public_node)
			{
				Singleton<PeerNode>::get_instance()->add_public_node(node);
			}
		}
	}
	return 0;
}

int handleBroadcastNodeReq(const std::shared_ptr<BroadcastNodeReq> &broadcastNodeReq, const MsgData &from)
{
	NodeInfo *nodeinfo = broadcastNodeReq->mutable_mynode();

	Node node;
	node.fd = from.fd;
	node.base58address = nodeinfo->base58addr();
	node.pub = nodeinfo->pub();
	node.sign = nodeinfo->sign();
	node.listen_ip = nodeinfo->listen_ip();
	node.listen_port = nodeinfo->listen_port();
	node.is_public_node = nodeinfo->is_public_node();
	node.sign_fee = nodeinfo->sign_fee();
	node.package_fee = nodeinfo->package_fee();
	node.public_base58addr = nodeinfo->public_base58addr();

	Node tmp_node;
	bool find = Singleton<PeerNode>::get_instance()->find_node(node.base58address, tmp_node);
	if (!find)
	{
		Singleton<PeerNode>::get_instance()->add(node);
		if (node.is_public_node)
		{
			Singleton<PeerNode>::get_instance()->add_public_node(node);
		}
	}
	return 0;
}

int handleTransMsgReq(const std::shared_ptr<TransMsgReq> &transMsgReq, const MsgData &from)
{
	NodeInfo *nodeinfo = transMsgReq->mutable_dest();
	const std::string &node_pub = nodeinfo->pub();
	const std::string &public_node_base58addr = nodeinfo->public_base58addr();
	const std::string &msg = transMsgReq->data();
	const std::string node_base58addr = nodeinfo->base58addr();

	{
		std::string data(msg.begin() + 4, msg.end() - sizeof(uint32_t) * 3);
		CommonMsg common_msg;
		int r = common_msg.ParseFromString(data);
		if (!r)
		{
			return 0;
		}

		std::string type = common_msg.type();
		{
			std::lock_guard<std::mutex> lock(global::g_mutex_req_cnt_map);
			global::reqCntMap[type].first += 1;
			global::reqCntMap[type].second += common_msg.data().size();
		}
	}

	auto self_node = Singleton<PeerNode>::get_instance()->get_self_node();
	if (self_node.base58address == public_node_base58addr)
	{
		Node dest;
		bool find = Singleton<PeerNode>::get_instance()->find_node(node_base58addr, dest);
		if (find)
		{
			transMsgReq->set_priority(transMsgReq->priority() & 0xE); 
			net_com::send_one_message(dest, std::move(transMsgReq->data()), transMsgReq->priority());
		}
		else
		{
			return 0;
		}
	}
	else
	{
		Node to;
		bool find = Singleton<PeerNode>::get_instance()->find_node(public_node_base58addr, to);
		if (find)
		{
			TransMsgReq trans_Msg_Req;
			NodeInfo *destnode = trans_Msg_Req.mutable_dest();
			destnode->set_base58addr(node_base58addr);
			destnode->set_pub(node_pub);
			destnode->set_public_base58addr(public_node_base58addr);
			trans_Msg_Req.set_data(msg);
			trans_Msg_Req.set_priority(transMsgReq->priority());
			net_com::send_message(to, trans_Msg_Req);
		}
		else
		{
			Node targetNode;
			if (!Singleton<PeerNode>::get_instance()->find_node(node_base58addr, targetNode))
			{
				return 0;
			}

			if (targetNode.public_base58addr.empty() && targetNode.is_public_node == false)
			{
				return 0;
			}

			if (targetNode.public_base58addr == self_node.base58address || (self_node.is_public_node && targetNode.is_public_node))
			{
				transMsgReq->set_priority(transMsgReq->priority() & 0xE); 
				net_com::send_one_message(targetNode, transMsgReq->data(), transMsgReq->priority());
			}
			else
			{
				Node targetPublicNode;
				if (!Singleton<PeerNode>::get_instance()->find_node(targetNode.public_base58addr, targetPublicNode))
				{
					return 0;
				}

				TransMsgReq trans_Msg_Req;
				NodeInfo *destnode = trans_Msg_Req.mutable_dest();
				destnode->set_base58addr(node_base58addr);
				destnode->set_pub(node_pub);
				destnode->set_public_base58addr(targetNode.public_base58addr);
				trans_Msg_Req.set_data(msg);
				trans_Msg_Req.set_priority(transMsgReq->priority());
				net_com::send_message(targetPublicNode, trans_Msg_Req);
			}
		}
	}
	return 0;
}

int handleBroadcastMsgReq(const std::shared_ptr<BroadcaseMsgReq> &broadcaseMsgReq, const MsgData &from)
{
	std::string data = broadcaseMsgReq->data();
	CommonMsg common_msg;
	int r = common_msg.ParseFromString(data);
	if (!r)
	{
		return 0;
	}
	MsgData toSelfMsgData = from;
	toSelfMsgData.pack.data = data;
	toSelfMsgData.pack.flag = broadcaseMsgReq->priority();
	auto ret = Singleton<ProtobufDispatcher>::get_instance()->handle(toSelfMsgData);
	if (0 != ret)
	{
		return ret;
	}

	// broadcast impl
	BroadcaseMsgReq req = *broadcaseMsgReq;

	const Node &selfNode = Singleton<PeerNode>::get_instance()->get_self_node();
	if (req.from().is_public_node())
	{
		const std::vector<Node> &&subNodeList = Singleton<PeerNode>::get_instance()->get_sub_nodelist(selfNode.base58address);
		for (auto &item : subNodeList)
		{
			if (req.from().base58addr() != item.base58address && item.is_public_node == false)
			{
				net_com::send_message(item, req);
			}
		}
	}
	else
	{
		std::string originNodeBase58addr = req.mutable_from()->base58addr(); 
		req.mutable_from()->set_is_public_node(selfNode.is_public_node);
		req.mutable_from()->set_pub(selfNode.pub);

		const std::vector<Node> publicNodeList = Singleton<PeerNode>::get_instance()->get_nodelist(NODE_PUBLIC);
		for (auto &item : publicNodeList)
		{
			if (req.from().base58addr() != item.base58address)
			{
				net_com::send_message(item, req);
			}
		}

		const std::vector<Node> &&subNodeList = Singleton<PeerNode>::get_instance()->get_sub_nodelist(selfNode.base58address);
		for (auto &item : subNodeList)
		{
			if (req.from().base58addr() != item.base58address && originNodeBase58addr != item.base58address && item.is_public_node == false)
			{
				net_com::send_message(item, req);
			}
		}
	}
	return 0;
}

int handleNotifyConnectReq(const std::shared_ptr<NotifyConnectReq> &notifyConnectReq, const MsgData &from)
{
	NodeInfo *server_node = notifyConnectReq->mutable_server_node();
	NodeInfo *client_node = notifyConnectReq->mutable_client_node();

	if (client_node->base58addr() == Singleton<PeerNode>::get_instance()->get_self_id())
	{
		Node node;
		node.base58address = server_node->base58addr();
		node.pub = server_node->pub();
		node.sign = server_node->sign();
		node.listen_ip = server_node->listen_ip();
		node.listen_port = server_node->listen_port();
		node.public_ip = server_node->public_ip();
		node.public_port = server_node->public_port();
		node.is_public_node = server_node->is_public_node();
		node.sign_fee = server_node->sign_fee();
		node.package_fee = server_node->package_fee();
		node.height = server_node->height();
		node.public_base58addr = server_node->public_base58addr();

		Node tem_node;
		auto find = Singleton<PeerNode>::get_instance()->find_node(node.base58address, tem_node);
		if (!find)
		{
			Singleton<PeerNode>::get_instance()->add(node);
			if (node.is_public_node)
			{
				Singleton<PeerNode>::get_instance()->add_public_node(node);
			}
			Singleton<PeerNode>::get_instance()->conect_nodelist();
		}
		else
		{
			if (tem_node.fd < 0)
			{
				Singleton<PeerNode>::get_instance()->conect_nodelist();
			}
		}
	}
	else
	{
		Node node;
		bool find = Singleton<PeerNode>::get_instance()->find_node(client_node->base58addr(), node);
		if (find && node.fd > 0)
		{
			NotifyConnectReq notifyConnectReq;

			NodeInfo *server_node1 = notifyConnectReq.mutable_server_node();
			server_node1->set_pub(server_node->pub());
			server_node1->set_base58addr(server_node->base58addr());
			server_node1->set_listen_ip(server_node->listen_ip());
			server_node1->set_listen_port(server_node->listen_port());
			server_node1->set_public_ip(server_node->public_ip());
			server_node1->set_public_port(server_node->public_port());
			server_node1->set_is_public_node(server_node->is_public_node());
			server_node1->set_sign_fee(server_node->sign_fee());
			server_node1->set_package_fee(server_node->package_fee());
			server_node1->set_height(server_node->height());

			NodeInfo *client_node1 = notifyConnectReq.mutable_client_node();
			client_node1->set_pub(client_node->pub());
			client_node1->set_base58addr(client_node->base58addr());

			CommonMsg msg;
			Pack::InitCommonMsg(msg, notifyConnectReq);

			net_pack pack;
			Pack::common_msg_to_pack(msg, 0, pack);
			net_com::send_one_message(node, pack);
		}
	}
	return 0;
}

int handlePingReq(const std::shared_ptr<PingReq> &pingReq, const MsgData &from)
{
	std::string id = pingReq->id();
	Node node;

	if (Singleton<PeerNode>::get_instance()->find_public_node(id, node))
	{
		node.ResetHeart();
	}

	if (Singleton<PeerNode>::get_instance()->find_node(id, node))
	{
		node.ResetHeart();
		net_com::SendPongReq(node);
	}
	return 0;
}

int handlePongReq(const std::shared_ptr<PongReq> &pongReq, const MsgData &from)
{
	std::string id = pongReq->id();
	Node node;
	if (Singleton<PeerNode>::get_instance()->find_public_node(id, node))
	{
		node.ResetHeart();
		Singleton<PeerNode>::get_instance()->update_public_node(node);
	}

	auto find = Singleton<PeerNode>::get_instance()->find_node(id, node);
	if (find)
	{
		node.ResetHeart();
		Singleton<PeerNode>::get_instance()->add_or_update(node);
	}
	return 0;
}

int handleSyncNodeReq(const std::shared_ptr<SyncNodeReq> &syncNodeReq, const MsgData &from)
{
	auto id = syncNodeReq->ids(0);
	auto self_base58addr = Singleton<PeerNode>::get_instance()->get_self_id();
	auto self_node = Singleton<PeerNode>::get_instance()->get_self_node();

	//DEBUGLOG("handleSyncNodeReq id:{}", id);

	auto node_size = syncNodeReq->nodes_size();
	if (node_size > 0)
	{
		Singleton<PeerNode>::get_instance()->delete_node_by_public_node_id(id);
	}

	for (int i = 0; i < node_size; i++)
	{
		const NodeInfo &nodeinfo = syncNodeReq->nodes(i);
		if(!CheckBase58Addr(nodeinfo.base58addr()))
		{
			continue;
		}
		if(nodeinfo.is_public_node() 
			&& nodeinfo.listen_ip() != nodeinfo.public_ip())
		{
			ERRORLOG("Inconsistent ip, nodeinfo.listen_ip() {}",IpPort::ipsz(nodeinfo.listen_ip()));
			ERRORLOG("Inconsistent ip, nodeinfo.public_ip() {}",IpPort::ipsz(nodeinfo.public_ip()));
			continue;
		}
	
		Node node;
		node.base58address = nodeinfo.base58addr();
		node.pub = nodeinfo.pub();
		node.sign = nodeinfo.sign();
		node.listen_ip = nodeinfo.listen_ip();
		node.listen_port = nodeinfo.listen_port();
		node.public_ip = nodeinfo.public_ip();
		node.public_port = nodeinfo.public_port();
		node.is_public_node = nodeinfo.is_public_node();
		node.sign_fee = nodeinfo.sign_fee();
		node.package_fee = nodeinfo.package_fee();
		node.height = nodeinfo.height();
		node.public_base58addr = nodeinfo.public_base58addr();
		if (self_node.base58address != node.base58address)
		{
			Singleton<PeerNode>::get_instance()->add(node);
			if (node.is_public_node)
			{
				Singleton<PeerNode>::get_instance()->add_public_node(node);
			}
		}
	}
	SyncNodeAck syncNodeAck;
	vector<Node> &&nodelist = Singleton<PeerNode>::get_instance()->get_sub_nodelist(self_base58addr);
	if (nodelist.size() == 0)
	{
		return 0;
	}
	syncNodeAck.add_ids(std::move(self_base58addr));
	for (auto &node : nodelist)
	{
		if (node.is_public_node && node.fd < 0) //liuzg
		{
			continue;
		}

		if (g_testflag == 0 && node.is_public_node) //liuzg
		{
			u32 &localIp = node.listen_ip;
			u32 &publicIp = node.public_ip;

			if (localIp != publicIp || IpPort::is_public_ip(localIp) == false)
			{
				continue;
			}
		}
		NodeInfo *nodeinfo = syncNodeAck.add_nodes();
		nodeinfo->set_base58addr(node.base58address);
		nodeinfo->set_listen_ip(node.listen_ip);
		nodeinfo->set_listen_port(node.listen_port);
		nodeinfo->set_public_ip(node.public_ip);
		nodeinfo->set_public_port(node.public_port);
		nodeinfo->set_is_public_node(node.is_public_node);
		nodeinfo->set_sign_fee(node.sign_fee);
		nodeinfo->set_package_fee(node.package_fee);
		nodeinfo->set_pub(node.pub);
		nodeinfo->set_height(node.height);
		nodeinfo->set_public_base58addr(node.public_base58addr);
	}

	net_com::send_message(from, syncNodeAck, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_2);
	return 0;
}

int handleSyncNodeAck(const std::shared_ptr<SyncNodeAck> &syncNodeAck, const MsgData &from)
{
	INFOLOG("handleSyncNodeAck");
	auto self_id = Singleton<PeerNode>::get_instance()->get_self_id();

	auto id = syncNodeAck->ids(0);
	DEBUGLOG("handleSyncNodeAck id:{}", id);

	int nodeSize = syncNodeAck->nodes_size();
	if (nodeSize > 0)
	{
		Singleton<PeerNode>::get_instance()->delete_node_by_public_node_id(id);
	}

	for (int i = 0; i < syncNodeAck->nodes_size(); i++)
	{
		const NodeInfo &nodeinfo = syncNodeAck->nodes(i);
		if (nodeinfo.base58addr().size() > 0)
		{
			Node node;
			node.base58address = nodeinfo.base58addr();
			node.pub = nodeinfo.pub();
			node.sign = nodeinfo.sign();
			node.listen_ip = nodeinfo.listen_ip();
			node.listen_port = nodeinfo.listen_port();
			node.public_ip = nodeinfo.public_ip();
			node.public_port = nodeinfo.public_port();
			node.is_public_node = nodeinfo.is_public_node();
			node.sign_fee = nodeinfo.sign_fee();
			node.package_fee = nodeinfo.package_fee();
			node.height = nodeinfo.height();
			node.public_base58addr = nodeinfo.public_base58addr();

			Node temp_node;
			bool find_result = Singleton<PeerNode>::get_instance()->find_node(node.base58address, temp_node);

			if (!find_result && (node.base58address != self_id))
			{
				{
					Singleton<PeerNode>::get_instance()->add(node);
				}
				if (node.is_public_node)
				{
					Singleton<PeerNode>::get_instance()->add_public_node(node);
				}
			}
		}
	}
	Singleton<PeerNode>::get_instance()->conect_nodelist();
	return 0;
}

int handleEchoReq(const std::shared_ptr<EchoReq> &echoReq, const MsgData &from)
{
	EchoAck echoAck;
	echoAck.set_id(Singleton<PeerNode>::get_instance()->get_self_id());
	net_com::send_message(echoReq->id(), echoAck, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_Low_0);
	return 0;
}

int handleEchoAck(const std::shared_ptr<EchoAck> &echoAck, const MsgData &from)
{
	std::cout << "echo from id:" << echoAck->id() << endl;
	return 0;
}

int handleUpdateFeeReq(const std::shared_ptr<UpdateFeeReq> &updateFeeReq, const MsgData &from)
{
	Singleton<PeerNode>::get_instance()->update_fee_by_id(updateFeeReq->id(), updateFeeReq->fee());
	return 0;
}

int handleUpdatePackageFeeReq(const std::shared_ptr<UpdatePackageFeeReq> &updatePackageFeeReq, const MsgData &from)
{
	Singleton<PeerNode>::get_instance()->update_package_fee_by_id(updatePackageFeeReq->id(), updatePackageFeeReq->package_fee());
	return 0;
}

int handleGetTransInfoReq(const std::shared_ptr<GetTransInfoReq> &transInfoReq, const MsgData &from)
{
	DBReader db_read;
	std::string hash = transInfoReq->txid();

	std::string strTxRaw;
	if (DBStatus::DB_SUCCESS != db_read.GetTransactionByHash(hash, strTxRaw))
	{
		ERRORLOG("GetTransactionByHash fail");
		return 0;
	}

	string blockhash;
	unsigned height;
	int stat;
	if (DBStatus::DB_SUCCESS != db_read.GetBlockHashByTransactionHash(hash, blockhash))
	{
		ERRORLOG("GetBlockHashByTransactionHash fail");
		return 0;
	}
	if (DBStatus::DB_SUCCESS != db_read.GetBlockHeightByBlockHash(blockhash, height))
	{
		ERRORLOG("GetBlockHeightByBlockHash fail");
		return 0;
	}
	GetTransInfoAck transInfoAck;
	transInfoAck.set_height(height);
	CTransaction *utxoTx = new CTransaction();
	utxoTx->ParseFromString(strTxRaw);
	transInfoAck.set_allocated_trans(utxoTx);

	net_com::send_message(transInfoReq->nodeid(), transInfoAck);
	INFOLOG("handleGetTransInfoReq send_message");
	return 0;
}
int handleGetTransInfoAck(const std::shared_ptr<GetTransInfoAck> &transInfoAck, const MsgData &from)
{
	std::lock_guard<std::mutex> lock(global::g_mutex_transinfo);
	global::g_is_utxo_empty = false;
	global::g_trans_info = *transInfoAck;
	return 0;
}


// Create: handle node height, 20211129  Liu
int handleNodeHeightChangedReq(const std::shared_ptr<NodeHeightChangedReq>& req, const MsgData& from)
{
	std::string id = req->id();
	uint32 height = req->height();
	Singleton<PeerNode>::get_instance()->add_height_cache(id,height);
	
	return 0;
}
