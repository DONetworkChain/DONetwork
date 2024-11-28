
#include "api.h"

#include <arpa/inet.h>
#include <signal.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <errno.h>

#include <string>
#include <sstream>
#include <utility>

#include "./global.h"
#include "./dispatcher.h"
#include "./socket_buf.h"
#include "./work_thread.h"
#include "./epoll_mode.h"
#include "./http_server.h"
#include "./ip_port.h"
#include "./peer_node.h"
#include "./global.h"

#include "../proto/net.pb.h"
#include "../proto/common.pb.h"
#include "../proto/block.pb.h"
#include "db/db_api.h"

#include "../common/global.h"
#include "../include/logging.h"
#include "../utils/time_util.h"
#include "../utils/console.h"

#include "../utils/account_manager.h"
#include "../utils/cycliclist.hpp"
#include "../utils/tmp_log.h"
#include "common/global_data.h"
#include "key_exchange.h"

int net_tcp::Socket(int family, int type, int protocol)
{
	int n;

	if ((n = socket(family, type, protocol)) < 0)
		ERRORLOG("can't create socket file");
	return n;
}

int net_tcp::Accept(int fd, struct sockaddr *sa, socklen_t *salenptr)
{
	int n;

	if ((n = accept(fd, sa, salenptr)) < 0)
	{
		if ((errno == ECONNABORTED) || (errno == EINTR) || (errno == EWOULDBLOCK))
		{
			goto ret;
		}
		else
		{
			ERRORLOG("accept error");
		}
	}
ret:
	return n;
}

int net_tcp::Bind(int fd, const struct sockaddr *sa, socklen_t salen)
{
	int n;

	if ((n = bind(fd, sa, salen)) < 0)
		ERRORLOG("bind error");
	return n;
}

int net_tcp::Connect(int fd, const struct sockaddr *sa, socklen_t salen)
{
	int n;

	int bufLen;
	int optLen = sizeof(bufLen);
	getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *)&bufLen, (socklen_t *)&optLen);

	int recvBuf = 1 * 1024 * 1024;
	SetSocketOption(fd, SOL_SOCKET, SO_RCVBUF, (const void *)&recvBuf, sizeof(int));

	int sndBuf = 1 * 1024 * 1024;
	SetSocketOption(fd, SOL_SOCKET, SO_SNDBUF, (const void *)&sndBuf, sizeof(int));

	getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *)&bufLen, (socklen_t *)&optLen);

	if ((n = connect(fd, sa, salen)) < 0)
	{
	}

	return n;
}

int net_tcp::Listen(int fd, int backLog)
{
	int n;

	if ((n = listen(fd, backLog)) < 0)
		ERRORLOG("listen error");
	return n;
}

int net_tcp::Send(int sockfd, const void *buf, size_t len, int flags)
{
	if (sockfd < 0)
	{
		ERRORLOG("Send func: file description err"); // Error sending file descriptor
		return -1;
	}
	int bytesLeft;
	int writtenBytes;
	char *ptr;
	ptr = (char *)buf;
	bytesLeft = len;
	while (bytesLeft > 0)
	{
		writtenBytes = write(sockfd, ptr, bytesLeft);
		if (writtenBytes <= 0) /* Something went wrong */
		{
			if (writtenBytes == 0)
			{
				continue;
			}
			if (errno == EINTR)
			{
				continue;
			}
			else if (errno == EAGAIN) /* EAGAIN : Resource temporarily unavailable*/
			{

				return len - bytesLeft;
			}
			else 
			{
				MagicSingleton<PeerNode>::GetInstance()->DeleteByFd(sockfd);
				return -2;
			}
		}

		bytesLeft -= writtenBytes;
		ptr += writtenBytes; /* Continue writing from the rest of the place */
	}
	return len;
}

int net_tcp::SetSocketOption(int fd, int level, int optName, const void *optVal, socklen_t optLen)
{
	int ret;

	if ((ret = setsockopt(fd, level, optName, optVal, optLen)) == -1)
		ERRORLOG("setsockopt error");
	return ret;
}

int net_tcp::ListenServerInit(int port, int listenNum)
{
	struct sockaddr_in servAddr;
	int listener;
	int opt = 1;
	listener = Socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);

	bzero(&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY); // any addr
	servAddr.sin_port = htons(port);

	SetSocketOption(listener, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt,
			   sizeof(opt));
	SetSocketOption(listener, SOL_SOCKET, SO_REUSEPORT, (const void *)&opt,
			   sizeof(opt));

	Bind(listener, (struct sockaddr *)&servAddr, sizeof(servAddr));

	int recvBuf = 1 * 1024 * 1024;
	SetSocketOption(listener, SOL_SOCKET, SO_RCVBUF, (const void *)&recvBuf, sizeof(int));
	int sndBuf = 1 * 1024 * 1024;
	SetSocketOption(listener, SOL_SOCKET, SO_SNDBUF, (const void *)&sndBuf, sizeof(int));
	Listen(listener, listenNum);

	return listener;
}
int net_tcp::SetFdNoBlocking(int sockfd)

{
	if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0) | O_NONBLOCK) == -1)
	{
		ERRORLOG("setnonblock error");
		return -1;
	}
	return 0;
}

int net_com::InitConnection(u32 u32_ip, u16 u16_port, u16 &connectedPort)
{
	int confd = 0;
	struct sockaddr_in servAddr = {0};
	struct sockaddr_in my_addr = {0};
	int ret = 0;

	confd = Socket(AF_INET, SOCK_STREAM, 0);
	int flags = 1;
	SetSocketOption(confd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(int));
	flags = 1;
	SetSocketOption(confd, SOL_SOCKET, SO_REUSEPORT, &flags, sizeof(int));

	// Connect to each other
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(u16_port);
	struct in_addr addr = {0};
	memcpy(&addr, &u32_ip, sizeof(u32_ip));
	inet_pton(AF_INET, inet_ntoa(addr), &servAddr.sin_addr);

	/*The default timeout timeout for Linux systems is 75s during blocking conditions*/
	if (SetFdNoBlocking(confd) < 0)
	{
		DEBUGLOG("setnonblock error");
		return -1;
	}

	ret = Connect(confd, (struct sockaddr *)&servAddr, sizeof(servAddr));

	struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
	getsockname(confd, (struct sockaddr*)&clientAddr, &clientAddrLen); // Gets the local address on the connection represented by sockfd
	connectedPort = ntohs(clientAddr.sin_port);

	if (ret != 0)
	{
		if (errno == EINPROGRESS)
		{
			struct epoll_event newPeerConnectionEvent;
			int epollFD = -1;
			struct epoll_event processableEvents;
			unsigned int numEvents = -1;

			if ((epollFD = epoll_create(1)) == -1)
			{
				ERRORLOG("Could not create the epoll FD list!");
				close(confd);
				return -2;
			}     

			newPeerConnectionEvent.data.fd = confd;
			newPeerConnectionEvent.events = EPOLLOUT | EPOLLIN | EPOLLERR;

			if (epoll_ctl(epollFD, EPOLL_CTL_ADD, confd, &newPeerConnectionEvent) == -1)
			{
				ERRORLOG("Could not add the socket FD to the epoll FD list!");
				close(confd);
				close(epollFD);
				return -3;
			}

			numEvents = epoll_wait(epollFD, &processableEvents, 1, 3*1000);

			if (numEvents < 0)
			{
				ERRORLOG("Serious error in epoll setup: epoll_wait () returned < 0 status!");
				close(epollFD);
				close(confd);
				return -4;
			}
			int retVal = -1;
			socklen_t retValLen = sizeof (retVal);
			if (getsockopt(confd, SOL_SOCKET, SO_ERROR, &retVal, &retValLen) < 0)
			{
				ERRORLOG("getsockopt SO_ERROR error!");
				close(confd);
				close(epollFD);
				return -5;
			}

			if (retVal == 0)  // succeed
			{
				close(epollFD);
				return confd;
			} 
			else
			{
				close(epollFD);
				close(confd);
				return -6;
			}	
		}
		else
		{
			close(confd);
			return -7;			
		}
	}

	return confd;
}

void net_com::SendMessageTask(const std::string& addr, BuildBlockBroadcastMsg &msg) {
  	net_com::SendMessage(addr, msg);
}

bool net_com::SendOneMessage(const Node &to, const NetPack &pack)
{
	auto msg = Pack::PackagToStr(pack);
	uint8_t priority = pack.flag & 0xF;

	return SendOneMessage(to, msg, priority);
}

bool net_com::SendOneMessage(const Node &to, const std::string &msg, const int8_t priority)
{
	MsgData sendData;
	sendData.type = E_WRITE;
	sendData.fd = to.fd;
	sendData.ip = to.publicIp;
	sendData.port = to.publicPort;
	
	MagicSingleton<BufferCrol>::GetInstance()->AddWritePack(sendData.ip, sendData.port, msg);
	bool bRet = global::g_queueWrite.Push(sendData);
	return true;

}

bool net_com::SendOneMessage(const MsgData& to, const NetPack &pack)
{
	MsgData sendData;
	sendData.type = E_WRITE;
	sendData.fd = to.fd;
	sendData.ip = to.ip;
	sendData.port = to.port;

	auto msg = Pack::PackagToStr(pack);	
	MagicSingleton<BufferCrol>::GetInstance()->AddWritePack(sendData.ip, sendData.port, msg);
	bool bRet = global::g_queueWrite.Push(sendData);
	return bRet;
}

bool net_com::SendEcdhMessage(const Node &dest, KeyExchangeRequest &msg)
{
	CommonMsg comm_msg;
	Pack::InitCommonMsg(comm_msg, msg, 0, 0);
	NetPack pack;
	Pack::PackCommonMsg(comm_msg, (uint8_t)Priority::kPriority_High_2, pack);

	return net_com::SendOneMessage(dest, pack);
}


uint64_t net_data::DataPackPortAndIp(uint16_t port, uint32_t ip)
{
	uint64_t ret = port;
	ret = ret << 32 | ip;
	return ret;
}

uint64_t net_data::DataPackPortAndIp(int port, std::string ip)
{
	uint64_t ret = port;
	uint32_t tmp;
	inet_pton(AF_INET, ip.c_str(), &tmp);
	ret = ret << 32 | tmp;
	return ret;
}
std::pair<uint16_t, uint32_t> net_data::DataPackPortAndIpToInt(uint64_t portAndIp)
{
	uint64_t tmp = portAndIp;
	uint32_t ip = tmp << 32 >> 32;
	uint16_t port = portAndIp >> 32;
	return std::pair<uint16_t, uint32_t>(port, ip);
}
std::pair<int, std::string> net_data::DataPackPortAndIpToString(uint64_t portAndIp)
{
	uint64_t tmp = portAndIp;
	uint32_t ip = tmp << 32 >> 32;
	uint16_t port = portAndIp >> 32;
	char buf[100];
	inet_ntop(AF_INET, (void *)&ip, buf, 16);
	return std::pair<uint16_t, std::string>(port, buf);
}

int net_com::AnalysisConnectionKind(Node &to)
{
	to.connKind = DRTO2O; //Outer and external direct connection
	return to.connKind;
}

bool net_com::InitializeNetwork()
{
	// Capture SIGPIPE signal to prevent accidental exit of the program
	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, NULL);

	// Block the SIGPIPE signal
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	sigprocmask(SIG_BLOCK, &set, NULL);

	// Ignore the SIGPIPE signal
	signal(SIGPIPE, SIG_IGN);

	if (MagicSingleton<Config>::GetInstance()->GetIP().empty())
	{
		std::string localhost_ip;
		if (!IpPort::GetLocalHostIp(localhost_ip))
		{
			DEBUGLOG("Failed to obtain the local Intranet IP address.");
			return false;
		}
		MagicSingleton<Config>::GetInstance()->SetIP(localhost_ip);
	}

	global::g_localIp = MagicSingleton<Config>::GetInstance()->GetIP();	
	
	// Get the native intranet IP address
	if(global::g_localIp.empty())
	{
		DEBUGLOG("IP address is empty.");
		return false;
	}

	if(IpPort::IsLan(global::g_localIp))
	{
		std::cout << "The current IP address is " << global::g_localIp << ". Please use an external IP address." << std::endl;
		return false;
	}

	INFOLOG("The Intranet ip is not empty");
	
	Account acc;
	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(acc) != 0)
	{
		return false;
	}

	MagicSingleton<PeerNode>::GetInstance()->SetSelfId(acc.GetAddr());
	MagicSingleton<PeerNode>::GetInstance()->SetSelfIdentity(acc.GetPubStr());
	MagicSingleton<PeerNode>::GetInstance()->SetSelfHeight();
	
	MagicSingleton<PeerNode>::GetInstance()->SetSelfIpListen(IpPort::IpNum(global::g_localIp.c_str()));
	MagicSingleton<PeerNode>::GetInstance()->SetSelfPortListen(SERVERMAINPORT);
	MagicSingleton<PeerNode>::GetInstance()->SetSelfIpPublic(IpPort::IpNum(global::g_localIp.c_str()));
	MagicSingleton<PeerNode>::GetInstance()->SetSelfPortPublic(SERVERMAINPORT);

	Config::Info info = {};
	MagicSingleton<Config>::GetInstance()->GetInfo(info);

	MagicSingleton<PeerNode>::GetInstance()->SetSelfName(info.name);
	MagicSingleton<PeerNode>::GetInstance()->SetSelfLogo(info.logo );

	MagicSingleton<PeerNode>::GetInstance()->SetSelfVer(global::kVersion);

	// Work thread pool start
	MagicSingleton<WorkThreads>::GetInstance()->Start();

	// Create a listening thread
	MagicSingleton<EpollMode>::GetInstance()->EpoolModeStart();
	
	// Start "refresh nodelist" thread 
    MagicSingleton<PeerNode>::GetInstance()->NodelistRefreshThreadInit();
	
	//Start Network node switching
	MagicSingleton<PeerNode>::GetInstance()->NodelistSwitchThread();

	// Start the heartbeat
	global::g_heartTimer.AsyncLoop(HEART_INTVL * 1000, net_com::DealHeart);

	return true;
}

//Test single message
int net_com::SendOneMessageByInput()
{
	DEBUGLOG(RED "SendOneMessageByInput start" RESET);
	std::string id;
	std::cout << "please input id:";
	std::cin >> id;

	while (true)
	{
		//Verify that the ID is legitimate
		bool result = isValidAddress(id);
		if (false == result)
		{
			std::cout << "invalid id , please input id:";
			std::cin >> id;
			continue;
		}
		else
		{
			break;
		}
	};

	std::string msg;
	std::cout << "please input msg:";
	std::cin >> msg;

	int num;
	std::cout << "please input num:";
	std::cin >> num;

	bool bl;
	for (int i = 0; i < num; ++i)
	{
		bl = net_com::SendPrintMsgReq(id, msg);

		if (bl)
		{
			printf("The %d send success\n", i + 1);
		}
		else
		{
			printf("The0 %d send fail\n", i + 1);
		}

	}
	return bl ? 0 : -1;
}

//Test the broadcast information
int net_com::BroadCastMessageByTest()
{
	std::string str_buf = "Hello World!";

	PrintMsgReq printMsgReq;
	printMsgReq.set_data(str_buf);

	bool isSucceed = net_com::BroadCastMessage(printMsgReq);
    if(isSucceed == false)
    {
        ERRORLOG(":broadcast PrintMsgReq failed!");
        return -1;
    }
	return 0;
}

bool net_com::SendBigDataByTest()
{
	std::string id;
	std::cout << "please input id:";
	std::cin >> id;
	auto IsVaild = [](std::string idStr) {
		int count = 0;
		for (auto i : idStr)
		{
			if (i != '1' || i != '0')
				return false;
			count++;
		}
		return count == 16;
	};
	while (IsVaild(id))
	{
		std::cout << "IsVaild id , please input id:";
		std::cin >> id;
	};
	Node tmpNode;
	if (!MagicSingleton<PeerNode>::GetInstance()->FindNode(std::string(id), tmpNode))
	{
		DEBUGLOG("invaild id, not in my peer node");
		return false;
	}
	std::string tmpData;
	int txtNum;
	std::cout << "please input test byte num:";
	std::cin >> txtNum;
	for (int i = 0; i < txtNum; i++)
	{
		char x, s;									  
		s = (char)rand() % 2;						  
		if (s == 1)									  
			x = (char)rand() % ('Z' - 'A' + 1) + 'A'; 
		else
			x = (char)rand() % ('z' - 'a' + 1) + 'a'; 
		tmpData.push_back(x);						 
	}
	tmpData.push_back('z');
	tmpData.push_back('z');
	tmpData.push_back('z');
	tmpData.push_back('z');
	tmpData.push_back('z');

	net_com::SendPrintMsgReq(tmpNode, tmpData, 1);
	return true;
}

bool net_com::SendPrintMsgReq(Node &to, const std::string data, int type)
{
	PrintMsgReq printMsgReq;
	printMsgReq.set_data(data);
	printMsgReq.set_type(type);
	net_com::SendMessage(to, printMsgReq);
	return true;
}

bool net_com::SendPrintMsgReq(const std::string & id, const std::string data, int type)
{
	PrintMsgReq printMsgReq;
	printMsgReq.set_data(data);
	printMsgReq.set_type(type);
	net_com::SendMessage(id, printMsgReq);
	return true;
}

int net_com::SendRegisterNodeReq(Node& dest, std::string &msgId, bool isGetNodeList)
{
	INFOLOG("SendRegisterNodeReq ip:{}, port:{} ,fd:{}",IpPort::IpSz(dest.publicIp), dest.publicPort, dest.fd);

	std::vector<Node> nodelist = MagicSingleton<PeerNode>::GetInstance()->GetNodelist();
	auto findResult = std::find_if(nodelist.begin(), nodelist.end(), [dest](const Node &findNode)
								{ return dest.address == findNode.address; });	
	if(findResult != nodelist.end()){
		DEBUGLOG("ConnectNode address:{}, ip:{}, port:{}",dest.address, IpPort::IpSz(dest.publicIp), dest.publicPort);
		return 0;
	}

	RegisterNodeReq getNodes;
	getNodes.set_is_get_nodelist(isGetNodeList);
	getNodes.set_msg_id(msgId);
	NodeInfo* mynode = getNodes.mutable_mynode();
	const Node & selfNode = MagicSingleton<PeerNode>::GetInstance()->GetSelfNode();

	if (dest.fd > 0)
	{
		return 0;
	}

	if(!isValidAddress(selfNode.address))
	{
		ERRORLOG(" SendRegisterNodeReq selfNode.address {} error",selfNode.address);
		return -1;
	}

    mynode->set_addr(selfNode.address);
	mynode->set_name(selfNode.name);
	mynode->set_listen_ip( selfNode.listenIp);
	mynode->set_logo(selfNode.logo);
	mynode->set_listen_port( selfNode.listenPort);

	mynode->set_time_stamp(MagicSingleton<TimeUtil>::GetInstance()->GetUTCTimestamp());
	mynode->set_height(MagicSingleton<PeerNode>::GetInstance()->GetSelfChainHeightNewest());
	mynode->set_version(global::kVersion);
	// sign
	std::string signature;
	Account acc;
	if(MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(acc) != 0)
	{
		ERRORLOG("The default account does not exist");
		return -2;
	}
	if (selfNode.address != acc.GetAddr())
	{
		ERRORLOG("The account address is incorrect : {} , : {}", selfNode.address, acc.GetAddr());
		return -3;
	}
	if(!acc.Sign(Getsha256hash(acc.GetAddr()), signature))
	{
		ERRORLOG("sign fail , address : {}", acc.GetAddr());
		return -4;
	}

	mynode->set_identity(acc.GetPubStr());
	mynode->set_sign(signature);

	auto ret = MagicSingleton<KeyExchangeManager>::GetInstance()->SendKeyExchangeReq(dest);
	if(ret < 0)
	{
		ERRORLOG("KeyExchange fail !!! ip:{}, fd:{}, ret:{}",IpPort::IpSz(dest.publicIp), dest.fd, ret);
		return -5;
	}
	std::string ipPort = std::to_string(dest.publicIp) + ":" + std::to_string(dest.publicPort);
	DEBUGLOG("AddResNode, msg_id:{} peerId:{}", msgId, ipPort);
	if(!GLOBALDATAMGRPTR.AddResNode(msgId, ipPort))
	{
		return -6;
	}
	net_com::SendMessage(dest, getNodes, net_com::Compress::kCompress_True, net_com::Priority::kPriority_High_2);
	
	return 0;
}

void net_com::SendPingReq(const Node& dest)
{
	PingReq pingReq;
	std::string defaultAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr();
	pingReq.set_id(defaultAddr);
	DEBUGLOG("dest addr:{}", dest.address);
	net_com::SendMessage(dest, pingReq, net_com::Compress::kCompress_True, net_com::Priority::kPriority_High_2);
}

void net_com::SendPongReq(const Node& dest)
{
	PongReq pongReq;
	std::string defaultAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultAddr();
	pongReq.set_id(defaultAddr);
	DEBUGLOG("dest addr:{}", dest.address);
	net_com::SendMessage(dest, pongReq, net_com::Compress::kCompress_True, net_com::Priority::kPriority_High_2);
}

void net_com::DealHeart()
{
	Node mynode = MagicSingleton<PeerNode>::GetInstance()->GetSelfNode();	
	std::vector<Node> pubNodeList = MagicSingleton<PeerNode>::GetInstance()->GetNodelist();

	//Exclude yourself
	std::vector<Node>::iterator end = pubNodeList.end();
	for(std::vector<Node>::iterator it = pubNodeList.begin(); it != end; ++it)
	{
		if(mynode.address == it->address)
		{
			it = pubNodeList.erase(it);
		}
	}
	std::vector<Node> nodelist;
	nodelist.insert(nodelist.end(),pubNodeList.begin(),pubNodeList.end());
	for(auto &node:nodelist)
	{
		node.pulse -= 1;
		if(node.pulse <= 0)
		{
			// net_com::SendPingReq(node);
			DEBUGLOG("DealHeart delete node: {}, ip:{} , port:{}, fd:{}", node.address, IpPort::IpSz(node.publicIp), node.publicPort, node.fd);

			MagicSingleton<PeerNode>::GetInstance()->DeleteNode(node.address);
		}
		else
		{
			MagicSingleton<PeerNode>::GetInstance()->Update(node);
			DEBUGLOG("SendPingReq, ip:{} , port:{}, fd:{}", IpPort::IpSz(node.publicIp), node.publicPort, node.fd);
			net_com::SendPingReq(node);
		}
	}	
}

bool net_com::SendSyncNodeReq(const Node& dest, std::string &msgId)
{
	DEBUGLOG("SendSyncNodeReq from.ip:{}", IpPort::IpSz(dest.publicIp));
	SyncNodeReq syncNodeReq;
	//Get its own node information
	auto self_node = MagicSingleton<PeerNode>::GetInstance()->GetSelfNode();
	std::vector<Node> nodelist = MagicSingleton<PeerNode>::GetInstance()->GetNodelist();
	
	if(nodelist.size() == 0)
	{
		return false;
	}
	//Stores its own node ID
	syncNodeReq.set_ids(std::move(self_node.address));
	syncNodeReq.set_msg_id(msgId);
	if(!GLOBALDATAMGRPTR.AddResNode(msgId, dest.address))
	{
		return false;
	}
	return net_com::SendMessage(dest, syncNodeReq, net_com::Compress::kCompress_True, net_com::Priority::kPriority_High_2);
}

void net_com::SendNodeHeightChanged()
{
	NodeHeightChangedReq heightChangeReq;
	std::string selfId = MagicSingleton<PeerNode>::GetInstance()->GetSelfId();

	heightChangeReq.set_id(selfId);
	uint32 chainHeight = 0;
	int ret = net_callback::chainHeightCallback(chainHeight);
	heightChangeReq.set_height(chainHeight);

	Account defaultEd;
	MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultEd);

	std::stringstream Height;

	Height << selfId << "_" << std::to_string(chainHeight);
	std::string serVinHash = Getsha256hash(Height.str());
	std::string signature;
	std::string pub;

	if (defaultEd.Sign(serVinHash, signature) == false)
	{
		std::cout << "tx sign fail !" << std::endl;
	}
	CSign * sign = heightChangeReq.mutable_sign();
	sign->set_sign(signature);
	sign->set_pub(defaultEd.GetPubStr());


	auto selfNode = MagicSingleton<PeerNode>::GetInstance()->GetSelfNode();
	std::vector<Node> publicNodes = MagicSingleton<PeerNode>::GetInstance()->GetNodelist();
	for (auto& node : publicNodes)
	{
		net_com::SendMessage(node, heightChangeReq, net_com::Compress::kCompress_False, net_com::Priority::kPriority_High_2);
	}
}

namespace net_callback
{
	GetChainHeightCallback chainHeightCallback =  nullptr;
	CalculateChainHeightCallback calculateChainHeightCallback = nullptr;
}

void net_callback::RegisterChainHeightCallback(GetChainHeightCallback callback)
{
	net_callback::chainHeightCallback = callback;
}

void net_callback::RegisterCalculateChainHeightCallback(CalculateChainHeightCallback callback)
{
	net_callback::calculateChainHeightCallback = callback;
}

bool net_com::BroadBroadcastMessage( BuildBlockBroadcastMsg& BuildBlockMsg, const net_com::Compress isCompress, const net_com::Encrypt isEncrypt, const net_com::Priority priority)
{	
	const std::vector<Node>&& publicNodeList = MagicSingleton<PeerNode>::GetInstance()->GetNodelist();
	if(publicNodeList.empty())
	{
		ERRORLOG("publicNodeList is empty!");
		return false;
	}

	const double threshold = 0.25;
	const std::size_t cntUnConnected = std::count_if(publicNodeList.cbegin(), publicNodeList.cend(), [](const Node &node){ return node.fd == -1;});
	double percent = static_cast<double>(cntUnConnected) / publicNodeList.size();
	if(percent > threshold)
	{
		ERRORLOG("Unconnected nodes are {},accounting for {}%", cntUnConnected, percent * 100);
		return false;
	}

	INFOLOG("Verification passed, start broadcasting!");

	CBlock block;
    block.ParseFromString(BuildBlockMsg.blockraw());

	int top_=block.height();
	
	auto getNextNumber=[&](int limit) ->int {
	  	std::random_device seed;
	 	std::ranlux48 engine(seed());
	 	std::uniform_int_distribution<int> u(0, limit-1);
	 	return u(engine);
	};

	auto getTargetIndexs=[&](int num,int limit,const std::vector<Node> & source)->std::set<std::string>
	{
		std::set<std::string> allAddresses;
		if(limit < num){
			ERRORLOG(" The source is less the num !! [limit:{}],[num:{}]",limit,num);
			return allAddresses;
		}
		else if(limit == num)
		{
			for(const auto & node : source)
			{
				allAddresses.insert(node.address);
			}
			return allAddresses;
		}

		while(allAddresses.size()< num){
			int index=getNextNumber(limit);
			allAddresses.insert(source[index].address);
		}
		return allAddresses;
	};

	auto getRootOfEquation=[](int listSize)->int
	{
		int x1=(-1+std::sqrt(1-4*(-listSize)))/2;
		int x2=(-1-std::sqrt(1-4*(-listSize)))/2;
		return (x1 >0) ? x1:x2;
	};

	std::vector<Node> nodeList = MagicSingleton<PeerNode>::GetInstance()->GetNodelist();
	std::set<std::string> addrs;
	
	if(block.height() < global::ca::kMinUnstakeHeight)
	{
		if(nodeList.size() <= global::g_broadcastThreshold)
		{
			BuildBlockMsg.set_type(1);//Set the number of broadcasts to two
			for(auto &node : nodeList)
			{
				BuildBlockMsg.add_castaddrs(node.address);
			}
			for(auto & node : nodeList){
				MagicSingleton<TaskPool>::GetInstance()->CommitBroadcastTask(std::bind(&net_com::SendMessageTask, node.address, BuildBlockMsg));
			}

		}else{
			std::set<std::string> addrs = getTargetIndexs(global::g_broadcastThreshold,nodeList.size(),nodeList);
			BuildBlockMsg.set_type(1);//Set the number of broadcasts to 1
			
			for(auto &addr:addrs)
			{
				BuildBlockMsg.add_castaddrs(addr);	
			}
			for(auto & addr : addrs) {		
				MagicSingleton<TaskPool>::GetInstance()->CommitBroadcastTask(std::bind(&net_com::SendMessageTask, addr, BuildBlockMsg));
			}
		}
	}
	else
	{
		DBReader dbReader;
		std::vector<Node> eligibleAddress;
		std::vector<std::string> pledgeUtxoHashs;
		for(auto & node : nodeList)
		{
			//Verification of  pledge
			int ret = dbReader.GetStakeAddressUtxo(node.address, pledgeUtxoHashs);
			if(DBStatus::DB_SUCCESS == ret || !pledgeUtxoHashs.empty()){
				eligibleAddress.push_back(node);
			}
		}

		if(nodeList.size() >= global::g_broadcastThreshold * global::g_broadcastThreshold)
		{
			int m = getRootOfEquation(nodeList.size());
			int threshold = eligibleAddress.size() > m ? m : eligibleAddress.size();
			addrs = getTargetIndexs(threshold, eligibleAddress.size(), eligibleAddress);
			
			BuildBlockMsg.set_type(1);//Set the number of broadcasts to 1
			for(auto &addr:addrs)
			{
				BuildBlockMsg.add_castaddrs(addr);	
			}
			
			for(auto & addr : addrs){	
				MagicSingleton<TaskPool>::GetInstance()->CommitBroadcastTask(std::bind(&net_com::SendMessageTask, addr, BuildBlockMsg));
			}
		}
		else
		{
			int threshold = eligibleAddress.size() > global::g_broadcastThreshold ? global::g_broadcastThreshold : eligibleAddress.size();
			std::set<std::string> addrs = getTargetIndexs(threshold, eligibleAddress.size(), eligibleAddress);

			BuildBlockMsg.set_type(1);//Set the number of broadcasts to 1
			
			for(auto & addr : addrs)
			{
				BuildBlockMsg.add_castaddrs(addr);	
			}

			for(auto & addr : addrs){	
				MagicSingleton<TaskPool>::GetInstance()->CommitBroadcastTask(std::bind(&net_com::SendMessageTask, addr, BuildBlockMsg));
			}
		}
	}
	
	return true;
}