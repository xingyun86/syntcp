// UdpClient.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <iostream>

// TODO: Reference additional headers your program requires here.

#include <network.h>

class UdpClient {
public:
	uint32_t nSendDataSize = 102400;
	uint32_t nRecvDataSize = 102400;
public:
#pragma pack(1)
	typedef enum AnchorMode {
		AnchorModeType_NORMAL = 0,
		AnchorModeType_LOCATE,
	};
	typedef struct ArtNetHeader {
		uint8_t ID[8];
		uint16_t OpCode;
	};
	typedef struct ArtNetVerHeader {
		ArtNetHeader Header;
		uint16_t ProtVer;
	};
	typedef struct ArtAddressPacket {
		uint8_t NetSwitch1;
		uint8_t filler;
		uint8_t ShortName[18];
		uint8_t LongName[64];
		uint8_t InputSubswitch[4];
		uint8_t OutputSubswitch[4];
		uint8_t NetSwitch2;
		uint8_t SwVideo;
		uint8_t Command;
	};
	typedef struct ArtIpProgCommad {
		uint8_t ProgramPort : 1;
		uint8_t ProgramSubnetMask : 1;
		uint8_t ProgramIP : 1;
		uint8_t ResetParameters : 1;
		uint8_t Unused : 2;
		uint8_t EnableDHCP : 1;
		uint8_t EnableProgramming : 1;
	};
	typedef struct ArtIpProgPacket {
		uint16_t filler1;
		ArtIpProgCommad Command;
		uint8_t filler2;
		uint32_t IPAddress;
		uint32_t SubnetMask;
		uint16_t Port;
		uint8_t spare[8];
	};
	typedef struct ArtPollReplyStatus1 {
		uint8_t UbeaPresent : 1;
		uint8_t RDMSupported : 1;
		uint8_t ROMBooted : 1;
		uint8_t unused0 : 1;
		uint8_t PortAddressProgrammingAuthority : 2;
		uint8_t IndicatorState : 2;
	};
	typedef struct ArtPollReplyPortInfo {
		uint16_t NumberOfPorts;
		uint8_t PortTypes[4];
		uint8_t InputStatus[4];
		uint8_t OutputStatus[4];
		uint8_t InputSubswitch[4];
		uint8_t OutputSubswitch[4];
	};

	typedef struct ArtPollReplyStatus2 {
		uint8_t WebConfigurationSupported : 1;
		uint8_t DHCPConfigurationUsed : 1;
		uint8_t DHCPConfigurationSupported : 1;
		uint8_t PortAddressSize : 1;
		uint8_t unused0:4;
	};
	typedef struct ArtPollReplyPacket {
		uint32_t IPAddress;
		uint16_t PortNumber;
		uint16_t VersionInfo;
		uint8_t NetSwitch;
		uint8_t SubSwitch;
		uint16_t Oem;
		uint8_t UBEA;
		ArtPollReplyStatus1 Status1;
		uint16_t ESTACode;
		uint8_t ShortName[18];
		uint8_t LongName[64];
		uint8_t NodeReport[64];
		ArtPollReplyPortInfo PortInfo;
		uint8_t SwVideo;
		uint8_t SwMacro;
		uint8_t SwRemote;
		uint8_t spare[3];
		uint8_t Style;
		uint8_t MAC[6];
		uint32_t BindIPAddress;
		uint8_t BindIndex;
		ArtPollReplyStatus2 Status2;
		uint8_t filler[26];
	};
	typedef struct ArtIpProgReplyStatus {
		uint8_t Unused0 : 6;
		uint8_t DHCPEnabled : 1;
		uint8_t Unused1 : 1;
	};
	typedef struct ArtIpProgReplyPacket {
		uint32_t filler;
		uint32_t IPAddress;
		uint32_t SubnetMask;
		uint16_t port;
		ArtIpProgReplyStatus Status;
		uint8_t spare[7];
	};
	typedef struct ArtAddressMsg {
		ArtNetVerHeader hdr;//OpCode=ArtAddress(0x6000)
		ArtAddressPacket pkt;
		uint8_t exc;
	};
	typedef struct ArtIpProgMsg {
		ArtNetVerHeader hdr;//OpCode=ArtIpProg(0xf800)
		ArtIpProgPacket pkt;
	};
	typedef struct ArtPollReplyMsg {
		ArtNetHeader hdr;//OpCode=ArtPollReply(0x2100)
		ArtPollReplyPacket pkt;
	};
	typedef struct ArtIpProgReplyMsg {
		ArtNetVerHeader hdr;//OpCode=ArtIpProg(0xf900)
		ArtIpProgReplyPacket pkt;
	};
#pragma pack()
	void setArtIpProgMsg(ArtIpProgMsg& msg, const char * ip, const char * mask="255.0.0.0")
	{
		memset(&msg, 0, sizeof(msg));
		memcpy(msg.hdr.Header.ID, "Art-Net", 7);
		msg.hdr.Header.OpCode = (0xf800);//ArtIpProg(0xf800)
		msg.hdr.ProtVer = (0x0e00);
		msg.pkt.filler1 = 0x0000;
		msg.pkt.Command.ProgramPort = 0x0;
		msg.pkt.Command.ProgramSubnetMask = 0x1;
		msg.pkt.Command.ProgramIP = 0x1;
		msg.pkt.Command.ResetParameters = 0x0;
		msg.pkt.Command.Unused = 0x01;
		msg.pkt.Command.EnableDHCP = 0x0;
		msg.pkt.Command.EnableProgramming = 0x1;
		msg.pkt.filler1 = 0x00;
		msg.pkt.IPAddress = inet_addr(ip);
		msg.pkt.SubnetMask = inet_addr(mask);
		msg.pkt.Port = 0x1936;
		memset(&msg.pkt.spare, 0, sizeof(msg.pkt.spare));
		memset(&msg.pkt.spare, 0xff, sizeof(msg.pkt.spare)/2);
	}
	void setArtAddressMsg(ArtAddressMsg& msg, AnchorMode mode)
	{
		memset(&msg, 0, sizeof(msg));
		memcpy(msg.hdr.Header.ID, "Art-Net", 7);
		msg.hdr.Header.OpCode = (0x6000);//ArtAddress(0x6000)
		msg.hdr.ProtVer = (0x0e00);
		msg.pkt.NetSwitch1 = 0x7f;
		memset(msg.pkt.InputSubswitch, 0x7f, sizeof(msg.pkt.InputSubswitch));
		memset(msg.pkt.OutputSubswitch, 0x7f, sizeof(msg.pkt.OutputSubswitch));
		msg.pkt.NetSwitch2 = 0x7f;
		msg.pkt.SwVideo = 0xff;
		switch (mode)
		{
		case UdpClient::AnchorModeType_NORMAL:msg.pkt.Command = 0x02;
			break;
		case UdpClient::AnchorModeType_LOCATE:msg.pkt.Command = 0x04;
			break;
		}
		msg.exc = 0x00;
	}

	int do_send_recv_data(
		void* recv_data, size_t recv_size, 
		const void* send_data, size_t send_size, 
		const char* dst_ip, const char* ip, const uint16_t port = 0x1936)
	{
		int ret = (-1);
		int sendBytes = 0;
		int recvBytes = 0;
		int tickcnt = 0;
		int timeout = 1000;
		const int optval = 1;
		PPS_SOCKET sendSocket = PPS_INVALID_SOCKET;
		sockaddr_in nameSockAddr;
		int nameSockAddrSize = sizeof(nameSockAddr);
		sockaddr_in sendSockAddr;
		int sendSockAddrSize = sizeof(sendSockAddr);
		sockaddr_in recvSockAddr;
		int recvSockAddrSize = sizeof(recvSockAddr);

		sendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
		ret = setsockopt(sendSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));
		if (ret == 0)
		{
			nameSockAddr.sin_family = AF_INET;
			nameSockAddr.sin_port = htons(port);
			nameSockAddr.sin_addr.s_addr = inet_addr(ip);
			ret = bind(sendSocket, (const sockaddr*)&nameSockAddr, nameSockAddrSize);
			if (ret == 0)
			{
				sendSockAddr.sin_family = AF_INET;
				sendSockAddr.sin_port = htons(port);
				sendSockAddr.sin_addr.s_addr = inet_addr(dst_ip);
				sendBytes = sendto(sendSocket, (const char*)send_data, send_size, 0, (const sockaddr*)&sendSockAddr, sendSockAddrSize);
				while (sendBytes == send_size) {
					std::this_thread::sleep_for(std::chrono::microseconds(100));
					tickcnt += 100;
					recvBytes = recvfrom(sendSocket, (char*)recv_data, recv_size, 0, (sockaddr*)&recvSockAddr, &recvSockAddrSize);
					if (recvBytes == recv_size) {
						ret = 0;
						break;
					}
					if (tickcnt >= timeout)
					{
						ret = (-1);
						break;
					}
				}
			}
		}
		PPS_CloseSocket(sendSocket);

		return ret;
	}
	int do_send_message(const char* dst_ip, const char* ip, const uint16_t port = 0x1936)
	{
		PPS_SOCKET sendSocket = PPS_INVALID_SOCKET;
		sockaddr_in sendSockAddr;//地址
		int sendSockAddrSize = sizeof(sendSockAddr);
		sockaddr_in recvSockAddr;//地址
		int recvSockAddrSize = sizeof(recvSockAddr);

		//创建Socket对象
		sendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
		const int optval = 1;
		//setsockopt(recvSocket, SOL_SOCKET, SO_BROADCAST, (char*)&optval, sizeof(optval)); //设置套接字选项
		setsockopt(sendSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval)); //设置地址复用选项
		//设置地址
		sockaddr_in nameSockAddr;//地址
		int nameSockAddrSize = sizeof(nameSockAddr);
		nameSockAddr.sin_family = AF_INET;
		nameSockAddr.sin_port = htons(port);
		nameSockAddr.sin_addr.s_addr = inet_addr(ip);
		bind(sendSocket, (const sockaddr*)&nameSockAddr, nameSockAddrSize);

		sendSockAddr.sin_family = AF_INET;
		sendSockAddr.sin_port = htons(port);
		sendSockAddr.sin_addr.s_addr = inet_addr(dst_ip);

		//从服务器接收数据报
		printf("Recving a datagram from the sender...\n");

		uint32_t send_size = nSendDataSize;
		uint8_t* send_data = new uint8_t[send_size]();
		uint32_t recv_size = nRecvDataSize;
		uint8_t* recv_data = new uint8_t[recv_size]();
		ArtAddressMsg addressMsg;
		//setArtAddressMsgNormal(addressMsg);
		//setArtAddressMsgIdentify(addressMsg);
		ArtIpProgMsg ipProgMsg;
		setArtIpProgMsg(ipProgMsg, "2.170.25.41");
		memcpy(send_data, &ipProgMsg, sizeof(ipProgMsg));
		send_size = sizeof(ipProgMsg);
		int i = 0;
		int iMax = 1;
		while (i++ < iMax)
		{
			int sendBytes = sendto(sendSocket, (const char*)send_data, send_size, 0, (const sockaddr*)&sendSockAddr, sendSockAddrSize);
			printf("sendto [%d] packet bytes=%d!\n", i, sendBytes);
			while (1)
			{
				std::this_thread::sleep_for(std::chrono::microseconds(100));
				int recvBytes = recvfrom(sendSocket, (char*)recv_data, recv_size, 0, (sockaddr*)&recvSockAddr, &recvSockAddrSize);
				if (recvBytes == sizeof(ArtPollReplyMsg)) {
					printf("recvfrom [%d] packet bytes=%d!\n", i, recvBytes);
					ArtPollReplyMsg* pMsg = (ArtPollReplyMsg*)recv_data;
					printf("IndicatorState=%d(0x%x)\n", pMsg->pkt.Status1.IndicatorState, pMsg->pkt.Status1.IndicatorState);
					break;
				}
				else if (recvBytes == sizeof(ArtIpProgReplyMsg)) {
					printf("recvfrom [%d] packet bytes=%d!\n", i, recvBytes);
					ArtIpProgReplyMsg* pMsg = (ArtIpProgReplyMsg*)recv_data;
					printf("IP=0x%x,SubnetMask=0x%x\n", pMsg->pkt.IPAddress, pMsg->pkt.SubnetMask);
					break;
				}
			}
		}
		delete[]recv_data;
		delete[]send_data;
		//发送完成，关闭Socket
		printf("finished recving,close socket.\n");
		PPS_CloseSocket(sendSocket);
		printf("Exting.\n");

		return 0;
	}
	int do_recv_groupcast(const char* ip, const char* group_ip = "239.2.2.2", const uint16_t port = 10101)
	{
		int nRet = 0;
		u_long nOptVal = 1;
		PPS_SOCKET sock = PPS_INVALID_SOCKET;

		sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

		if (sock == PPS_INVALID_SOCKET) {
			printf("Error at socket(): %d,%s\n", NET_ERR_CODE, NET_ERR_STR(NET_ERR_CODE).c_str());
			return 1;
		}

		sockaddr_in recvSockAddr = { 0 };
		int recvSockAddrSize = sizeof(recvSockAddr);
		sockaddr_in nameSockAddr = { 0 };
		int nameSockAddrSize = sizeof(nameSockAddr);
		ip_mreq multiCastMreq = { 0 };
		int multiCastMreqSize = sizeof(multiCastMreq);

		nameSockAddr.sin_family = AF_INET;
		nameSockAddr.sin_addr.s_addr = inet_addr(ip);
		nameSockAddr.sin_port = htons(port);

		multiCastMreq.imr_interface.s_addr = inet_addr(ip);
		multiCastMreq.imr_multiaddr.s_addr = inet_addr(group_ip);

		///////////////////////////////////////////////////////////
		//0 restricted to the same host
		//1 restricted to the same subnet
		//32 restricted to the same site
		//64 restricted to the same region
		//128 restricted to the same continent
		//255 unrestricted
		///////////////////////////////////////////////////////////
		nOptVal = 255; // TTL[0,255]
		nRet = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&nOptVal, sizeof(nOptVal));
		if (nRet != 0) {
			printf("setsockopt fail:%d(%s)", NET_ERR_CODE, NET_ERR_STR(NET_ERR_CODE));
			return -1;
		}
		nOptVal = 1;//loop=0禁止回送，lpoop=1允许回送
		nRet = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char*)&nOptVal, sizeof(nOptVal));
		if (nRet != 0) {
			printf("setsockopt fail:%d(%s)", NET_ERR_CODE, NET_ERR_STR(NET_ERR_CODE));
			return -1;
		}
		nOptVal = 1;
		nRet = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&nOptVal, sizeof(nOptVal));
		if (nRet != 0) {
			printf("setsockopt fail:%d(%s)", NET_ERR_CODE, NET_ERR_STR(NET_ERR_CODE));
			return -1;
		}

		// 加入组播
		nRet = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&multiCastMreq, multiCastMreqSize);
		if (nRet != 0) {
			printf("setsockopt fail:%d(%s)", NET_ERR_CODE, NET_ERR_STR(NET_ERR_CODE));
			return -1;
		}

		nRet = bind(sock, (sockaddr*)&nameSockAddr, (int)nameSockAddrSize);
		if (nRet != 0) {
			printf("bind fail:%d(%s)", NET_ERR_CODE, NET_ERR_STR(NET_ERR_CODE));
			return -1;
		}
		printf("socket:%d bind success\n", sock);

		printf("udp group start\n");
		uint32_t send_size = nSendDataSize;
		uint8_t* send_data = new uint8_t[send_size]();
		uint32_t recv_size = nRecvDataSize;
		uint8_t* recv_data = new uint8_t[recv_size]();
		while (true)
		{
			memset(recv_data, 0, recv_size);
			nRet = recvfrom(sock, (char*)recv_data, recv_size, 0, (sockaddr*)&recvSockAddr, (PPS_SOCKLEN_T*)&recvSockAddrSize);
			if (nRet <= 0) {
				printf("recvfrom fail:%d(%s)", NET_ERR_CODE, NET_ERR_STR(NET_ERR_CODE));
				return -1;
			}
			char ip[16] = { 0 };
			PPS_INET_NTOA_IPV4(ip, sizeof(ip) / sizeof(*ip), &recvSockAddr.sin_addr);
			printf("[%s]recv data:(%d)%s\n", ip, nRet, (char*)recv_data);
		}
		delete[]recv_data;
		delete[]send_data;

		PPS_CloseSocket(sock);

		return 0;
	}
	int do_recv_broadcast(const char* ip, const uint16_t port = 0x1936)
	{
		PPS_SOCKET recvSocket = PPS_INVALID_SOCKET;
		sockaddr_in recvSockAddr;//服务器地址
		int recvSockAddrSize = sizeof(recvSockAddr);

		//创建Socket对象
		recvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
		const int optval = 1;
		//setsockopt(recvSocket, SOL_SOCKET, SO_BROADCAST, (char*)&optval, sizeof(optval)); //设置套接字选项
		setsockopt(recvSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval)); //设置地址复用选项
		//设置服务器地址
		sockaddr_in nameSockAddr;//服务器地址
		int nameSockAddrSize = sizeof(nameSockAddr);
		nameSockAddr.sin_family = AF_INET;
		nameSockAddr.sin_port = htons(port);
		nameSockAddr.sin_addr.s_addr = inet_addr(ip);
		bind(recvSocket, (const sockaddr*)&nameSockAddr, nameSockAddrSize);

		//从服务器接收数据报
		printf("Recving a datagram from the sender...\n");

		uint32_t send_size = nSendDataSize;
		uint8_t* send_data = new uint8_t[send_size]();
		uint32_t recv_size = nRecvDataSize;
		uint8_t* recv_data = new uint8_t[recv_size]();
		int i = 0;
		int iMax = 100;
		while (i++ < iMax)
		{
			int recvBytes = recvfrom(recvSocket, (char*)recv_data, recv_size, 0, (sockaddr*)&recvSockAddr, (PPS_SOCKLEN_T*)&recvSockAddrSize);
			printf("recvfrom [%d] packet bytes=%d!\n", i, recvBytes);
			//sendto(recvSocket, (const char*)recv_data, recv_size, 0, (const sockaddr*)&fromAddr, fromAddrSize);
			std::this_thread::sleep_for(std::chrono::microseconds(1000));
		}
		delete[]recv_data;
		delete[]send_data;
		//发送完成，关闭Socket
		printf("finished recving,close socket.\n");
		PPS_CloseSocket(recvSocket);
		printf("Exting.\n");

		return 0;
	}
	int run()
	{
		NET_INIT();
		char hostname[33] = { 0 };
		std::vector<std::shared_ptr<std::thread>> task_list;
		std::vector<std::string> ipv4_list;
		SockUtil::Inst()->enum_host_addr_ipv4(ipv4_list);
		ArtAddressMsg addressMsg;
		ArtPollReplyMsg pollReplyMsg;
		setArtAddressMsg(addressMsg, AnchorModeType_NORMAL);
		int ret = do_send_recv_data(&pollReplyMsg, sizeof(pollReplyMsg), &addressMsg, sizeof(addressMsg), "2.170.25.41", "2.168.1.140", 6454);
		if (ret == 0)
		{
			printf("Success(0x%x)\n", pollReplyMsg.pkt.Status1.IndicatorState);
		}
		else
		{
			printf("Failure(%d)\n", ret);
		}
		return 0;
		for (auto it: ipv4_list)
		{
			auto* pit = &it;
			struct in_addr _in_addr = { 0 };
			PPS_INET_ATON_IPV4(&_in_addr, it.c_str());
			task_list.push_back(std::make_shared<std::thread>(
				[](void* p)
				{
					char ip[16] = { 0 };
					struct in_addr _in_addr = { 0 };
					_in_addr.s_addr = (unsigned long)p;
					PPS_INET_NTOA_IPV4(ip, sizeof(ip) / sizeof(*ip), &_in_addr);
					//UdpClient::Inst()->do_recv_broadcast(ip);
					//UdpClient::Inst()->do_recv_groupcast(ip, "224.0.2.101", 9981);
					UdpClient::Inst()->do_send_message("2.170.25.40", ip);
				}, (void*)_in_addr.s_addr)
			);
		}
		for (auto& it : task_list)
		{
			if (it->joinable())
			{
				it->join();
			}
		}
		return 0;
	}
public:
	static UdpClient* Inst()
	{
		static UdpClient UdpClientInstance;
		return &UdpClientInstance;
	}
};