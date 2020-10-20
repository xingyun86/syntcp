// SynTcp.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <iostream>

// TODO: Reference additional headers your program requires here.
// SyncTcpClient.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define  _WINSOCK_DEPRECATED_NO_WARNINGS 
#include <string>
#include <thread>
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")

typedef enum
{
	CMD_HB = 0x0,
	CMD_ADD = 0x1,
	CMD_DEL = 0x2,
	CMD_MOD = 0x3,
	CMD_QRY = 0x4,
} CMD_TYPE;

typedef enum {
	DAT_HB = 0x0,
	DAT_USER = 0x1,
	DAT_MAXIMUM,
} DAT_TYPE;

#pragma pack(1)
typedef struct
{
	uint16_t cmd; //CMD_TYPE
	uint16_t dat; //DAT_TYPE
	uint8_t gzip;
	uint32_t len;
}PACKET_HEADER;
#pragma pack()

class WinSockEnv {
public:
	WSADATA wsadata = { 0 };
	WinSockEnv()
	{
		//初始化套接字库
		WORD w_req = MAKEWORD(2, 2);//版本号
		int err;
		err = WSAStartup(w_req, &wsadata);
		if (err != 0)
		{
			std::cout << "Initialize winsock library failed！" << std::endl;
		}
		else
		{
			std::cout << "Initialize winsock library ok！" << std::endl;
		}
		//检测版本号
		if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wHighVersion) != 2)
		{
			std::cout << "Winsock library version failed！" << std::endl;
			WSACleanup();
		}
		else
		{
			std::cout << "Winsock library version ok！" << std::endl;
		}
	}
	~WinSockEnv()
	{
		WSACleanup();
	}
public:
	static WinSockEnv* Inst()
	{
		static WinSockEnv winSockEnvInstance;
		return &winSockEnvInstance;
	}
};
class ClientHandle {
public:
	const char* pHost = "192.168.1.140";
	unsigned short nPort = 1234;
	int seq = 1;
	std::string recv_data = "";
	std::string send_json = "";
	CMD_TYPE cmd;
	DAT_TYPE dat;
	bool bRunning = false;
private:
	int send_with_recv_core(std::string& recv_data, const std::string& send_data, const char* pHost, unsigned short nPort)
	{
		int ret = 0;
		size_t send_len = 0;
		size_t recv_len = 0;
		u_long nNonBlock = 0;
		SOCKET s = INVALID_SOCKET;
		sockaddr_in sain = { 0 };

		recv_data.resize(102400, '\0');

		sain.sin_family = AF_INET;
		sain.sin_addr.s_addr = inet_addr(pHost);
		sain.sin_port = htons(nPort);

		s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
		if (s == INVALID_SOCKET)
		{
			std::cout << "Socket failed！ErrId=" << WSAGetLastError() << std::endl;
			ret = -1;
			goto __LEAVE_CLEAN__;
		}

		if (ioctlsocket(s, FIONBIO, &nNonBlock) == SOCKET_ERROR)
		{
			std::cout << "ioctlsocket() failed with error!ErrId=" << WSAGetLastError() << std::endl;
			ret = -3;
			goto __LEAVE_CLEAN__;
		}

		if (connect(s, (const sockaddr*)&sain, sizeof(sockaddr)) == SOCKET_ERROR)
		{
			std::cout << "Connect to server failed！ErrId=" << WSAGetLastError() << std::endl;
			usage();
			ret = -2;
			goto __LEAVE_CLEAN__;
		}
		std::cout << "Connect to server ok！" << std::endl;

		send_len = send(s, send_data.data(), (int)send_data.size(), 0);
		if (send_len < 0)
		{
			std::cout << "Send failed！ErrId=" << WSAGetLastError() << std::endl;
			ret = -4;
			goto __LEAVE_CLEAN__;
		}
		std::cout << "Send ok！" << send_data.c_str() << std::endl;
		recv_len = recv(s, (char*)recv_data.data(), (int)recv_data.size(), 0);
		if (recv_len < 0)
		{
			std::cout << "Recv failed！ErrId=" << WSAGetLastError() << std::endl;
			ret = -5;
			goto __LEAVE_CLEAN__;
		}
		std::cout << "Recv ok:" << recv_data.c_str() << std::endl;

	__LEAVE_CLEAN__:
		if (s != INVALID_SOCKET)
		{
			shutdown(s, 2);
			closesocket(s);
		}

		return ret;
	}
	int send_with_recv(std::string& recv_data, CMD_TYPE cmd, DAT_TYPE dat, const std::string& send_json, const char* pHost, unsigned short nPort)
	{
		PACKET_HEADER header = { 0 };
		std::string send_data(sizeof(header) + send_json.size(), '\0');
		header.cmd = cmd;
		header.dat = dat;
		header.len = (uint32_t)send_json.size();
		memcpy((void*)(send_data.data()), &header, sizeof(header));
		memcpy((void*)(send_data.data() + sizeof(header)), send_json.data(), header.len);
		return send_with_recv_core(recv_data, send_data, pHost, nPort);
	}
	void print_debug(const std::string& data) {
		if (data.size() > sizeof(PACKET_HEADER))
		{
			PACKET_HEADER* pHeader = (PACKET_HEADER*)data.data();
			if (pHeader != NULL)
			{
				std::string json = data.substr(sizeof(PACKET_HEADER));
				std::cout << "cmd=" << pHeader->cmd << ",dat=" << pHeader->dat << ",len=" << pHeader->len << std::endl;
				std::cout << json.c_str() << std::endl;
			}
		}
	}
	void help()
	{
		std::cout << R"(
		Help: 0-exit, 1-AddUser
		)" << std::endl;
	}
	void handle_command(bool& bRunning, int nAction)
	{
		recv_data = "";
		switch (cmd)
		{
		case '\n':return; break;
		case '0':bRunning = false; break;
		case '1':
		{
			cmd = CMD_ADD;
			dat = DAT_USER;
			send_json = R"({"seq":")" + std::to_string(seq++) + R"("})";
		}
		break;
		default:
			break;
		}

		send_with_recv(recv_data, cmd, dat, send_json, pHost, nPort);
		print_debug(recv_data);
	}
public:
	void usage()
	{
		std::cout << "Usage:\n\ttcpclient 192.168.1.2\n\ttcpclient 192.168.1.2 1234" << std::endl;
	}
	void Run()
	{
		bRunning = true;
		while (bRunning)
		{
			help();
			handle_command(bRunning, getchar());
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
	}
public:
	static ClientHandle* Inst() {
		static ClientHandle clientHandleInstance;
		return &clientHandleInstance;
	}
};