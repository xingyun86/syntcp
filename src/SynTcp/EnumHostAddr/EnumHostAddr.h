// EnumHostAddr.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <iostream>

// TODO: Reference additional headers your program requires here.

#include <string>
#include <thread>
#ifdef _MSC_VER
#define  _WINSOCK_DEPRECATED_NO_WARNINGS 
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#endif

#pragma pack(1)
typedef struct __xxx__ { uint8_t v; };
#pragma pack()

#include <vector>
class SockUtil {
public:
#ifdef _MSC_VER
	WSADATA wsadata = { 0 };
#endif
	SockUtil()
	{
#ifdef _MSC_VER
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
#endif
	}
	~SockUtil()
	{
#ifdef _MSC_VER
		WSACleanup();
#endif
	}
private:
	int enum_host_addr(std::vector<std::string> & sv, int af/*= AF_INET or AF_INET6*/)
	{
		int ret = 0;
		char ip[65] = { 0 };
		struct sockaddr_in* addr = nullptr;
#ifdef _MSC_VER
		char host_name[33] = { 0 };
		struct addrinfo hints = { 0 };
		struct addrinfo* res = nullptr;
		struct addrinfo* cur = nullptr;
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = af; /* Allow IPv4 */
		hints.ai_flags = AI_PASSIVE; /* For wildcard IP address */
		hints.ai_protocol = 0; /* Any protocol */
		hints.ai_socktype = SOCK_STREAM;
		ret = gethostname(host_name, sizeof(host_name) / sizeof(*host_name));
		if (ret == 0)
		{
			ret = getaddrinfo(host_name, nullptr, &hints, &res);
			if (ret == 0) {
				for (cur = res; cur != nullptr; cur = cur->ai_next) {
					addr = (struct sockaddr_in*)cur->ai_addr;
					std::cout << inet_ntop(af, &addr->sin_addr, ip, sizeof(ip) / sizeof(*ip)) << std::endl;
					sv.push_back(ip);
				}
				freeaddrinfo(res);
			}
		}
#else
		struct ifaddrs* ifa = nullptr;
		struct ifaddrs* oifa = nullptr;
		ret = getifaddrs(&ifa);
		if (ret == 0)
		{
			oifa = ifa;
			while (ifa != nullptr)
			{
				// IPv4 排除localhost
				if (ifa->ifa_addr != nullptr
					&& ifa->ifa_addr->sa_family == af
					&& strncmp(ifa->ifa_name, "lo", 2) != 0)
				{
					addr = (struct sockaddr_in*)ifa->ifa_addr;
					std::cout << inet_ntop(af, &addr->sin_addr, ip, sizeof(ip) / sizeof(*ip)) << std::endl;
					sv.push_back(ip);
				}
				ifa = ifa->ifa_next;
			}
			freeifaddrs(oifa);
		}
#endif
		return ret;
	}
public:
	int enum_host_addr_ipv4(std::vector<std::string>& sv)
	{
		return enum_host_addr(sv, AF_INET);
	}
	int enum_host_addr_ipv6(std::vector<std::string>& sv)
	{
		return enum_host_addr(sv, AF_INET6);
	}
public:
	static SockUtil* Inst()
	{
		static SockUtil SockUtilInstance;
		return &SockUtilInstance;
	}
};
