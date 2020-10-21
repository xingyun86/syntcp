// EnumHostAddr.cpp : Defines the entry point for the application.
//

#include "EnumHostAddr.h"

int main(int argc, char** argv) {
	std::vector<std::string> svIpv4;
	SockUtil::Inst()->enum_host_addr_ipv4(svIpv4);
	return 0;
}
