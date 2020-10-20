// SynTcp.cpp : Defines the entry point for the application.
//

#include "SynTcp.h"

int main(int argc, char** argv) {
	WinSockEnv::Inst();

	ClientHandle::Inst()->pHost = "192.168.1.140";
	ClientHandle::Inst()->nPort = 1234;
	if (argc == 2)
	{
		ClientHandle::Inst()->pHost = argv[1];
	}
	else if (argc == 3)
	{
		ClientHandle::Inst()->pHost = argv[1];
		ClientHandle::Inst()->nPort = atoi(argv[2]);
	}

	ClientHandle::Inst()->Run();

	return 0;
}
