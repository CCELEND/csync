
#include "tcp_socket.h"

using namespace std;

void 
err(string errMsg)
{
	cout << errMsg << " failed! code: " << WSAGetLastError() << " line: " << __LINE__ << endl;
}

// 初始化网络库，打开网络库/启动网络库，启动了这个库，这个库里的函数/功能才能使用
bool 
init_socket_lib()
{
	// 初始化代码
	WORD wVersion = MAKEWORD(2, 2);
	// MAKEWORD：将两个 byte 型合成一个 word 型，一个在高八位，一个在低八位
	// MAKEWORD(1,1)只能一次接收一次，不能马上发送，只支持 TCP/IP 协议，不支持异步
	// MAKEWORD(2,2)可以同时接收和发送，支持多协议，支持异步
	WSADATA wsadata;
	if (WSAStartup(wVersion, &wsadata))	// WSA:widows socket ansyc	windows 异步套接字
	{
		err("WSAStartup");
		return false;
	}
	return true;
}

// 关闭
bool 
close_socket_lib()
{
	if (WSACleanup())
	{
		err("WSACleanup");
	}

	return true;
}


bool 
send_all(SOCKET& sock, char* buffer, int size)
{
	while (size > 0)
	{
		int SendSize = send(sock, buffer, size, 0);
		if (SOCKET_ERROR == SendSize)
			return false;

		size = size - SendSize; //用于循环发送且退出功能
		buffer += SendSize;     //用于计算已发 buffer 的偏移量
	}

	return true;
}

bool 
recv_all(SOCKET& sock, char* buffer, int size)
{
	while (size > 0)//剩余部分大于0
	{
		int RecvSize = recv(sock, buffer, size, 0);
		if (SOCKET_ERROR == RecvSize)
			return false;

		size = size - RecvSize;
		buffer += RecvSize;
	}

	return true;
}

SOCKET 
create_server_socket()
{
	//1.创建一个空的 socket
		// socket()无错误发生则返回引用新套接口的描述字，否则返回 INVALID_SOCKET 错误
	SOCKET listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == listen_fd)
	{
		err("socket");
		return INVALID_SOCKET;
	}
	// AF_INET：指定地址协议族，INET 指 IPV4
	// SOCK_STREAM：代表流式套接字
	// IPPROTO_TCP：指定使用 TCP/IP 中的协议，此处指定使用 TCP 协议

//2.给 socket 绑定本地 ip 地址和端口号
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);	// htons()：把本地字节序转成网络字节序
	addr.sin_addr.S_un.S_addr = ADDR_ANY;	// 绑定本地任意 ip

	//3.bind 绑定端口
	if (SOCKET_ERROR == bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)))
	{
		err("bind");
		return INVALID_SOCKET;
	}

	//4.开始监听
	listen(listen_fd, 10);	// 同时允许10个用户进行访问
	return listen_fd;
}


SOCKET 
create_client_socket(const char* ip)
{
	//1.创建一个空的socket
		// socket() 无错误发生则返回引用新套接口的描述字，否则返回 INVALID_SOCKET 错误
	SOCKET connect_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == connect_fd)
	{
		err("socket");
		return INVALID_SOCKET;
	}
	// AF_INET：指定地址协议族，INET 指 IPV4
	// SOCK_STREAM：代表流式套接字
	// IPPROTO_TCP：指定使用 TCP/IP 中的协议，此处指定使用 TCP 协议

//2.给 socket 绑定 ip 地址和端口号
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);	// htons()：把本地字节序转成网络字节序
	addr.sin_addr.S_un.S_addr = inet_addr(ip);	// 绑定对方 ip

	//3.连接到对等 socket
	if (INVALID_SOCKET == connect(connect_fd, (struct sockaddr*)&addr, sizeof(addr)))
	{
		err("connect");
		return INVALID_SOCKET;
	}

	return connect_fd;
}