
#include "tcp_socket.h"

using namespace std;

void 
err(string errMsg)
{
	cout << errMsg << " failed! code: " << WSAGetLastError() << " line: " << __LINE__ << endl;
}

// ��ʼ������⣬�������/��������⣬����������⣬�������ĺ���/���ܲ���ʹ��
bool 
init_socket_lib()
{
	// ��ʼ������
	WORD wVersion = MAKEWORD(2, 2);
	// MAKEWORD�������� byte �ͺϳ�һ�� word �ͣ�һ���ڸ߰�λ��һ���ڵͰ�λ
	// MAKEWORD(1,1)ֻ��һ�ν���һ�Σ��������Ϸ��ͣ�ֻ֧�� TCP/IP Э�飬��֧���첽
	// MAKEWORD(2,2)����ͬʱ���պͷ��ͣ�֧�ֶ�Э�飬֧���첽
	WSADATA wsadata;
	if (WSAStartup(wVersion, &wsadata))	// WSA:widows socket ansyc	windows �첽�׽���
	{
		err("WSAStartup");
		return false;
	}
	return true;
}

// �ر�
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

		size = size - SendSize; //����ѭ���������˳�����
		buffer += SendSize;     //���ڼ����ѷ� buffer ��ƫ����
	}

	return true;
}

bool 
recv_all(SOCKET& sock, char* buffer, int size)
{
	while (size > 0)//ʣ�ಿ�ִ���0
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
	//1.����һ���յ� socket
		// socket()�޴������򷵻��������׽ӿڵ������֣����򷵻� INVALID_SOCKET ����
	SOCKET listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == listen_fd)
	{
		err("socket");
		return INVALID_SOCKET;
	}
	// AF_INET��ָ����ַЭ���壬INET ָ IPV4
	// SOCK_STREAM��������ʽ�׽���
	// IPPROTO_TCP��ָ��ʹ�� TCP/IP �е�Э�飬�˴�ָ��ʹ�� TCP Э��

//2.�� socket �󶨱��� ip ��ַ�Ͷ˿ں�
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);	// htons()���ѱ����ֽ���ת�������ֽ���
	addr.sin_addr.S_un.S_addr = ADDR_ANY;	// �󶨱������� ip

	//3.bind �󶨶˿�
	if (SOCKET_ERROR == bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)))
	{
		err("bind");
		return INVALID_SOCKET;
	}

	//4.��ʼ����
	listen(listen_fd, 10);	// ͬʱ����10���û����з���
	return listen_fd;
}


SOCKET 
create_client_socket(const char* ip)
{
	//1.����һ���յ�socket
		// socket() �޴������򷵻��������׽ӿڵ������֣����򷵻� INVALID_SOCKET ����
	SOCKET connect_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == connect_fd)
	{
		err("socket");
		return INVALID_SOCKET;
	}
	// AF_INET��ָ����ַЭ���壬INET ָ IPV4
	// SOCK_STREAM��������ʽ�׽���
	// IPPROTO_TCP��ָ��ʹ�� TCP/IP �е�Э�飬�˴�ָ��ʹ�� TCP Э��

//2.�� socket �� ip ��ַ�Ͷ˿ں�
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);	// htons()���ѱ����ֽ���ת�������ֽ���
	addr.sin_addr.S_un.S_addr = inet_addr(ip);	// �󶨶Է� ip

	//3.���ӵ��Ե� socket
	if (INVALID_SOCKET == connect(connect_fd, (struct sockaddr*)&addr, sizeof(addr)))
	{
		err("connect");
		return INVALID_SOCKET;
	}

	return connect_fd;
}