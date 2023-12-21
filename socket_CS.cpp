
#include "tcp_socket.h"
#include "RSA_AES_key_agreement.h"
#include "file_sync.h"
#include "file_hash.h"

using namespace std;

void server_fun()
{
	// 创建服务器 socket 该 socket 仅用于监听）
	SOCKET listen_fd = create_server_socket();	
	cout << "[*] Server socket create success, waiting connect..." << endl;

	// 等待客户端连接
	sockaddr_in caddr;
	caddr.sin_family = AF_INET;
	int caddrlen = sizeof(sockaddr_in);

	// 该 socket 用于与客户端进行连接
	SOCKET accept_fd = accept(listen_fd, (sockaddr*)&caddr, &caddrlen);	
	if (accept_fd == INVALID_SOCKET)
	{
		err("Accept");
	}
	cout << "[+] Connect success!" << endl;

	unsigned char sync_data_key[data_key_bytes_length] = { 0 };
	unsigned char sync_data_iv[AES_BLOCK_SIZE] = { 0 };

	// 密钥协商
	key_agreement_s_fun(accept_fd, sync_data_key, sync_data_iv);
	printf("[+] Key negotiation completed!\n\n");

	// 处理来自客户端的同步请求
	file_sync_s_fun(accept_fd, sync_data_key, sync_data_iv);

	closesocket(accept_fd);
	closesocket(listen_fd);
}

void client_fun()
{
	string ip;
	printf("Enter target ip address >> ");
	getline(cin, ip);

	SOCKET connect_fd = create_client_socket(ip.c_str());
	cout << "[+] Connect success!" << endl;

	unsigned char sync_data_key[data_key_bytes_length] = { 0 };
	unsigned char sync_data_iv[AES_BLOCK_SIZE] = { 0 };

	// 密钥协商
	key_agreement_c_fun(connect_fd, sync_data_key, sync_data_iv);
	printf("[+] Key negotiation completed!\n\n");

	// 文件数据同步
	file_sync_c_fun(connect_fd, sync_data_key, sync_data_iv);

	closesocket(connect_fd);
}
