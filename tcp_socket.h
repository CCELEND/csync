#pragma once

#include <mutex>
#include <string>
#include <fstream>
#include <iostream>
#include <condition_variable>
#include <stdbool.h>
#include <WinSock2.h>
#include <Windows.h>

#pragma comment(lib,"ws2_32.lib")	// 库文件
#pragma warning(disable:4996)

// #define err(errMsg)	cout<<errMsg<<"failed,code "<<WSAGetLastError()<<" line:"<<__LINE__<<endl;
#define PORT 8401	// 0-1024为系统保留

void err(std::string errMsg);

// 初始化网络库
bool init_socket_lib();

// 关闭网络库
bool close_socket_lib();

// 创建客户 socket
SOCKET create_client_socket(const char* ip);

// 创建服务器 socket
SOCKET create_server_socket();

void client_fun();
void server_fun();

// 发送接收数据
bool send_all(SOCKET& sock, char* buffer, int size);
bool recv_all(SOCKET& sock, char* buffer, int size);