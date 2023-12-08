#pragma once

#include <mutex>
#include <string>
#include <fstream>
#include <iostream>
#include <condition_variable>
#include <stdbool.h>
#include <WinSock2.h>
#include <Windows.h>

#pragma comment(lib,"ws2_32.lib")	// ���ļ�
#pragma warning(disable:4996)

// #define err(errMsg)	cout<<errMsg<<"failed,code "<<WSAGetLastError()<<" line:"<<__LINE__<<endl;
#define PORT 8401	// 0-1024Ϊϵͳ����

void err(std::string errMsg);

// ��ʼ�������
bool init_socket_lib();

// �ر������
bool close_socket_lib();

// �����ͻ� socket
SOCKET create_client_socket(const char* ip);

// ���������� socket
SOCKET create_server_socket();

void client_fun();
void server_fun();

// ���ͽ�������
bool send_all(SOCKET& sock, char* buffer, int size);
bool recv_all(SOCKET& sock, char* buffer, int size);