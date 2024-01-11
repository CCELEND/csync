#pragma once
#include "AES_need.h"
#include "RSA_need.h"
#include "tcp_socket.h"

// 0: 公钥，1: 验证随机序列
struct key_agreement_c
{
	int c_type;
	int raw_data_size;
	int encrypted_data_size;
};
// 2: 随机序列, 3: AES 数据 key 和初始向量 IV
struct key_agreement_s
{
	int s_type;
	int size;
};

void key_agreement_c_fun(SOCKET& connect_fd, 
	unsigned char* sync_data_key, unsigned char* sync_data_iv);
void key_agreement_s_fun(SOCKET& accept_fd, 
	unsigned char* sync_data_key, unsigned char* sync_data_iv);
int  generate_random_bytes(unsigned char* randoms, int random_bytes_length);

//unsigned char* generate_key_agreement_c_packet(
std::tuple<unsigned char*, int>
generate_key_agreement_c_packet(
	int c_type, int raw_data_size, int encrypted_data_size,
	unsigned char* encrypted_data);

//unsigned char* generate_key_agreement_s_packet(
std::tuple<unsigned char*, int>
generate_key_agreement_s_packet(
	int s_type, int size,
	unsigned char* encrypted_data);

// 客户端过程
void send_KROOT_PUB_KEY(SOCKET& connect_fd, 
	const std::string& pub_key,
	const AES_KEY* root_aes_encrypt_key, const unsigned char* root_iv);

void recv_PUB_KET_randoms(SOCKET& connect_fd, 
	unsigned char* verify_randoms,
	unsigned char* recv_buf,
	const std::string& pri_key);

void send_PRI_KET_verify_randoms(SOCKET& connect_fd, 
	const unsigned char* verify_randoms,
	const std::string& pri_key);

void recv_PUB_KEY_KDATA_KIV(SOCKET& connect_fd, 
	unsigned char* data_key, unsigned char* data_iv,
	unsigned char* recv_buf,
	const std::string& pri_key);

// 服务器过程
void recv_KROOT_PUB_KEY(SOCKET& accept_fd, 
	std::string& pub_key,
	unsigned char* recv_buf,
	const AES_KEY* root_aes_decrypt_key, const unsigned char* root_iv);

void send_PUB_KET_randoms(SOCKET& accept_fd, 
	const unsigned char* randoms,
	const std::string& pub_key);

void recv_PRI_KET_verify_randoms(SOCKET& accept_fd, 
	unsigned char* verify_randoms,
	unsigned char* recv_buf,
	const std::string& pub_key);

void send_PUB_KEY_KDATA_KIV(SOCKET& accept_fd, 
	const unsigned char* data_key, const unsigned char* data_iv,
	const std::string& pub_key);