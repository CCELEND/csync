#pragma once

#include "RSA_AES_key_agreement.h"
#include "file_data.h"
#include "file_hash.h"
#include "tcp_socket.h"

// 客户端 4: 文件路径，5: 文件 hash 表请求，7: 缺少文件的 hash
// 服务器 6: 文件 hash 表，8: 文件基本信息
struct file_sync
{
	int type;
	int raw_size;
	int encrypted_size;
};
// 文件基本信息
struct sync_file_info
{
	int block_total;
	size_t file_total_size;
	unsigned char file_name[64];
	unsigned char file_hash[64];
};

// 文件数据
struct sync_file_data
{
	int block_index;
	int raw_block_size;
	int encrypted_block_size;
};

struct file_name_hash_table
{
	unsigned char name[64];
	unsigned char hash[64];
};

void file_sync_c_fun(SOCKET& connect_fd, const unsigned char* sync_data_key, const unsigned char* sync_data_iv);
void file_sync_s_fun(SOCKET& accept_fd,  const unsigned char* sync_data_key, const unsigned char* sync_data_iv);

unsigned char* generate_file_sync_packet(
	int type, int raw_size, int encrypted_size,
	unsigned char* encrypted_data,
	int* packet_size);

unsigned char* generate_file_block_packet(
	int block_index, int raw_block_size, int encrypted_block_size,
	unsigned char* encrypted_data,
	int* packet_size);

struct file_name_hash_table* file_name_hash_map_to_struct(
	const std::map<std::string, std::string>& file_name_hash,
	int* size);

void struct_to_file_name_hash_map(const struct file_name_hash_table* file_name_hash_table,
	std::map<std::string, std::string>& file_name_hash,
	int num);

struct sync_file_info* get_file_info_to_struct(const std::string& directory_path,
	const std::map<std::string, std::string>& req_file_name_hash,
	int* list_size);

// 客户端过程
void send_KDATA_DIR_PATH(SOCKET& connect_fd, const std::string& directory_path,
	const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv);

void recv_KDATA_HASH_TABLE(SOCKET& connect_fd, std::map<std::string, std::string>& file_name_hash,
	unsigned char* recv_buf,
	const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv);

void send_KDATA_REQ_HASH_TABLE(SOCKET& connect_fd, const std::map<std::string, std::string>& req_file_name_hash,
	const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv);

void recv_KDATA_FILE_INFO(SOCKET& connect_fd, sync_file_info* file_info,
	unsigned char* recv_buf,
	const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv);

void recv_KDATA_FILE_BLOCK(SOCKET& connect_fd, unsigned char* file_data_buf,
	unsigned char* recv_buf,
	const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv);

// 服务器过程
void recv_KDATA_DIR_PATH(SOCKET& accept_fd, std::string& directory_path,
	unsigned char* recv_buf,
	const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv);

void send_KDATA_HASH_TABLE(SOCKET& accept_fd, const std::map<std::string, std::string>& file_name_hash,
	const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv);

void recv_KDATA_REQ_HASH_TABLE(SOCKET& accept_fd, std::map<std::string, std::string>& req_file_name_hash,
	unsigned char* recv_buf,
	const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv);

void send_KDATA_FILE_INFO(SOCKET& accept_fd, const sync_file_info* file_info,
	const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv);

void send_KDATA_FILE_BLOCK(SOCKET& accept_fd, const unsigned char* file_block,
	const int file_block_size, const int file_block_index,
	const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv);


