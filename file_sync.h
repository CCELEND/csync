#pragma once

#include <tuple>
#include "RSA_AES_key_agreement.h"
#include "file_data.h"
#include "file_hash.h"
#include "tcp_socket.h"

#define FILE_BLOCK_MAX_LENGTH 8000

// 客户端 4: 文件路径，5: 同步开始，7: 缺少文件的哈希表，9: 同步结束
// 服务器 6: 文件哈希表，8: 文件信息
struct file_sync
{
	int type;
	int raw_size;
	int encrypted_size;
};

// 文件信息
// 包括文件总块数，文件总大小，文件名，文件哈希
struct sync_file_info
{
	int block_total;
	size_t file_total_size;
	unsigned char file_name[64];
	unsigned char file_hash[64];
};
// 文件数据
// 包括文件块序号，原始文件块大小，加密文件块大小
struct sync_file_data
{
	int block_index;
	int raw_block_size;
	int encrypted_block_size;
};

// 文件名，文件哈希
struct file_name_hash
{
	unsigned char name[64];
	unsigned char hash[64];
};

void file_sync_c_fun(SOCKET& connect_fd, 
	const unsigned char* sync_data_key, const unsigned char* sync_data_iv);
void file_sync_s_fun(SOCKET& accept_fd,  
	const unsigned char* sync_data_key, const unsigned char* sync_data_iv);

// 生成 file_sync_packet 头包
std::tuple<unsigned char*, int>
generate_file_sync_packet(
	int type, int raw_size, int encrypted_size,
	unsigned char* encrypted_data);

// 生成同步文件数据的块包
std::tuple<unsigned char*, int>
generate_file_block_packet(
	int block_index, int raw_block_size, int encrypted_block_size,
	unsigned char* encrypted_data);

// map 转换结构体列表
std::tuple<struct file_name_hash*, int>
file_name_hash_map_to_struct(const std::map<std::string, std::string>& file_name_hash_map);

// 结构体转换 map
void 
struct_to_file_name_hash_map(const struct file_name_hash* file_name_hash_list,
	std::map<std::string, std::string>& file_name_hash_map,
	int num);

// 通过文件目录得到同步文件结构体
std::tuple<struct sync_file_info*, int>
get_file_info_to_struct(const std::string& directory_path,
	const std::map<std::string, std::string>& req_file_name_hash_map);

// 客户端过程
void send_sync_start(SOCKET& connect_fd);
void send_sync_quit(SOCKET& connect_fd);

void send_KDATA_DIR_PATH(SOCKET& connect_fd, 
	const std::string& directory_path,
	const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv);

void recv_KDATA_NAME_HASH_LIST(SOCKET& connect_fd, 
	std::map<std::string, std::string>& file_name_hash_map,
	unsigned char* recv_buf,
	const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv);

void send_KDATA_REQ_NAME_HASH_LIST(SOCKET& connect_fd, 
	const std::map<std::string, std::string>& req_file_name_hash_map,
	const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv);

void recv_KDATA_FILE_INFO(SOCKET& connect_fd, 
	sync_file_info* file_info,
	unsigned char* recv_buf,
	const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv);

void recv_KDATA_FILE_BLOCK(SOCKET& connect_fd, 
	unsigned char* file_data_buf,
	unsigned char* recv_buf,
	const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv);

// 服务器过程
void recv_KDATA_DIR_PATH(SOCKET& accept_fd, 
	std::string& directory_path,
	unsigned char* recv_buf,
	const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv);

void send_KDATA_NAME_HASH_LIST(SOCKET& accept_fd, 
	const std::map<std::string, std::string>& file_name_hash_map,
	const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv);

void recv_KDATA_REQ_NAME_HASH_LIST(SOCKET& accept_fd, 
	std::map<std::string, std::string>& req_file_name_hash_map,
	unsigned char* recv_buf,
	const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv);

void send_KDATA_FILE_INFO(SOCKET& accept_fd, 
	const sync_file_info* file_info,
	const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv);

void send_KDATA_FILE_BLOCK(SOCKET& accept_fd, 
	const unsigned char* file_block,
	const int file_block_size, const int file_block_index,
	const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv);


