#pragma once

#include <tuple>
#include "RSA_AES_key_agreement.h"
#include "file_data.h"
#include "file_hash.h"
#include "tcp_socket.h"

#define FILE_BLOCK_MAX_LENGTH 8000

// �ͻ��� 4: �ļ�·����5: ͬ����ʼ��7: ȱ���ļ��Ĺ�ϣ��9: ͬ������
// ������ 6: �ļ���ϣ��8: �ļ���Ϣ
struct file_sync
{
	int type;
	int raw_size;
	int encrypted_size;
};

// �ļ���Ϣ
// �����ļ��ܿ������ļ��ܴ�С���ļ������ļ���ϣ
struct sync_file_info
{
	int block_total;
	size_t file_total_size;
	unsigned char file_name[64];
	unsigned char file_hash[64];
};
// �ļ�����
// �����ļ�����ţ�ԭʼ�ļ����С�������ļ����С
struct sync_file_data
{
	int block_index;
	int raw_block_size;
	int encrypted_block_size;
};

// �ļ������ļ���ϣ
struct file_name_hash
{
	unsigned char name[64];
	unsigned char hash[64];
};

void file_sync_c_fun(SOCKET& connect_fd, 
	const unsigned char* sync_data_key, const unsigned char* sync_data_iv);
void file_sync_s_fun(SOCKET& accept_fd,  
	const unsigned char* sync_data_key, const unsigned char* sync_data_iv);

// ���� file_sync_packet ͷ��
std::tuple<unsigned char*, int>
generate_file_sync_packet(
	int type, int raw_size, int encrypted_size,
	unsigned char* encrypted_data);

// ����ͬ���ļ����ݵĿ��
std::tuple<unsigned char*, int>
generate_file_block_packet(
	int block_index, int raw_block_size, int encrypted_block_size,
	unsigned char* encrypted_data);

// map ת���ṹ���б�
std::tuple<struct file_name_hash*, int>
file_name_hash_map_to_struct(const std::map<std::string, std::string>& file_name_hash_map);

// �ṹ��ת�� map
void 
struct_to_file_name_hash_map(const struct file_name_hash* file_name_hash_list,
	std::map<std::string, std::string>& file_name_hash_map,
	int num);

// ͨ���ļ�Ŀ¼�õ�ͬ���ļ��ṹ��
std::tuple<struct sync_file_info*, int>
get_file_info_to_struct(const std::string& directory_path,
	const std::map<std::string, std::string>& req_file_name_hash_map);

// �ͻ��˹���
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

// ����������
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


