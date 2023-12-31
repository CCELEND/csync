
#include "file_sync.h"

void
send_KDATA_DIR_PATH(SOCKET& connect_fd, 
    const std::string& directory_path,
    const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv)
{
    int directory_path_length = directory_path.length();
    int directory_path_encrypted_data_size = AES_block_alignment(directory_path_length);

    // 分配 data AES 加密后文件路径的缓冲区
    unsigned char* encrypted_directory_path;
    encrypted_directory_path = new unsigned char[directory_path_encrypted_data_size];
    memset(encrypted_directory_path, 0, directory_path_encrypted_data_size);
    // data AES 加密文件路径
    aes_cbc_encrypt((const unsigned char*)(directory_path.c_str()), encrypted_directory_path,
        directory_path_length, data_aes_encrypt_key, data_iv);

    // 生成 file_sync_packet
    std::tuple<unsigned char*, int> file_sync_packet_info;
    file_sync_packet_info = generate_file_sync_packet(
        4, directory_path_length, directory_path_encrypted_data_size,
        encrypted_directory_path);
    unsigned char* file_sync_packet = std::get<0>(file_sync_packet_info);
    int file_sync_packet_size = std::get<1>(file_sync_packet_info);
    

    // 发送 data AES 加密文件路径
    printf("[*] Sending synchronized file directory...\n\n");
    send_all(connect_fd, (char*)file_sync_packet, file_sync_packet_size);

    delete[] encrypted_directory_path;
    delete[] file_sync_packet;
}

void
recv_KDATA_NAME_HASH_LIST(SOCKET& connect_fd, 
    std::map<std::string, std::string>& file_name_hash_map,
    unsigned char* recv_buf,
    const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv)
{
    struct file_sync file_sync_head { 0 };
    int file_sync_head_size = sizeof(struct file_sync);

    printf("[*] Recving file name hash list...\n");
    recv_all(connect_fd, (char*)recv_buf, file_sync_head_size);
    memcpy(&file_sync_head, (struct file_sync*)recv_buf,
        file_sync_head_size);

    if (file_sync_head.type == 6)
    {
        int file_name_hash_list_size;
        int encrypted_file_name_hash_list_size;
        file_name_hash_list_size = file_sync_head.raw_size;
        encrypted_file_name_hash_list_size = file_sync_head.encrypted_size;

        unsigned char* decrypted_file_name_hash_list;
        decrypted_file_name_hash_list = new unsigned char[encrypted_file_name_hash_list_size];
        memset(decrypted_file_name_hash_list, 0, encrypted_file_name_hash_list_size);

        recv_all(connect_fd, (char*)recv_buf, encrypted_file_name_hash_list_size);

        // data AES 解密获得文件哈希表
        aes_cbc_decrypt(recv_buf, decrypted_file_name_hash_list,
            encrypted_file_name_hash_list_size, data_aes_decrypt_key, data_iv);

        int num = encrypted_file_name_hash_list_size / 128;
        struct file_name_hash* file_name_hash_list;
        file_name_hash_list = (struct file_name_hash*)decrypted_file_name_hash_list;

        struct_to_file_name_hash_map(file_name_hash_list, file_name_hash_map, num);

        delete[] decrypted_file_name_hash_list;
    }

}

void
send_KDATA_REQ_NAME_HASH_LIST(SOCKET& connect_fd, 
    const std::map<std::string, std::string>& req_file_name_hash_map,
    const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv)
{
    std::tuple<struct file_name_hash*, int> file_name_hash_list_info;
    file_name_hash_list_info = file_name_hash_map_to_struct(req_file_name_hash_map);
    struct file_name_hash* file_name_hash_list = std::get<0>(file_name_hash_list_info);
    int file_name_hash_list_size = std::get<1>(file_name_hash_list_info);
    
    // 分配 data AES 加密后缺少的文件哈希表的缓冲区
    unsigned char* encrypted_file_name_hash_list;
    encrypted_file_name_hash_list = new unsigned char[file_name_hash_list_size];
    memset(encrypted_file_name_hash_list, 0, file_name_hash_list_size);
    // data AES 加密缺少的文件哈希表
    aes_cbc_encrypt((const unsigned char*)(file_name_hash_list), encrypted_file_name_hash_list,
        file_name_hash_list_size, data_aes_encrypt_key, data_iv);

    // 生成 file_sync_packet
    std::tuple<unsigned char*, int> file_sync_packet_info;
    file_sync_packet_info = generate_file_sync_packet(
        7, file_name_hash_list_size, file_name_hash_list_size,
        encrypted_file_name_hash_list);
    unsigned char* file_sync_packet = std::get<0>(file_sync_packet_info);
    int file_sync_packet_size = std::get<1>(file_sync_packet_info);

    // 发送 data AES 加密缺少的文件哈希表
    printf("[*] Sending request file name hash list...\n");
    send_all(connect_fd, (char*)file_sync_packet, file_sync_packet_size);

    delete[] file_name_hash_list;
    delete[] encrypted_file_name_hash_list;
    delete[] file_sync_packet;
}

void
recv_KDATA_FILE_INFO(SOCKET& connect_fd, 
    sync_file_info* file_info,
    unsigned char* recv_buf,
    const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv)
{
    struct file_sync file_sync_head { 0 };
    int file_sync_head_size = sizeof(struct file_sync);

    printf("[*] Recving file information...\n");
    recv_all(connect_fd, (char*)recv_buf, file_sync_head_size);
    memcpy(&file_sync_head, (struct file_sync*)recv_buf,
        file_sync_head_size);

    if (file_sync_head.type == 8)
    {
        int file_info_size;
        int encrypted_file_info_size;
        file_info_size = file_sync_head.raw_size;
        encrypted_file_info_size = file_sync_head.encrypted_size;

        unsigned char* decrypted_file_info;
        decrypted_file_info = new unsigned char[encrypted_file_info_size];
        memset(decrypted_file_info, 0, encrypted_file_info_size);

        recv_all(connect_fd, (char*)recv_buf, encrypted_file_info_size);

        // data AES 解密获得文件信息
        aes_cbc_decrypt(recv_buf, decrypted_file_info,
            encrypted_file_info_size, data_aes_decrypt_key, data_iv);
        memcpy(file_info, (struct sync_file_info*)decrypted_file_info, 
            file_info_size);

        printf("[+] [ %s ] information: file size: %llu\n", 
            file_info->file_name, file_info->file_total_size);

        delete[] decrypted_file_info;
    }
}

void 
recv_KDATA_FILE_BLOCK(SOCKET& connect_fd, 
    unsigned char* file_data_buf,
    unsigned char* recv_buf,
    const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv)
{
    struct sync_file_data sync_file_data_head { 0 };
    int sync_file_data_head_size = sizeof(struct sync_file_data);

    recv_all(connect_fd, (char*)recv_buf, sync_file_data_head_size);
    memcpy(&sync_file_data_head, (struct sync_file_data*)recv_buf,
        sync_file_data_head_size);

    int file_block_index = sync_file_data_head.block_index;
    int raw_file_block_size = sync_file_data_head.raw_block_size;
    int encrypted_file_block_size = sync_file_data_head.encrypted_block_size;

    unsigned char* decrypted_file_block;
    decrypted_file_block = new unsigned char[encrypted_file_block_size];
    memset(decrypted_file_block, 0, encrypted_file_block_size);

    recv_all(connect_fd, (char*)recv_buf, encrypted_file_block_size);

    // data AES 解密获得文件块数据
    aes_cbc_decrypt(recv_buf, decrypted_file_block, encrypted_file_block_size, 
        data_aes_decrypt_key, data_iv);

    memcpy(file_data_buf + file_block_index * FILE_BLOCK_MAX_LENGTH, decrypted_file_block,
        raw_file_block_size);

    delete[] decrypted_file_block;
}

void
send_sync_start(SOCKET& connect_fd)
{
    struct file_sync file_sync_head { 0 };
    int file_sync_head_size = sizeof(struct file_sync);

    file_sync_head.type = 5;
    file_sync_head.raw_size = 0;
    file_sync_head.encrypted_size = 0;

    send_all(connect_fd, 
        (char*)&file_sync_head, file_sync_head_size);
}
void
send_sync_quit(SOCKET& connect_fd)
{
    struct file_sync file_sync_head { 0 };
    int file_sync_head_size = sizeof(struct file_sync);

    file_sync_head.type = 9;
    file_sync_head.raw_size = 0;
    file_sync_head.encrypted_size = 0;

    send_all(connect_fd, 
        (char*)&file_sync_head, file_sync_head_size);
}