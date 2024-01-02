
#include "file_sync.h"

void
recv_KDATA_DIR_PATH(SOCKET& accept_fd, 
    std::string& directory_path,
    unsigned char* recv_buf,
    const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv)
{
    struct file_sync file_sync_head { 0 };
    int file_sync_head_size = sizeof(struct file_sync);
    
    printf("[*] Recving synchronized file directory...\n");
    recv_all(accept_fd, (char*)recv_buf, file_sync_head_size);
    memcpy(&file_sync_head, (struct file_sync*)recv_buf,
        file_sync_head_size);

    if (file_sync_head.type == 4)
    {
        int directory_path_length, encrypted_directory_path_size;
        directory_path_length = file_sync_head.raw_size;
        encrypted_directory_path_size = file_sync_head.encrypted_size;

        unsigned char* decrypted_directory_path;
        decrypted_directory_path = new unsigned char[encrypted_directory_path_size];
        memset(decrypted_directory_path, 0, encrypted_directory_path_size);

        recv_all(accept_fd, (char*)recv_buf, encrypted_directory_path_size);

        // data AES 解密获得路径
        aes_cbc_decrypt(recv_buf, decrypted_directory_path,
            encrypted_directory_path_size, data_aes_decrypt_key, data_iv);

        directory_path = std::string((char*)decrypted_directory_path);
        printf("[+] Synchronized file directory: %s\n\n", 
            directory_path.c_str());

        delete[] decrypted_directory_path;
    }
}

void
send_KDATA_NAME_HASH_LIST(SOCKET& accept_fd, 
    const std::map<std::string, std::string>& file_name_hash_map,
    const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv)
{
    std::tuple<struct file_name_hash*, int> file_name_hash_list_info;
    file_name_hash_list_info = file_name_hash_map_to_struct(file_name_hash_map);
    struct file_name_hash* file_name_hash_list = std::get<0>(file_name_hash_list_info);
    int file_name_hash_list_size = std::get<1>(file_name_hash_list_info);

    // 分配 data AES 加密后文件哈希表的缓冲区
    unsigned char* encrypted_file_name_hash_list;
    encrypted_file_name_hash_list = new unsigned char[file_name_hash_list_size];
    memset(encrypted_file_name_hash_list, 0, file_name_hash_list_size);
    // data AES 加密文件哈希表
    aes_cbc_encrypt((const unsigned char*)(file_name_hash_list), encrypted_file_name_hash_list,
        file_name_hash_list_size, data_aes_encrypt_key, data_iv);

    // 生成 file_sync_packet
    std::tuple<unsigned char*, int> file_sync_packet_info;
    file_sync_packet_info = generate_file_sync_packet(
        6, file_name_hash_list_size, file_name_hash_list_size,
        encrypted_file_name_hash_list);
    unsigned char* file_sync_packet = std::get<0>(file_sync_packet_info);
    int file_sync_packet_size = std::get<1>(file_sync_packet_info);

    // 发送 data AES 加密文件哈希表
    printf("[*] Sending file name hash list...\n\n");
    send_all(accept_fd, (char*)file_sync_packet, file_sync_packet_size);

    delete[] file_name_hash_list;
    delete[] encrypted_file_name_hash_list;
    delete[] file_sync_packet;
}

void 
recv_KDATA_REQ_NAME_HASH_LIST(SOCKET& accept_fd, 
    std::map<std::string, std::string>& req_file_name_hash_map,
    unsigned char* recv_buf,
    const AES_KEY* data_aes_decrypt_key, const unsigned char* data_iv)
{
    struct file_sync file_sync_head { 0 };
    int file_sync_head_size = sizeof(struct file_sync);

    printf("[*] Recving request file name hash list...\n");
    recv_all(accept_fd, (char*)recv_buf, file_sync_head_size);
    memcpy(&file_sync_head, (struct file_sync*)recv_buf,
        file_sync_head_size);

    if (file_sync_head.type == 7)
    {
        int file_name_hash_list_size, encrypted_file_name_hash_list_size;
        file_name_hash_list_size = file_sync_head.raw_size;
        encrypted_file_name_hash_list_size = file_sync_head.encrypted_size;

        unsigned char* decrypted_file_name_hash_list;
        decrypted_file_name_hash_list = new unsigned char[encrypted_file_name_hash_list_size];
        memset(decrypted_file_name_hash_list, 0, encrypted_file_name_hash_list_size);

        recv_all(accept_fd, (char*)recv_buf, encrypted_file_name_hash_list_size);

        // data AES 解密获得文件哈希表
        aes_cbc_decrypt(recv_buf, decrypted_file_name_hash_list,
            encrypted_file_name_hash_list_size, data_aes_decrypt_key, data_iv);

        int num = encrypted_file_name_hash_list_size / 128;
        struct file_name_hash* file_name_hash_list;
        file_name_hash_list = (struct file_name_hash*)decrypted_file_name_hash_list;

        struct_to_file_name_hash_map(file_name_hash_list, req_file_name_hash_map, num);       
        printf("\n");

        delete[] decrypted_file_name_hash_list;
    }
}

void
send_KDATA_FILE_INFO(SOCKET& accept_fd, 
    const sync_file_info* file_info,
    const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv)
{
    int file_info_size = sizeof(struct sync_file_info);
    int encrypted_file_info_size = AES_block_alignment(file_info_size);

    // 分配 data AES 加密后文件信息
    unsigned char* encrypted_file_info;
    encrypted_file_info = new unsigned char[encrypted_file_info_size];
    memset(encrypted_file_info, 0, encrypted_file_info_size);
    // data AES 加密文件信息
    aes_cbc_encrypt((const unsigned char*)(file_info), encrypted_file_info,
        file_info_size, data_aes_encrypt_key, data_iv);

    // 生成 file_sync_packet
    std::tuple<unsigned char*, int> file_sync_packet_info;
    file_sync_packet_info = generate_file_sync_packet(
        8, file_info_size, encrypted_file_info_size,
        encrypted_file_info);
    unsigned char* file_sync_packet = std::get<0>(file_sync_packet_info);
    int file_sync_packet_size = std::get<1>(file_sync_packet_info);

    // 发送 data AES 加密文件信息
    printf("[*] Sending [ %s ] information...\n", 
        file_info->file_name);
    send_all(accept_fd, (char*)file_sync_packet, file_sync_packet_size);

    delete[] encrypted_file_info;
    delete[] file_sync_packet;
}

void send_KDATA_FILE_BLOCK(SOCKET& accept_fd, 
    const unsigned char* file_block,
    const int file_block_size, const int file_block_index,
    const AES_KEY* data_aes_encrypt_key, const unsigned char* data_iv)
{
    // 数据对齐
    int encrypted_file_block_size = AES_block_alignment(file_block_size);

    // 分配 data AES 加密后文件块缓冲区
    unsigned char* encrypted_file_block;
    encrypted_file_block = new unsigned char[encrypted_file_block_size];
    memset(encrypted_file_block, 0, encrypted_file_block_size);

    // data AES 加密文件块
    aes_cbc_encrypt(file_block, encrypted_file_block,
        file_block_size, data_aes_encrypt_key, data_iv);

    // 生成 file_block_packet
    std::tuple<unsigned char*, int> file_block_packet_info;
    file_block_packet_info = generate_file_block_packet(
        file_block_index, file_block_size, encrypted_file_block_size,
        encrypted_file_block);
    unsigned char* file_block_packet = std::get<0>(file_block_packet_info);
    int file_block_packet_size = std::get<1>(file_block_packet_info);
   
    send_all(accept_fd, (char*)file_block_packet, file_block_packet_size);

    delete[] encrypted_file_block;
    delete[] file_block_packet;
}

