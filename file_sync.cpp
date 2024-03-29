#include "file_sync.h"

std::tuple<unsigned char*, int>
generate_file_sync_packet(
    int type, int raw_size, int encrypted_size,
    unsigned char* encrypted_data)
{
    struct file_sync file_sync_head { 0 };
    int file_sync_head_size = sizeof(struct file_sync);
    file_sync_head.type = type;
    file_sync_head.raw_size = raw_size;
    file_sync_head.encrypted_size = encrypted_size;

    int file_sync_data_size = encrypted_size;
    int file_sync_packet_size = file_sync_head_size + file_sync_data_size;

    unsigned char* file_sync_packet;
    file_sync_packet = new unsigned char[file_sync_packet_size];
    memset(file_sync_packet, 0, file_sync_packet_size);

    memcpy(file_sync_packet,
        &file_sync_head, file_sync_head_size);
    memcpy(file_sync_packet + file_sync_head_size,
        encrypted_data, file_sync_data_size);

    std::tuple<unsigned char*, int> result;
    result = std::make_tuple(file_sync_packet, file_sync_packet_size);
    return result;
}

std::tuple<unsigned char*, int>
generate_file_block_packet(
    int block_index, int raw_block_size, int encrypted_block_size,
    unsigned char* encrypted_data)
{
    struct sync_file_data file_block_head { 0 };
    int file_block_head_size = sizeof(struct sync_file_data);
    file_block_head.block_index = block_index;
    file_block_head.raw_block_size = raw_block_size;
    file_block_head.encrypted_block_size = encrypted_block_size;

    int file_block_data_size = encrypted_block_size;
    int file_block_packet_size = file_block_head_size + file_block_data_size;

    unsigned char* file_block_packet;
    file_block_packet = new unsigned char[file_block_packet_size];
    memset(file_block_packet, 0, file_block_packet_size);

    memcpy(file_block_packet,
        &file_block_head, file_block_head_size);
    memcpy(file_block_packet + file_block_head_size,
        encrypted_data, file_block_data_size);

    std::tuple<unsigned char*, int> result;
    result = std::make_tuple(file_block_packet, file_block_packet_size);
    return result;
}


// map 值提取到结构体
std::tuple<struct file_name_hash*, int> 
file_name_hash_map_to_struct(const std::map<std::string, std::string>& file_name_hash_map)
{
    size_t num = file_name_hash_map.size();
    int file_name_hash_list_size = num * sizeof(struct file_name_hash);
    struct file_name_hash* file_name_hash_list;
    file_name_hash_list = new struct file_name_hash[num];
    memset(file_name_hash_list, 0, file_name_hash_list_size);

    int i = 0;
    size_t len = 0;
    for (auto it : file_name_hash_map)
    {
        len = it.first.length();
        if (len > 63) 
            return std::make_tuple(nullptr, 0);

        memcpy(file_name_hash_list[i].name, it.first.c_str(), len);
        memcpy(file_name_hash_list[i].hash, it.second.c_str(), 64);
        i++;
    }

    std::tuple<struct file_name_hash*, int> result;
    result = std::make_tuple(file_name_hash_list, file_name_hash_list_size);
    return result;
}

// 结构体值提取到 map
void 
struct_to_file_name_hash_map(const struct file_name_hash* file_name_hash_list,
    std::map<std::string, std::string>& file_name_hash_map,
    int num)
{
    std::string file_name, file_hash;
    unsigned char name[65] = { 0 };
    unsigned char hash[65] = { 0 };

    for (int i = 0; i < num; i++)
    {
        file_name = "";
        file_hash = "";

        memcpy(name, file_name_hash_list[i].name, 64);
        memcpy(hash, file_name_hash_list[i].hash, 64);
        file_name = std::string((char*)name);
        file_hash = std::string((char*)hash);

        file_name_hash_map[file_name] = file_hash;
    }

}

std::tuple<struct sync_file_info*, int>
get_file_info_to_struct(const std::string& directory_path, 
    const std::map<std::string, std::string>& req_file_name_hash_map)
{
    int num = req_file_name_hash_map.size();
    int file_info_list_size = num * sizeof(struct sync_file_info);

    struct sync_file_info* file_info_list;
    file_info_list = new struct sync_file_info[num];
    memset(file_info_list, 0, file_info_list_size);

    int i = 0, block_num = 0, len = 0;
    size_t file_size;
    std::string file_path, file_name, file_hash;
    for (auto it : req_file_name_hash_map)
    {
        file_name = it.first; 
        file_hash = it.second;
        file_path = directory_path + "\\" + file_name;

        struct stat statbuf { 0 };
        stat(file_path.c_str(), &statbuf);
        file_size = statbuf.st_size;

        if (file_size % FILE_BLOCK_MAX_LENGTH)
            block_num = file_size / FILE_BLOCK_MAX_LENGTH + 1;
        else
            block_num = file_size / FILE_BLOCK_MAX_LENGTH;

        file_info_list[i].block_total = block_num;
        file_info_list[i].file_total_size = file_size;

        len = file_name.length();
        memcpy(file_info_list[i].file_name, file_name.c_str(), len);
        memcpy(file_info_list[i].file_hash, file_hash.c_str(), 64);
        i++;
    }

    std::tuple<struct sync_file_info*, int> result;
    result = std::make_tuple(file_info_list, file_info_list_size);
    return result;
}

static void
SYNC_C(SOCKET& connect_fd, 
    const std::string& local_directory_path, const std::string& target_directory_path,
    unsigned char* recv_buf,
    const AES_KEY* data_aes_encrypt_key, const AES_KEY* data_aes_decrypt_key, const unsigned char* sync_data_iv)
{
    // 发送同步开始操作
    send_sync_start(connect_fd);

    // 更新本地目录文件哈希 map
    std::map<std::string, std::string> file_name_hash_c_map;
    update_file_name_hash_map(local_directory_path, file_name_hash_c_map);
    printf("[+] [ %s ] file name hash map:\n", 
        local_directory_path.c_str());
    show_file_name_hash_map(file_name_hash_c_map);
    printf("\n");

    // 接收服务器文件哈希 map
    std::map<std::string, std::string> file_name_hash_s_map;
    recv_KDATA_NAME_HASH_LIST(connect_fd, 
        file_name_hash_s_map, recv_buf,
        data_aes_decrypt_key, sync_data_iv);
    printf("[+] [ %s ] file name hash map:\n", 
        target_directory_path.c_str());
    show_file_name_hash_map(file_name_hash_s_map);
    printf("\n");

    // 创建请求文件的哈希 map
    std::map<std::string, std::string> req_file_name_hash_map;
    create_req_file_name_hash_map(file_name_hash_c_map, 
        file_name_hash_s_map, req_file_name_hash_map);

    // 发送请求文件的哈希 map
    send_KDATA_REQ_NAME_HASH_LIST(connect_fd, 
        req_file_name_hash_map,
        data_aes_encrypt_key, sync_data_iv);

    if (req_file_name_hash_map.size() == 0)
    {
        printf("\n[+] Synchronized.\n");
    }
    else
    {
        printf("[+] Request file name hash map:\n");
        show_file_name_hash_map(req_file_name_hash_map);
        printf("\n");

        // 建立接收文件的信息表缓冲区
        size_t num = req_file_name_hash_map.size();
        struct sync_file_info* file_info_list;
        file_info_list = new struct sync_file_info[num];
        memset(file_info_list, 0, num * sizeof(struct sync_file_info));

        size_t file_size;
        unsigned char* file_data_buf;
        std::string file_path;
        for (int i = 0; i < num; i++)
        {
            // 接收文件信息
            recv_KDATA_FILE_INFO(connect_fd, 
                &file_info_list[i], recv_buf,
                data_aes_decrypt_key, sync_data_iv);

            file_size = file_info_list[i].file_total_size;
            file_data_buf = new unsigned char[file_size];
            memset(file_data_buf, 0, file_size);

            printf("[*] Recving [ %s ] file block...\n", 
                file_info_list[i].file_name);
            for (int j = 0; j < file_info_list[i].block_total; j++)
            {
                // 接收文件块数据
                recv_KDATA_FILE_BLOCK(connect_fd, 
                    file_data_buf, recv_buf,
                    data_aes_decrypt_key, sync_data_iv);
            }

            // 保存文件
            printf("[*] Saving [ %s ] file...\n", 
                file_info_list[i].file_name);
            file_path = local_directory_path + "\\" + std::string((char*)file_info_list[i].file_name);
            save_data_to_file(file_path.c_str(), file_data_buf, file_size);

            delete[] file_data_buf;
        }
        delete[] file_info_list;

        update_file_name_hash_map(local_directory_path, file_name_hash_c_map);
        printf("[+] Sync successful!\n");
    }
    printf("\n");
}

void 
file_sync_c_fun(SOCKET& connect_fd, 
	const unsigned char* sync_data_key, const unsigned char* sync_data_iv)
{
    // 设置 data AES 加密解密密钥
    AES_KEY data_aes_encrypt_key, data_aes_decrypt_key;
    set_aes_enc_dec_key(sync_data_key, data_key_bits_length, 
        &data_aes_encrypt_key, &data_aes_decrypt_key);

    // 输入本地同步路径
    std::string local_directory_path;
    printf("Enter the path for local file synchronization >> ");
    std::getline(std::cin, local_directory_path);
    printf("\n");

    // 输入服务器文件路径
    std::string target_directory_path;
    printf("Enter the directory path of the synchronization target >> ");
    std::getline(std::cin, target_directory_path);
    printf("\n");

    // 发送服务器的文件路径
    send_KDATA_DIR_PATH(connect_fd, 
        target_directory_path,
        &data_aes_encrypt_key, sync_data_iv);

    // 接收缓冲区
    unsigned char* recv_buf;
    recv_buf = new unsigned char[0x2000];
    memset(recv_buf, 0, 0x2000);

    // 发送同步请求 or 同步结束
    std::string you_operate;
    while (true)
    {
        printf("Please select a operate, synchronous or quit(SYNC or Q) >> ");
        std::getline(std::cin, you_operate);
        printf("\n");
        if (you_operate == "SYNC" || you_operate == "Q") 
        {
            if (you_operate == "SYNC")
            {
                SYNC_C(connect_fd, local_directory_path, target_directory_path, 
                    recv_buf,
                    &data_aes_encrypt_key, &data_aes_decrypt_key, sync_data_iv);
            }
            else
            {
                // 同步结束操作
                send_sync_quit(connect_fd);
                break;
            }   
        }
        else
        {
            printf("[-] Reenter!\n");
        }
    }

    delete[] recv_buf;
}

static void
send_file_info_and_block_data(SOCKET& accept_fd, 
    const std::string& directory_path, struct sync_file_info* file_info_list, int num,
    const AES_KEY* data_aes_encrypt_key, const unsigned char* sync_data_iv)
{
    size_t file_size;
    unsigned char* file_data_buf, * file_block;
    std::string file_path;
    int file_block_size;

    // 发送文件信息和文件块
    for (int i = 0; i < num; i++)
    {
        // 发送文件信息
        send_KDATA_FILE_INFO(accept_fd, 
            &file_info_list[i],
            data_aes_encrypt_key, sync_data_iv);

        // 读取文件数据到缓冲区
        std::tuple<unsigned char*, size_t> file_info;
        file_path = directory_path + "\\" + std::string((char*)file_info_list[i].file_name);
        file_info = load_data_from_file(file_path.c_str());
        file_data_buf = std::get<0>(file_info);
        file_size = std::get<1>(file_info);

        printf("[*] Sending [ %s ] file block...\n", 
            file_info_list[i].file_name);
        for (int file_block_index = 0; file_block_index < file_info_list[i].block_total; file_block_index++)
        {
            if (file_block_index == file_info_list[i].block_total - 1)
                file_block_size = int(file_size - file_block_index * FILE_BLOCK_MAX_LENGTH);
            else
                file_block_size = FILE_BLOCK_MAX_LENGTH;
            file_block = file_data_buf + file_block_index * FILE_BLOCK_MAX_LENGTH;

            // 发送文件块
            send_KDATA_FILE_BLOCK(accept_fd, 
                file_block, 
                file_block_size, file_block_index,
                data_aes_encrypt_key, sync_data_iv);
        }

        delete[] file_data_buf;
    }
    delete[] file_info_list;

    printf("[+] Sync successful!\n");
}

static void
SYNC_S(SOCKET& accept_fd,
    const std::string& directory_path, std::map<std::string, std::string> file_name_hash_s_map,
    unsigned char* recv_buf,
    const AES_KEY* data_aes_encrypt_key, const AES_KEY* data_aes_decrypt_key, const unsigned char* sync_data_iv)
{
    struct file_sync file_sync_head { 0 };
    int file_sync_head_size = sizeof(struct file_sync);

    while (true)
    {
        // 接收客户端的同步请求或者同步结束操作
        printf("[*] Waiting for client operation...\n\n");
        recv_all(accept_fd, (char*)recv_buf, file_sync_head_size);
        memcpy(&file_sync_head, (struct file_sync*)recv_buf,
            file_sync_head_size);

        if (file_sync_head.type == 5)
        {
            // 更新本地文件哈希 map
            update_file_name_hash_map(directory_path, file_name_hash_s_map);

            // 本地文件哈希 map 转换结构体列表再发送
            send_KDATA_NAME_HASH_LIST(accept_fd, 
                file_name_hash_s_map,
                data_aes_encrypt_key, sync_data_iv);

            // 接收客户端的请求文件结构体列表
            std::map<std::string, std::string> req_file_name_hash_map;
            recv_KDATA_REQ_NAME_HASH_LIST(accept_fd, 
                req_file_name_hash_map, recv_buf,
                data_aes_decrypt_key, sync_data_iv);

            // 如果请求文件哈希 map 为空，说明客户端已经同步完毕
            if (req_file_name_hash_map.size() == 0)
            {
                printf("[+] Client synchronized.\n");
            }
            else
            {
                printf("[+] Request file name hash map:\n");
                show_file_name_hash_map(req_file_name_hash_map);
                printf("\n");

                // 获取对应文件信息，建立文件信息表
                std::tuple<struct sync_file_info*, int> file_info_list_info;
                file_info_list_info = get_file_info_to_struct(directory_path, req_file_name_hash_map);
                struct sync_file_info* file_info_list = std::get<0>(file_info_list_info);
                int num, file_info_list_size = std::get<1>(file_info_list_info);

                num = file_info_list_size / sizeof(struct sync_file_info);
                //printf("[+] File info:\n");
                //for (int i = 0; i < num; i++)
                //{
                //    printf("block: %d\n", file_info_list[i].block_total);
                //    printf("file name: %s\n", file_info_list[i].file_name);
                //    printf("file size: %llu\n", file_info_list[i].file_total_size);
                //}

                // 发送文件信息和文件块
                send_file_info_and_block_data(accept_fd,
                    directory_path, file_info_list, num,
                    data_aes_encrypt_key, sync_data_iv);
            }

            printf("\n");
        }
        else if (file_sync_head.type == 9)
        {
            printf("[+] Sync ended.\n\n");
            return;
        }
        else
        {
            printf("[-] Wrong header!\n\n");
        }
    }

}

void
file_sync_s_fun(SOCKET& accept_fd,
    const unsigned char* sync_data_key, const unsigned char* sync_data_iv)
{
    // 设置 data AES 加密解密密钥
    AES_KEY data_aes_encrypt_key, data_aes_decrypt_key;
    set_aes_enc_dec_key(sync_data_key, data_key_bits_length, 
        &data_aes_encrypt_key, &data_aes_decrypt_key);

    // 接收缓冲区
    unsigned char* recv_buf;
    recv_buf = new unsigned char[0x2000];
    memset(recv_buf, 0, 0x2000);

    // 接收文件路径
    std::string directory_path;
    recv_KDATA_DIR_PATH(accept_fd, directory_path, 
        recv_buf,
        &data_aes_decrypt_key, sync_data_iv);

    // 根据同步路径更新文件路径的文件哈希 map
    std::map<std::string, std::string> file_name_hash_s_map;
    update_file_name_hash_map(directory_path, file_name_hash_s_map);
    printf("[+] [ %s ] file name hash map:\n", 
        directory_path.c_str());
    show_file_name_hash_map(file_name_hash_s_map);
    printf("\n");

    SYNC_S(accept_fd, 
        directory_path, file_name_hash_s_map,
        recv_buf,
        &data_aes_encrypt_key, &data_aes_decrypt_key, sync_data_iv);

    delete[] recv_buf;
}