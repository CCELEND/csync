#include "file_sync.h"

unsigned char*
generate_file_sync_packet(
    int type, int raw_size, int encrypted_size,
    unsigned char* encrypted_data,
    int* packet_size)
{
    struct file_sync file_sync_head { 0 };
    int file_sync_head_size = sizeof(struct file_sync);
    file_sync_head.type = type;
    file_sync_head.raw_size = raw_size;
    file_sync_head.encrypted_size = encrypted_size;

    int file_sync_data_size = encrypted_size;

    unsigned char* file_sync_packet;
    int file_sync_packet_size = file_sync_head_size + file_sync_data_size;
    file_sync_packet = new unsigned char[file_sync_packet_size];
    memset(file_sync_packet, 0, file_sync_packet_size);

    memcpy(file_sync_packet,
        &file_sync_head, file_sync_head_size);
    memcpy(file_sync_packet + file_sync_head_size,
        encrypted_data, file_sync_data_size);
    
    *packet_size = file_sync_packet_size;
    return file_sync_packet;
}

unsigned char*
generate_file_block_packet(
    int block_index, int raw_block_size, int encrypted_block_size,
    unsigned char* encrypted_data,
    int* packet_size)
{
    struct sync_file_data file_block_head { 0 };
    int file_block_head_size = sizeof(struct sync_file_data);
    file_block_head.block_index = block_index;
    file_block_head.raw_block_size = raw_block_size;
    file_block_head.encrypted_block_size = encrypted_block_size;

    int file_block_data_size = encrypted_block_size;

    unsigned char* file_block_packet;
    int file_block_packet_size = file_block_head_size + file_block_data_size;
    file_block_packet = new unsigned char[file_block_packet_size];
    memset(file_block_packet, 0, file_block_packet_size);

    memcpy(file_block_packet,
        &file_block_head, file_block_head_size);
    memcpy(file_block_packet + file_block_head_size,
        encrypted_data, file_block_data_size);

    *packet_size = file_block_packet_size;
    return file_block_packet;
}


// map ֵ��ȡ���ṹ��
struct file_name_hash_table* 
file_name_hash_map_to_struct(const std::map<std::string, std::string>& file_name_hash, 
        int* size)
{
    int num = file_name_hash.size();
    int file_name_hash_table_size = num * sizeof(struct file_name_hash_table);
    struct file_name_hash_table* file_name_hash_table;
    file_name_hash_table = new struct file_name_hash_table[num];
    memset(file_name_hash_table, 0, file_name_hash_table_size);

    int i = 0;
    size_t len = 0;
    for (auto it : file_name_hash)
    {
        len = it.first.length();
        if (len > 63) return nullptr;
        memcpy(file_name_hash_table[i].name, it.first.c_str(), len);
        memcpy(file_name_hash_table[i].hash, it.second.c_str(), 64);
        i++;
    }

    *size = file_name_hash_table_size;
    return file_name_hash_table;
}

// �ṹ��ֵ��ȡ�� map
void struct_to_file_name_hash_map(const struct file_name_hash_table* file_name_hash_table,
    std::map<std::string, std::string>& file_name_hash,
    int num)
{
    std::string file_name, file_hash;
    unsigned char name[65] = { 0 };
    unsigned char hash[65] = { 0 };
    for (int i = 0; i < num; i++)
    {
        file_name = "";
        file_hash = "";
        memcpy(name, file_name_hash_table[i].name, 64);
        memcpy(hash, file_name_hash_table[i].hash, 64);
        file_name = std::string((char*)name);
        file_hash = std::string((char*)hash);

        file_name_hash[file_name] = file_hash;
    }

}

struct sync_file_info*
get_file_info_to_struct(const std::string& directory_path, 
    const std::map<std::string, std::string>& req_file_name_hash,
    int* list_size)
{
    int num = req_file_name_hash.size();
    int file_info_list_size = num * sizeof(struct sync_file_info);

    struct sync_file_info* file_info_list;
    file_info_list = new struct sync_file_info[num];
    memset(file_info_list, 0, file_info_list_size);

    int i = 0, block_num = 0, len = 0;
    size_t file_size;
    std::string file_path, file_name, file_hash;
    for (auto it : req_file_name_hash)
    {
        file_name = it.first; 
        file_hash = it.second;
        file_path = directory_path + "\\" + file_name;
        //std::cout << file_path << std::endl;
        //std::cout << file_name << std::endl;

        struct stat statbuf { 0 };
        stat(file_path.c_str(), &statbuf);
        file_size = statbuf.st_size;

        if (file_size % 8000)
            block_num = file_size / 8000 + 1;
        else
            block_num = file_size / 8000;

        file_info_list[i].block_total = block_num;
        file_info_list[i].file_total_size = file_size;
        len = file_name.length();
        memcpy(file_info_list[i].file_name, file_name.c_str(), len);
        memcpy(file_info_list[i].file_hash, file_hash.c_str(), 64);
        i++;
    }
    *list_size = file_info_list_size;
    return file_info_list;
}

void 
file_sync_c_fun(SOCKET& connect_fd, 
	const unsigned char* sync_data_key, const unsigned char* sync_data_iv)
{
    // ���� data AES ���ܽ�����Կ
    AES_KEY data_aes_encrypt_key, data_aes_decrypt_key;
    set_aes_enc_dec_key(sync_data_key, data_key_bits_length, &data_aes_encrypt_key, &data_aes_decrypt_key);

    // ���뱾��ͬ��·��
    std::string local_directory_path;
    printf("Enter the path for local file synchronization >> ");
    std::getline(std::cin, local_directory_path);
    printf("\n");

    //// ���±���Ŀ¼�ļ� hash ��
    //std::map<std::string, std::string> file_name_hash_c;
    //update_file_hash_table(local_directory_path, file_name_hash_c);
    //printf("[+] Local file hash table:\n");
    //show_file_hash_table(file_name_hash_c);
    //printf("\n");

    // ����������ļ�·�������ܷ���
    std::string target_directory_path;
    printf("Enter the directory path of the synchronization target >> ");
    std::getline(std::cin, target_directory_path);
    printf("\n");

    send_KDATA_DIR_PATH(connect_fd, target_directory_path,
        &data_aes_encrypt_key, sync_data_iv);

    unsigned char* recv_buf;
    recv_buf = new unsigned char[0x2000];
    memset(recv_buf, 0, 0x2000);

    // ����ͬ������ or ͬ������
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
                send_sync_start(connect_fd);

                // ���±���Ŀ¼�ļ� hash ��
                std::map<std::string, std::string> file_name_hash_c;
                update_file_hash_table(local_directory_path, file_name_hash_c);
                printf("[+] Local file hash table:\n");
                show_file_hash_table(file_name_hash_c);
                printf("\n");

                // ���շ������ļ���ϣ��
                std::map<std::string, std::string> file_name_hash_s;
                recv_KDATA_HASH_TABLE(connect_fd, file_name_hash_s, recv_buf,
                    &data_aes_decrypt_key, sync_data_iv);

                // ���������ļ��Ĺ�ϣ��
                std::map<std::string, std::string> req_file_name_hash;
                create_req_file_hash_table(file_name_hash_c, file_name_hash_s, req_file_name_hash);

                printf("[+] Request file hash table:\n");
                show_file_hash_table(req_file_name_hash);
                printf("\n");

                // ���������ļ��Ĺ�ϣ��
                send_KDATA_REQ_HASH_TABLE(connect_fd, req_file_name_hash,
                    &data_aes_encrypt_key, sync_data_iv);

                // �����ļ���Ϣ
                int num = req_file_name_hash.size();
                struct sync_file_info* file_info_list;
                file_info_list = new struct sync_file_info[num];
                memset(file_info_list, 0, num * sizeof(struct sync_file_info));

                size_t file_size;
                unsigned char* file_data_buf;
                std::string file_path;
                for (int i = 0; i < num; i++)
                {
                    // �����ļ���Ϣ
                    recv_KDATA_FILE_INFO(connect_fd, &file_info_list[i], recv_buf,
                        &data_aes_decrypt_key, sync_data_iv);

                    file_size = file_info_list[i].file_total_size;
                    file_data_buf = new unsigned char[file_size];
                    memset(file_data_buf, 0, file_size);

                    printf("[*] Recving [ %s ] file block...\n", file_info_list[i].file_name);
                    for (int j = 0; j < file_info_list[i].block_total; j++)
                    {
                        // �����ļ�������
                        recv_KDATA_FILE_BLOCK(connect_fd, file_data_buf, recv_buf,
                            &data_aes_decrypt_key, sync_data_iv);
                    }

                    // �����ļ�
                    printf("[*] Saving [ %s ] file...\n", file_info_list[i].file_name);
                    file_path = local_directory_path + "\\" + std::string((char*)file_info_list[i].file_name);
                    save_data_to_file(file_path.c_str(), file_data_buf, file_size);

                    delete[] file_data_buf;
                }
                delete[] file_info_list;
                printf("\n");

                update_file_hash_table(local_directory_path, file_name_hash_c);
                printf("[+] Sync successful!\n\n");
            }
            else
            {
                send_sync_quit(connect_fd);
                break;
            }
            
        }
        else
        {
            printf("Reenter!\n");
        }
    }

    //// ���շ������ļ���ϣ��
    //std::map<std::string, std::string> file_name_hash_s;
    //recv_KDATA_HASH_TABLE(connect_fd, file_name_hash_s, recv_buf,
    //    &data_aes_decrypt_key, sync_data_iv);

    //// ���������ļ��Ĺ�ϣ��
    //std::map<std::string, std::string> req_file_name_hash;
    //create_req_file_hash_table(file_name_hash_c, file_name_hash_s, req_file_name_hash);

    //printf("[+] Request file hash table:\n");
    //show_file_hash_table(req_file_name_hash);
    //printf("\n");

    //// ���������ļ��Ĺ�ϣ��
    //send_KDATA_REQ_HASH_TABLE(connect_fd, req_file_name_hash,
    //    &data_aes_encrypt_key, sync_data_iv);

    //// �����ļ���Ϣ
    //int num = req_file_name_hash.size();
    //struct sync_file_info* file_info_list;
    //file_info_list = new struct sync_file_info[num];
    //memset(file_info_list, 0, num * sizeof(struct sync_file_info));

    //size_t file_size;
    //unsigned char* file_data_buf;
    //std::string file_path;
    //for (int i = 0; i < num; i++)
    //{
    //    // �����ļ���Ϣ
    //    recv_KDATA_FILE_INFO(connect_fd, &file_info_list[i], recv_buf,
    //        &data_aes_decrypt_key, sync_data_iv);

    //    file_size = file_info_list[i].file_total_size;
    //    file_data_buf = new unsigned char[file_size];
    //    memset(file_data_buf, 0, file_size);

    //    printf("[*] Recving [ %s ] file block...\n", file_info_list[i].file_name);
    //    for (int j = 0; j < file_info_list[i].block_total; j++)
    //    {
    //        // �����ļ�������
    //        recv_KDATA_FILE_BLOCK(connect_fd, file_data_buf, recv_buf,
    //            &data_aes_decrypt_key, sync_data_iv);
    //    }

    //    // �����ļ�
    //    printf("[*] Saving [ %s ] file...\n", file_info_list[i].file_name);
    //    file_path = local_directory_path + "\\" + std::string((char*)file_info_list[i].file_name);
    //    save_data_to_file(file_path.c_str(), file_data_buf, file_size);

    //    delete[] file_data_buf;
    //}
    //delete[] file_info_list;
    //printf("\n");

    //update_file_hash_table(local_directory_path, file_name_hash_c);

    delete[] recv_buf;
}

void
file_sync_s_fun(SOCKET& accept_fd,
    const unsigned char* sync_data_key, const unsigned char* sync_data_iv)
{
    // ���� data AES ���ܽ�����Կ
    AES_KEY data_aes_encrypt_key, data_aes_decrypt_key;
    set_aes_enc_dec_key(sync_data_key, data_key_bits_length, &data_aes_encrypt_key, &data_aes_decrypt_key);

    unsigned char* recv_buf;
    recv_buf = new unsigned char[0x2000];
    memset(recv_buf, 0, 0x2000);

    // �����ļ�·��
    std::string directory_path;
    recv_KDATA_DIR_PATH(accept_fd, directory_path, recv_buf,
        &data_aes_decrypt_key, sync_data_iv);

    // ����·�������ļ�·�����ļ� hash ��
    std::map<std::string, std::string> file_name_hash_s;
    update_file_hash_table(directory_path, file_name_hash_s);
    printf("[+] File hash table:\n");
    show_file_hash_table(file_name_hash_s);
    printf("\n");

    struct file_sync file_sync_head { 0 };
    int file_sync_head_size = sizeof(struct file_sync);
    while (true)
    {
        printf("[*] Waiting for client operation...\n\n");
        recv_all(accept_fd, (char*)recv_buf, file_sync_head_size);
        memcpy(&file_sync_head, (struct file_sync*)recv_buf,
            file_sync_head_size);
        if (file_sync_head.type == 5)
        {
            update_file_hash_table(directory_path, file_name_hash_s);
            // ���ͼ��ܵ��ļ� hash �� 
            send_KDATA_HASH_TABLE(accept_fd, file_name_hash_s,
                &data_aes_encrypt_key, sync_data_iv);

            // ���������ļ���ϣ��
            std::map<std::string, std::string> req_file_name_hash;
            recv_KDATA_REQ_HASH_TABLE(accept_fd, req_file_name_hash, recv_buf,
                &data_aes_decrypt_key, sync_data_iv);

            // ��ȡ��Ӧ�ļ���Ϣ�������ļ���Ϣ��
            int num, file_info_list_size;
            struct sync_file_info* file_info_list;
            file_info_list = get_file_info_to_struct(directory_path, req_file_name_hash, &file_info_list_size);
            num = file_info_list_size / sizeof(struct sync_file_info);
            //printf("[+] File info:\n");
            //for (int i = 0; i < num; i++)
            //{
            //    printf("block: %d\n", file_info_list[i].block_total);
            //    printf("file name: %s\n", file_info_list[i].file_name);
            //    printf("file size: %llu\n", file_info_list[i].file_total_size);
            //}

            size_t file_size;
            unsigned char* file_data_buf, * file_block;
            std::string file_path;
            int file_block_size;
            // �����ļ�������Ϣͷ���ļ���
            for (int i = 0; i < num; i++)
            {
                // �����ļ���Ϣ
                send_KDATA_FILE_INFO(accept_fd, &file_info_list[i],
                    &data_aes_encrypt_key, sync_data_iv);
                // ��ȡ�ļ����ݵ�������
                file_path = directory_path + "\\" + std::string((char*)file_info_list[i].file_name);
                file_data_buf = load_data_from_file(file_path.c_str(), &file_size);

                printf("[*] Sending [ %s ] file block...\n", file_info_list[i].file_name);
                for (int j = 0; j < file_info_list[i].block_total; j++)
                {
                    if (j == file_info_list[i].block_total - 1)
                        file_block_size = file_size - j * 8000;
                    else
                        file_block_size = 8000;

                    file_block = file_data_buf + j * 8000;
                    // ��ʼ�����ļ���
                    send_KDATA_FILE_BLOCK(accept_fd, file_block, file_block_size, j,
                        &data_aes_encrypt_key, sync_data_iv);
                }

                delete[] file_data_buf;
            }
            delete[] file_info_list;
            printf("\n");
            printf("[+] Sync successful!\n\n");
        }
        else
        {
            printf("[+] Sync ended.\n\n");
            break;
        }

    }

    //// ���ͼ��ܵ��ļ� hash �� 
    //send_KDATA_HASH_TABLE(accept_fd, file_name_hash_s,
    //    &data_aes_encrypt_key, sync_data_iv);

    //// ���������ļ���ϣ��
    //std::map<std::string, std::string> req_file_name_hash;
    //recv_KDATA_REQ_HASH_TABLE(accept_fd, req_file_name_hash, recv_buf,
    //    &data_aes_decrypt_key, sync_data_iv);

    //// ��ȡ��Ӧ�ļ���Ϣ�������ļ���Ϣ��
    //int num, file_info_list_size;
    //struct sync_file_info* file_info_list;
    //file_info_list = get_file_info_to_struct(directory_path, req_file_name_hash, &file_info_list_size);
    //num = file_info_list_size / sizeof(struct sync_file_info);
    ////printf("[+] File info:\n");
    ////for (int i = 0; i < num; i++)
    ////{
    ////    printf("block: %d\n", file_info_list[i].block_total);
    ////    printf("file name: %s\n", file_info_list[i].file_name);
    ////    printf("file size: %llu\n", file_info_list[i].file_total_size);
    ////}

    //size_t file_size;
    //unsigned char* file_data_buf, * file_block;
    //std::string file_path;
    //int file_block_size;
    //// �����ļ�������Ϣͷ���ļ���
    //for (int i = 0; i < num; i++)
    //{
    //    // �����ļ���Ϣ
    //    send_KDATA_FILE_INFO(accept_fd, &file_info_list[i],
    //        &data_aes_encrypt_key, sync_data_iv);
    //    // ��ȡ�ļ����ݵ�������
    //    file_path = directory_path + "\\" + std::string((char*)file_info_list[i].file_name);
    //    file_data_buf = load_data_from_file(file_path.c_str(), &file_size);

    //    printf("[*] Sending [ %s ] file block...\n", file_info_list[i].file_name);
    //    for (int j = 0; j < file_info_list[i].block_total; j++)
    //    {
    //        if (j == file_info_list[i].block_total - 1)
    //            file_block_size = file_size - j * 8000;
    //        else
    //            file_block_size = 8000;

    //        file_block = file_data_buf + j * 8000;
    //        // ��ʼ�����ļ���
    //        send_KDATA_FILE_BLOCK(accept_fd, file_block, file_block_size, j,
    //            &data_aes_encrypt_key, sync_data_iv);
    //    }

    //    delete[] file_data_buf;
    //}
    //delete[] file_info_list;
    //printf("\n");

    delete[] recv_buf;
}