
#include "RSA_AES_key_agreement.h"
#include "tcp_socket.h"

int
generate_random_bytes(unsigned char* randoms, int random_bytes_length)
{
    // 使用 OpenSSL 的随机数生成函数生成随机序列
    if (RAND_bytes(randoms, random_bytes_length) != 1)
    {
        std::cerr << "Error generating random bytes!" << std::endl;
        return -1;
    }

    return 0;
}

unsigned char* 
generate_key_agreement_c_packet(
    int c_type, int raw_data_size, int encrypted_data_size,
    unsigned char* encrypted_data,
    int* packet_size)
{
    struct key_agreement_c key_agreement_c_head { 0 };
    int key_agreement_c_head_size = sizeof(struct key_agreement_c);
    key_agreement_c_head.c_type = c_type;
    key_agreement_c_head.raw_data_size = raw_data_size;
    key_agreement_c_head.encrypted_data_size = encrypted_data_size;

    int key_agreement_c_data_size = encrypted_data_size;

    unsigned char* key_agreement_c_packet;
    int key_agreement_c_packet_size = key_agreement_c_head_size + key_agreement_c_data_size;
    key_agreement_c_packet = new unsigned char[key_agreement_c_packet_size];
    memset(key_agreement_c_packet, 0, key_agreement_c_packet_size);

    memcpy(key_agreement_c_packet,
        &key_agreement_c_head, key_agreement_c_head_size);
    memcpy(key_agreement_c_packet + key_agreement_c_head_size,
        encrypted_data, key_agreement_c_data_size);

    *packet_size = key_agreement_c_packet_size;
    return key_agreement_c_packet;

}

unsigned char*
generate_key_agreement_s_packet(
    int s_type, int size,
    unsigned char* encrypted_data,
    int* packet_size)
{
    struct key_agreement_s key_agreement_s_head { 0 };
    int key_agreement_s_head_size = sizeof(struct key_agreement_s);
    key_agreement_s_head.s_type = s_type;
    key_agreement_s_head.size = size;

    int key_agreement_s_data_size = size;

    unsigned char* key_agreement_s_packet;
    int key_agreement_s_packet_size = key_agreement_s_head_size + key_agreement_s_data_size;
    key_agreement_s_packet = new unsigned char[key_agreement_s_packet_size];
    memset(key_agreement_s_packet, 0, key_agreement_s_packet_size);

    memcpy(key_agreement_s_packet,
        &key_agreement_s_head, key_agreement_s_head_size);
    memcpy(key_agreement_s_packet + key_agreement_s_head_size,
        encrypted_data, key_agreement_s_data_size);

    *packet_size = key_agreement_s_packet_size;
    return key_agreement_s_packet;
}


void
key_agreement_c_fun(SOCKET& connect_fd, 
    unsigned char* sync_data_key, unsigned char* sync_data_iv)
{
    printf("[*] Generating RSA negotiation key pairs...\n");
    std::string pub_key;
    std::string pri_key;
    // 生成协商 rsa 密钥对
    generate_rsa_key(pub_key, pri_key);

    printf("[*] Loading AES root key and iv...\n");
    // 加载 root key 文件
    unsigned char root_key[root_key_bytes_length];
    load_aes_key_from_file("root_key.bin", root_key, root_key_bytes_length);
    // 加载 root IV 文件
    unsigned char root_iv[AES_BLOCK_SIZE];
    load_aes_iv_from_file("root_iv.bin", root_iv);
    // 设置 root AES 加密解密密钥
    AES_KEY root_aes_encrypt_key, root_aes_decrypt_key;
    set_aes_enc_dec_key(root_key, root_key_bits_length, &root_aes_encrypt_key, &root_aes_decrypt_key);

    unsigned char* recv_buf;
    recv_buf = new unsigned char[0x2000];
    memset(recv_buf, 0, 0x2000);

    // 发送 root AES 加密的公钥
    send_KROOT_PUB_KEY(connect_fd, pub_key, &root_aes_encrypt_key, root_iv);

    // 接收来自服务器的用公钥加密的随机序列
    unsigned char verify_randoms[0x10] = { 0 };
    recv_PUB_KET_randoms(connect_fd, verify_randoms, recv_buf, pri_key);
    printf("[+] Verify random sequence: ");
    for (int i = 0; i < 0x10; ++i) {
        printf("%02x", verify_randoms[i]);
    }
    std::cout << std::endl;

    // 发送私钥加密的验证随机序列
    send_PRI_KET_verify_randoms(connect_fd, verify_randoms, pri_key);

    unsigned char data_key[data_key_bytes_length];
    unsigned char data_iv[AES_BLOCK_SIZE];

    recv_PUB_KEY_KDATA_KIV(connect_fd, data_key, data_iv, recv_buf, pri_key);

    printf("[+] AES data key: ");
    for (int i = 0; i < 0x10; ++i) {
        printf("%02x", data_key[i]);
    }
    std::cout << std::endl;
    printf("[+] AES IV: ");
    for (int i = 0; i < 0x10; ++i) {
        printf("%02x", data_iv[i]);
    }
    std::cout << std::endl;

    memcpy(sync_data_key, data_key, data_key_bytes_length);
    memcpy(sync_data_iv, data_iv, AES_BLOCK_SIZE);

    delete[] recv_buf;
}

void
key_agreement_s_fun(SOCKET& accept_fd, 
    unsigned char* sync_data_key, unsigned char* sync_data_iv)
{
    printf("[*] Loading AES root key and iv...\n");
    // 加载 root key 文件
    unsigned char root_key[root_key_bytes_length];
    load_aes_key_from_file("root_key.bin", root_key, root_key_bytes_length);
    // 加载 root IV 文件
    unsigned char root_iv[AES_BLOCK_SIZE];
    load_aes_iv_from_file("root_iv.bin", root_iv);
    // 设置 root AES 加密解密密钥
    AES_KEY root_aes_encrypt_key, root_aes_decrypt_key;
    set_aes_enc_dec_key(root_key, root_key_bits_length, &root_aes_encrypt_key, &root_aes_decrypt_key);

    unsigned char* recv_buf;
    recv_buf = new unsigned char[0x2000];
    memset(recv_buf, 0, 0x2000);
    std::string pub_key;

    // 接收来自客户端的 root AES 加密的公钥
    recv_KROOT_PUB_KEY(accept_fd, pub_key, recv_buf, &root_aes_decrypt_key, root_iv);

    // 生成随机序列
    unsigned char randoms[0x10];
    generate_random_bytes(randoms, 0x10);
    printf("[+] Random sequence: ");
    for (int i = 0; i < 0x10; ++i) {
        printf("%02x", randoms[i]);
    }
    std::cout << std::endl;
    // 发送公钥加密随机序列
    send_PUB_KET_randoms(accept_fd, randoms, pub_key);

    // 接收来自客户端的私钥加密的验证随机序列
    unsigned char verify_randoms[0x10];
    recv_PRI_KET_verify_randoms(accept_fd, verify_randoms, recv_buf, pub_key);

    //for (int i = 0; i < 0x10; ++i) {
    //    printf("%02x", verify_randoms[i]);
    //}
    //std::cout << std::endl;
    // 验证随机序列和客户端发送的是否一致
    if (!memcmp(randoms, verify_randoms, 0x10))
    {
        printf("[+] Verification successful!\n");
    }

    // 生成数据密钥和iv
    printf("[*] Generating AES data key and IV...\n");
    unsigned char data_key[data_key_bytes_length];
    unsigned char data_iv[AES_BLOCK_SIZE];
    generate_aes_key(data_key, data_key_bytes_length);
    generate_aes_IV(data_iv);

    printf("[+] AES data key: ");
    for (int i = 0; i < 0x10; ++i) {
        printf("%02x", data_key[i]);
    }
    std::cout << std::endl;
    printf("[+] AES IV: ");
    for (int i = 0; i < 0x10; ++i) {
        printf("%02x", data_iv[i]);
    }
    std::cout << std::endl;

    // 发送公钥加密的 data kry 和 IV
    send_PUB_KEY_KDATA_KIV(accept_fd, data_key, data_iv, pub_key);

    memcpy(sync_data_key, data_key, data_key_bytes_length);
    memcpy(sync_data_iv, data_iv, AES_BLOCK_SIZE);
        
    delete[] recv_buf;
}