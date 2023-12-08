#include "RSA_AES_key_agreement.h"

void 
recv_KROOT_PUB_KEY(SOCKET& accept_fd, std::string& pub_key,
    unsigned char* recv_buf,
    const AES_KEY* root_aes_decrypt_key, const unsigned char* root_iv)
{
    struct key_agreement_c key_agreement_c_head { 0 };
    int key_agreement_c_head_size = sizeof(struct key_agreement_c);

    printf("[*] Receiving RSA negotiation public key...\n");
    recv_all(accept_fd, (char*)recv_buf, key_agreement_c_head_size);
    memcpy(&key_agreement_c_head, (struct key_agreement_c*)recv_buf,
        key_agreement_c_head_size);

    if (key_agreement_c_head.c_type == 0)
    {
        int pub_key_length, encrypted_pub_key_size;
        pub_key_length = key_agreement_c_head.raw_data_size;
        encrypted_pub_key_size = key_agreement_c_head.encrypted_data_size;
        printf("[+] Encryption RSA negotiation public key length: %d\n", encrypted_pub_key_size);

        // 分配 root AES 解密后公钥数据的缓冲区
        unsigned char* decrypted_pub_key;
        decrypted_pub_key = new unsigned char[encrypted_pub_key_size];
        memset(decrypted_pub_key, 0, encrypted_pub_key_size);

        recv_all(accept_fd, (char*)recv_buf, encrypted_pub_key_size);
        // root AES 解密获得公钥
        aes_cbc_decrypt(recv_buf, decrypted_pub_key,
            encrypted_pub_key_size, root_aes_decrypt_key, root_iv);

        pub_key = std::string((char*)decrypted_pub_key);
        printf("[+] RSA negotiation public key:\n%s\n", pub_key.c_str());

        delete[] decrypted_pub_key;
    }

}

void 
send_PUB_KET_randoms(SOCKET& accept_fd, const unsigned char* randoms,
    const std::string& pub_key)
{
    printf("[*] Generating public key encrypted random sequence...\n");
    int encrypted_randoms_length = RSA_ENC_bytes_length;

    // 分配公钥加密后随机序列的缓冲区
    unsigned char* encrypted_randoms;
    encrypted_randoms = new unsigned char[encrypted_randoms_length];
    memset(encrypted_randoms, 0, encrypted_randoms_length);
    // 公钥加密随机序列
    RSA_pub_encrypt(randoms, encrypted_randoms, pub_key, 0x10);

    // 生成 key_agreement_s_packet
    int key_agreement_s_packet_size;
    unsigned char* key_agreement_s_packet;

    key_agreement_s_packet = generate_key_agreement_s_packet(
        2, encrypted_randoms_length,
        encrypted_randoms,
        &key_agreement_s_packet_size);

    printf("[*] Sending public key encrypted random sequence...\n");
    // 发送公钥加密随机序列
    send_all(accept_fd, (char*)key_agreement_s_packet, key_agreement_s_packet_size);

    delete[] encrypted_randoms;
    delete[] key_agreement_s_packet;
}

void 
recv_PRI_KET_verify_randoms(SOCKET& accept_fd, unsigned char* verify_randoms,
    unsigned char* recv_buf,
    const std::string& pub_key)
{
    struct key_agreement_c key_agreement_c_head { 0 };
    int key_agreement_c_head_size = sizeof(struct key_agreement_c);

    printf("[*] Receiving private key encrypted verify random sequence...\n");
    recv_all(accept_fd, (char*)recv_buf, key_agreement_c_head_size);
    memcpy(&key_agreement_c_head, (struct key_agreement_c*)recv_buf,
        key_agreement_c_head_size);

    if (key_agreement_c_head.c_type == 1)
    {
        int verify_random_length, encrypted_verify_random_length;
        verify_random_length = key_agreement_c_head.raw_data_size;
        encrypted_verify_random_length = key_agreement_c_head.encrypted_data_size;
        printf("[+] Encryption verify random sequence length: %d\n", encrypted_verify_random_length);

        unsigned char* encrypted_verify_random = new unsigned char[encrypted_verify_random_length];
        recv_all(accept_fd, (char*)recv_buf, encrypted_verify_random_length);
        memcpy(encrypted_verify_random, recv_buf, encrypted_verify_random_length);
        // 公钥解密客户端发送的验证随机序列
        RSA_pub_decrypt(encrypted_verify_random, verify_randoms, pub_key, encrypted_verify_random_length);

        delete[] encrypted_verify_random;
    }
}

void send_PUB_KEY_KDATA_KIV(
    SOCKET& accept_fd, const unsigned char* data_key, const unsigned char* data_iv,
    const std::string& pub_key)
{
    printf("[*] Generating public key encrypted AES data key and IV...\n");
    int encrypted_data_key_length = RSA_ENC_bytes_length;
    int encrypted_data_iv_length = RSA_ENC_bytes_length;
    int encrypted_data_key_iv_length = encrypted_data_key_length + encrypted_data_iv_length;

    // 分配公钥加密后 data key 的缓冲区
    unsigned char* encrypted_data_key;
    encrypted_data_key = new unsigned char[encrypted_data_key_length];
    memset(encrypted_data_key, 0, encrypted_data_key_length);
    // 公钥加密 data key
    RSA_pub_encrypt(data_key, encrypted_data_key, pub_key, 0x10);

    // 分配公钥加密后 data iv 的缓冲区
    unsigned char* encrypted_data_iv;
    encrypted_data_iv = new unsigned char[encrypted_data_iv_length];
    memset(encrypted_data_iv, 0, encrypted_data_iv_length);
    // 公钥加密 data iv
    RSA_pub_encrypt(data_iv, encrypted_data_iv, pub_key, 0x10);

    unsigned char* encrypted_data_key_iv;
    encrypted_data_key_iv = new unsigned char[encrypted_data_key_iv_length];
    memset(encrypted_data_key_iv, 0, encrypted_data_key_iv_length);

    memcpy(encrypted_data_key_iv, encrypted_data_key, encrypted_data_key_length);
    memcpy(encrypted_data_key_iv + encrypted_data_key_length, 
        encrypted_data_iv, encrypted_data_iv_length);

    // 生成 key_agreement_s_packet
    int key_agreement_s_packet_size;
    unsigned char* key_agreement_s_packet;

    key_agreement_s_packet = generate_key_agreement_s_packet(
        3, encrypted_data_key_iv_length,
        encrypted_data_key_iv,
        &key_agreement_s_packet_size);

    printf("[*] Sending public key encrypted AES data key and IV...\n");
    // 发送公钥加密的 data key 和 data iv
    send_all(accept_fd, (char*)key_agreement_s_packet, key_agreement_s_packet_size);

    delete[] encrypted_data_key;
    delete[] encrypted_data_iv;
    delete[] encrypted_data_key_iv;
    delete[] key_agreement_s_packet;
}