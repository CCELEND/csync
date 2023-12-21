
#include "RSA_AES_key_agreement.h"

void 
send_KROOT_PUB_KEY(SOCKET& connect_fd, const std::string& pub_key,
    const AES_KEY* root_aes_encrypt_key, const unsigned char* root_iv)
{
    int pub_key_length = pub_key.length();
    int pub_key_encrypted_data_size = AES_block_alignment(pub_key_length);

    printf("[+] RSA negotiates public key information:\n");
    printf("[+] Public Key length: %d\n", pub_key_length);
    printf("%s\n", pub_key.c_str());

    // ���� root AES ���ܺ�Կ���ݵĻ�����
    unsigned char* encrypted_pub_key;
    encrypted_pub_key = new unsigned char[pub_key_encrypted_data_size];
    memset(encrypted_pub_key, 0, pub_key_encrypted_data_size);
    // root AES ���ܹ�Կ
    aes_cbc_encrypt((const unsigned char*)(pub_key.c_str()), encrypted_pub_key,
        pub_key_length, root_aes_encrypt_key, root_iv);

    // ���� key_agreement_c_packet
    int key_agreement_c_packet_size;
    unsigned char* key_agreement_c_packet;

    key_agreement_c_packet = generate_key_agreement_c_packet(
        0, pub_key_length, pub_key_encrypted_data_size,
        encrypted_pub_key,
        &key_agreement_c_packet_size);

    // ���� root AES ���ܵĹ�Կ
    printf("[*] Sending RSA negotiation public key...\n");
    send_all(connect_fd, (char*)key_agreement_c_packet, key_agreement_c_packet_size);

    delete[] key_agreement_c_packet;
    delete[] encrypted_pub_key;
}

void 
recv_PUB_KET_randoms(SOCKET& connect_fd, unsigned char* verify_randoms,
    unsigned char* recv_buf, 
    const std::string& pri_key)
{
    struct key_agreement_s key_agreement_s_head { 0 };
    int key_agreement_s_head_size = sizeof(struct key_agreement_s);

    // �������Է������Ĺ�Կ���ܵ��������
    printf("[*] Receiving public key encrypted random sequence...\n");
    recv_all(connect_fd, (char*)recv_buf, key_agreement_s_head_size);
    memcpy(&key_agreement_s_head, (struct key_agreement_c*)recv_buf,
        key_agreement_s_head_size);

    if (key_agreement_s_head.s_type == 2)
    {
        int encrypted_randoms_size;
        encrypted_randoms_size = key_agreement_s_head.size;
        unsigned char* encrypted_randoms = new unsigned char[encrypted_randoms_size];
        recv_all(connect_fd, (char*)recv_buf, encrypted_randoms_size);
        memcpy(encrypted_randoms, recv_buf, encrypted_randoms_size);

        // ˽Կ���ܻ����֤�������
        RSA_pri_decrypt(encrypted_randoms, verify_randoms, pri_key, encrypted_randoms_size);

        delete[] encrypted_randoms;
    }
}

void 
send_PRI_KET_verify_randoms(SOCKET& connect_fd, const unsigned char* verify_randoms,
    const std::string& pri_key)
{
    printf("[*] Generating private key encrypted verify random sequence...\n");
    int encrypted_verify_randoms_length = RSA_ENC_bytes_length;

    // ����˽Կ���ܺ���֤������еĻ�����
    unsigned char* encrypted_verify_randoms;
    encrypted_verify_randoms = new unsigned char[encrypted_verify_randoms_length];
    memset(encrypted_verify_randoms, 0, encrypted_verify_randoms_length);
    // ˽Կ������֤�������
    RSA_pri_encrypt(verify_randoms, encrypted_verify_randoms, pri_key, 0x10);

    // ���� key_agreement_c_packet
    int key_agreement_c_packet_size;
    unsigned char* key_agreement_c_packet;

    key_agreement_c_packet = generate_key_agreement_c_packet(
        1, 0x10, encrypted_verify_randoms_length,
        encrypted_verify_randoms,
        &key_agreement_c_packet_size);

    // ����˽Կ���ܵ���֤�������
    printf("[*] Sending private key encrypted verify random sequence...\n");
    send_all(connect_fd, (char*)key_agreement_c_packet, key_agreement_c_packet_size);

    delete[] key_agreement_c_packet;
    delete[] encrypted_verify_randoms;
}

void 
recv_PUB_KEY_KDATA_KIV(SOCKET& connect_fd, unsigned char* data_key, unsigned char* data_iv,
    unsigned char* recv_buf,
    const std::string& pri_key)
{
    struct key_agreement_s key_agreement_s_head { 0 };
    int key_agreement_s_head_size = sizeof(struct key_agreement_s);

    // �������Է������Ĺ�Կ���� data key �� IV
    printf("[*] Receiving public key encrypted AES data key and IV...\n");
    recv_all(connect_fd, (char*)recv_buf, key_agreement_s_head_size);
    memcpy(&key_agreement_s_head, (struct key_agreement_c*)recv_buf,
        key_agreement_s_head_size);

    if (key_agreement_s_head.s_type == 3)
    {
        int encrypted_data_key_length = RSA_ENC_bytes_length;
        int encrypted_data_iv_length = RSA_ENC_bytes_length;

        int encrypted_data_key_iv_size;
        encrypted_data_key_iv_size = key_agreement_s_head.size;
        unsigned char* encrypted_data_key_iv = new unsigned char[encrypted_data_key_iv_size];
        recv_all(connect_fd, (char*)recv_buf, encrypted_data_key_iv_size);
        memcpy(encrypted_data_key_iv, recv_buf, encrypted_data_key_iv_size);

        unsigned char* encrypted_data_key;
        encrypted_data_key = new unsigned char[encrypted_data_key_length];
        memcpy(encrypted_data_key, encrypted_data_key_iv, encrypted_data_key_length);

        unsigned char* encrypted_data_iv;
        encrypted_data_iv = new unsigned char[encrypted_data_iv_length];
        memcpy(encrypted_data_iv, encrypted_data_key_iv + encrypted_data_key_length, 
            encrypted_data_iv_length);

        // ˽Կ���ܻ�� data key
        RSA_pri_decrypt(encrypted_data_key, data_key, pri_key, encrypted_data_key_length);

        // ˽Կ���ܻ�� data iv
        RSA_pri_decrypt(encrypted_data_iv, data_iv, pri_key, encrypted_data_iv_length);

        delete[] encrypted_data_key_iv;
        delete[] encrypted_data_key;
        delete[] encrypted_data_iv;
    }

}