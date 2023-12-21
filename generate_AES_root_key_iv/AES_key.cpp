
#include "AES_need.h"

size_t
AES_block_alignment(size_t data_size)
{
    return ((data_size + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
}

int
generate_aes_key(unsigned char* key, int key_bytes_length)
{
    // 使用 OpenSSL 的随机数生成函数生成随机数作为密钥
    if (RAND_bytes(key, key_bytes_length) != 1)
    {
        std::cerr << "Error generating random key!" << std::endl;
        return -1;
    }

    return 0;
}

int
generate_aes_IV(unsigned char* iv)
{
    // 使用 OpenSSL 的随机数生成函数生成随机数作为 IV
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1)
    {
        std::cerr << "Error generating random IV!" << std::endl;
        return -1;
    }

    return 0;
}

int
set_aes_enc_dec_key(const unsigned char* key, int key_bits_length,
    AES_KEY* aes_encrypt_key, AES_KEY* aes_decrypt_key)
{
    // 设置 AES 加密密钥
    if (AES_set_encrypt_key(key, key_bits_length, aes_encrypt_key) < 0)
    {
        std::cerr << "Error setting AES encryption key!" << std::endl;
        return -1;
    }

    // 设置 AES 解密密钥
    if (AES_set_decrypt_key(key, key_bits_length, aes_decrypt_key) < 0)
    {
        std::cerr << "Error setting AES decryption key!" << std::endl;
        return -1;
    }

    return 0;
}

// 保存密钥到文件
int
save_aes_key_to_file(const char* key_file_name, const unsigned char* key, size_t key_length)
{
    std::ofstream out_file(key_file_name, std::ios::binary);
    if (!out_file)
    {
        std::cerr << "Error opening random key file for writing！" << std::endl;
        return -1;
    }

    out_file.write(reinterpret_cast<const char*>(key), key_length);
    out_file.close();

    return 0;
}


int
load_aes_key_from_file(const char* key_file_name, unsigned char* key, size_t key_length)
{
    std::ifstream in_file(key_file_name, std::ios::binary);
    if (!in_file)
    {
        std::cerr << "Error opening random key file for reading" << std::endl;
        return -1;
    }

    in_file.read(reinterpret_cast<char*>(key), key_length);
    in_file.close();

    return 0;
}

// 保存 iv 到文件
int
save_aes_iv_to_file(const char* iv_file_name, const unsigned char* iv)
{
    std::ofstream out_file(iv_file_name, std::ios::binary);
    if (!out_file)
    {
        std::cerr << "Error opening random iv file for writing！" << std::endl;
        return -1;
    }

    out_file.write(reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);
    out_file.close();

    return 0;
}

int
load_aes_iv_from_file(const char* iv_file_name, unsigned char* iv)
{
    std::ifstream in_file(iv_file_name, std::ios::binary);
    if (!in_file)
    {
        std::cerr << "Error opening random iv file for reading" << std::endl;
        return -1;
    }

    in_file.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
    in_file.close();

    return 0;
}

