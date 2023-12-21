#pragma once
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <iostream>
#include <fstream>

// 256比特 root 密钥
#define root_key_bits_length 256
#define root_key_bytes_length  (root_key_bits_length/8)
// 128比特 data 密钥
#define data_key_bits_length 128
#define data_key_bytes_length  (data_key_bits_length/8)

// AES_key.cpp
size_t AES_block_alignment(size_t data_size);
int generate_aes_key(unsigned char* key, int key_bytes_length);
int generate_aes_IV(unsigned char* iv);
void save_aes_key_to_file(const char* key_file_name, const unsigned char* key, size_t key_length);
void load_aes_key_from_file(const char* key_file_name, unsigned char* key, size_t key_length);
void save_aes_iv_to_file(const char* iv_file_name, const unsigned char* iv);
void load_aes_iv_from_file(const char* iv_file_name, unsigned char* iv);
int  set_aes_enc_dec_key(const unsigned char* key, int key_bits_length,
    AES_KEY* aes_encrypt_key, AES_KEY* aes_decrypt_key);

// AES_key_enc_dec.cpp
// encrypted_data: 输出数据，能够容纳下输入数据，且长度必须是16字节的倍数,
// data_size: 输入数据的实际长度
void aes_cbc_encrypt(const unsigned char* data, unsigned char* encrypted_data,
    size_t data_size, const AES_KEY* aes_encrypt_key, const unsigned char* iv);
void aes_cbc_decrypt(const unsigned char* encrypted_data, unsigned char* decrypted_data,
    size_t encrypted_data_size, const AES_KEY* aes_decrypt_key, const unsigned char* iv);