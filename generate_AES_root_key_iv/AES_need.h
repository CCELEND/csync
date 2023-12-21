#pragma once
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <iostream>
#include <fstream>
#include <string>

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
int save_aes_key_to_file(const char* key_file_name, const unsigned char* key, size_t key_length);
int load_aes_key_from_file(const char* key_file_name, unsigned char* key, size_t key_length);
int save_aes_iv_to_file(const char* iv_file_name, const unsigned char* iv);
int load_aes_iv_from_file(const char* iv_file_name, unsigned char* iv);
int set_aes_enc_dec_key(const unsigned char* key, int key_bits_length,
    AES_KEY* aes_encrypt_key, AES_KEY* aes_decrypt_key);
