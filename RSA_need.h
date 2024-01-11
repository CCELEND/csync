#pragma once
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>

#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include <openssl/x509.h>


#define RSA_KEY_LENGTH   2048             // 密钥长度
#define RSA_ENC_bytes_length	 (RSA_KEY_LENGTH/8)
#define PUB_KEY_FILE "private_key.pem"    // 公钥路径
#define PRI_KEY_FILE "public_key.pem"     // 私钥路径

void generate_rsa_key(std::string& out_pub_key, std::string& out_pri_key);

void RSA_pri_decrypt(const unsigned char* encrypted_data, unsigned char* decrypted_data, 
	const std::string& pri_key, int encrypted_data_length);

void RSA_pub_decrypt(const unsigned char* encrypted_data, unsigned char* decrypted_data,
	const std::string& pub_key, int encrypted_data_length);

void RSA_pub_encrypt(const unsigned char* data, unsigned char* encrypted_data,
	const std::string& pub_key, int data_length);

void RSA_pri_encrypt(const unsigned char* data, unsigned char* encrypted_data,
	const std::string& pri_key, int data_length);