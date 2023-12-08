#pragma once
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>

std::string sha_256(const unsigned char* data, size_t data_size, unsigned char* hash_val);