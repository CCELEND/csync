
#include "SHA_need.h"

std::string
sha_256(const unsigned char* data, size_t data_size, unsigned char* hash_val)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, data_size);
    SHA256_Final(hash, &sha256);

    memcpy(hash_val, hash, SHA256_DIGEST_LENGTH);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

//int main() {
//    std::string input = "Hello, SHA-256!";
//    unsigned char hash_val[SHA256_DIGEST_LENGTH];
//    std::string hashed = sha_256(input.c_str(), input.length(), hash_val);
//
//    std::cout << "Input: " << input << std::endl;
//    std::cout << "SHA-256 Hash: " << hashed << std::endl;
//
//    return 0;
//}
