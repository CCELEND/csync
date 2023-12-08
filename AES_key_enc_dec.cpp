
#include "AES_need.h"

void
aes_cbc_encrypt(const unsigned char* data, unsigned char* encrypted_data,
    size_t data_size, const AES_KEY* aes_encrypt_key, const unsigned char* iv)
{
    unsigned char temp_iv[AES_BLOCK_SIZE];
    memcpy(temp_iv, iv, AES_BLOCK_SIZE);

    AES_cbc_encrypt(data, encrypted_data,
        data_size, aes_encrypt_key, temp_iv, AES_ENCRYPT);

}

void
aes_cbc_decrypt(const unsigned char* encrypted_data, unsigned char* decrypted_data,
    size_t encrypted_data_size, const AES_KEY* aes_decrypt_key, const unsigned char* iv)
{
    unsigned char temp_iv[AES_BLOCK_SIZE];
    memcpy(temp_iv, iv, AES_BLOCK_SIZE);

    AES_cbc_encrypt(encrypted_data, decrypted_data,
        encrypted_data_size, aes_decrypt_key, temp_iv, AES_DECRYPT);
}
