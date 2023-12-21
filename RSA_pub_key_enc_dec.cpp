
#include "RSA_need.h"

void RSA_pub_encrypt(const unsigned char* data, unsigned char* encrypted_data,
	const std::string& pub_key, int data_length)
{
	BIO* keybio = BIO_new_mem_buf((unsigned char*)pub_key.c_str(), -1);
	RSA* rsa = RSA_new();

	//第2种格式的公钥
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	if (rsa == nullptr)
	{
		unsigned long err = ERR_get_error(); //获取错误号
		char err_msg[1024] = { 0 };
		ERR_error_string(err, err_msg); // 格式：error:errId:库:函数:原因
		printf("[-] Err msg: err: %ld, msg: %s\n", err, err_msg);
		return;
	}

	RSA_public_encrypt(data_length,
		data, encrypted_data, rsa, RSA_PKCS1_PADDING);

	BIO_free_all(keybio);
	RSA_free(rsa);
}

void
RSA_pub_decrypt(const unsigned char* encrypted_data, unsigned char* decrypted_data,
	const std::string& pub_key, int encrypted_data_length)
{
	RSA* rsa = RSA_new();
	BIO* keybio;
	keybio = BIO_new_mem_buf((unsigned char*)pub_key.c_str(), -1);

	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	if (rsa == nullptr)
	{
		unsigned long err = ERR_get_error(); //获取错误号
		char err_msg[1024] = { 0 };
		ERR_error_string(err, err_msg); // 格式：error:errId:库:函数:原因
		printf("[-] Err msg: err: %ld, msg: %s\n", err, err_msg);
		return;
	}

	RSA_public_decrypt(encrypted_data_length,
		encrypted_data, decrypted_data, rsa, RSA_PKCS1_PADDING);

	BIO_free_all(keybio);
	RSA_free(rsa);
}