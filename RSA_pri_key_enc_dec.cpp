
#include "RSA_need.h"
/*
@brief : 私钥加密
@para  : clear_text  -[i] 需要进行加密的明文
		 pri_key     -[i] 私钥
@return: 加密后的数据
**/
//std::string rsa_pri_encrypt(const std::string& clear_text, std::string& pri_key)
//{
//	std::string encrypt_text;
//	BIO* keybio = BIO_new_mem_buf((unsigned char*)pri_key.c_str(), -1);
//	RSA* rsa = RSA_new();
//
//	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
//	if (!rsa)
//	{
//		BIO_free_all(keybio);
//		return std::string("");
//	}
//
//	// 获取 RSA 单次可以处理的数据块的最大长度
//	int key_len = RSA_size(rsa);
//	int block_len = key_len - 11;    // 因为填充方式为 RSA_PKCS1_PADDING, 要在 key_len 基础上减去11
//
//	// 申请内存：存贮加密后的密文数据
//	char* sub_text = new char[key_len + 1];
//	memset(sub_text, 0, key_len + 1);
//
//	int ret = 0;
//	int pos = 0;
//	std::string sub_str;
//	// 对数据进行分段加密（返回值是加密后数据的长度）
//	while (pos < clear_text.length())
//	{
//		sub_str = clear_text.substr(pos, block_len);
//		memset(sub_text, 0, key_len + 1);
//		ret = RSA_private_encrypt(sub_str.length(),
//			(const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
//		if (ret >= 0)
//		{
//			encrypt_text.append(std::string(sub_text, ret));
//		}
//		pos += block_len;
//	}
//
//	// 释放内存  
//	delete[] sub_text;
//	BIO_free_all(keybio);
//	RSA_free(rsa);
//
//	return encrypt_text;
//}


/*
@brief : 私钥解密
@para  : cipher_text -[i] 加密的密文
		 pri_key     -[i] 私钥
@return: 解密后的数据
**/
//std::string rsa_pri_decrypt(const std::string& cipher_text, const std::string& pri_key)
//{
//	std::string decrypt_text;
//	RSA* rsa = RSA_new();
//	BIO* keybio;
//	keybio = BIO_new_mem_buf((unsigned char*)pri_key.c_str(), -1);
//
//	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
//	if (rsa == nullptr)
//	{
//		unsigned long err = ERR_get_error(); //获取错误号
//		char err_msg[1024] = { 0 };
//		ERR_error_string(err, err_msg); // 格式：error:errId:库:函数:原因
//		printf("err msg: err:%ld, msg:%s\n", err, err_msg);
//		return std::string();
//	}
//
//	// 获取RSA单次处理的最大长度
//	int key_len = RSA_size(rsa);
//
//	char* sub_text = new char[key_len + 1];
//	memset(sub_text, 0, key_len + 1);
//
//	size_t ret = 0;
//	std::string sub_str;
//	int pos = 0;
//	// 对密文进行分段解密
//	while (pos < cipher_text.length())
//	{
//		sub_str = cipher_text.substr(pos, key_len);
//		memset(sub_text, 0, key_len + 1);
//		ret = RSA_private_decrypt(sub_str.length(),
//			(const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
//		if (ret >= 0)
//		{
//			decrypt_text.append(std::string(sub_text, ret));
//			pos += key_len;
//		}
//	}
//
//	// 释放内存  
//	delete[] sub_text;
//	BIO_free_all(keybio);
//	RSA_free(rsa);
//
//	return decrypt_text;
//}

void RSA_pri_encrypt(const unsigned char* data, unsigned char* encrypted_data,
	const std::string& pri_key, int data_length)
{
	BIO* keybio = BIO_new_mem_buf((unsigned char*)pri_key.c_str(), -1);
	RSA* rsa = RSA_new();

	//第2种格式的公钥
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	if (rsa == nullptr)
	{
		unsigned long err = ERR_get_error(); //获取错误号
		char err_msg[1024] = { 0 };
		ERR_error_string(err, err_msg); // 格式：error:errId:库:函数:原因
		printf("[-] Err msg: err: %ld, msg: %s\n", err, err_msg);
		return;
	}

	RSA_private_encrypt(data_length,
		data, encrypted_data, rsa, RSA_PKCS1_PADDING);

	BIO_free_all(keybio);
	RSA_free(rsa);
}

void 
RSA_pri_decrypt(const unsigned char* encrypted_data, unsigned char* decrypted_data, 
	const std::string& pri_key, int encrypted_data_length)
{
	RSA* rsa = RSA_new();
	BIO* keybio;
	keybio = BIO_new_mem_buf((unsigned char*)pri_key.c_str(), -1);

	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	if (rsa == nullptr)
	{
		unsigned long err = ERR_get_error(); //获取错误号
		char err_msg[1024] = { 0 };
		ERR_error_string(err, err_msg); // 格式：error:errId:库:函数:原因
		printf("[-] Err msg: err: %ld, msg: %s\n", err, err_msg);
		return;
	}

	RSA_private_decrypt(encrypted_data_length,
		encrypted_data, decrypted_data, rsa, RSA_PKCS1_PADDING);

	BIO_free_all(keybio);
	RSA_free(rsa);
}