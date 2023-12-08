
#include "RSA_need.h"

// 创建密钥对：私钥和公钥
void generate_rsa_key(std::string& out_pub_key, std::string& out_pri_key)
{
	size_t pri_len = 0; // 私钥长度
	size_t pub_len = 0; // 公钥长度
	char* pri_key = nullptr; // 私钥
	char* pub_key = nullptr; // 公钥

	// 生成密钥对
	RSA* keypair = RSA_generate_key(RSA_KEY_LENGTH, RSA_3, NULL, NULL);

	BIO* pri = BIO_new(BIO_s_mem());
	BIO* pub = BIO_new(BIO_s_mem());

	// 生成私钥
	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	// 生成第2种格式的公钥
	PEM_write_bio_RSA_PUBKEY(pub, keypair);

	// 获取长度  
	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	// 密钥对读取到字符串
	pri_key = new char[pri_len + 1];
	pub_key = new char[pub_len + 1];

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	out_pub_key = pub_key;
	out_pri_key = pri_key;

	// 释放内存
	RSA_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);

	delete[] pri_key;
	delete[] pub_key;
}