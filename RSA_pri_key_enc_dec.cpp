
#include "RSA_need.h"
/*
@brief : ˽Կ����
@para  : clear_text  -[i] ��Ҫ���м��ܵ�����
		 pri_key     -[i] ˽Կ
@return: ���ܺ������
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
//	// ��ȡ RSA ���ο��Դ�������ݿ����󳤶�
//	int key_len = RSA_size(rsa);
//	int block_len = key_len - 11;    // ��Ϊ��䷽ʽΪ RSA_PKCS1_PADDING, Ҫ�� key_len �����ϼ�ȥ11
//
//	// �����ڴ棺�������ܺ����������
//	char* sub_text = new char[key_len + 1];
//	memset(sub_text, 0, key_len + 1);
//
//	int ret = 0;
//	int pos = 0;
//	std::string sub_str;
//	// �����ݽ��зֶμ��ܣ�����ֵ�Ǽ��ܺ����ݵĳ��ȣ�
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
//	// �ͷ��ڴ�  
//	delete[] sub_text;
//	BIO_free_all(keybio);
//	RSA_free(rsa);
//
//	return encrypt_text;
//}


/*
@brief : ˽Կ����
@para  : cipher_text -[i] ���ܵ�����
		 pri_key     -[i] ˽Կ
@return: ���ܺ������
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
//		unsigned long err = ERR_get_error(); //��ȡ�����
//		char err_msg[1024] = { 0 };
//		ERR_error_string(err, err_msg); // ��ʽ��error:errId:��:����:ԭ��
//		printf("err msg: err:%ld, msg:%s\n", err, err_msg);
//		return std::string();
//	}
//
//	// ��ȡRSA���δ������󳤶�
//	int key_len = RSA_size(rsa);
//
//	char* sub_text = new char[key_len + 1];
//	memset(sub_text, 0, key_len + 1);
//
//	size_t ret = 0;
//	std::string sub_str;
//	int pos = 0;
//	// �����Ľ��зֶν���
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
//	// �ͷ��ڴ�  
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

	//��2�ָ�ʽ�Ĺ�Կ
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	if (rsa == nullptr)
	{
		unsigned long err = ERR_get_error(); //��ȡ�����
		char err_msg[1024] = { 0 };
		ERR_error_string(err, err_msg); // ��ʽ��error:errId:��:����:ԭ��
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
		unsigned long err = ERR_get_error(); //��ȡ�����
		char err_msg[1024] = { 0 };
		ERR_error_string(err, err_msg); // ��ʽ��error:errId:��:����:ԭ��
		printf("[-] Err msg: err: %ld, msg: %s\n", err, err_msg);
		return;
	}

	RSA_private_decrypt(encrypted_data_length,
		encrypted_data, decrypted_data, rsa, RSA_PKCS1_PADDING);

	BIO_free_all(keybio);
	RSA_free(rsa);
}