
#include "RSA_need.h"

// ������Կ�ԣ�˽Կ�͹�Կ
void generate_rsa_key(std::string& out_pub_key, std::string& out_pri_key)
{
	size_t pri_len = 0; // ˽Կ����
	size_t pub_len = 0; // ��Կ����
	char* pri_key = nullptr; // ˽Կ
	char* pub_key = nullptr; // ��Կ

	// ������Կ��
	RSA* keypair = RSA_generate_key(RSA_KEY_LENGTH, RSA_3, NULL, NULL);

	BIO* pri = BIO_new(BIO_s_mem());
	BIO* pub = BIO_new(BIO_s_mem());

	// ����˽Կ
	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	// ���ɵ�2�ָ�ʽ�Ĺ�Կ
	PEM_write_bio_RSA_PUBKEY(pub, keypair);

	// ��ȡ����  
	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	// ��Կ�Զ�ȡ���ַ���
	pri_key = new char[pri_len + 1];
	pub_key = new char[pub_len + 1];

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	out_pub_key = pub_key;
	out_pri_key = pri_key;

	// �ͷ��ڴ�
	RSA_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);

	delete[] pri_key;
	delete[] pub_key;
}