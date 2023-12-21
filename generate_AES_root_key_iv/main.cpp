
#include "AES_need.h"

int main()
{
	std::string you_key_type;
	while (true)
	{
		printf("Please select a key type, root or data(R or D) >> ");

		std::getline(std::cin, you_key_type);
		if (you_key_type == "R" || you_key_type == "D" ||
			you_key_type == "root" || you_key_type == "data")
			break;
		else
			printf("Reenter!\n");
	}

	if (you_key_type == "root" || you_key_type == "R")
	{
		unsigned char root_key[root_key_bytes_length];
		unsigned char root_iv[AES_BLOCK_SIZE];

		if (!generate_aes_key(root_key, root_key_bytes_length) &&
			!save_aes_key_to_file("root_key.bin", root_key, root_key_bytes_length))
		{
			printf("[+] Successfully saved root AES key.\n");
		}
		else
			printf("[-] Failed to save root AES key!\n");

		if (!generate_aes_IV(root_iv) &&
			!save_aes_iv_to_file("root_iv.bin", root_iv))
		{
			printf("[+] Successfully saved root AES iv.\n");
		}
		else
			printf("[-] Failed to saved root AES iv.\n");


		system("pause");
	}
	else
	{
		unsigned char data_key[data_key_bytes_length];
		unsigned char data_iv[AES_BLOCK_SIZE];

		if (!generate_aes_key(data_key, data_key_bytes_length) &&
			!save_aes_key_to_file("data_key.bin", data_key, data_key_bytes_length))
		{
			printf("[+] Successfully saved data AES key.\n");
		}
		else
			printf("[-] Failed to save data AES key!\n");

		if (!generate_aes_IV(data_iv) &&
			!save_aes_iv_to_file("data_iv.bin", data_iv))
		{
			printf("[+] Successfully saved data AES iv.\n");
		}
		else
			printf("[-] Failed to save data AES iv!\n");

		system("pause");
	}

	return 0;
}