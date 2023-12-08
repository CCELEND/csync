#include <iostream>
#include <string>
#include "tcp_socket.h"
#include "RSA_AES_key_agreement.h"

int main()
{
	std::string you_character;
	while (true)
	{
		printf("Please select a role, client or server(C or S) >> ");
		std::getline(std::cin, you_character);
		if (you_character == "C" || you_character == "S")
			break;
		else
			printf("Reenter!\n");
	}

	if (!init_socket_lib()) exit(0);

	if (you_character == "C")
	{
		client_fun();
		system("pause");
	}
	else
	{
		server_fun();
		system("pause");
	}

	close_socket_lib();
	return 0;
}