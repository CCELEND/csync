#pragma once

#include <iostream>
#include <fstream>

unsigned char* load_data_from_file(const char* input_file_name, size_t* filesize_p);

void save_data_to_file(const char* output_file_name, const unsigned char* data_buf,
	size_t data_size);