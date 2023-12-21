#pragma once
#include <iostream>
#include <filesystem>
#include <map>
#include "SHA_need.h"
#include "file_data.h"

void 
update_file_hash_table(const std::string directory_path,
	std::map<std::string, std::string>& file_name_hash);

void 
show_file_hash_table(const std::map<std::string, std::string>& file_name_hash);

void 
create_req_file_hash_table(const std::map<std::string, std::string>& file_name_hash_c,
    const std::map<std::string, std::string>& file_name_hash_s,
    std::map<std::string, std::string>& req_file_name_hash);
