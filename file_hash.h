#pragma once
#include <iostream>
#include <filesystem>
#include <map>
#include "SHA_need.h"
#include "file_data.h"

void 
update_file_name_hash_map(const std::string directory_path,
	std::map<std::string, std::string>& file_name_hash_map);

void 
show_file_name_hash_map(const std::map<std::string, std::string>& file_name_hash_map);

void 
create_req_file_name_hash_map(const std::map<std::string, std::string>& file_name_hash_c_map,
    const std::map<std::string, std::string>& file_name_hash_s_map,
    std::map<std::string, std::string>& req_file_name_hash_map);
