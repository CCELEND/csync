#include "file_hash.h"
namespace fs = std::filesystem;

// 指定目录路径建立哈希 map
void 
update_file_name_hash_map(const std::string directory_path, 
    std::map<std::string, std::string>& file_name_hash_map)
{
    unsigned char* file_data_buf = nullptr;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    std::string file_name, file_path, file_hash;
    size_t file_size;
    // 遍历目录下的所有文件
    for (const auto& entry : fs::directory_iterator(directory_path))
    {
        file_name = entry.path().filename().string();
        file_path = directory_path + "\\" + file_name;

        std::tuple<unsigned char*, size_t> file_info;
        file_info = load_data_from_file(file_path.c_str());
        file_data_buf = std::get<0>(file_info);
        file_size = std::get<1>(file_info);

        file_hash = sha_256(file_data_buf, file_size, hash);

        file_name_hash_map[file_name] = file_hash;

        delete[] file_data_buf;
    }
}

void
show_file_name_hash_map(const std::map<std::string, std::string>& file_name_hash_map)
{
    for (auto it : file_name_hash_map)
    {
        printf("{ %-16s : %s }\n", it.first.c_str(), it.second.c_str());
    }

}


void
create_req_file_name_hash_map(const std::map<std::string, std::string>& file_name_hash_c_map,
    const std::map<std::string, std::string>& file_name_hash_s_map,
    std::map<std::string, std::string>& req_file_name_hash_map)
{
    std::map<std::string, std::string> temp;
    temp = file_name_hash_s_map;
    req_file_name_hash_map = temp;

    for (auto it_temp : temp)
    {
        for (auto it_c: file_name_hash_c_map)
        {
            if (it_temp.second == it_c.second) 
            {
                //  删除key==it_temp.first的元素
                req_file_name_hash_map.erase(it_temp.first);
            }
        }
    }
}