#include "file_hash.h"
namespace fs = std::filesystem;

// 指定目录路径建立哈希表
void 
update_file_hash_table(const std::string directory_path, 
    std::map<std::string, std::string>& file_name_hash)
{
    unsigned char* file_data_buf = nullptr;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    std::string file_name, file_path, file_hash;
    size_t file_size;
    // 遍历目录下的所有文件
    for (const auto& entry : fs::directory_iterator(directory_path))
    {
        file_name = entry.path().filename().string();
        //printf("[+] File name: %s\n", file_name.c_str());
        file_path = directory_path + "\\" + file_name;

        file_data_buf = load_data_from_file(file_path.c_str(), &file_size);
        file_hash = sha_256(file_data_buf, file_size, hash);
        //printf("[+] File hash: %s\n", file_hash.c_str());

        file_name_hash[file_name] = file_hash;

        delete[] file_data_buf;
    }

}

void
show_file_hash_table(const std::map<std::string, std::string>& file_name_hash)
{
    for (auto it : file_name_hash)
        printf("{ %-16s : %s }\n", it.first.c_str(), it.second.c_str());

}


void
create_req_file_hash_table(const std::map<std::string, std::string>& file_name_hash_c,
    const std::map<std::string, std::string>& file_name_hash_s,
    std::map<std::string, std::string>& req_file_name_hash)
{
    //auto iter1 = map1.begin();
    //iter1 != map1.end()
    // myMap.erase(2) 删除key==2的元素 
    std::map<std::string, std::string> temp;
    //temp = file_name_hash_c.size() >= file_name_hash_s.size() ? file_name_hash_c : file_name_hash_s;
    temp = file_name_hash_s;
    req_file_name_hash = temp;

    for (auto it_temp : temp)
    {
        for (auto it_c: file_name_hash_c)
        {
            if (it_temp.second == it_c.second) 
            {
                //printf("{ %s }\n", it_c.second.c_str());
                req_file_name_hash.erase(it_temp.first);
            }
        }
    }
}