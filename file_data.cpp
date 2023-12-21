
#include "file_data.h"

std::tuple<unsigned char*, size_t>
load_data_from_file(const char* input_file_name)
{
    std::tuple<unsigned char*, size_t> result;

    std::ifstream in_file(input_file_name, std::ios::binary);
    if (!in_file.is_open())
    {
        perror("Error opening file!");
        result = std::make_tuple(nullptr, 0);
        return result;
    }

    size_t file_size;
    struct stat statbuf;
    stat(input_file_name, &statbuf);
    file_size = statbuf.st_size;

    unsigned char* file_data_buf;
    file_data_buf = new unsigned char[file_size];
    memset(file_data_buf, 0, file_size);

    in_file.read(reinterpret_cast<char*>(file_data_buf), file_size);
    in_file.close();

    result = std::make_tuple(file_data_buf, file_size);
    return result;
}

void
save_data_to_file(const char* output_file_name, const unsigned char* data_buf, size_t data_size)
{
    std::ofstream out_file(output_file_name, std::ios::binary);
    if (!out_file.is_open())
    {
        perror("Error opening file");
        return;
    }

    out_file.write(reinterpret_cast<const char*>(data_buf), data_size);
    out_file.close();
}