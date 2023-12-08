
#include "file_data.h"

unsigned char*
load_data_from_file(const char* input_file_name, size_t* file_size_p)
{
    std::ifstream in_file(input_file_name, std::ios::binary);
    if (!in_file.is_open())
    {
        perror("Error opening file");
        *file_size_p = 0;
        return NULL;
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

    *file_size_p = file_size;
    return file_data_buf;
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