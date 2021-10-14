#include "crypt.h"

namespace easy { namespace crypt { namespace hex {

std::string encode(const unsigned char *input, size_t input_len)
{
    if(NULL == input || input_len <= 0)
    {
        return "";
    }
    std::string output;
    char hex_chr[3];
    for(size_t i = 0; i < input_len; ++i)
    {
        memset(hex_chr, 0, sizeof(hex_chr));
        snprintf(hex_chr, 3, "%02x", input[i]);
        output.append(hex_chr);
    }
    return output;
}

void encode(const std::string &input, std::string &output)
{
    if(input.empty())
    {
        return;
    }
    int input_len = input.size();
    char hex_chr[3];
    for(int i = 0; i < input_len; ++i)
    {
        memset(hex_chr, 0, sizeof(hex_chr));
        snprintf(hex_chr, 3, "%02x", input.c_str()[i]);
        output.append(hex_chr);
    }
}

void decode(const char *input, const int input_len, std::string &output)
{
    int cout = 0;
    // 提供一个缓冲区，减少拷贝构造
    char steam_char[512];
    memset(steam_char, 0, sizeof(steam_char));
    unsigned char high_char, low_char;

    for (int i = 0; i < input_len; i += 2)
    {
        high_char = toupper(input[i]);
        low_char  = toupper(input[i + 1]);

        high_char -= (high_char > 0x39 ? 0x37 : 0x30);
        low_char -= (low_char > 0x39 ? 0x37 : 0x30);

        if(cout == (sizeof(steam_char)))
        {
            output.append(steam_char);
            memset(steam_char, 0, sizeof(steam_char));
            cout = 0;
        }
        steam_char[cout] = ((high_char << 4) | low_char);
        cout++;
    }
    output.append(steam_char);
}

}}}
