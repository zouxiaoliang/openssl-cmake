#include "crypt.h"

namespace easy { namespace crypt { namespace base64 {

std::string encode(const std::string &source_content)
{
    const char *data = source_content.c_str();
    int data_byte = source_content.size();
    //编码表
    const char encode_table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    //返回值
    std::string dest_encode;
    unsigned char tmp[4]={0};
    int line_length=0;
    for(int i=0; i<(int)(data_byte / 3); i++)
    {
        tmp[1] = *data++;
        tmp[2] = *data++;
        tmp[3] = *data++;
        dest_encode+= encode_table[tmp[1] >> 2];
        dest_encode+= encode_table[((tmp[1] << 4) | (tmp[2] >> 4)) & 0x3F];
        dest_encode+= encode_table[((tmp[2] << 2) | (tmp[3] >> 6)) & 0x3F];
        dest_encode+= encode_table[tmp[3] & 0x3F];
        if(line_length+=4,line_length==76) {dest_encode+="\r\n";line_length=0;}
    }
    //对剩余数据进行编码
    int Mod=data_byte % 3;
    if(Mod==1)
    {
        tmp[1] = *data++;
        dest_encode+= encode_table[(tmp[1] & 0xFC) >> 2];
        dest_encode+= encode_table[((tmp[1] & 0x03) << 4)];
        dest_encode+= "==";
    }
    else if(Mod==2)
    {
        tmp[1] = *data++;
        tmp[2] = *data++;
        dest_encode+= encode_table[(tmp[1] & 0xFC) >> 2];
        dest_encode+= encode_table[((tmp[1] & 0x03) << 4) | ((tmp[2] & 0xF0) >> 4)];
        dest_encode+= encode_table[((tmp[2] & 0x0F) << 2)];
        dest_encode+= "=";
    }

    return dest_encode;
}

std::string decode(const std::string &encode_content)
{
    const char * data = encode_content.c_str();
    int data_byte = encode_content.size();
    //解码表
    const char decode_table[] =
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            62, // '+'
            0, 0, 0,
            63, // '/'
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // '0'-'9'
            0, 0, 0, 0, 0, 0, 0,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // 'A'-'Z'
            0, 0, 0, 0, 0, 0,
            26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
            39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // 'a'-'z'
        };
    //返回值
    std::string str_decode;
    int value;
    int i= 0;
    while (i < data_byte)
    {
        if (*data != '\r' && *data!='\n')
        {
            value = decode_table[*data++] << 18;
            value += decode_table[*data++] << 12;
            str_decode += (value & 0x00FF0000) >> 16;
            if (*data != '=')
            {
                value += decode_table[*data++] << 6;
                str_decode+=(value & 0x0000FF00) >> 8;
                if (*data != '=')
                {
                    value += decode_table[*data++];
                    str_decode += value & 0x000000FF;
                }
            }
            i += 4;
        }
        else// 回车换行,跳过
        {
            data++;
            i++;
        }
    }
    return str_decode;
}

}}}
