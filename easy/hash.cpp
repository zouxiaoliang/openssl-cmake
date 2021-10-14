#include "crypt.h"

#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

namespace easy { namespace crypt { namespace hash {

/// @brief 哈希表
static uint64_t s_crypt_table[0x500];

#ifdef HASH_DEBUG
#include <stdio.h>
#define DEF_LOG(fmt...) printf(fmt)
#else
#define DEF_LOG(fmt...)
#endif

/**
 * @brief init_hash_table 初始化hash表
 * @return 0 成功； 1 表示已经初始化
 */
int init_hash_table()
{
    DEF_LOG("%s\n", "初始化hash表...");
    static bool is_init =  false;
    if (is_init)
    {
        DEF_LOG("%s\n", "hash表 已经初始化");
        return 1;
    }
    memset(s_crypt_table, 0x0, sizeof(s_crypt_table));

    uint64_t seed = 0x00100001, index1 = 0, index2 = 0, i;

    for( index1 = 0; index1 < 0x100; ++index1 )
    {
        for( index2 = index1, i = 0; i < 5; ++i, index2 += 0x100 )
        {
            uint64_t temp1, temp2;
            seed = (seed * 125 + 3) % 0x2AAAAB;
            temp1 = (seed & 0xFFFF) << 0x10;
            seed = (seed * 125 + 3) % 0x2AAAAB;
            temp2 = (seed & 0xFFFF);
            s_crypt_table[index2] = ( temp1 | temp2 );
        }
    }
    DEF_LOG("%s\n", "初始化hash表 完成");

    return 0;
}

/**
 * @brief The HashInit class 哈希表初始类
 */
class HashInit
{
public:
    HashInit()
    {
        init_hash_table();
    }
};

/// @brief 程序启动前初始化哈希表
static const HashInit hash_init = HashInit();

uint64_t hash(const char *str, size_t str_len, uint32_t hash_type, bool case_sensitive)
{
    const unsigned char *key = reinterpret_cast<const unsigned char *>(str);
    size_t index = 0;

    uint64_t seed1 = 0x7FED7FED, seed2 = 0xEEEEEEEE;
    uint32_t ch;

    while( 0 != *key && index < str_len )
    {
        ch = *key++;

        // 大小写敏感的计算，将大写的英文字母转换成小写字母

        if (!case_sensitive)

        {
            if( ch >= 'A' && ch <= 'Z' )
            {
                ch += 'a' - 'A';
            }
        }

        seed1 = s_crypt_table[(hash_type << 8) + ch] ^ (seed1 + seed2);
        seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;

        ++index;
    }

    return seed1;
}

std::string md5(const char *str, size_t str_len)
{
    if(NULL == str)
    {
        return "";
    }

    MD5_CTX ctx;
    MD5_Init(&ctx);

    MD5_Update(&ctx, (void *)str, str_len);

    unsigned char data[MD5_DIGEST_LENGTH] = {0};
    memset(data, 0, MD5_DIGEST_LENGTH);

    MD5_Final(data, &ctx);

    return crypt::hex::encode(data, MD5_DIGEST_LENGTH);
}

std::string sha1(const char *str, size_t str_len)
{
    if(NULL == str)
    {
        return "";
    }

    SHA_CTX ctx;
    SHA1_Init(&ctx);

    SHA1_Update(&ctx, (void *)str, str_len);

    unsigned char data[SHA_DIGEST_LENGTH] = { 0 };
    memset(data, 0, SHA_DIGEST_LENGTH);

    SHA1_Final(data, &ctx);

    return crypt::hex::encode(data, SHA_DIGEST_LENGTH);
}

std::string sha256(const char *str, size_t str_len)
{
    if(NULL == str)
    {
        return "";
    }


    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    SHA256_Update(&ctx, (void *)str, str_len);

    unsigned char data[SHA256_DIGEST_LENGTH];
    memset(data, 0, SHA256_DIGEST_LENGTH);

    SHA256_Final(data, &ctx);

    return hex::encode(data, SHA256_DIGEST_LENGTH);
}

/**
 * @brief fmd5
 * @param filename
 * @return
 */
std::string fmd5(const char *filename)
{
    if (0 != ::access(filename, F_OK | R_OK))
    {
        return "";
    }

    // fopen是否支持symbolic link
    FILE *fd = fopen(filename, "rb");
    if (nullptr == fd) {
        // std::cout << "not open MD5 file, path: " << filename << std::endl;
        return "";
    }

    MD5_CTX ctx;
    MD5_Init(&ctx);
    const int size = 1024;
    char buffer[size] = { 0 };
    int len = 0;
    while (0 != (len = fread(buffer, 1, size, fd))) {
        MD5_Update(&ctx, (void *)buffer, len);
        memset(buffer, 0, size);
    }
    fclose(fd);

    unsigned char data[MD5_DIGEST_LENGTH] = {0};
    memset(data, 0, MD5_DIGEST_LENGTH);

    MD5_Final(data, &ctx);
    return hex::encode(data, MD5_DIGEST_LENGTH);
}

/**
 * @brief fsha1
 * @param filename
 * @return
 */
std::string fsha1(const char *filename)
{
    if (0 != ::access(filename, F_OK | R_OK))
    {
        return "";
    }

    // fopen是否支持symbolic link
    FILE *fd = fopen(filename, "rb");
    if (nullptr == fd) {
        // std::cout << "not open MD5 file, path: " << filename << std::endl;
        return "";
    }

    SHA_CTX ctx;
    SHA1_Init(&ctx);
    const int size = 1024;
    char buffer[size] = { 0 };
    int len = 0;
    while (0 != (len = fread(buffer, 1, size, fd))) {
        SHA1_Update(&ctx, (void *)buffer, len);
        memset(buffer, 0, size);
    }
    fclose(fd);

    unsigned char data[SHA_DIGEST_LENGTH] = { 0 };
    memset(data, 0, SHA_DIGEST_LENGTH);

    SHA1_Final(data, &ctx);
    return hex::encode(data, SHA_DIGEST_LENGTH);
}

/**
 * @brief fsha256
 * @param filename
 * @return
 */
std::string fsha256(const char *filename)
{
    if (0 != ::access(filename, F_OK | R_OK))
    {
        return "";
    }

    // fopen是否支持symbolic link
    FILE *fd = fopen(filename, "rb");
    if (nullptr == fd) {
        // std::cout << "not open MD5 file, path: " << filename << std::endl;
        return "";
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    const int size = 1024;
    char buffer[size] = { 0 };
    int len = 0;

    while (0 != (len = fread(buffer, 1, size, fd))) {
        SHA256_Update(&ctx, (void *)buffer, len);
        memset(buffer, 0, size);
    }
    fclose(fd);

    unsigned char data[SHA256_DIGEST_LENGTH];
    memset(data, 0, SHA256_DIGEST_LENGTH);

    SHA256_Final(data, &ctx);
    return hex::encode(data, SHA256_DIGEST_LENGTH);
}

}}}
