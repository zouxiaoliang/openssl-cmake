#ifndef CRYPT_H
#define CRYPT_H

#include <stddef.h>
#include <string.h>
#include <string>

#include <memory>

namespace easy { namespace crypt {

static const unsigned char my_key[16] = {'x', 'k', '0', 'h', '7', 'O','6','b','w','z','w','y','4','S','q','Z'};
static const unsigned char my_iv[16] = {'x', 'k', '0', 'h', '7', 'O','6','b','w','z','w','y','4','S','q','Z'};

namespace aes {

struct Key;
typedef std::shared_ptr<Key> KeyPtr;
extern KeyPtr make_key(int type, const char *key, size_t key_length, const char *iv, size_t iv_length);

namespace ecb {

/**
 * @brief encrypt 加密算法
 * @param source_content 原始消息内容
 * @param length 原始消息长度
 * @param key 密钥
 * @return 加密后内容
 */
std::string encrypt(const char *source_content, size_t length, const unsigned char *key, size_t key_len);

/**
 * @brief decrypt 解密算法
 * @param encrypt_content 加密后消息内容
 * @param length 加密后消息长度
 * @param key 密钥
 * @return  原始消息内容
 */
std::string decrypt(const char *encrypt_content, size_t length, const unsigned char *key, size_t key_len);

}
namespace cfb {
/**
 * @brief crypt 加解密算法
 * @param content 待处理数据
 * @param length 待处理内容长度
 * @param key 密钥
 * @param key_len 密钥
 * @param iv_src 空间向量
 * @param iv_len 空间大小
 * @param enc AES_ENCRYPT: 加密; AES_DECRYPT: 解密
 * @return 加解密后的数据
 */
std::string crypt(
        const char *content, size_t length,
        const unsigned char *key, size_t key_len,
        const unsigned char *iv_src, size_t iv_len,
        const int enc);
}
namespace cbc {
/**
 * @brief encrypt 加密算法
 * @param content 明文
 * @param length 明文长度
 * @param key 密钥
 * @param key_len 密钥长度
 * @attention
 *  1、对较短的文本进行加密
 *  2、对加密得到的是字节流，需要外部自行用base64或hex进行处理称字符串
 * @return 密文
 */
std::string encrypt(const char *content, size_t length,
                    const char *key, size_t key_len);

std::string encrypt(const char *content, size_t length, Key &key);

/**
 * @brief decrypt 解密算法
 * @param content 密文
 * @param length 密文长度
 * @param key 密钥
 * @param key_len 对较短的文本进行解密
 * @attention 解密得到的是一个C类型的字符串
 * @return 明文
 */
std::string decrypt(const char *content, size_t length,
                    const char *key, size_t key_len);

std::string decrypt(const char *content, size_t length, Key &key);
}
}

namespace base64 {
/**
 * @brief encode 对字符串内容进行编码
 * @param source_content 原始消息内容
 * @return 编码后的消息内容
 */
std::string encode(const std::string &source_content);

/**
 * @brief decode 对字符串内容进行解码
 * @param encode_content 编码后的消息内容
 * @return 原始消息内容
 */
std::string decode(const std::string &encode_content);
}

namespace hex {
/**
 * @brief encode 将字节流加密为16进制字符串
 * @param input[in] 加密的字节流
 * @param input_len[in] 字节流长度
 * @return 加密后的字符串
 */
std::string encode(const unsigned char* input, size_t input_len);

/**
 * @brief encode 将字节流加密为16进制字符串
 * @param input[in] 加密的字节流
 * @param output[out] 加密后的字符串
 */
void encode(const std::string &input, std::string &output);

/**
 * @brief decode 将16进制字符串解码成字节流
 * @param input[in] 解码字节串
 * @param input_len[in] 字符串长度
 * @param output[out] 解码后的原始字符串
 */
void decode(const char* input, const int input_len, std::string &output);
}

namespace hash {

/**
 * @brief hash 字符串哈希算法
 * @param str 待hash的字符串
 * @param str_len 字符串长度
 * @param hash_type 哈希偏移标识
 * @param case_sensitive 是否大消息敏感，默认是敏感的
 * @return 哈希值
 */
uint64_t hash(const char *str, size_t str_len, uint32_t hash_type = 1, bool case_sensitive = true);

/**
 * @brief md5 对一段流计算MD5算法
 * @param str 内容指针
 * @param str_len 内容长度
 * @return md5
 */
std::string md5(const char *str, size_t str_len);

/**
 * @brief sha1 对一段流计算sha1算法
 * @param str 内容指针
 * @param str_len 内容长度
 * @return sha1
 */
std::string sha1(const char *str, size_t str_len);

/**
 * @brief sha256 对一段流计算sha1算法
 * @param str 内容指针
 * @param str_len 内容长度
 * @return sha256
 */
std::string sha256(const char *str, size_t str_len);

/**
 * @brief fmd5
 * @param filename
 * @return
 */
std::string fmd5(const char *filename);

/**
 * @brief fsha1
 * @param filename
 * @return
 */
std::string fsha1(const char *filename);

/**
 * @brief fsha256
 * @param filename
 * @return
 */
std::string fsha256(const char *filename);
}

namespace rc4 {

struct Key;
typedef std::shared_ptr<Key> KeyPtr;
extern KeyPtr make_key(const char *key = 0, size_t key_length = 0);

class Coder
{
public:
    /**
     * @brief Coder
     * @param key 密码
     * @param key_length 密码长度
     */
    Coder(const char *key = 0, size_t key_length = 0);
    Coder(rc4::KeyPtr key);
    ~Coder();

    /**
     * @brief init 初始化对象，如果在构造函数没有设置key可以通过init来重置key
     * @param key 密码
     * @param key_length 密码长度
     */
    void init(const char *key = 0, size_t key_length = 0);

    /**
     * @brief code 编码
     * @param bytes_in 输入
     * @param bytes_out 输出
     * @param bytes_length 长度，输入和输出长度必须一致
     * @return true: 成功; false: 失败
     */
    bool code(const unsigned char *bytes_in, unsigned char *bytes_out, size_t bytes_length);

private:
    rc4::KeyPtr m_key;
};

}

}}

#endif // CRYPT_H
