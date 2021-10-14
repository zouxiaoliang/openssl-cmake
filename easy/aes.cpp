#include "crypt.h"
#include "openssl/aes.h"

namespace easy { namespace  crypt { namespace aes {

struct Key
{
    Key(int type,
        const char *key, size_t key_length,
        const char *iv = 0, size_t iv_length = 0);

    inline bool valid() { return m_valid; }

    std::string m_key;
    std::string m_iv;

    mutable AES_KEY m_aes_key;
    bool m_valid;
};

KeyPtr make_key(int type, const char *key, size_t key_length, const char *iv, size_t iv_length)
{
    auto k = std::make_shared<Key>(type, key, key_length, iv, iv_length);
    if (!k->valid()) return nullptr;

    return k;
}

Key::Key(int type, const char *key, size_t key_length, const char *iv, size_t iv_length)
{
    m_key.assign(key, key_length);
    if (NULL == iv || 0 == iv_length)
    {
        m_iv.assign(key, key_length);
    }
    else
    {
        m_iv.assign(iv, iv_length);
    }

    if (AES_ENCRYPT == type)
        m_valid = AES_set_encrypt_key((const unsigned char*)m_key.c_str(), m_key.length() * 8, &m_aes_key) >= 0;
    else
        m_valid = AES_set_decrypt_key((const unsigned char*)m_key.c_str(), m_key.length() * 8, &m_aes_key) >= 0;
}

std::string ecb::encrypt(const char *source_content, size_t length, const unsigned char *key, size_t key_len)
{
    if (NULL == source_content || 0 == length || NULL == key || 128 != key_len) {
        return "";
    }

    AES_KEY aes;
    if(AES_set_encrypt_key(key, key_len, &aes) < 0)
    {
        return "";
    }

    std::string output;
    char in[AES_BLOCK_SIZE];
    char out[AES_BLOCK_SIZE];

    for (size_t i = length; 0 != i; i = (i >= AES_BLOCK_SIZE ? i - AES_BLOCK_SIZE: 0))
    {
        ::bzero(in, AES_BLOCK_SIZE);
        ::bzero(out, AES_BLOCK_SIZE);
        memcpy(in, &source_content[length - i], (i >= AES_BLOCK_SIZE ? AES_BLOCK_SIZE: i));
        AES_ecb_encrypt((unsigned char *)in, (unsigned char *)out, &aes, AES_ENCRYPT);
        output += std::string(out, AES_BLOCK_SIZE);
    }
    return output;
}

std::string ecb::decrypt(const char *encrypt_content, size_t length, const unsigned char *key, size_t key_len)
{
    if (NULL == encrypt_content || 0 == length || NULL == key || 128 != key_len)
    {
        return "";
    }

    AES_KEY aes;
    if(AES_set_decrypt_key(key, key_len, &aes) < 0)
    {
        return "";
    }

    std::string output;
    char out[AES_BLOCK_SIZE + 1];
    for (size_t i = 0; i < length; i += AES_BLOCK_SIZE)
    {
        ::bzero(out, AES_BLOCK_SIZE + 1);
        AES_ecb_encrypt((unsigned char *)&encrypt_content[i], (unsigned char *)out, &aes, AES_DECRYPT);
        output += out;
    }
    return output;
}

std::string cfb::crypt(const char *content, size_t length,
                                   const unsigned char *key, size_t key_len,
                                   const unsigned char *iv_src, size_t iv_len,
                                   const int enc)
{
    if (NULL == content || 0 == length
        || NULL == key || 128 != key_len
        || NULL == iv_src || 128 !=iv_len
        || (enc != AES_DECRYPT && enc != AES_ENCRYPT))
    {
        return "";
    }

    AES_KEY aes;
    if(AES_set_encrypt_key(key, key_len, &aes) < 0)
    {
        return "";
    }

    std::string output;
    char in[AES_BLOCK_SIZE];
    char out[AES_BLOCK_SIZE];

    unsigned char iv[16];
    ::bzero(iv, sizeof(iv));
    memcpy(iv, iv_src, (sizeof(iv) > iv_len ? iv_len : sizeof(iv)));

    int num = 0;
    for (size_t i = length; 0 != i; i = (i >= AES_BLOCK_SIZE ? i - AES_BLOCK_SIZE: 0))
    {
        ::bzero(in, AES_BLOCK_SIZE);
        ::bzero(out, AES_BLOCK_SIZE);
        memcpy(in, &content[length - i], (i >= AES_BLOCK_SIZE ? AES_BLOCK_SIZE: i));
        AES_cfb128_encrypt((unsigned char *)in, (unsigned char *)out, AES_BLOCK_SIZE, &aes, iv, &num, enc);
        output += std::string(out, AES_BLOCK_SIZE);
    }
    return output;
}

/**
 * @brief pad 对原始消息进行padding
 * @param content 原始消息内容
 * @param p 填充内容
 */
void pad(std::string &content, char p = '\0')
{
    size_t length = 16;
    // 计算需要填充的字节数
    size_t add = length - (content.length() % length);
    content += std::string(add, p);
}

std::string cbc::encrypt(const char *content, size_t length, const char *key, size_t key_len)
{
    if (NULL == content || 0 == length || NULL == key || 16 != key_len)
    {
        return "";
    }

    AES_KEY enc_key;
    if (AES_set_encrypt_key((const unsigned char*)key, key_len * 8, &enc_key) < 0)
    {
        return "";
    }

    unsigned char iv[AES_BLOCK_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    memcpy(iv, key, AES_BLOCK_SIZE);

    std::string text(content, length);
    pad(text);

    // 计算加密前的长度
    size_t before = (length + AES_BLOCK_SIZE) & (~AES_BLOCK_SIZE);
    // 计算加密后的长度
    size_t after = (before / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

    std::string out;
    out.reserve(after);
    out.resize(after);

    AES_cbc_encrypt(
        (const unsigned char *)text.c_str(),
        (unsigned char *)out.c_str(),
        text.length(),
        &enc_key,
        iv,
        AES_ENCRYPT
        );

    return out;
}

std::string cbc::encrypt(const char *content, size_t length, Key &key)
{
    if (NULL == content || 0 == length || !key.valid())
    {
        return "";
    }

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, key.m_iv.c_str(),  AES_BLOCK_SIZE);

    std::string text(content, length);
    pad(text);

    // 计算加密前的长度
    size_t before = (length + AES_BLOCK_SIZE) & (~AES_BLOCK_SIZE);
    // 计算加密后的长度
    size_t after = (before / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

    std::string out;
    out.reserve(after);
    out.resize(after);

    AES_cbc_encrypt(
        (const unsigned char *)text.c_str(),
        (unsigned char *)out.c_str(),
        text.length(),
        &key.m_aes_key,
        iv,
        AES_ENCRYPT
        );

    return out;
}

std::string cbc::decrypt(const char *content, size_t length, const char *key, size_t key_len)
{
    if (NULL == content || 0 == length || NULL == key || 16 != key_len)
    {
        return "";
    }

    AES_KEY dec_key;
    if (AES_set_decrypt_key((const unsigned char*)key, key_len * 8, &dec_key) < 0)
    {
        return "";
    }

    unsigned char iv[AES_BLOCK_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    memcpy(iv, key, AES_BLOCK_SIZE);

    std::string out;
    out.reserve(length);
    out.resize(length);

    AES_cbc_encrypt(
        (const unsigned char *)content,
        (unsigned char *)out.c_str(),
        length,
        &dec_key,
        iv,
        AES_DECRYPT
        );

    return out.c_str();
}

std::string cbc::decrypt(const char *content, size_t length, Key &key)
{
    if (NULL == content || 0 == length || !key.valid())
    {
        return "";
    }

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, key.m_iv.c_str(),  AES_BLOCK_SIZE);

    std::string out;
    out.reserve(length);
    out.resize(length);

    AES_cbc_encrypt(
        (const unsigned char *)content,
        (unsigned char *)out.c_str(),
        length,
        &key.m_aes_key,
        iv,
        AES_DECRYPT
        );

    return out.c_str();
}

}}}
