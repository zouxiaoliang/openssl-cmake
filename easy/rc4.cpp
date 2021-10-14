#include "crypt.h"
#include <openssl/rc4.h>

namespace easy { namespace crypt { namespace rc4 {

struct Key
{
    Key(const char *key = 0, size_t key_length = 0)
    {
        init(key, key_length);
    }

    void init(const char *key, size_t key_length)
    {
        if (NULL != key && 0 != key_length)
        {
            m_key.assign(key, key_length);
        }

        ::memset(&m_rc4_key, 0x0, sizeof(m_rc4_key));
        RC4_set_key(&m_rc4_key, m_key.size(), (unsigned char *)m_key.c_str());
    }

    std::string m_key;
    RC4_KEY m_rc4_key;
};

KeyPtr make_key(const char *key, size_t key_length)
{
    auto k = std::make_shared<Key>(key, key_length);
    return k;
}

Coder::Coder(const char *key, size_t key_length)
{
    m_key = rc4::make_key(key, key_length);
}

Coder::~Coder()
{

}

void Coder::init(const char *key, size_t key_length)
{
    if (m_key) m_key->init(key, key_length);
}

bool Coder::code(const unsigned char *bytes_in, unsigned char *bytes_out, size_t bytes_length)
{
    if (NULL == bytes_in || NULL == bytes_out || 0 == bytes_length)
    {
        return false;
    }

    RC4(&m_key->m_rc4_key, bytes_length, bytes_in, bytes_out);
    return true;
}

}}}
