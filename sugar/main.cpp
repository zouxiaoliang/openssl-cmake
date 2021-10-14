#include <iostream>

#include <easy/crypt.h>

int main(int argc, char* argv[]) {
    const char* hl = "hello world!!!";
    std::cout << hl << std::endl;
    std::cout << "md5: " << easy::crypt::hash::md5(hl, strlen(hl)) << std::endl;
    return 0;
}
