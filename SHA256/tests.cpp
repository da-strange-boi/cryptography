#include <iostream>
#include <string>
#include "SHA.cpp"

// https://www.di-mgt.com.au/sha_testvectors.html

bool test(std::string s1, std::string s2) {
    return s1 == s2;
}

int main() {
    bool test1 = test("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", SHA256("abc"));
    bool test2 = test("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", SHA256(""));
    bool test3 = test("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", SHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
    bool test4 = test("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1", SHA256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));

    // one million (1,000,000) repetitions of the character "a"
    std::string test5M = "";
    for (int i = 0; i < 1000000; i++) {
        test5M += "a";
    }
    bool test5 = test("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", SHA256(test5M));

    bool result = test1 && test2 && test3 && test4 && test5;
    std::cout << "Test 1: " << (test1 ? "Passed" : "Failed") << std::endl;
    std::cout << "Test 2: " << (test2 ? "Passed" : "Failed") << std::endl;
    std::cout << "Test 3: " << (test3 ? "Passed" : "Failed") << std::endl;
    std::cout << "Test 4: " << (test4 ? "Passed" : "Failed") << std::endl;
    std::cout << "Test 5: " << (test5 ? "Passed" : "Failed") << std::endl;
    std::cout << "\nTest Status: " << (result ? "Passed" : "Failed") << std::endl;

    return 0;
}

