The ChaCha20 alogirthm as outlined in this [document](https://datatracker.ietf.org/doc/html/rfc8439)

## Example

```cpp
std::string key = "some long key";
std::string text = "very secret text to never be shown";
std::vector<uint32> nonce = { 0x00000000, 0x0000004a, 0x00000000 };

// Encrypt text
std::vector<uint8> ciphertext = ChaCha20Encrypt(serialize(str_to_uint8(key)), 1, to32bit(serialize(nonce)), str_to_uint8(text));
// Decrypt the encrypted data
std::vector<uint8> plaintext = ChaCha20Decrypt(serialize(str_to_uint8(key)), 1, to32bit(serialize(nonce)), ciphertext);

// print each letter
for (int i = 0; i < plaintext.size(); i++)
    std::cout << (char)plaintext[i];
```

## Todo

* "pretty up" the functions
* ChaCha20Block test fails due to being outdated
* Add the Poly1305 authenticator