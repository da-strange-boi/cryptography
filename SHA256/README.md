The SHA256 algorithm as outlined in this [document](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). Test vectors from this [document](https://www.di-mgt.com.au/sha_testvectors.html)

## Example

```cpp
std::string text = "text to be hashed";
std::string hashed = SHA256(text);
// 73745bd3cf0d2069a653a586e6da6884abcab8aca20a3b0769654bdf6bf5d1ee
```

## Todo

* cleanup "word" class
* cleanup wording
* fix the (ugly) fix on line 129