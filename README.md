# aes-sbox
Golang AES Sbox implementation

https://golang.org/pkg/crypto/aes/

# Encryption method

- Encrypt a message using aes key
- Encrypt a file using aes key
- Encrypt a file using a message as a key

- Mode: CTR, CBC, CFB, OFB (https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

# Sample command

- Encrypt a message using aes key
- Usage: `aes_sbox --help`

After Encryption: Key and encrypted file will be put into `crypto` folder.

After Decryption: The decrypted file will be put into `output` folder with its original extension.

## CTR
```
$ aes_sbox -do "encrypt" -mode "CTR" -keysize 32 -file "test_img.jpg"
```

```
$ aes_sbox -do "decrypt" -mode "CTR" -keysize 32 -file "test_img.jpg"
```
## CFB
```
$ aes_sbox -do "encrypt" -mode "CFB" -keysize 32 -file "test_img.jpg"
```

```
$ aes_sbox -do "decrypt" -mode "CFB" -keysize 32 -file "test_img.jpg"
```
## OFB
```
$ aes_sbox -do "encrypt" -mode "OFB" -keysize 32 -file "test_img.jpg"
```

```
$ aes_sbox -do "decrypt" -mode "OFB" -keysize 32 -file "test_img.jpg"
```

# Contact
vnkeymaster(at)gmail.com
