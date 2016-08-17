package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

const (
	OutFolder     = "output/"
	CryptoFolder  = "crypto/"
	KeyFile       = CryptoFolder + "aes.%s.%d.key"
	EncryptedFile = CryptoFolder + "aes.%s.%d.enc"
)

var (
	IVector = []byte("batman and robin") // 16 bytes
	keySize = flag.Int("keysize", 32, "The keysize in bytes to use: 16, 24, or 32 (default)")
	do      = flag.String("do", "encrypt", "The operation to perform: decrypt or encrypt (default) ")
	theFile = flag.String("file", "", "The file for AES encrypt/decrypt that you want")
	theKey  = flag.String("key", "testtesttest", "The key for encryption")
	mode    = flag.String("mode", "ctr", "Mode of AES: CTR, CBC, CFB, OFG ")
)

func MakeKey() []byte {
	key := make([]byte, *keySize)

	n, err := rand.Read(key)
	if err != nil {
		log.Fatalf("failed to read new random key: %s", err)
	}
	if n < *keySize {
		log.Fatalf("failed to read entire key, only read %d out of %d", n, *keySize)
	}
	return key
}

func SaveKey(filename string, key []byte) {
	block := &pem.Block{
		Type:  "AES KEY",
		Bytes: key,
	}
	err := ioutil.WriteFile(filename, pem.EncodeToMemory(block), 0644)
	if err != nil {
		log.Fatalf("failed saving key to %s: %s", filename, err)
	}
}

func ReadKey(filename string) ([]byte, error) {
	key, err := ioutil.ReadFile(filename)
	if err != nil {
		return key, err
	}
	block, _ := pem.Decode(key)
	return block.Bytes, nil
}

func Key() []byte {
	file := fmt.Sprintf(KeyFile, *theFile, *keySize)
	key, err := ReadKey(file)
	if err != nil {
		log.Println("failed reading keyfile, making a new one...")
		key = MakeKey()
		SaveKey(file, key)
	}
	return key
}

func MakeCipher() cipher.Block {
	c, err := aes.NewCipher(Key())
	if err != nil {
		log.Fatalf("failed making the AES cipher: %s", err)
	}
	return c
}

func ReadFromFile(file string) ([]byte, error) {
	data, err := ioutil.ReadFile(file)
	return data, err
}

func WriteToFile(data []byte, file string) {
	ioutil.WriteFile(file, data, 777)
}

func Crypt(bytes []byte, isDecrypt bool) []byte {

	var stream cipher.Stream
	var block cipher.BlockMode

	blockCipher := MakeCipher()
	switch strings.ToUpper(*mode) {
	case "CTR":
		stream = cipher.NewCTR(blockCipher, IVector)
		stream.XORKeyStream(bytes, bytes)
	case "CFB":
		if isDecrypt {
			stream = cipher.NewCFBDecrypter(blockCipher, IVector)
		} else {
			stream = cipher.NewCFBEncrypter(blockCipher, IVector)
		}
		stream.XORKeyStream(bytes, bytes)
	case "CBC":
		// return block
		if isDecrypt {
			block = cipher.NewCBCDecrypter(blockCipher, IVector)
		} else {
			block = cipher.NewCBCEncrypter(blockCipher, IVector)
		}
		block.CryptBlocks(bytes, bytes)
	case "OFB":
		stream = cipher.NewOFB(blockCipher, IVector)
		stream.XORKeyStream(bytes, bytes)
	default:
		log.Fatalf("unknown cipher mode: %s", *mode)
	}

	return bytes
}

func Encrypt() {
	content, err := ReadFromFile(*theFile)
	encrypted := Crypt(content, false)
	err = ioutil.WriteFile(fmt.Sprintf(EncryptedFile, *theFile, *keySize), encrypted, 0644)
	if err != nil {
		log.Fatalf("failed writing encrypted file: %s", err)
	}
}

func Decrypt() {

	encFileName := fmt.Sprintf(EncryptedFile, *theFile, *keySize)
	bytes, err := ioutil.ReadFile(encFileName)
	if err != nil {
		log.Fatalf("failed reading encrypted file: %s", err)
	}
	output := Crypt(bytes, true)
	fullDir := strings.Split(encFileName, "/")
	file := strings.Split(fullDir[len(fullDir)-1], ".")
	decFileName := OutFolder + strings.Join(file[1:len(file)-2], ".")
	WriteToFile(output, decFileName)
}

func main() {
	flag.Parse()

	if _, err := os.Stat(*theFile); os.IsNotExist(err) {
		log.Fatalf("%s is not a file.", *theFile)
	}

	switch *keySize {
	case 16, 24, 32:
		// Keep calm and carry on...
	default:
		log.Fatalf("%d is not a valid keysize. Must be one of 16, 24, 32", *keySize)
	}

	switch *do {
	case "encrypt":
		Encrypt()
	case "decrypt":
		Decrypt()
	default:
		log.Fatalf("%s is not a valid operation. Must be one of encrypt or decrypt", *do)
	}
}
