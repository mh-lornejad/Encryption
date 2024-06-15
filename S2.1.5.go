package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
)

func encryptAES(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

    return ciphertext, nil
}

func main() {
    key := []byte("32-byte-long-encryption-key") // Replace with your AES key
    plaintext := []byte("Hello, AES encryption!")

    ciphertext, err := encryptAES(key, plaintext)
    if err != nil {
        fmt.Println("Error encrypting:", err)
        return
    }

    fmt.Println("Encrypted:", base64.StdEncoding.EncodeToString(ciphertext))
}
