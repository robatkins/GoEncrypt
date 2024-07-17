package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "io"
    "io/ioutil"
    "os"
    "path/filepath"

    "golang.org/x/crypto/pbkdf2"
)

func main() {
    var choice string
    fmt.Println("Do you want to (e)ncrypt or (d)ecrypt a file?")
    fmt.Scanln(&choice)

    fmt.Println("Enter the path to the file or directory:")
    var path string
    fmt.Scanln(&path)

    fmt.Println("Enter a password (will be used to generate a key):")
    var password string
    fmt.Scanln(&password)

    key := generateKeyFromPassword(password)

    info, err := os.Stat(path)
    if os.IsNotExist(err) {
        fmt.Println("Error: File or directory does not exist.")
        return
    } else if err != nil {
        fmt.Println("Error accessing the path:", err)
        return
    }

    if choice == "e" {
        if info.IsDir() {
            err = encryptDirectory(path, key)
        } else {
            err = encryptFile(path, key)
        }
    } else if choice == "d" {
        if info.IsDir() {
            err = decryptDirectory(path, key)
        } else {
            err = decryptFile(path, key)
        }
    } else {
        fmt.Println("Invalid choice. Please enter 'e' to encrypt or 'd' to decrypt.")
        return
    }

    if err != nil {
        fmt.Println("Error processing:", err)
    } else {
        fmt.Println("Operation successful")
    }
}

func generateKeyFromPassword(password string) []byte {
    salt := []byte("unique-salt") // Salt should be unique and consistent
    key := pbkdf2.Key([]byte(password), salt, 4096, 32, sha256.New)
    return key
}

func encryptDirectory(dirPath string, key []byte) error {
    return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if !info.IsDir() {
            return encryptFile(path, key)
        }
        return nil
    })
}

func encryptFile(filePath string, key []byte) error {
    plaintext, err := ioutil.ReadFile(filePath)
    if err != nil {
        return fmt.Errorf("reading file: %v", err)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return fmt.Errorf("creating cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return fmt.Errorf("creating GCM: %v", err)
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return fmt.Errorf("generating nonce: %v", err)
    }

    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

    encryptedFilePath := filePath + ".enc"
    if err := ioutil.WriteFile(encryptedFilePath, ciphertext, 0644); err != nil {
        return fmt.Errorf("writing encrypted file: %v", err)
    }

    return nil
}

func decryptDirectory(dirPath string, key []byte) error {
    return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if !info.IsDir() && filepath.Ext(path) == ".enc" {
            return decryptFile(path, key)
        }
        return nil
    })
}

func decryptFile(filePath string, key []byte) error {
    ciphertext, err := ioutil.ReadFile(filePath)
    if err != nil {
        return fmt.Errorf("reading file: %v", err)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return fmt.Errorf("creating cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return fmt.Errorf("creating GCM: %v", err)
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return fmt.Errorf("decrypting file: %v", err)
    }

    decryptedFilePath := filePath[:len(filePath)-4] // Remove ".enc" extension
    if err := ioutil.WriteFile(decryptedFilePath, plaintext, 0644); err != nil {
        return fmt.Errorf("writing decrypted file: %v", err)
    }

    return nil
}