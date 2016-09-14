package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

func Encrypt(password string, val []byte) (string, error) {

	key := []byte(fixLength(password))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	encrypted := make([]byte, aes.BlockSize+len(val))
	iv := encrypted[:aes.BlockSize]
	msg := encrypted[aes.BlockSize:]
	hash := make([]byte, sha256.Size)

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(msg, val)

	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	hash = mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(append(encrypted, hash...)), nil
}

func Decrypt(password, encrypted string) ([]byte, error) {
	// make sure the key is the proper length:

	val, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	key := []byte(fixLength(password))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(val) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := val[:aes.BlockSize]
	oldHash := val[len(val)-sha256.Size:]
	val = val[aes.BlockSize : len(val)-sha256.Size]

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(val))
	newHash := mac.Sum(nil)

	if !hmac.Equal(oldHash, newHash) {
		return nil, errors.New("invalid hash")
	}

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(val, val)
	return val, nil
}

func fixLength(val string) string {
	if offset := len(val) % aes.BlockSize; offset != 0 {
		val += strings.Repeat("_", aes.BlockSize-offset)
	}
	return val
}
