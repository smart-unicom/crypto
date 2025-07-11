// Package wcipher 用于加密和解密数据的包
package wcipher

import (
	"crypto/cipher"
)

// Cipher 提供统一的加密/解密数据接口
type Cipher interface {
	Encrypt(src []byte) []byte
	Decrypt(src []byte) []byte
}

type blockCipher struct {
	padding Padding
	encrypt cipher.BlockMode
	decrypt cipher.BlockMode
}

// NewBlockCipher 创建新的块加密
func NewBlockCipher(padding Padding, encrypt, decrypt cipher.BlockMode) Cipher {
	return &blockCipher{
		encrypt: encrypt,
		decrypt: decrypt,
		padding: padding,
	}
}

// Encrypt 加密
func (blockCipher *blockCipher) Encrypt(plaintext []byte) []byte {
	plaintext = blockCipher.padding.Padding(plaintext, blockCipher.encrypt.BlockSize())
	ciphertext := make([]byte, len(plaintext))
	blockCipher.encrypt.CryptBlocks(ciphertext, plaintext)
	return ciphertext
}

// Decrypt 解密
func (blockCipher *blockCipher) Decrypt(ciphertext []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	blockCipher.decrypt.CryptBlocks(plaintext, ciphertext)
	plaintext = blockCipher.padding.UnPadding(plaintext)
	return plaintext
}

// ---------------------------------------------------------------------------------------

type streamCipher struct {
	encrypt cipher.Stream
	decrypt cipher.Stream
}

// NewStreamCipher 创建新的流加密
func NewStreamCipher(encrypt cipher.Stream, decrypt cipher.Stream) Cipher {
	return &streamCipher{
		encrypt: encrypt,
		decrypt: decrypt}
}

// Encrypt 流加密
func (streamCipher *streamCipher) Encrypt(plaintext []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	streamCipher.encrypt.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

// Decrypt 流解密
func (streamCipher *streamCipher) Decrypt(ciphertext []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	streamCipher.decrypt.XORKeyStream(plaintext, ciphertext)
	return plaintext
}
