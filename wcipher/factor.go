package wcipher

import (
	"crypto/aes"
	"crypto/des"
)

// NewAES 创建默认AES密码器，使用ECB工作模式，pkcs57填充，
// 算法密钥长度128 192 256位，使用密钥作为初始向量。
func NewAES(key []byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return NewECBMode().Cipher(block, key[:block.BlockSize()]), err
}

// NewAESWith 根据指定的工作模式创建AES密码器，
// 算法密钥长度为128 192 256位，使用密钥作为初始向量。
func NewAESWith(key []byte, mode CipherMode) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.Cipher(block, key[:block.BlockSize()]), nil
}

// NewDES 创建默认DES密码器，使用ECB工作模式，pkcs57填充，
// 算法密钥长度64位，使用密钥作为初始向量。
func NewDES(key []byte) (Cipher, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return NewECBMode().Cipher(block, key[:block.BlockSize()]), nil
}

// NewDESWith 根据指定的工作模式创建DES密码器，
// 算法密钥长度为64位，使用密钥作为初始向量。
func NewDESWith(key []byte, mode CipherMode) (Cipher, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.Cipher(block, key[:block.BlockSize()]), nil
}
