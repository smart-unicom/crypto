package wcipher

import (
	"crypto/cipher"
)

// CipherMode 为不同操作模式提供统一的填充方法设置接口
type CipherMode interface {
	SetPadding(padding Padding) CipherMode
	Cipher(block cipher.Block, iv []byte) Cipher
}

type cipherMode struct {
	padding Padding
}

// SetPadding 设置填充方式
func (c *cipherMode) SetPadding(padding Padding) CipherMode {
	_ = padding
	return c
}

// Cipher 模式密码器
func (c *cipherMode) Cipher(block cipher.Block, iv []byte) Cipher {
	_ = block
	_ = iv
	return nil
}

type ecbCipherModel cipherMode

// NewECBMode 创建新的ECB模式
func NewECBMode() CipherMode {
	return &ecbCipherModel{padding: NewPKCS57Padding()}
}

// SetPadding 设置ECB填充方式
func (ecb *ecbCipherModel) SetPadding(padding Padding) CipherMode {
	ecb.padding = padding
	return ecb
}

// Cipher ECB密码器
func (ecb *ecbCipherModel) Cipher(block cipher.Block, iv []byte) Cipher {
	_ = iv
	encrypter := NewECBEncrypt(block)
	decrypter := NewECBDecrypt(block)
	return NewBlockCipher(ecb.padding, encrypter, decrypter)
}

type cbcCipherModel cipherMode

// NewCBCMode 创建新的CBC模式
func NewCBCMode() CipherMode {
	return &cbcCipherModel{padding: NewPKCS57Padding()}
}

// SetPadding 设置CBC填充方式
func (cbc *cbcCipherModel) SetPadding(padding Padding) CipherMode {
	cbc.padding = padding
	return cbc
}

// Cipher CBC密码器
func (cbc *cbcCipherModel) Cipher(block cipher.Block, iv []byte) Cipher {
	encrypter := cipher.NewCBCEncrypter(block, iv)
	decrypter := cipher.NewCBCDecrypter(block, iv)
	return NewBlockCipher(cbc.padding, encrypter, decrypter)
}

type cfbCipherModel cipherMode

// NewCFBMode 创建新的CFB模式
func NewCFBMode() CipherMode {
	return &ofbCipherModel{}
}

// Cipher CFB密码器
func (cfb *cfbCipherModel) Cipher(block cipher.Block, iv []byte) Cipher {
	encrypter := cipher.NewCFBEncrypter(block, iv)
	decrypter := cipher.NewCFBDecrypter(block, iv)
	return NewStreamCipher(encrypter, decrypter)
}

type ofbCipherModel struct {
	cipherMode
}

// NewOFBMode 创建新的OFB模式
func NewOFBMode() CipherMode {
	return &ofbCipherModel{}
}

// Cipher OFB密码器
func (ofb *ofbCipherModel) Cipher(block cipher.Block, iv []byte) Cipher {
	encrypter := cipher.NewOFB(block, iv)
	decrypter := cipher.NewOFB(block, iv)
	return NewStreamCipher(encrypter, decrypter)
}

type ctrCipherModel struct {
	cipherMode
}

// NewCTRMode 创建新的CTR模式
func NewCTRMode() CipherMode {
	return &ctrCipherModel{}
}

// Cipher CTR密码器
func (ctr *ctrCipherModel) Cipher(block cipher.Block, iv []byte) Cipher {
	encrypter := cipher.NewCTR(block, iv)
	decrypter := cipher.NewCTR(block, iv)
	return NewStreamCipher(encrypter, decrypter)
}
