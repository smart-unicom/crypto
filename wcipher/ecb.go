package wcipher

import (
	"crypto/cipher"
)

type ecb struct {
	block     cipher.Block
	blockSize int
}

type ecbEncrypt ecb

func (e *ecbEncrypt) BlockSize() int {
	return e.blockSize
}

func (e *ecbEncrypt) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("crypto/cipher: 输入不是完整块")
	}
	for len(src) > 0 {
		e.block.Encrypt(dst, src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}

type ecbDecrypt ecb

func (e *ecbDecrypt) BlockSize() int {
	return e.blockSize
}

func (e *ecbDecrypt) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("crypto/cipher: 输入不是完整块")
	}
	for len(src) > 0 {
		e.block.Decrypt(dst, src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}

// NewECBEncrypt ECB加密
func NewECBEncrypt(block cipher.Block) cipher.BlockMode {
	return &ecbEncrypt{block: block, blockSize: block.BlockSize()}
}

// NewECBDecrypt ECB解密
func NewECBDecrypt(block cipher.Block) cipher.BlockMode {
	return &ecbDecrypt{block: block, blockSize: block.BlockSize()}
}
