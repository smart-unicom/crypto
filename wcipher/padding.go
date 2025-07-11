package wcipher

import (
	"bytes"
)

// Padding 为各种填充方法提供统一的数据填充/恢复接口
type Padding interface {
	Padding(src []byte, blockSize int) []byte
	UnPadding(src []byte) []byte
}

type padding struct{}

type pkcs57Padding padding

// NewPKCS57Padding 创建新的PKCS57填充
func NewPKCS57Padding() Padding {
	return &pkcs57Padding{}
}

// Padding PKCS57填充
func (p *pkcs57Padding) Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(src, padText...)
}

// UnPadding PKCS57去填充
func (p *pkcs57Padding) UnPadding(src []byte) []byte {
	length := len(src)
	unPadding := int(src[length-1])
	return src[:(length - unPadding)]
}
